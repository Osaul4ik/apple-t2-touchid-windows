# Capture and power-resume architecture

## Ownership

- `T2SepBootstrap` unlocks SEP once per boot. Neither lock-screen capture nor a
  sleep/resume transition reruns that bootstrap.
- Windows Biometric Framework (WBF) owns the single `CAPTURE_DATA` request.
  The WBDI driver keeps that same request pending across sleep unless Windows
  itself cancels it.
- Apple BiometricKit owns the active fingerprint match transaction. A
  transaction must not remain active across system suspend. The driver
  discards any result from the interrupted transaction and sends BiometricKit
  `Cancel`.
- After resume, if the original WBF request is still pending, the driver starts
  a new BiometricKit `verify` transaction to service that same request. This is
  not a new WBF request and does not repeat SEP bootstrap/unlock.

## Power state flow

```text
WBF CAPTURE_DATA pending
        |
        | suspend notification / WDF queue stop
        v
invalidate pre-sleep result -> BiometricKit Cancel
        |
        | keep WBF request pending; no active StartMatch during sleep
        v
system suspended
        |
        | resume notification / EvtIoResume
        v
if WBF has not canceled: run a fresh BiometricKit verify for same request
        |
        +-- WBF CancelIoEx at any time -> complete as canceled, stop
        +-- match -> return sample to WBF
```

The power callback only signals the capture worker; it does not perform
BridgeXPC work itself. The worker unwinds `Verify`, whose cancel guard sends
command 12, rejects the pre-suspend outcome, waits for resume, then reconnects
and starts the next match only while the original WBF request remains live.

## Linux BiometricKit command parity

The Windows verify path is aligned with Linux `src/t2-fprintd.py` and
`src/bridge-xpc-probe.py` for each actual verification transaction:

1. BridgeXPC HELO, get bridge version, set client version.
2. BiometricKit command 2 (`ResetSensor`, value 2).
3. BiometricKit command 12 (`Cancel` any stale operation).
4. Get FDR calibration (BridgeXPC method 11), then command `0x20` with value
   3 and the FDR data.
5. Command `0x42` per-user identity list.
6. Stability gate: commands `0x51`, `0x42`, `0x51`; compare the user/global
   identity views before matching.
7. Command 4 (`StartMatch`) with Linux counted identity payload.
8. Receive and acknowledge each BridgeXPC event; derive the result only from a
   valid `match_result` event.
9. Command 12 (`Cancel`) after the match transaction ends.
10. Re-read commands `0x42` and `0x51`; reject the result if identity inventory
    changed during matching.

When a touch returns `NO_MATCH`, that BiometricKit transaction ends with the
same Cancel and post-match attestation. The pending WBF capture then starts the
next full verify transaction, rather than sending a bare repeated `StartMatch`.

The WBF adapter still has Windows-specific request ownership, cancellation,
and sample-delivery behavior. The active SEP verification's command ordering
and cleanup follow Linux; WBF may also issue its observed second capture after
one successful sample, which the driver handles as a short-lived replay of
that same result rather than a second physical scan.

## Microsoft contracts and validation

Microsoft documents `CAPTURE_DATA` as pending until capture completes or the
client cancels it. WDF `EvtIoStop` must complete, requeue, or acknowledge a
request whose power-managed queue is stopping; when the driver retains
ownership with `WdfRequestStopAcknowledge(FALSE)`, WDF calls `EvtIoResume` when
the device returns to D0. The power path follows that ownership model and also
uses a process-level suspend notification because hardware logs show this
root-enumerated device does not receive `EvtIoStop` for system sleep.

References:

- [Supporting Biometric IOCTL Calling Sequence](https://learn.microsoft.com/en-us/windows-hardware/drivers/biometric/supporting-biometric-ioctl-calling-sequence)
- [EVT_WDF_IO_QUEUE_IO_STOP](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfio/nc-wdfio-evt_wdf_io_queue_io_stop)
- [EVT_WDF_IO_QUEUE_IO_RESUME](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfio/nc-wdfio-evt_wdf_io_queue_io_resume)
- [Linux reference: t2-fprintd.py](https://github.com/jmurth1234/t2-touchid-linux/blob/main/src/t2-fprintd.py)
- [Linux reference: bridge-xpc-probe.py](https://github.com/jmurth1234/t2-touchid-linux/blob/main/src/bridge-xpc-probe.py)

The Windows code has not been compiled or exercised on hardware in this
environment. Sleep/resume and cold-boot verification still require WDK build
and T2-device validation.

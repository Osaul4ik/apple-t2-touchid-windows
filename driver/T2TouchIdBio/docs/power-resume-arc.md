# WBF power/resume architecture

## Ownership and contract

The stack has four owners with deliberately narrow responsibilities:

1. **Windows Biometric Framework / LogonUI** owns the authentication session. It decides when to activate a biometric unit and submits `IOCTL_BIOMETRIC_CAPTURE_DATA`. An adapter cannot safely manufacture a new LogonUI authentication request after resume.
2. **The WBDI UMDF device** answers biometric IOCTLs, keeps at most one capture pending, supports cancellation, and reports the sensor state. `IOCTL_BIOMETRIC_RESET` returns the device to a known/idle state.
3. **The engine adapter** consumes only the sample returned by the sensor path, clears volatile match/enrollment state at suspend/resume, and never creates authentication work itself.
4. **The T2/SEP bridge** performs one fresh verification for each actual WBF capture. A match is returned only for a live capture; pre-sleep results are never replayed across a power transition.

Microsoft documents `SensorAdapterActivate` as taking the sensor out of idle, `SensorAdapterDeactivate` as putting it into idle, and `SensorAdapterNotifyPowerChange` as preparing the sensor for a power transition. WBDI capture requests must remain pending until completion/cancel and must support cancellation. `IOCTL_BIOMETRIC_RESET` resets the sensor to a known or idle state. These contracts do not give a driver an API to ask LogonUI to start a new authentication attempt.

References:

- [Sensor Adapter Functions](https://learn.microsoft.com/en-us/windows/win32/secbiomet/sensor-adapter-functions)
- [PIBIO_ENGINE_NOTIFY_POWER_CHANGE_FN](https://learn.microsoft.com/en-us/windows/win32/api/winbio_adapter/nc-winbio_adapter-pibio_engine_notify_power_change_fn)
- [Supporting Biometric IOCTL Calling Sequence](https://learn.microsoft.com/en-us/windows-hardware/drivers/biometric/supporting-biometric-ioctl-calling-sequence)
- [Biometric overview / WBDI IOCTLs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/_biometric/)

## Resume state flow

```text
WBF CAPTURE pending
       |
       | PBT_APMSUSPEND
       v
Cancel the SEP wait -> complete WBDI request as CANCELED + SENSOR_READY
       |
       | system resumes
       v
Invalidate volatile state; arm one-shot warm-up; clear stale cancel state
       |
       | WBF decides whether to restart sign-in capture
       +---- no new CAPTURE_DATA ----> driver cannot authenticate or re-arm
       |
       +---- fresh CAPTURE_DATA ----> reset/calibrate if needed -> fresh match
```

The supplied trace follows the upper `no new CAPTURE_DATA` branch after resume: `NotifyPowerChange` and the UMDF resume callback run, then the engine gets `Deactivate`. There is no subsequent `Activate` or capture until about 444 seconds into the trace. That later capture performs reset and calibration and returns a real `MATCH`. This points to WBF/LogonUI session lifecycle, not a broken fingerprint template or a dead T2 transport.

## Changes in this revision

- `EngineNotifyPowerChange` now handles only the three events documented for the engine callback. For `PBT_APMPOWERSTATUSCHANGE` (decimal 10, which is what the trace records), it calls `GetSystemPowerStatus` and leaves any in-flight sample alone. Suspend/resume clears only volatile sample and enrollment state.
- A suspend generation distinguishes power interruption from ordinary cancellation. A capture interrupted by sleep completes with `WINBIO_E_CANCELED` and `WINBIO_SENSOR_READY`; it cannot be mislabeled as `WINBIO_E_BAD_CAPTURE`, which describes a failed biometric capture rather than a power transition.
- The post-resume warm-up remains lazy and runs only when WBF submits a fresh capture. No synthetic match, cached pre-sleep result, background capture, or service restart is used.

## Limits and validation

The changes keep the adapter within the WBF/WBDI ownership model and fix the captured error classification. They cannot force LogonUI/WBF to restart a credential-provider session. If the rebuilt driver still receives `Deactivate` without a new `Activate`/`CAPTURE_DATA` after resume, the remaining issue is outside the WBDI device's documented control surface; a workaround that restarts `WbioSrvc` or fabricates capture activity would be a separate, unsupported system-level design.

The attached trace reports `winBioHresult=0x80098008` after `power-suspend`, while the supplied source maps `VerifyOutcome::Cancelled` to `WINBIO_E_CANCELED`. This mismatch indicates that the installed binaries were not built from the exact source revision in the archive (or contain a separate power-specific outcome path). Rebuild and install the updated UMDF and engine-adapter binaries together before comparing a new trace.

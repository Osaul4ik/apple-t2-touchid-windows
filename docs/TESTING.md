# Testing T2 Touch ID

Three layers: what runs on any Linux box, what CI runs on Windows, and what only
the hardware can tell. A release candidate needs all three.

## 1. Host tests (no Windows, no T2)

```sh
tests/host/run-tests-wine.sh        # needs mingw-w64 + wine (64-bit prefix)
```

Builds the shared user-mode code (`protocol/`) with mingw-w64 and runs, under wine:

* `T2TouchIdTests` - protocol unit tests (frames, plist payloads, match results,
  port order, native verdicts, the log file sink, ...).
* `T2TouchIdScenarioTests` - the **whole connect flow** against a simulated T2
  (`tests/FakeT2.*`): RemoteXPC peer record, BiometricKit HELO, decoy HTTP/2
  services, T2Ncm.sys (mode / sticky / state, and what its mode does to traffic),
  and the host side of a VPN (WSAEACCES or silently dropped IPv6). It plugs in
  through `protocol/BridgeXpc/TransportHooks.h`; the code under test is unmodified.
  After every connect it checks the core invariant: *driver mode == committed
  transport*. The scenarios cover cold start, cached port, a port moved by a T2
  reboot, VPN kill-switch / silent VPN / VPN mid-session, the sticky tunnel across a
  process restart, VPN gone with and without a re-check, GUI Rescan on a sticky
  tunnel, another process clearing the sticky flag, BiometricKit not up yet, cancel
  mid-scan, AutoSwitch off, T2Ncm.sys missing, and the transport owner pipe (rescan,
  counters, busy while a capture is armed, client timeout cancelling the owner's
  scan, a squatted pipe name).
* compile checks of `driver/T2TouchIdBio/umdf/TransportGlue.cpp` and the CLI.

The CI job `host-tests` runs the same script on every push.

## 2. CI on Windows

The main job builds everything with the WDK (PREfast `/analyze`, warnings as
errors, CodeQL), runs `T2TouchIdTests.exe`, signs, packages and compiles the
installer. A red PREfast build is a real finding, not noise.

## 3. Hardware checklist (before tagging a release)

Use a test machine. Collect `Collect diagnostics…` (GUI developer card) after every
failed step and keep the zip with the report.

### Driver Verifier (kernel drivers)

```bat
verifier /standard /driver T2TouchIdTransport.sys T2Ncm.sys T2NcmCtrl.sys
shutdown /r /t 0
```

Run all steps below with Verifier on, then `verifier /reset` and reboot. A bug check
under Verifier is a release blocker: keep `C:\Windows\MEMORY.DMP`.

For the UMDF driver: `WudfVerifier` is not needed; instead enable Application Verifier
basics for `WUDFHost.exe` only if a crash is suspected (it slows every UMDF driver).

### Install / upgrade / uninstall

| # | Step | Expected |
|---|------|----------|
| 1 | Clean install with Setup.exe | restart; Touch ID works at the lock screen |
| 2 | Run the **same** Setup.exe again | "drivers already installed and working" -> keep -> **no restart** |
| 3 | Install a newer build | drivers replaced, restart, enrollment still works |
| 4 | Setup with Secure Boot on (T2: Startup Security Utility "Full Security") | refused up front, nothing changed |
| 5 | Uninstall, answer "keep settings / vault" | reinstall works without importing the vault again |
| 6 | Uninstall everything | no T2 driver package left (`pnputil /enum-drivers`), Test Mode question asked |

### Transport (the VPN cases)

| # | Step | Expected (`t2touchid transport-status`) |
|---|------|------|
| 7 | Cold boot, no VPN, unlock with a finger | `transport: native`, `sticky: 0` |
| 8 | Turn the VPN on, lock, touch | works; `transport: tunnel`, `tunnel_commits` +1 |
| 9 | VPN off, lock, touch | works; after the network change `native_rechecks` +1, `native_returns` +1, `sticky: 0` |
| 10 | GUI Rescan with the VPN on, then off | port found both times; `owner: T2TouchIdBio driver` in the output |
| 11 | Kill `t2touchid.exe` in the middle of a Rescan | next lock-screen touch still works (driver mode restored by T2Ncm) |
| 12 | Lock screen visible, press Rescan in the GUI of another session | `sensor busy`, nothing changes |

### Power

| # | Step | Expected |
|---|------|------|
| 13 | 50 x sleep / wake (`psshutdown -d -t 0` or lid), touch after each | every touch matches; no Code 10/43 in Device Manager |
| 14 | 20 x lock / unlock | same |
| 15 | Hibernate / resume, fast startup cold boot | first touch after boot works within ~10 s |

### SEP

| # | Step | Expected (`t2touchid status`) |
|---|------|------|
| 16 | After boot | `DMA / OOL registered`, `AKS exchanges N ok, 0 failed` |
| 17 | Wrong password in the vault | bootstrap reason "SEP rejected", GUI says so; no hang |
| 18 | 100 lock-screen matches in a row | `failed` and `SEP timeouts` stay 0 |

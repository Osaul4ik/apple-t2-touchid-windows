# T2 Touch ID for Windows — architecture

This file describes how the parts fit together **as of RC**, where state lives,
which events move it, and what is still planned. Component-level details stay in
the per-component docs (`T2NCM/docs`, `driver/T2TouchIdBio/docs`).

## Components

| Component | Runs as | Job |
|---|---|---|
| `T2TouchIdTransport.sys` (KMDF) | kernel | T2 SEP PCI mailbox, OOL DMA buffers, AppleKeyStore exchange |
| `T2SepBootstrap.exe` (service) | LocalSystem | one-shot per boot: load + unlock the macOS keybag from `sep-vault.bin` |
| `T2Ncm.sys` / `T2NcmCtrl.sys` (NDIS 6.30) | kernel | T2 USB CDC-NCM network link; IPv4↔IPv6 tunnel rewrite |
| `T2TouchIdBio.dll` (UMDF, WBDI) | WUDFHost (LocalService) | Windows Hello sensor: BridgeXPC → BiometricKit verify |
| `T2TouchIdEngineAdapter.dll` | WbioSrvc | WBF engine adapter: maps a match to the enrolled Windows identity |
| `t2touchid.exe` | admin console / GUI child | diagnostics; `network [--rescan]` and `transport-status` go to the driver over the owner pipe, `verify` |
| `T2TouchID_GUI.exe` (WPF) | admin | vault import, status, Rescan / Test, settings |
| `protocol/` (static lib) | linked into the three user-mode binaries above | BridgeXPC, BiometricKit, AppleKeyStore, **discovery + transport policy** |

## The BridgeXPC transport

The T2 runs `bkremoted` on an ephemeral TCP port reachable over the NCM link at the
T2's IPv6 link-local address. Two ways to reach it:

* **Native IPv6** — the default.
* **IPv4 tunnel** — when a VPN / WFP filter drops IPv6 before it reaches T2Ncm:
  userspace connects to a mapped `169.254.x.y`, `T2Ncm.sys` rewrites the frames to
  IPv6 on the wire. The mode is **global in the driver** (in tunnel mode every
  inbound IPv6 TCP/UDP frame is rewritten), so the two are tried one after the other,
  never at once.

### One owner of the transport

The UMDF driver (WUDFHost, LocalService) owns the transport. It serves
`\\.\pipe\T2TouchIdTransport` (`protocol/Ipc/TransportPipe`, handler
`protocol/Discovery/TransportService`, wiring `driver/T2TouchIdBio/umdf/TransportGlue.cpp`):

* `op=status` - transport, sticky flag, cached port, counters (`TransportStats`);
* `op=connect force=0|1 timeout=ms` - the retry ladder (`ConnectWithLadder`) in the
  driver's process, reply with port / transport / bridge version.

The CLI asks there first (`network`, `network --rescan`, `transport-status`) and runs
the same code locally only when the pipe does not exist (driver not running). A
connect is refused with `busy` while a capture is armed, and a capture that arrives
during one cancels it within 50 ms. Pipe security: DACL SYSTEM / Administrators /
LocalService, no remote clients, `FILE_FLAG_FIRST_PIPE_INSTANCE`, and the client only
trusts a LocalService / SYSTEM server.

### One implementation of discovery + connect

`protocol/Discovery/BridgeDiscovery` (`ConnectToBiometricKitBridge`) is the only code
that finds the port and connects. The UMDF driver (lock-screen capture ladder) and
the CLI (`network`, `network --rescan`, `identities`, `warmup`, `verify` — i.e. the
GUI's Rescan and Test buttons) both call it. Until RC the CLI had its own copy
without the phase lock and without the tunnel fallback, which is why a Rescan could
miss the port and could never switch to the tunnel with a VPN on.

One call is one **step**: readiness gate → native IPv6 (registry port, else a
full-chain scan) → IPv4 tunnel when native is blocked or the tunnel is committed →
"not yet". Callers repeat steps on a backoff (`Queue.cpp ConnectForCaptureWithRetry`,
`main.cpp ConnectBridgeCli`). `ConnectOptions::forceRescan` (Rescan) skips the
registry port and the cool-down and re-checks native even on a committed tunnel.

### Where transport state lives

| State | Lives in | Lifetime | Written by |
|---|---|---|---|
| BridgeXPC port (+ RemoteXPC port) | `HKLM\SOFTWARE\T2TouchId\Network\PortCache\<MAC>` | persistent | discovery, only after a live HELO / scan confirmation |
| Committed transport ("sticky tunnel") | `T2Ncm.sys` memory (`IOCTL_T2NCM_SET/GET_TUNNEL_STATE`) | until reboot | discovery (tunnel handshake → 1, native handshake → 0) |
| Live driver mode | `T2Ncm.sys` memory (`IOCTL_T2NCM_SET_TRANSPORT_MODE`) | until reboot | `TransportPhase` (probe override, restored on exit) |
| Per-process copy of the sticky flag | `TransportState` (TransportMode.cpp) | process | re-synced from the driver at the start of **every** connect (`RefreshStickyFromDriver`) |
| Transport counters | `TransportState` | process (the owner's) | discovery; read with `op=status` / `t2touchid transport-status` |
| AKS exchange counters | `T2TouchIdTransport.sys` (`T2_TRANSPORT_STATUS_V2`) | until reboot | every `IOCTL_T2_AKS_EXCHANGE`; `t2touchid status` |
| AutoSwitch, grace timers | `HKLM\SOFTWARE\T2TouchId\Network` | persistent | GUI |
| Scan resume cursor, EMA budgets, gate generation | process memory | process | discovery |

### Invariants

1. **Driver mode == committed mode whenever no phase is running.** Every mode flip
   happens inside a `TransportPhase` (cross-process named mutex + RAII scope that puts
   the committed mode back on every exit path).
2. **A dead phase owner cannot leave the driver in its probe mode.** The control
   handle that moved the live mode away from the committed one is recorded as its
   owner in `T2Ncm.sys`; `IRP_MJ_CLEANUP` of that handle restores the committed mode
   (`Tunnel.c T2NcmTunnelReleaseModeOwner`). This covers a GUI timeout kill, a crash,
   a WUDFHost restart.
3. **No process trusts a stale view of the driver.** The "last pushed mode" cache is
   reset at the start of every phase, and the sticky flag is re-read at the start of
   every connect, because the CLI and WUDFHost both write it.
4. **The port is never thrown away by a failure.** Only a confirmed port overwrites it.

### Events that move the transport

| Event | Source | Effect |
|---|---|---|
| Connect step | capture ladder / CLI | native → tunnel on a blocked native path; commit on handshake |
| Real unlock | `WTS_SESSION_UNLOCK` (Queue.cpp) | one native re-check on the next connect |
| **Host network change** (VPN up/down) | `NetworkWatch` (`NotifyIpInterfaceChange` + `NotifyRouteChange2`, debounced) | committed tunnel → one native re-check on the next connect; native + armed capture → 250 ms SYN probe, and if the path is gone the active match is invalidated so the worker reconnects (and switches) at once |
| Rescan | GUI → `t2touchid network --rescan` | full scan, native re-checked even on a committed tunnel |
| Suspend / resume | `PowerRegisterSuspendResumeNotification` | IOCTLs frozen across Dx; push cache reset on resume |
| Reboot | — | everything in driver memory resets: cold boot starts on native |

## Cancellation

* Driver: WBF `CancelIoEx`, suspend, screen lock and network change all go through
  the capture cancel event; the worker sends BiometricKit `Cancel (0x0c)` on teardown.
* CLI: `--cancel-event <name>` (the GUI signals it on its own timeout and kills the
  process only 10 s later) and Ctrl+C for the BridgeXPC commands.

## Code layout of the transport

* `protocol/BridgeXpc/TransportMode.h` - the API only; `TransportMode.cpp` - all state
  in one `TransportState` object (+ `testing::ResetState`).
* `MakePeerAddress` / `ConnectToPeer` - the one place that builds the T2's socket
  address (native `[fe80%if]:port`, tunnel `169.254.a.b:port`).
* `TransportHooks.h` - optional seams (T2Ncm IOCTLs, peer address, connect verdict,
  tunnel neighbor, readiness gate, Network registry root). Never installed in
  production; the scenario tests drive the real code through them.
* `T2NCM/driver/Control.c` - the `\\.\T2Ncm` control device (moved out of
  NdisMiniport.c).

## Logs

Every user-mode line (driver, CLI, T2SepBootstrap) also goes to
`%ProgramData%\T2TouchId\Logs\<process>.log` (wall-clock prefix, 4 MiB rotation;
`Logging\FileLog=0` turns it off). The installer gives LocalService modify on that
folder only. `tools/Collect-T2Diagnostics.ps1` (GUI: *Collect diagnostics…*) zips it
with the device / driver / service / network / event-log state. Kernel drivers still
log to DebugView (Capture Kernel) or the existing `T2TouchIdDiag` ETW provider.

## Testing

See [TESTING.md](TESTING.md): host tests with a simulated T2 (mingw + wine, also in
CI), the Windows CI, and the hardware checklist (Driver Verifier, install / upgrade,
VPN cases, power, SEP).

## Still open

1. **Capture engine split.** `Queue.cpp` (~3100 lines) still holds the capture ladder,
   the power / session-lock monitor and the WBDI dispatch. The transport glue is out
   (TransportGlue.cpp behind CaptureState.h); the session-lock window and power hooks
   are next, behind the same kind of narrow interface.
2. **GUI as MVVM.** `MainWindow.xaml.cs` is code-behind; a view-model for status /
   transport / vault would make it testable. Needs a WPF build to verify, so it is
   done together with GUI work that can be tried on Windows.
3. **Verify through the owner.** `identities` / `warmup` / `verify` still open their
   own BridgeXPC session (they follow the owner's transport through the driver's
   sticky flag and the shared port cache).

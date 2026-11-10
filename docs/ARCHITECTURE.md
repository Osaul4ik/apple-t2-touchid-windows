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
| `t2touchid.exe` | admin console / GUI child | diagnostics, `network --rescan`, `verify` |
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
| Per-process copy of the sticky flag | `TransportMode.h` atomics | process | re-synced from the driver at the start of **every** connect (`RefreshStickyFromDriver`) |
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

## Roadmap (not done yet)

1. **Single transport owner with IPC.** Today two processes (WUDFHost and the CLI)
   run the same policy, serialized by the phase mutex and reconciled through the
   driver. The target is one owner (the UMDF host or a small service) exposing
   `status / rescan / verify / revalidate` over a named pipe; GUI and CLI become thin
   clients and never touch `T2Ncm` or BridgeXPC directly.
2. **Split `TransportMode.h`** (≈1400 lines of inline code with function-local
   statics) into `.cpp` modules with an explicit `TransportState` struct.
3. **Scenario tests** for discovery with a simulated T2 peer (BridgeXPC + RemoteXPC on
   loopback): blocked IPv6, port moved, service not up yet, VPN toggled mid-session.
4. **Process tag in every log line** (`WUDFHost` / `t2touchid` / `T2SepBootstrap`).

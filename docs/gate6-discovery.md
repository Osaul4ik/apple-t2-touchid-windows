# Gate 6 — RemoteXPC / BiometricKit port discovery

## Phase 1 (implemented)

1. Locate T2 NCM adapter IPv6 link-local (`FindT2NcmEndpoints` /
   `GetEndpointByIfIndex`).
2. Concurrent TCP connect to ports **49152–65535** with HTTP/2 client
   preface; keep peers whose first frame type is **SETTINGS (0x04)**.

CLI:

```text
t2touchid.exe network              # auto-find T2 NCM by description
t2touchid.exe network 27           # force ifIndex 27
t2touchid.exe network 27 --no-scan # only print link-local
```

## Phase 1.5 — active-preface fallback (implemented)

The reference `discover-biometric-port.py` assumes the peer sends SETTINGS
unprompted. On hardware, a fully silent TCP-open port (`recv=0B`) is
ambiguous: it could be a non-HTTP/2 service, or an ordinary RFC 7540 server
waiting for the client to speak first — the passive scan can't tell them
apart. `PortScan.cpp` now retries once on silence: sends the standard
client preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + empty SETTINGS), then
re-checks for a SETTINGS reply.

A hit here is tagged `[HTTP/2 SETTINGS after active preface]` /
`activePrefaceTried=true` and reported separately from ordinary Phase-1
hits — it does not confirm BiometricKit, and if it fires it means the
"peer speaks first" assumption is wrong for this port range and Phase 1
needs the active send made unconditional, not just a fallback.

## Phase 2 (implemented, not yet verified on hardware)

Linux reference (`discover-biometric-port.py` + `pymobiledevice3`):

```text
for each HTTP/2 candidate port:
    RemoteXPC connect
    send_device_handshake / receive peer record
    Services["com.apple.eos.BiometricKit"]["Port"]  → BridgeXPC port
```

`discover-biometric-port.py` only calls into `pymobiledevice3`'s
`RemoteXPCConnection` — it does not itself define the wire format. Since
`pymobiledevice3` isn't vendored in this repo, `protocol/Discovery/RemoteXpc.{h,cpp}`
implements the wire format from a different verification source:
jkcoxson/idevice's clean-room Rust reimplementation of the same client
(`src/xpc/http2/{mod,frame}.rs`, `src/xpc/{mod,format}.rs`), which the
crate's own comments describe as "ported from pymobiledevice3". See the
header comment in `RemoteXpc.h` for exactly which pieces of that source
map to which parts of this file.

`RemoteXpcConnection` runs `do_handshake()` (SETTINGS + WINDOW_UPDATE +
root/reply channel open) then `send_device_handshake()`, then reads one
non-empty message off the root channel as the peer record.
`DiscoverServicePort()` walks the HTTP/2 candidates from Phase 1/1.5 in
order and treats any candidate that completes RemoteXPC but doesn't
advertise `com.apple.eos.BiometricKit` as a decoy, not a failure — same
as the Python reference's blanket `except Exception: continue`. Never
claims a port without seeing it in a decoded `Services` dictionary.

`t2touchid.exe network` now runs Phase 2 automatically against every
Phase-1/1.5 HTTP/2 hit and prints the BiometricKit port if found.

**Verified on real T2 hardware (16.09.2026)** — Phase 2 RemoteXPC discovery
found `com.apple.eos.BiometricKit` and returned its BridgeXPC port (49197
on this run, out of 21 HTTP/2-SETTINGS candidates in the 49152–65535
range). Neither of the two failure culprits below materialized: the
non-HPACK HEADERS channel-open frame was accepted as-is, and the
`RemoteXPCVersionFlags`/`MessagingProtocolVersion` values idevice sends
were accepted by this T2's `remoted`.

## Gate 7 phase 1 — BridgeXPC HELO + getBridgeVersion (verified on real hardware, 16.09.2026)

`t2touchid.exe network` now also opens a real `bridgexpc::Connection` to
the discovered port and runs the HELO handshake (Milestone 1 §7) followed
by `getBridgeVersion`. On real hardware this returned `BridgeXPC verified:
HELO OK, bridge version=3` — confirming the port discovered in Phase 2 is
a live BridgeXpc endpoint, not just a plausible-looking number, and that
this repo's HELO/getBridgeVersion wire format matches the real device.

Previously-open questions this closes: the byte-level RemoteXPC framing
described in Phase 2 above works against the live T2 `remoted`-equivalent
as implemented, with no changes needed to the channel-open frame or the
version-flags fields.

## Gate 8 — BiometricKit commands (implemented, CLI wired, NOT yet run on real hardware)

`t2touchid.exe identities` and `t2touchid.exe verify` are now wired to the
discovered/verified BridgeXPC connection above, running the sequence from
`docs/linux-reference-analysis.md` §2 (`setClientVersion` → reset sensor →
cancel → FDR calibration → identity-list, then for `verify` only:
start-match → event loop → verdict). This is unverified past the
handshake — the biometric command layer (`SendBiometricCommand`,
`VerificationEngine`) was already implemented before this hardware run but
has not itself been exercised against the sensor yet.

## Hardware baseline (01.09.2026)

| Item | Value |
|------|-------|
| Adapter | Apple T2 USB NCM Network Adapter (Up) |
| ifIndex | 27 |
| link-local | `fe80::dcc9:6760:e950:2ecd%27` Preferred |

### Second run, same day — ifIndex differs

| Item | Value |
|------|-------|
| Adapter | Ethernet 2 / Apple T2 USB NCM Network Adapter |
| ifIndex | 4 |
| link-local | `fe80::b77c:ae51:65f4:41e4%4` |
| Scan result | 6 TCP-open, 0 HTTP/2 (all `recv=0B`, silent even under Phase 1.5) |

`ifIndex` is not stable across boots/re-enumeration — confirms `network`
must keep doing auto-discovery by description rather than a hardcoded
index. This run's 6 open ports gave no SETTINGS frame either passively or
after the active-preface fallback, so on this boot they are either decoys
or a genuinely different set of ports than the earlier baseline — still
open whether that's boot-to-boot port churn or these 6 were never
BiometricKit-related to begin with.

### Third run (16.09.2026) — Phase 2 + Gate 7 phase 1 both confirmed

| Item | Value |
|------|-------|
| Adapter | Ethernet 2 / Apple T2 USB NCM Network Adapter |
| ifIndex | 3 |
| Scan result | 28 TCP-open, 21 HTTP/2 SETTINGS (49152–65535, concurrency 64, 150ms timeout) |
| BiometricKit BridgeXPC port | 49197 |
| BridgeXPC handshake | HELO OK, `getBridgeVersion` → bridge version 3 |

First real-hardware confirmation of both Phase 2 (RemoteXPC service
discovery) and Gate 7 phase 1 (live BridgeXpc HELO + getBridgeVersion) —
see the sections above.
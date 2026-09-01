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

## Phase 2 (not implemented)

Linux reference (`discover-biometric-port.py` + `pymobiledevice3`):

```text
for each HTTP/2 candidate port:
    RemoteXPC connect
    send_device_handshake / receive peer record
    Services["com.apple.eos.BiometricKit"]["Port"]  → BridgeXPC port
```

Decoy services accept HTTP/2 preface but reject RSD — must not be treated
as BiometricKit. Until phase 2 exists, `network` reports HTTP/2 hits only
and does **not** claim a BiometricKit port.

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
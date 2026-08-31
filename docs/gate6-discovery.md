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

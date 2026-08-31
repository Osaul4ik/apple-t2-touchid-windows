# Apple T2 USB NCM binding (PID 8233)

**Status: confirmed on hardware (01.09.2026).**

Inbox `UsbNcm.sys` drives `USB\VID_05AC&PID_8233` through the project INF
`T2NCM/apple-t2-ncm.inf`. NDIS adapter comes up; service runs.

## Answer to the binding question

```text
Can Microsoft's inbox UsbNcm.sys drive the Apple T2
USB\VID_05AC&PID_8233 CDC-NCM function through a normal
third-party INF?

YES
```

Evidence (target machine, Boot Camp, Windows 11):

| Check | Result |
|-------|--------|
| Problem | `CM_PROB_NONE` |
| Service | `UsbNcm` — **Running** |
| Driver binary | `\SystemRoot\System32\drivers\UsbNcm.sys` (inbox) |
| NDIS adapter | `Ethernet 2` — Apple T2 USB NCM Network Adapter — **Up / Connected** |
| MAC | `AC-DE-48-00-11-22` |
| MTU | 9000 |
| PnP Device ID | `USB\VID_05AC&PID_8233\0000000000000000` |
| Selected INF | `oem181.inf` ← published from `apple-t2-ncm.inf` |
| Driver rank | `00FF0001` (beats Apple null on same HWID) |

`LinkSpeed 0 bps` with `MediaConnectState = Connected` is normal for NCM
(no traditional PHY speed).

## Why parent match (not MI_00 / MI_01)

When Apple `oem15.inf` Null is bound to the parent:

```text
USB\VID_05AC&PID_8233
```

child PDOs for `MI_00` / `MI_01` are **not created**. An INF that only
matches `&MI_00` never installs.

Hardware confirmation: binding NCM on the **parent** is what causes the
interfaces to appear and the NDIS adapter to come up.

Apple's null package is **not** modified. Our package matches the same
parent HWID and wins by PnP rank (Authenticode vs WHQL null is still a
valid selection when the user installs our package / higher rank path).

## Topology (verified)

```text
USB\VID_05AC&PID_8233
        │
        │  apple-t2-ncm.inf  (wins over Apple null by rank)
        ▼
   UsbNcm.sys (inbox)
        │
        ▼
   NDIS adapter "Apple T2 USB NCM Network Adapter"
   (Status Up, Connected, MTU 9000)
```

- No private copy of `UsbNcm.sys`
- No USB filter / bus driver
- No edits to `C:\Windows\INF\oem15.inf` or AppleNull64 DriverStore entries

## INF design (what actually worked)

File: `T2NCM/apple-t2-ncm.inf`

| Item | Value |
|------|-------|
| Class | Net `{4d36e972-e325-11ce-bfc1-08002be10318}` |
| HWID | `USB\VID_05AC&PID_8233` (**parent only**) |
| Service | `UsbNcm` via `Include/Needs` → `usbncm.inf` |
| Ndi | **Explicit** `AddReg` (Service, UpperRange=ndis5, LowerRange=ethernet) |
| Characteristics | `0x84`, BusType=15, `*IfType=6`, connector/connection flags |

### Code 56 lesson

First revision relied only on `Include/Needs` for Ndi. Result:

```text
Service = UsbNcm (assigned)
Status  = CM_PROB_NEED_CLASS_CONFIG (0x38)
Service state = Stopped
No NDIS adapter
```

SetupAPI showed `Included INFs = usbncm.inf` and service creation, but the
Net class installer never finished. Adding explicit `Characteristics` /
`*IfType` / `Ndi` AddReg (same shape as public `usbncm.inf`) cleared
Code 56 after reinstall + reboot:

```text
Status = OK / CM_PROB_NONE
UsbNcm = Running
Ethernet 2 = Up
```

## Build / package / sign

`.github/workflows/BuildT2TouchId.yml`:

1. Stage `T2NCM/apple-t2-ncm.inf` → `artifacts/ncm/`
2. StampInf (same `DRIVER_DATE` / `DRIVER_VERSION` as transport)
3. InfVerif
4. Inf2Cat → `apple-t2-ncm.cat`
5. SignTool on `.cat` when `CERT` / `CERT_PWD` present (test cert OK)
6. **No** hard-fail `signtool verify` (test root is untrusted by design)
7. Artifact `AppleT2NCM-<version>`

## Install (target)

```powershell
pnputil /add-driver apple-t2-ncm.inf /install
# or Device Manager → Update driver → Have Disk
# reboot if Code 56 appears after first install
```

Verify:

```powershell
Get-PnpDevice -PresentOnly | ? { $_.InstanceId -like "*8233*" } |
  fl Status, Problem, Service, FriendlyName
Get-Service UsbNcm
Get-NetAdapter -IncludeHidden | ? { $_.DriverFileName -like "*UsbNcm*" }
Get-NetIPAddress -InterfaceAlias "Ethernet 2" -AddressFamily IPv6
```

## Next gate

With the NCM adapter **Up**, Gate 6 is unblocked:

- Enumerate IPv6 link-local on this interface (`fe80::/10`, scope = ifIndex)
- RemoteXPC / port discovery toward BridgeXPC on that scope

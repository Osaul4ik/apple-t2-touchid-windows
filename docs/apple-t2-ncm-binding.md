# Apple T2 USB NCM binding (PID 8233)

## Goal

Make the T2 CDC-NCM function (`USB\VID_05AC&PID_8233`) usable under
Windows so BridgeXPC / RemoteXPC discovery can run over the resulting
NDIS adapter. The package binds the **inbox** Microsoft `UsbNcm.sys`
host driver; it does **not** ship a private copy of that binary.

## Observed hardware

| Item | Value |
|------|-------|
| Parent | `USB\VID_05AC&PID_8233` |
| Parent class | System (Apple null / `oem15.inf`) |
| Parent service | (null) |
| MI_00 | CDC NCM Control — class 02, subclass 0D, protocol 00 |
| MI_01 | CDC Data — class 0A, protocol 01 (alt 0 empty, alt 1 bulk IN/OUT) |
| Union | control=0, subordinate=1 |
| Current failure | both MI_00 and MI_01 → `CM_PROB_FAILED_INSTALL` (Code 28) |

## Topology enforced by this package

```
USB\VID_05AC&PID_8233
        │
        ▼
   usbccgp.sys                 (untouched)
        │
        ├── MI_00  (control) ──► apple-t2-ncm.inf → UsbNcm.sys → NDIS adapter
        └── MI_01  (data)    ──► associated via CDC Union descriptor
                                 (claimed by the same UsbNcm instance)
```

- Apple’s existing `oem15.inf` null binding on the **parent** is left alone.
- No filter driver, no custom bus driver, no modification of
  `C:\Windows\INF\oem15.inf` or the DriverStore copy of AppleNull64.

## INF design

File: `T2NCM/apple-t2-ncm.inf`

- Class = Net / ClassGUID = `{4d36e972-e325-11ce-bfc1-08002be10318}`
- Matches **only** `USB\VID_05AC&PID_8233&MI_00` (control interface).
- Uses `Include = usbncm.inf` + `Needs = UsbNcm_Device.NT` (and
  `.Services` / `.HW`) so Service = `UsbNcm` and the Ndi registry values
  come from the Microsoft inbox package.
- Does **not** match the parent and does **not** list a generic
  `USB\Class_02&SubClass_0d` ID.

Matching only the control interface avoids creating two independent
UsbNcm instances for MI_00 and MI_01.

## Build / package / sign

Integrated into `.github/workflows/BuildT2TouchId.yml`:

1. Stage `T2NCM/apple-t2-ncm.inf` → `artifacts/ncm/`
2. InfVerif
3. Inf2Cat → `apple-t2-ncm.cat`
4. SignTool (when `CERT` / `CERT_PWD` secrets are present)
5. `signtool verify /pa`
6. Upload artifact `AppleT2NCM-<version>`

Unsigned builds are allowed (same policy as the transport driver) and
emit a warning; a release build with secrets set **fails** if signing or
verification fails.

## Critical open question (hardware only)

> Can Microsoft’s inbox `UsbNcm.sys` actually drive the Apple T2
> `USB\VID_05AC&PID_8233` CDC-NCM function through a normal third-party
> INF?

The inbox INF primarily matches `USB\MS_COMP_WINNCM`. The T2 does not
expose that compatible ID. Whether `UsbNcm.sys` accepts a third-party
match on the VID/PID/MI_00 path (and correctly consumes the Union /
NCM functional descriptors) can only be answered by installing the
package on real hardware and inspecting SetupAPI + `pnputil`.

If the answer is **NO**, the correct report is:

```
INBOX NCM DRIVER BINDING: NOT SUPPORTED
```

with the SetupAPI rank/selection evidence. Do not invent a workaround
that patches Microsoft binaries or Apple’s null INF.

## Installation test checklist (on target)

```powershell
# Before
Get-PnpDevice -PresentOnly |
  Where-Object { $_.InstanceId -like "USB\VID_05AC&PID_8233&MI_*" } |
  Format-Table Status, Problem, Class, FriendlyName, InstanceId

# Install package (from DriverStore / pnputil / Device Manager → Have Disk)

# After
pnputil /enum-devices /instanceid "<MI_00 instance>" /drivers
Get-NetAdapter -IncludeHidden
# SetupAPI: C:\Windows\INF\setupapi.dev.log  search VID_05AC&PID_8233
```

Expected if binding succeeds:

- MI_00 Status = OK, Service = UsbNcm, Driver = UsbNcm.sys
- One NDIS adapter appears (if T2 firmware presents an operational NCM
  network function)
- Parent still under usbccgp + Apple null package

# T2Ncm.sys — Architecture

> **Revised.** This document originally described a KMDF function driver
> that owned PnP and power for MI_01 and was going to attach an NDIS
> miniport to the side of it. That is no longer the design. T2Ncm.sys is
> now an **NDIS 6.30 miniport driver**, NDIS owns PnP and the power
> policy, and KMDF is used only as a USB client library. The reasoning
> and the full callback mapping live in
> [T2Ncm-Power-Inversion.md](T2Ncm-Power-Inversion.md); this file has
> been updated to match, but that one is the authority on the lifecycle.

## 1. Repo audit (Osaul4ik/apple-t2-touchid-windows @ Dev_lifecycle)

| Area | Finding |
|---|---|
| KMDF infra | `driver/T2TouchIdTransport/` — KMDF **PCI** driver (SEP mailbox). Pattern: `driver.h` (constants+`T2_LOG`), `driver.c` (DriverEntry), `device.c` (PnP/state machine), one `.c` per subsystem (`akstore.c`, `dma.c`, `mailbox.c`). This is the pattern to replicate for T2Ncm, but T2Ncm is **USB**, not PCI, and needs an **NDIS 6 miniport** on top — no existing project does that. |
| Logging | No `Trace.c`/WPP. Deliberate: `#define T2_LOG(_x_) DbgPrintEx _x_` in `driver.h`, because `KdPrintEx` is compiled out in Release (`DBG=0`) and this project ships test-signed Release. **T2Ncm reuses this exact macro**, not WPP. |
| Build/signing | `T2TouchIdTransport.vcxproj`: `ConfigurationType=Driver`, `DriverType=KMDF`, `PlatformToolset=WindowsKernelModeDriver10.0`, `KMDF_VERSION_MAJOR/MINOR = 1.15` (pinned for Windows 10 compat — no co-installer above 1.13). INF is deliberately **not** a vcxproj `<Inf>` item (auto InfVerif needs a missing x86 InfVerif.dll on CI runners) — stamped/verified/cataloged as separate CI steps instead. **T2Ncm follows the same pattern.** |
| Existing T2 USB/AKS transport | None at USB level — the only transport driver in the repo talks to the T2 over **PCI** (SEP mailbox for Touch ID), completely unrelated bus/protocol to the CDC-NCM interface on MI_00/MI_01. Nothing to reuse here except the coding conventions and CI patterns. |
| Existing T2 NCM attempt | `T2NCM/apple-t2-ncm.inf` + `apple-t2-composite.inf`: the **failed approach** — vendor-HWID match on `MI_00` that rebinds to the **inbox `UsbNcm.sys`** (`AddService = UsbNcm`, `KmdfService = UsbNcm, UsbNcm_wdfsect`). This is exactly the Code 10 / `STATUS_DEVICE_HARDWARE_ERROR` you're hitting — confirmed by the USBPcap trace (no transactions after `SET_CONFIGURATION` before the fail). Per your directive this file is **replaced**, not patched, by a real `T2Ncm.sys` binding. |
| Common protocol defs | `protocol/` (AppleKeyStore/BiometricKit/BridgeXpc) is BridgeXPC/AKS wire protocol for Touch ID over the SEP transport — not CDC-NCM. Not reusable for T2Ncm's wire format; **is** the eventual consumer sitting on top of the NDIS NIC once TCP/IP is up (Task 27). |
| CI | Three workflows: `BuildT2TouchId.yml` (KMDF PCI driver + protocol/tools/tests, vcpkg/libplist), `BuildNCM_Inf.yml` (**package-only** — stamps/validates/cats/signs the two `T2NCM/*.inf` files, no source build, because there was no NCM driver source), `Cit2touchid.yml` (not inspected, out of scope). WDK install pattern: official fwlink installer `https://go.microsoft.com/fwlink/?linkid=2085767` + `StampInf`/`InfVerif`/`Inf2Cat`/`signtool` located by searching `Windows Kits\10\...` rather than hardcoded paths. **T2Ncm gets a new `BuildT2Ncm.yml` that actually compiles the driver**, built on this pattern — `BuildNCM_Inf.yml` stays as-is for now (still valid for the composite INF) until T2NCM's ncm.inf is swapped for the new vendor one below.

## 2. Where T2Ncm.sys lives

```
T2NCM/
    apple-t2-composite.inf          parent (usbccgp.sys), ships no binary
    apple-t2-ncm.inf                MI_01 — Net class, ships T2Ncm.sys
    apple-t2-ncm-ctrl-stub.inf      MI_00 — ships T2NcmCtrl.sys
    driver/
        T2Ncm.vcxproj               -> T2Ncm.sys      (NDIS 6.30 miniport)
        T2NcmCtrl.vcxproj           -> T2NcmCtrl.sys  (KMDF claim stub)

        Driver.h / Driver.c         DriverEntry: WDF in miniport mode, then
                                     NdisMRegisterMiniportDriver
        NdisMiniport.h / .c         ALL NDIS entry points — Initialize/Halt,
                                     Pause/Restart, Send/Return, OIDs, PnP
                                     events, and the diagnostic control device
        Device.h / Device.c         WdfDeviceMiniportCreate + lifecycle state
                                     machine + status snapshot
        Power.h / .c                OID_PNP_SET_POWER / QUERY_POWER handling
        UsbTransport.h / .c         USB target/pipe/descriptor layer
        NcmProtocol.h / .c          GET_NTB_PARAMETERS / format negotiation
        NcmRx.h / .c                NTB16 RX parser + bulk-IN engine + NDIS
                                     receive indication
        NcmTx.h / .c                NTB16 TX builder + bulk-OUT engine + the
                                     asynchronous NBL send path
        CtrlStub.c                  SEPARATE BINARY — MI_00 claim only
```

**Two binaries, not one.** MI_00 and MI_01 enumerate as independent PDOs,
so they always needed two driver bindings; they now also need two
*images*. T2Ncm.sys's `DriverEntry` creates its WDF driver with
`WdfDriverInitNoDispatchOverride` and hands the driver object to NDIS,
while the MI_00 stub has to own its dispatch table to receive PnP and
power IRPs. One `DriverEntry` cannot do both, so the stub moved to
`CtrlStub.c` / `T2NcmCtrl.sys` and the old `g_T2NcmStubRole`
role-selection global is gone.

## 3. Topology (unchanged from your spec, confirmed against the descriptor dump)

```
USB\VID_05AC&PID_8233
        |
        v
   usbccgp.sys
        |
        +-----------------------------+
        |                             |
        v                             v
MI_00 NCM Control                MI_01 NCM Data
Class 02 SubClass 0D Prot 00     Class 0A, EP 0x82 IN / 0x01 OUT (alt 1)
EP 0x81 IN interrupt                    ^
        |                               |
        v                               |
  T2NcmCtrl.sys                     T2Ncm.sys
  (claim only)                          |
                     |
                     v
              NDIS 6.30 Miniport — NDIS owns PnP and the power policy;
              KMDF is a USB client library below it (WdfDeviceMiniportCreate)
                     |
                     v
             ONE Ethernet NIC  (IF_TYPE_ETHERNET_CSMACD / NdisMedium802_3)
                     |
                     v
              Windows TCP/IP → existing BridgeXPC/T2 user-mode client (Task 27, untouched)
```

## 4. Current state

Implemented: USB configuration and pipe discovery, the CDC-NCM control
plane (GET_NTB_PARAMETERS / SET_NTB_FORMAT / SET_NTB_INPUT_SIZE / MAC),
the NTB16 RX parser and TX builder, the full NDIS 6.30 miniport
(initialize, halt, pause, restart, send, receive, OID handling, PnP
events, reset, shutdown), and the inverted power model.

Diagnostics moved with the rewrite. A `WdfDeviceMiniportCreate` device
never sees an IRP, so `IOCTL_T2NCM_GET_STATUS` and
`IOCTL_T2NCM_SEND_TEST_FRAME` are now served by a control device created
with `NdisMRegisterDeviceEx` and reached through `\\.\T2Ncm` instead of a
device interface GUID. `T2NCM_STATUS` gained the fields that make the
inverted model observable from user mode — `PowerState` next to
`DataPathRunning`, plus the two drain counters — and the new fields were
appended so an older tool still reads every offset it knows.

**Not yet validated on hardware.** None of this has been built with a
real WDK or run against a MacBook — there is no WDK and no T2 device in
the environment this was written in. Expect the first hardware session to
be about NDIS registration and TCP/IP binding, in that order.
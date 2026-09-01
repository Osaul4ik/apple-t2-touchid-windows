# T2Ncm.sys — Architecture (Task 1 deliverable)

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
driver/
    T2TouchIdTransport/   (existing, untouched — PCI/SEP, unrelated bus)
    T2Ncm/                (new)
        T2Ncm.vcxproj
        Driver.h / Driver.c        DriverEntry, WDF driver object
        Device.h / Device.c        PnP/Power callbacks + lifecycle state machine
        UsbTransport.h / .c        USB target/pipe/descriptor layer (Tasks 5-6)
        NcmProtocol.h / .c         GET_NTB_PARAMETERS / format negotiation (Tasks 7-11)
        NcmRx.h / .c                NTB16 RX parser + bulk-IN engine (Tasks 14-15)
        NcmTx.h / .c                NTB16 TX builder + bulk-OUT engine (Tasks 13,16)
        NdisMiniport.h / .c        NDIS 6 miniport glue (Tasks 18-20)
        Power.h / .c                D0Entry/D0Exit orchestration (Task 21)
inf/
    apple-t2-ncm.inf            new — binds T2Ncm.sys directly, no UsbNcm.sys
```

`T2NCM/apple-t2-composite.inf` (parent, owned by `usbccgp.sys`) is untouched. `T2NCM/apple-t2-ncm.inf` is superseded by `inf/apple-t2-ncm.inf` below — recommend deleting the old one in the same PR that adds `driver/T2Ncm/` so there is never a moment where both compete for `MI_00`.

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
        +-------- T2Ncm.sys -----------+
                     |
                     v
              NDIS 6 Miniport (KMDF/NDIS hybrid — NDIS_WDF_PNP_POWER_EVENT_CALLBACKS,
              same model Microsoft's own mobile-broadband/RNDIS miniports use)
                     |
                     v
             ONE Ethernet NIC  (IF_TYPE_ETHERNET_CSMACD / NdisMedium802_3)
                     |
                     v
              Windows TCP/IP → existing BridgeXPC/T2 user-mode client (Task 27, untouched)
```

## 4. Sequencing (per your incremental-milestone rule)

This turn ships **Task 1–3**: audit (above), project skeleton with the module boundaries and a real PnP lifecycle state machine (Task 4), and the corrected INF (Task 3) + CI build workflow. Descriptor parsing (Task 5) and USB pipe/config setup (Task 6) are stubbed with explicit `T2NCM_STATUS_NOT_IMPLEMENTED`-style TODOs tied to task numbers — filled in the next pass so Task 25's diagnostic milestone can be reached before any NDIS/NCM wire code is written, per your Task 30/31 constraint against implementing USB+NCM+NDIS in one change.

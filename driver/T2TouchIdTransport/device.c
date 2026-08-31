// SPDX-License-Identifier: GPL-2.0-only
// device.c
//
// PCI enumeration/BAR-mapping: BAR4 is now selected by reading its real
// base address directly out of PCI config space (offset 0x20) via
// BUS_INTERFACE_STANDARD.GetBusData, then matching that address against
// the assigned resource list - see T2QueryBar4ViaPciConfig below. This
// replaces an earlier "assume the first memory resource is BAR4"
// heuristic that was proven wrong on real hardware: the T2 SEP PCI
// function exposes THREE memory BARs (confirmed via
// docs/milestone-2-hardware-results.md), and the first one enumerated by
// KMDF's translated resource list is not reliably BAR4. The old heuristic
// is kept only as a last-resort fallback if GetBusData is ever
// unavailable, and is clearly logged as unreliable when used.

#include "driver.h"
#include <wdmguid.h>   // GUID_BUS_INTERFACE_STANDARD

// Built locally instead of relying on the SDK's SDDL_DEVOBJ_SYS_ALL_ADM_ALL
// (declared in wdmsec.h, defined only in wdmsec.lib): that external symbol
// was resolving to an invalid/garbage UNICODE_STRING at runtime on this
// build - WdfDeviceInitAssignSDDLString failed with
// STATUS_INVALID_SECURITY_DESCR ("SECURITY_DESCRIPTOR structure is not
// valid"), which fails AddDevice and shows up as Device Manager Code 31.
// Same SDDL text (SYSTEM + Administrators full control, everyone else
// denied), no wdmsec.lib dependency, nothing to resolve wrong.
DECLARE_CONST_UNICODE_STRING(g_T2SddlDevObjSysAllAdmAll, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

static VOID T2EvtIoDeviceControlAksExchange(_In_ WDFREQUEST Request, _In_ PT2_DEVICE_CONTEXT Ctx);

// Milestone 2B §2: single choke point for transport state transitions so
// every change is logged and the state machine documented in driver.h
// stays the one source of truth. Caller must already hold ExchangeLock.
VOID
T2SetTransportState(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ T2_TRANSPORT_STATE NewState)
{
    if (Ctx->State != NewState) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "T2TouchIdTransport: transport state %d -> %d\n", Ctx->State, NewState));
    }
    Ctx->State = NewState;
}

// Reads the SEP function's real BAR4 base address directly out of PCI
// config space (offset 0x20 - BAR0 is at 0x10, each BAR is 4 bytes, so
// BAR4 is the 5th slot: 0x10 + 4*4 = 0x20). This is the disambiguation
// the file-header comment always said was needed: on real hardware this
// PCI function exposes THREE memory BARs (confirmed via
// docs/milestone-2-hardware-results.md hardware run - two "unexpected
// second memory BAR" warnings, sizes 0x80000 and 0x10000), so "first
// memory resource in the translated list" is not a safe stand-in for
// "BAR4". Returns the raw (bus-relative) base address; the caller must
// match it against ResourcesRaw, not ResourcesTranslated, because raw
// descriptors carry the same bus-relative addresses that live in the PCI
// BAR registers themselves.
static NTSTATUS
T2QueryBar4ViaPciConfig(_In_ WDFDEVICE Device, _Out_ PHYSICAL_ADDRESS *Bar4Base)
{
    NTSTATUS status;
    BUS_INTERFACE_STANDARD busInterface;
    ULONG bytesRead;
    UCHAR barBytes[8] = { 0 };
    ULONG bar4Raw, barType;

    RtlZeroMemory(&busInterface, sizeof(busInterface));
    status = WdfFdoQueryForInterface(Device, &GUID_BUS_INTERFACE_STANDARD,
        (PINTERFACE)&busInterface, sizeof(busInterface), 1, NULL);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: WdfFdoQueryForInterface(BUS_INTERFACE_STANDARD) failed, status=0x%x\n",
            status));
        return status;
    }

    // Read BAR4 (offset 0x20) and BAR5 (offset 0x24) in one shot - BAR5
    // is only meaningful if BAR4 turns out to be a 64-bit BAR, but reading
    // both up front avoids a second round trip through GetBusData.
    bytesRead = busInterface.GetBusData(busInterface.Context, PCI_WHICHSPACE_CONFIG,
        barBytes, 0x20, sizeof(barBytes));

    if (busInterface.InterfaceDereference) {
        busInterface.InterfaceDereference(busInterface.Context);
    }

    if (bytesRead < 4) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: GetBusData read only %u of 4+ bytes at PCI config offset 0x20\n",
            bytesRead));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    bar4Raw = *(PULONG)&barBytes[0];
    if ((bar4Raw & 0x1) != 0) {
        // Bit 0 set = I/O space BAR, not memory - wrong offset or wrong
        // function entirely for a device this driver expects to be
        // memory-mapped.
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: PCI config offset 0x20 is an I/O BAR (raw=0x%x), expected memory\n",
            bar4Raw));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    barType = (bar4Raw >> 1) & 0x3; // 0 = 32-bit, 2 = 64-bit (bit pattern per PCI spec)
    if (barType == 0x2) {
        if (bytesRead < 8) {
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "T2TouchIdTransport: BAR4 is a 64-bit BAR but BAR5 (high dword) was not read\n"));
            return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
        ULONG bar5Raw = *(PULONG)&barBytes[4];
        Bar4Base->QuadPart = ((LONGLONG)bar5Raw << 32) | (LONGLONG)(bar4Raw & 0xFFFFFFF0u);
    } else {
        Bar4Base->QuadPart = (LONGLONG)(bar4Raw & 0xFFFFFFF0u);
    }

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: PCI config space reports BAR4 base 0x%I64x (%s)\n",
        Bar4Base->QuadPart, (barType == 0x2) ? "64-bit" : "32-bit"));
    return STATUS_SUCCESS;
}

// Enable PCI bus mastering (and memory space) on the SEP function.
// VERIFIED FROM SOURCE: Linux t2_sep_transport.c calls pci_set_master(pdev)
// before any OOL registration / AKS exchange. Without the bus-master bit
// SEP cannot DMA into the host OOL buffers and therefore never posts an
// EP7 reply → the exact "timed out waiting for SEP inbox reply" symptom
// observed on Gate 4 (capabilities / load-keybag).
NTSTATUS
T2EnablePciBusMaster(_In_ WDFDEVICE Device)
{
    NTSTATUS status;
    BUS_INTERFACE_STANDARD busInterface;
    USHORT command = 0;
    ULONG bytes;

    RtlZeroMemory(&busInterface, sizeof(busInterface));
    status = WdfFdoQueryForInterface(Device, &GUID_BUS_INTERFACE_STANDARD,
        (PINTERFACE)&busInterface, sizeof(busInterface), 1, NULL);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: WdfFdoQueryForInterface for bus-master enable failed, status=0x%x\n",
            status));
        return status;
    }

    bytes = busInterface.GetBusData(busInterface.Context, PCI_WHICHSPACE_CONFIG,
        &command, 0x04 /* PCI_COMMAND */, sizeof(command));
    if (bytes != sizeof(command)) {
        if (busInterface.InterfaceDereference) {
            busInterface.InterfaceDereference(busInterface.Context);
        }
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: GetBusData(PCI_COMMAND) read only %u bytes\n", bytes));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    // PCI_ENABLE_MEMORY_SPACE = 0x0002, PCI_ENABLE_BUS_MASTER = 0x0004
    // (standard PCI command register bits; same values Linux pci_set_master uses).
    if ((command & 0x0006) == 0x0006) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "T2TouchIdTransport: PCI bus-master + memory already enabled (cmd=0x%04x)\n",
            command));
        if (busInterface.InterfaceDereference) {
            busInterface.InterfaceDereference(busInterface.Context);
        }
        return STATUS_SUCCESS;
    }

    command |= 0x0006; // memory space + bus master
    bytes = busInterface.SetBusData(busInterface.Context, PCI_WHICHSPACE_CONFIG,
        &command, 0x04, sizeof(command));
    if (busInterface.InterfaceDereference) {
        busInterface.InterfaceDereference(busInterface.Context);
    }

    if (bytes != sizeof(command)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: SetBusData(PCI_COMMAND) wrote only %u bytes\n", bytes));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: enabled PCI bus-master + memory space (cmd=0x%04x)\n",
        command));
    return STATUS_SUCCESS;
}

NTSTATUS
T2EvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    UNREFERENCED_PARAMETER(Driver);

    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFDEVICE device;
    PT2_DEVICE_CONTEXT ctx;
    WDF_OBJECT_ATTRIBUTES lockAttributes;

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDevicePrepareHardware = T2EvtDevicePrepareHardware;
    pnpPowerCallbacks.EvtDeviceReleaseHardware = T2EvtDeviceReleaseHardware;
    pnpPowerCallbacks.EvtDeviceD0Entry = T2EvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit = T2EvtDeviceD0Exit;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(DeviceInit, FALSE);

    // WdfDeviceInitAssignSDDLString requires the device object to be named
    // first (explicitly via WdfDeviceInitAssignName, or auto-generated here) -
    // "you cannot provide a security descriptor for an unnamed device
    // object" (WDK docs). Without this, WdfDeviceInitAssignSDDLString fails
    // with STATUS_INVALID_SECURITY_DESCR, which is the actual cause of the
    // Code 31 / "SECURITY_DESCRIPTOR structure is not valid" failure - not
    // the SDDL string's content, which was already correct.
    WdfDeviceInitSetCharacteristics(DeviceInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

    // Root-only equivalent: restrict the device interface with a SDDL that
    // grants Administrators/SYSTEM only. Mirrors Linux /dev/t2-aks mode 0600.
    // MUST be assigned before WdfDeviceCreate: WdfDeviceCreate consumes and
    // nulls out DeviceInit on success, so calling
    // WdfDeviceInitAssignSDDLString afterward passes a NULL DeviceInit and
    // trips WDF_VIOLATION (0x10D, Arg1=4, "NULL parameter").
    status = WdfDeviceInitAssignSDDLString(DeviceInit,
        &g_T2SddlDevObjSysAllAdmAll); // SYSTEM + Administrators full control, everyone else denied
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, T2_DEVICE_CONTEXT);
    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ctx = GetDeviceContext(device);
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Device = device;

    WDF_OBJECT_ATTRIBUTES_INIT(&lockAttributes);
    lockAttributes.ParentObject = device;
    status = WdfWaitLockCreate(&lockAttributes, &ctx->ExchangeLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ctx->NextTransaction = 0;

    status = WdfDeviceCreateDeviceInterface(
        device, &GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = T2EvtIoDeviceControl;
    // Milestone 2B §4: this is a power-managed default queue (the WDF
    // default), so the framework can call EvtIoStop for a request that is
    // still executing when a power-down/PnP-stop/remove is starting. Our
    // IOCTL handlers are synchronous and complete the request themselves
    // (possibly after a long AKS mailbox exchange under ExchangeLock) - see
    // T2EvtIoStop for why we acknowledge-and-let-finish rather than force
    // completion here.
    queueConfig.EvtIoStop = T2EvtIoStop;
    // Lifecycle audit: no EvtIoResume is registered, and none is needed.
    // EvtIoResume exists for drivers that hold a request across EvtIoStop
    // and need to know when it is safe to act on it again; this driver
    // never does that (see T2EvtIoStop) - the request stays exclusively
    // owned by the thread already running its (possibly slow) handler,
    // which completes it itself regardless of queue stop/resume state. The
    // framework resumes dispatching *new* requests to this queue on its
    // own once un-stopped; there is no in-flight, driver-held request state
    // that a resume callback would need to react to.

    WDFQUEUE queue;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
T2EvtDevicePrepareHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFCMRESLIST ResourcesRaw,
    _In_ WDFCMRESLIST ResourcesTranslated
    )
{
    PT2_DEVICE_CONTEXT ctx = GetDeviceContext(Device);
    ULONG count = WdfCmResourceListGetCount(ResourcesTranslated);
    ULONG rawCount = WdfCmResourceListGetCount(ResourcesRaw);
    BOOLEAN foundBar = FALSE;
    PHYSICAL_ADDRESS bar4Base = { 0 };
    NTSTATUS pciStatus;

    // Confirmed on real hardware (docs/milestone-2-hardware-results.md):
    // this SEP PCI function exposes THREE memory BARs, not the single one
    // this driver originally assumed. Blindly taking "the first memory
    // resource" mapped the wrong region - mailbox reads returned constant
    // 0x0 status words that never legitimately reflect real inbox/outbox
    // state, and SET_OOL_IN spun through T2_SEP_MAX_SKIPPED_REPLIES bogus
    // "replies" before failing with STATUS_DEVICE_PROTOCOL_ERROR. Read
    // BAR4's real base address out of PCI config space and match it
    // against the assigned resource list instead of guessing.
    pciStatus = T2QueryBar4ViaPciConfig(Device, &bar4Base);

    if (NT_SUCCESS(pciStatus)) {
        // ResourcesRaw and ResourcesTranslated are parallel lists - index i
        // in one always corresponds to the same underlying resource as
        // index i in the other (WDF guarantee). Raw descriptors carry the
        // bus-relative address that matches what's actually programmed
        // into the PCI BAR register; translated descriptors carry the
        // CPU-usable address MmMapIoSpaceEx needs. We match on raw, then
        // map using translated.
        ULONG scanCount = (rawCount < count) ? rawCount : count;
        for (ULONG i = 0; i < scanCount; i++) {
            PCM_PARTIAL_RESOURCE_DESCRIPTOR rawDesc = WdfCmResourceListGetDescriptor(ResourcesRaw, i);
            if (rawDesc->Type == CmResourceTypeMemory &&
                rawDesc->u.Memory.Start.QuadPart == bar4Base.QuadPart) {
                PCM_PARTIAL_RESOURCE_DESCRIPTOR desc = WdfCmResourceListGetDescriptor(ResourcesTranslated, i);
                ctx->Bar4PhysicalAddress = desc->u.Memory.Start;
                ctx->Bar4Length = desc->u.Memory.Length;
                foundBar = TRUE;
                T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "T2TouchIdTransport: BAR4 confirmed via PCI config space at resource index %u "
                    "(len=0x%x)\n", i, desc->u.Memory.Length));
                break;
            }
        }
        if (!foundBar) {
            T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "T2TouchIdTransport: PCI config space reports BAR4 base 0x%I64x but no matching "
                "memory resource was found in the assigned resource list\n", bar4Base.QuadPart));
        }
    } else {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "T2TouchIdTransport: could not confirm BAR4 via PCI config space (status=0x%x); "
            "falling back to first-memory-resource heuristic - THIS IS UNRELIABLE, do not "
            "trust a successful mailbox read that follows this warning\n", pciStatus));
    }

    if (!foundBar) {
        // Last-resort fallback only - kept so the driver doesn't outright
        // refuse to load if GetBusData is ever unavailable on some target,
        // but this is exactly the heuristic that mapped the wrong BAR on
        // real hardware. Any warning below means BAR4 selection is still
        // unconfirmed.
        for (ULONG i = 0; i < count; i++) {
            PCM_PARTIAL_RESOURCE_DESCRIPTOR desc = WdfCmResourceListGetDescriptor(ResourcesTranslated, i);

            if (desc->Type == CmResourceTypeMemory) {
                if (!foundBar) {
                    ctx->Bar4PhysicalAddress = desc->u.Memory.Start;
                    ctx->Bar4Length = desc->u.Memory.Length;
                    foundBar = TRUE;
                } else {
                    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "T2TouchIdTransport: unexpected second memory BAR "
                        "(len=0x%x) - BAR4 selection logic needs review\n",
                        desc->u.Memory.Length));
                }
            }
        }
    }

    if (!foundBar) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: no memory resource found (expected BAR4)\n"));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (ctx->Bar4Length < T2_SEP_BAR_MIN_SIZE) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: BAR smaller than expected (0x%x < 0x%x)\n",
            ctx->Bar4Length, T2_SEP_BAR_MIN_SIZE));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    ctx->Bar4VirtualAddress = (PUCHAR)MmMapIoSpaceEx(
        ctx->Bar4PhysicalAddress, ctx->Bar4Length,
        PAGE_READWRITE | PAGE_NOCACHE);
    if (ctx->Bar4VirtualAddress == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ctx->Bar4Mapped = TRUE;

    // Observation-only by default (mirrors Linux register_ool=false): do
    // NOT enable bus mastering or allocate DMA here. That only happens on
    // an explicit IOCTL_T2_REGISTER_OOL request (dma.c).
    ULONG inbox = READ_REGISTER_ULONG((PULONG)(ctx->Bar4VirtualAddress + T2_SEP_INBOX_STATUS));
    ULONG outbox = READ_REGISTER_ULONG((PULONG)(ctx->Bar4VirtualAddress + T2_SEP_OUTBOX_STATUS));
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: mailbox inbox=0x%x empty=%d outbox=0x%x full=%d\n",
        inbox, (inbox & T2_SEP_INBOX_EMPTY_BIT) != 0,
        outbox, (outbox & T2_SEP_OUTBOX_FULL_BIT) != 0));
    // T2_LOG (see driver.h) wraps the real DbgPrintEx, not the KdPrintEx
    // macro, so it always references inbox/outbox regardless of build
    // configuration - no C4189 risk here anymore, and no
    // UNREFERENCED_PARAMETER needed.

    // Milestone 2B §2/§7: if OOL was ever successfully registered with SEP
    // on this device context (OolInRegistered/OolOutRegistered), it stays
    // Invalid even across a fresh PrepareHardware - T2EvtDeviceReleaseHardware
    // deliberately never frees or deregisters that memory (no dereg opcode
    // exists, and this same WDFDEVICE/context can be reused across a
    // Stop/Start resource-rebalance without ever being destroyed), so SEP
    // may still hold and use that physical address. Re-arming to
    // HardwareReady here would let a later IOCTL_T2_REGISTER_OOL allocate a
    // brand-new buffer while the old one is still live SEP-side - exactly
    // the false-Ready/unsafe-retry situation §6/§7 rule out. Only a
    // context that never reached SEP can safely restart at HardwareReady.
    WdfWaitLockAcquire(ctx->ExchangeLock, NULL);
    if (!ctx->OolInRegistered && !ctx->OolOutRegistered && !ctx->OolSepMayKnowAddress) {
        T2SetTransportState(ctx, T2TransportHardwareReady);
    } else {
        T2SetTransportState(ctx, T2TransportInvalid);
    }
    WdfWaitLockRelease(ctx->ExchangeLock);

    return STATUS_SUCCESS;
}

NTSTATUS
T2EvtDeviceReleaseHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFCMRESLIST ResourcesTranslated
    )
{
    UNREFERENCED_PARAMETER(ResourcesTranslated);
    PT2_DEVICE_CONTEXT ctx = GetDeviceContext(Device);

    // Milestone 2B §7: block any new AKS exchange/registration attempt
    // before touching anything else below, and serialize against whatever
    // may currently be in flight - ExchangeLock is the same lock
    // T2EvtIoDeviceControlAksExchange/RegisterOol hold while touching SEP,
    // so acquiring it here guarantees no such operation is mid-flight once
    // we proceed to unmap/release.
    WdfWaitLockAcquire(ctx->ExchangeLock, NULL);
    T2SetTransportState(ctx, T2TransportStopping);
    WdfWaitLockRelease(ctx->ExchangeLock);

    // VERIFIED FROM SOURCE (Milestone 1, section 3 "Pinning"): the Linux
    // module deliberately never deregisters SEP-registered OOL buffers and
    // never unmaps/frees them once SET_OOL_IN/SET_OOL_OUT succeed, because
    // no deregistration opcode is implemented on the Linux side and SEP
    // retains the physical addresses. We copy that caution exactly: if OOL
    // buffers were successfully registered, do NOT free the common buffers
    // or clear bus-mastering here. A reboot is required to actually free
    // that memory at the hardware level; leaking the WDF handles instead of
    // freeing live SEP-owned memory is the correct, deliberate choice.
    BOOLEAN oolWasRegistered = ctx->OolInRegistered || ctx->OolOutRegistered || ctx->OolSepMayKnowAddress;
    if (oolWasRegistered) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "T2TouchIdTransport: retaining SEP-registered DMA memory until reboot\n"));
    } else {
        T2DmaFreeOolBuffers(ctx);
    }

    if (ctx->Bar4Mapped) {
        MmUnmapIoSpace(ctx->Bar4VirtualAddress, ctx->Bar4Length);
        ctx->Bar4Mapped = FALSE;
    }

    // Milestone 2B §2/§7: land in a state that documents WHY, rather than
    // just clearing a boolean. If SEP-owned OOL memory is being retained,
    // this transport instance must never look Ready again (Invalid,
    // permanent for this context - see the matching check in
    // T2EvtDevicePrepareHardware). Otherwise nothing SEP-visible ever
    // happened and it is safe to fall back to a clean slate.
    WdfWaitLockAcquire(ctx->ExchangeLock, NULL);
    T2SetTransportState(ctx, oolWasRegistered ? T2TransportInvalid : T2TransportNotInitialized);
    WdfWaitLockRelease(ctx->ExchangeLock);

    return STATUS_SUCCESS;
}

NTSTATUS
T2EvtDeviceD0Entry(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
    )
{
    PT2_DEVICE_CONTEXT ctx = GetDeviceContext(Device);

    // Sleep/wake audit trail (Milestone 2B §2.2 follow-up): log entry to
    // every D0Entry with the D-state we're coming from, unconditionally,
    // before any early-return below - this is what lets a DebugView/ETW
    // capture actually answer "did the device power up at all, and from
    // what state" when correlating against a suspected sleep/wake drain,
    // instead of only seeing the liveness-check line lower down (which is
    // skipped by both early returns).
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: D0Entry ENTER PreviousState=%d (WdfPowerDevice: "
        "D0=1 D1=2 D2=3 D3=4 D3Final=5)\n", PreviousState));

    // Milestone 2 section 26 / Milestone 2B §3: never assume old
    // protocol/session state remains valid across a power transition.
    // User-mode protocol state (BridgeXpc/BiometricKit session) must
    // independently re-initialize after any D0 exit -> D0 entry regardless
    // of what we do here.
    WdfWaitLockAcquire(ctx->ExchangeLock, NULL);

    if (!ctx->Bar4Mapped) {
        // PrepareHardware has not run yet (or failed) for this power-up -
        // nothing transport-specific to revalidate; leave State as-is
        // (NotInitialized) and let PrepareHardware set it when it runs.
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "T2TouchIdTransport: D0Entry EXIT - Bar4 not mapped yet, "
            "deferring to PrepareHardware, State unchanged (%d)\n",
            ctx->State));
        WdfWaitLockRelease(ctx->ExchangeLock);
        return STATUS_SUCCESS;
    }

    if (ctx->State == T2TransportInvalid) {
        // SEP-owned OOL memory is being retained (§7) - this transport
        // instance stays Invalid across power transitions too, for the
        // same reason it stays Invalid across a fresh PrepareHardware.
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "T2TouchIdTransport: D0Entry EXIT - State=Invalid (SEP-owned OOL "
            "memory retained until reboot), staying Invalid across this "
            "power transition\n"));
        WdfWaitLockRelease(ctx->ExchangeLock);
        return STATUS_SUCCESS;
    }

    // Do a real liveness check of the mailbox registers rather than
    // trusting that D0 entry alone means the SEP side resumed cleanly - a
    // read that succeeds is the same liveness signal T2EvtIoDeviceControlGetStatus
    // uses. A read that comes back all-ones (T2_SEP_MAILBOX_DEAD_READ) means
    // nothing actually answered on the bus (link still down / device not
    // really back yet), which is treated as a liveness *failure* below, not
    // just an unusual register value.
    ULONG inbox = READ_REGISTER_ULONG((PULONG)(ctx->Bar4VirtualAddress + T2_SEP_INBOX_STATUS));
    BOOLEAN livenessOk = (inbox != T2_SEP_MAILBOX_DEAD_READ);
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: D0Entry mailbox liveness check inbox=0x%x empty=%d ... %s\n",
        inbox, (inbox & T2_SEP_INBOX_EMPTY_BIT) != 0,
        livenessOk ? "success" : "failed"));

    // State-model fix (D0 resume OOL state inconsistency): an ordinary
    // D0 -> D3 -> D0 cycle must never leave TransportState and
    // Ool*Registered contradicting each other (HardwareReady while OOL is
    // still fully registered, which is exactly what let a status query
    // report "OOL registered" right next to an AKS exchange rejected with
    // STATUS_DEVICE_NOT_READY). Hardware testing confirmed the same SEP OOL
    // registration keeps working across an ordinary sleep/resume - so if
    // the mailbox came back alive AND both OOL buffers were confirmed
    // registered before this power transition, resume directly to Ready.
    // Do NOT re-run IOCTL_T2_REGISTER_OOL here (no SET_OOL_IN/SET_OOL_OUT) -
    // the existing registration is trusted, not re-sent.
    //
    // Any other case fails closed into HardwareReady, same as before: a
    // dead mailbox, or an incomplete/absent OOL registration, means the
    // *next* IOCTL_T2_AKS_EXCHANGE gets an immediate STATUS_DEVICE_NOT_READY
    // (see the Ctx->State != T2TransportReady check in
    // T2EvtIoDeviceControlAksExchange) instead of a silent stale-Ready
    // mailbox timeout, and IOCTL_T2_REGISTER_OOL must be explicitly re-run
    // to reach Ready again (T2DmaAllocateOolBuffers is idempotent and
    // T2DmaRegisterOolBuffers re-sends SET_OOL_IN/OUT unconditionally
    // whenever State == HardwareReady, so that path is unaffected).
    BOOLEAN oolFullyRegistered = ctx->OolInRegistered && ctx->OolOutRegistered;

    if (livenessOk && oolFullyRegistered) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "T2TouchIdTransport: D0Entry resume (PreviousState=%d, "
            "OolInRegistered=1, OolOutRegistered=1, PriorState=%d) -> Ready; "
            "not re-running IOCTL_T2_REGISTER_OOL\n",
            PreviousState, ctx->State));
        T2SetTransportState(ctx, T2TransportReady);
    } else {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "T2TouchIdTransport: D0Entry (PreviousState=%d, livenessOk=%d, "
            "OolInRegistered=%d, OolOutRegistered=%d, PriorState=%d) -> "
            "HardwareReady; next AKS exchange fails closed until "
            "IOCTL_T2_REGISTER_OOL re-confirms with SEP\n",
            PreviousState, livenessOk, ctx->OolInRegistered,
            ctx->OolOutRegistered, ctx->State));
        T2SetTransportState(ctx, T2TransportHardwareReady);
    }

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: D0Entry EXIT - State=%d\n", ctx->State));

    WdfWaitLockRelease(ctx->ExchangeLock);
    return STATUS_SUCCESS;
}

NTSTATUS
T2EvtDeviceD0Exit(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
    )
{
    PT2_DEVICE_CONTEXT ctx = GetDeviceContext(Device);

    // Sleep/wake audit trail: log entry with the D-state we're heading
    // into (D3 covers S1-S4 system sleep/hibernate; see the D0Entry log
    // line above for the WdfPowerDevice numeric legend) before we even try
    // to acquire the lock, so a hang/long-wait acquiring ExchangeLock
    // (bounded by an in-flight exchange, see the comment below) is still
    // visible in the log as "D0Exit was entered but hasn't exited yet".
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: D0Exit ENTER TargetState=%d, current State=%d\n",
        TargetState, ctx->State));

    // Milestone 2B §3/§9: block new AKS exchanges/registration before the
    // power transition proceeds. Acquiring ExchangeLock here is also what
    // makes this safe against a transaction currently in flight: since
    // T2EvtIoDeviceControlAksExchange/RegisterOol hold this same lock for
    // the entire duration of their SEP call, this Acquire blocks until any
    // such call already in progress has finished (bounded by
    // T2_SEP_TRANSACTION_DEADLINE_US) - D0Exit cannot return, and the power
    // transition cannot proceed, out from under a live exchange.
    WdfWaitLockAcquire(ctx->ExchangeLock, NULL);
    if (ctx->State == T2TransportReady || ctx->State == T2TransportRegisteringOol) {
        // Not Ready again until D0Entry positively revalidates - see
        // T2EvtDeviceD0Entry. RegisteringOol should not normally still be
        // set here (the handler holds this same lock for the whole
        // registration), but fold it in defensively rather than leaving a
        // stale in-progress-looking state across the transition.
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "T2TouchIdTransport: D0Exit demoting State %d -> HardwareReady "
            "before power-down\n", ctx->State));
        T2SetTransportState(ctx, T2TransportHardwareReady);
    }
    WdfWaitLockRelease(ctx->ExchangeLock);

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: D0Exit EXIT TargetState=%d, State=%d\n",
        TargetState, ctx->State));

    return STATUS_SUCCESS;
}

static VOID
T2EvtIoDeviceControlGetStatus(_In_ WDFREQUEST Request, _In_ PT2_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    PT2_TRANSPORT_STATUS out;
    size_t outLen;

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID*)&out, &outLen);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    // WdfRequestRetrieveOutputBuffer's contract guarantees outLen is at
    // least the MinimumRequiredSize (sizeof(*out)) we passed in whenever it
    // returns success - that guarantee just isn't expressed in the KMDF
    // header's SAL (_Outptr_result_bytebuffer_(*Length) ties the buffer's
    // size to *Length alone, not to the input minimum), so /analyze can't
    // derive it on its own. Restated explicitly rather than suppressed.
    _Analysis_assume_(outLen >= sizeof(*out));
    RtlZeroMemory(out, sizeof(*out));
    out->PciPresent = TRUE;
    out->VendorId = T2_SEP_VENDOR_ID;
    out->DeviceId = T2_SEP_DEVICE_ID;
    out->Bar4Mapped = Ctx->Bar4Mapped;
    out->Bar4Size = Ctx->Bar4Length;
    out->OolRegistered = Ctx->OolInRegistered && Ctx->OolOutRegistered;

    if (Ctx->Bar4Mapped) {
        ULONG inbox = READ_REGISTER_ULONG((PULONG)(Ctx->Bar4VirtualAddress + T2_SEP_INBOX_STATUS));
        UNREFERENCED_PARAMETER(inbox);
        out->MailboxAccessible = TRUE; // a successful MMIO read is our liveness signal
    }

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*out));
}

static VOID
T2EvtIoDeviceControlRegisterOol(_In_ WDFREQUEST Request, _In_ PT2_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;

    WdfWaitLockAcquire(Ctx->ExchangeLock, NULL);

    if (Ctx->State == T2TransportReady) {
        // Idempotent: already fully registered - a second call is a no-op
        // success, never a second live registration.
        WdfWaitLockRelease(Ctx->ExchangeLock);
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    if (Ctx->State != T2TransportHardwareReady) {
        // Milestone 2B §6: only HardwareReady may start (or retry) a
        // registration attempt. NotInitialized/Stopping mean hardware
        // isn't ready yet or is going away; RegisteringOol means another
        // attempt is (unexpectedly, since this lock is held throughout one)
        // already in progress; Invalid means a previous attempt already
        // reached SEP with OOL_IN and must never be retried with a fresh
        // allocation (§5/§7) - a real, deliberate terminal state for that
        // specific case, not a permanent "attempted" flag misused as
        // failure-forever.
        WdfWaitLockRelease(Ctx->ExchangeLock);
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }

    Ctx->OolRegisterAttempted = TRUE; // diagnostic only, see driver.h
    T2SetTransportState(Ctx, T2TransportRegisteringOol);

    status = T2DmaAllocateOolBuffers(Ctx);
    if (NT_SUCCESS(status)) {
        status = T2DmaRegisterOolBuffers(Ctx);
    }

    if (NT_SUCCESS(status)) {
        T2SetTransportState(Ctx, T2TransportReady);
    } else if (Ctx->OolInRegistered || Ctx->OolSepMayKnowAddress) {
        // Terminal, not retryable. Ctx->OolInRegistered means SET_OOL_IN
        // was *confirmed* before SET_OOL_OUT failed. Ctx->OolSepMayKnowAddress
        // covers the wider case: SET_OOL_IN (or OUT) was handed to the
        // mailbox hardware but its own confirmation never came back (reply
        // timeout / skipped-message overflow) - OolInRegistered can still
        // be FALSE here even though SEP may already hold the address. Both
        // are treated identically: never free, never retry with a fresh
        // allocation (§5/§7).
        T2SetTransportState(Ctx, T2TransportInvalid);
    } else {
        // Genuinely failed before anything left this host for SEP
        // (allocation failure, bus-master enable failure, or the mailbox
        // send itself never went out) - dma.c already rolled back any
        // partial allocation on the allocate path; free anything still
        // outstanding from the register path and it's safe to retry.
        T2DmaFreeOolBuffers(Ctx);
        T2SetTransportState(Ctx, T2TransportHardwareReady);
    }

    WdfWaitLockRelease(Ctx->ExchangeLock);

    WdfRequestComplete(Request, status);
}

VOID
T2EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PT2_DEVICE_CONTEXT ctx = GetDeviceContext(WdfIoQueueGetDevice(Queue));

    switch (IoControlCode) {
    case IOCTL_T2_GET_STATUS:
        T2EvtIoDeviceControlGetStatus(Request, ctx);
        break;
    case IOCTL_T2_REGISTER_OOL:
        T2EvtIoDeviceControlRegisterOol(Request, ctx);
        break;
    case IOCTL_T2_AKS_EXCHANGE:
        T2EvtIoDeviceControlAksExchange(Request, ctx);
        break;
    default:
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        break;
    }
}

// Milestone 2B §4 (revisited — EvtIoStop/cancellation lifecycle audit,
// see docs/milestone-2b-evtiostop-cancellation-audit.md for the full
// writeup): EvtIoStop for the power-managed default queue.
//
// KMDF only invokes this callback for a request that has already been
// DELIVERED to (and is owned by) this driver - i.e. a request currently
// executing inside T2EvtIoDeviceControl on some dispatch thread, blocked
// inside T2SepControl/T2SepAksTransaction's receive loop under
// ExchangeLock. A request still sitting in the queue, not yet dispatched
// (e.g. queued behind another one - this is a WdfIoQueueDispatchSequential
// queue), is never handed to the driver at all while the queue is being
// stopped/purged: the framework retains or cancels those itself and never
// calls this callback for them (VERIFIED per Microsoft's KMDF "Canceled
// and Suspended Requests" documentation: "If the request has been
// delivered and is owned by the driver, the framework does not cancel
// it"). So the "the owning handler will complete this" assumption below
// always holds for every request this callback actually sees - there is
// no undispatched-request case to additionally handle here.
//
// A long-running IOCTL_T2_AKS_EXCHANGE or IOCTL_T2_REGISTER_OOL request may
// still be executing (blocked inside T2AksExchange/T2DmaRegisterOolBuffers
// under ExchangeLock, on whatever dispatch thread WDF ran the callback on)
// when the framework needs to stop the queue for a power-down, PnP stop, or
// remove. We deliberately do NOT try to force-complete or cancel that
// request from here:
//   - the mailbox transaction it is waiting on may still be legitimately
//     in flight with real hardware/SEP, and forcing early completion would
//     race with the owning handler's own WdfRequestComplete call, i.e.
//     double-completion (explicitly out of scope per the Definition of
//     Done and §12);
//   - whether the transaction can even be safely aborted mid-flight is
//     unknown for this protocol (no SEP opcode exists to cancel a
//     control/AKS exchange already sent), so the conservative choice is to
//     let it run to its own conclusion rather than invent a fake abort;
//   - registering the request as cancelable (WdfRequestMarkCancelable) so
//     an app-initiated CancelIoEx/process-exit could interrupt the wait
//     was deliberately NOT added: T2MailboxReceive's poll loop has no safe
//     mid-iteration abort point that wouldn't risk completing the request
//     from the EvtRequestCancel callback at the same time the owning
//     handler thread is still touching MMIO/the reply buffer under
//     ExchangeLock - exactly the double-completion/use-after-free shape
//     this callback already avoids by not force-completing on its own.
// T2_SEP_TRANSACTION_DEADLINE_US already bounds how long that "let it
// finish" can take (~15s per control/AKS transaction, ~30s worst case for
// IOCTL_T2_REGISTER_OOL's two sequential SET_OOL_IN/SET_OOL_OUT calls) -
// this can never hang forever, satisfying the "guaranteed to complete in a
// bounded amount of time" condition under which Microsoft's own KMDF
// documentation says a driver may legitimately take this
// acknowledge-and-let-finish approach in EvtIoStop instead of requeuing or
// force-completing. Per WdfRequestStopAcknowledge's documented contract,
// the framework itself will not let the device actually leave D0 (or
// complete a remove) until this acknowledged request is completed - so
// this bound is also the actual upper limit on how long a sleep/
// Disable-device transition can be held up by an in-flight exchange, on
// top of (not instead of) the ExchangeLock-based serialization
// T2EvtDeviceD0Exit/T2EvtDeviceReleaseHardware already do.
//
// ActionFlags (WdfRequestStopActionSuspend vs ...Purge) only changes
// whether the framework can later resume dispatching to this queue - it
// does not change what we do here (both cases: acknowledge, let the
// in-flight handler finish and complete it itself), so both are logged
// identically for diagnostics and handled the same way. We call
// WdfRequestStopAcknowledge(Request, FALSE) to tell the framework "I see
// this request, I am not completing/requeuing it right now, I will
// complete it myself later" - the correct response either for
// WdfRequestStopActionSuspend (resumable stop) or
// WdfRequestStopActionPurge (surprise-remove): in both cases the owning
// handler, not this callback, completes the request.
VOID
T2EvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
    )
{
    UNREFERENCED_PARAMETER(Queue);

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "T2TouchIdTransport: EvtIoStop for in-flight request 0x%p "
        "(ActionFlags=0x%x: Suspend=%d Purge=%d RequestCancelable=%d); "
        "acknowledging without completing - letting the owning handler "
        "finish and complete it itself (bounded by "
        "T2_SEP_TRANSACTION_DEADLINE_US per SEP transaction)\n",
        Request, ActionFlags,
        (ActionFlags & WdfRequestStopActionSuspend) != 0,
        (ActionFlags & WdfRequestStopActionPurge) != 0,
        (ActionFlags & WdfRequestStopRequestCancelable) != 0));

    WdfRequestStopAcknowledge(Request, FALSE);
}

// Payload travels inline in the METHOD_BUFFERED request/response buffers
// (see public.h for why: passing raw user VAs inside the struct and
// probing them here would only be safe if this callback always ran on the
// calling thread in the calling process's context, which KMDF does not
// guarantee). WdfRequestRetrieveInputBuffer/RetrieveOutputBuffer hand back
// pointers into a buffer the I/O manager already copied to/from user-mode
// for us, in the correct process context, before this callback ever runs -
// no ProbeForRead/ProbeForWrite or __try/except needed for that part.
static VOID
T2EvtIoDeviceControlAksExchange(_In_ WDFREQUEST Request, _In_ PT2_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    PT2_AKS_EXCHANGE_IN in;
    PT2_AKS_EXCHANGE_OUT out;
    size_t inLen = 0;
    size_t outLen = 0;
    SIZE_T requestLength;
    SIZE_T responseCapacity;
    SIZE_T responseLength = 0;
    UINT8 operation;
    PUCHAR requestBody = NULL;
    PUCHAR responseBody = NULL;

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(*in), (PVOID*)&in, &inLen);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    requestLength = inLen - sizeof(*in);

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID*)&out, &outLen);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }
    responseCapacity = outLen - sizeof(*out);
    operation = in->Operation;

    // Milestone 2B §2: cheap pre-check outside the lock, purely to avoid
    // allocating scratch buffers for a request we already know will be
    // rejected. The authoritative check is the one taken under
    // ExchangeLock immediately before T2AksExchange below - this one can
    // race with a concurrent D0Exit/ReleaseHardware and that's fine, it
    // only ever causes an extra allocate+free, never an unsafe exchange.
    if (Ctx->State != T2TransportReady) {
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }

    // Kernel-side allow-list re-check — independent of whatever public.h's
    // enum implies the caller validated. This is the actual security
    // boundary (Milestone 2, section 25: "No generic arbitrary AKS opcode
    // execution").
    if (!T2AksOperationAllowed(operation)) {
        WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
        return;
    }

    if (requestLength > T2_AKS_MAX_BODY_SIZE || responseCapacity > T2_AKS_MAX_BODY_SIZE) {
        WdfRequestComplete(Request, STATUS_INVALID_BUFFER_SIZE);
        return;
    }

    // For METHOD_BUFFERED, `in` and `out` alias the SAME system buffer, so
    // the request body must be copied out to a scratch allocation before
    // anything below writes into `out` - otherwise we'd clobber the still
    // -unread request body in place.
    if (requestLength > 0) {
        requestBody = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, requestLength, 'qeRT');
        if (requestBody == NULL) {
            WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
            return;
        }
        RtlCopyMemory(requestBody, (PUCHAR)in + sizeof(*in), requestLength);
    }

    if (responseCapacity > 0) {
        responseBody = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, responseCapacity, 'peRT');
        if (responseBody == NULL) {
            if (requestBody) ExFreePoolWithTag(requestBody, 'qeRT');
            WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
            return;
        }
    }

    WdfWaitLockAcquire(Ctx->ExchangeLock, NULL);
    // Authoritative check (Milestone 2B §2/§3): D0Exit/ReleaseHardware
    // acquire this same lock to move State out of Ready, so if we observe
    // Ready here, no such transition can be racing us - and this check
    // plus the exchange itself run as one atomic unit under the lock, so
    // nothing can move the state out from under an in-progress exchange
    // either (that guarantee is exactly what makes D0Exit's Acquire above
    // block until an in-flight exchange finishes).
    if (Ctx->State != T2TransportReady) {
        status = STATUS_DEVICE_NOT_READY;
    } else {
        status = T2AksExchange(Ctx, operation, requestBody, requestLength,
            responseBody, responseCapacity, &responseLength);
    }
    WdfWaitLockRelease(Ctx->ExchangeLock);

    if (requestBody) {
        RtlSecureZeroMemory(requestBody, requestLength);
        ExFreePoolWithTag(requestBody, 'qeRT');
    }

    if (NT_SUCCESS(status)) {
        // T2AksExchange already enforces responseLength <= responseCapacity
        // internally (akstore.c: "if (bodyLen > ResponseCapacity) return
        // STATUS_BUFFER_TOO_SMALL"), so this clamp should never actually
        // trigger on any successful exchange. It's kept as a real runtime
        // invariant rather than an _Analysis_assume_ claim for two reasons:
        // /analyze's dataflow needs to see the bound enforced by control
        // flow to clear the RtlCopyMemory read below, and it's genuine
        // defense-in-depth if T2AksExchange's own check is ever weakened
        // by a future change without this call site being revisited.
        if (responseLength > responseCapacity) {
            NT_ASSERT(FALSE);
            responseLength = responseCapacity;
        }
        _Analysis_assume_(responseBody != NULL || responseLength == 0);
        if (responseLength > 0) {
            // /analyze still flags this read even with the clamp above
            // making responseLength <= responseCapacity a real, checked
            // runtime invariant (confirmed across two independent fixes -
            // an _Analysis_assume_ claim, then this clamp - neither
            // satisfied it). This is a known /analyze limitation tracking
            // buffer size for ExAllocatePool2-allocated memory across
            // value-narrowing control flow, not an actual defect: the
            // clamp two lines above is what actually keeps this safe.
            #pragma warning(suppress: 6385)
            RtlCopyMemory((PUCHAR)out + sizeof(*out), responseBody, responseLength);
        }
        out->ResponseLength = (UINT32)responseLength;
    }

    if (responseBody) {
        RtlSecureZeroMemory(responseBody, responseCapacity);
        ExFreePoolWithTag(responseBody, 'peRT');
    }

    if (NT_SUCCESS(status)) {
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*out) + responseLength);
        return;
    }

    WdfRequestComplete(Request, status);
}
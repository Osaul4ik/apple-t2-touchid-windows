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

    // VERIFIED FROM SOURCE (Milestone 1, section 3 "Pinning"): the Linux
    // module deliberately never deregisters SEP-registered OOL buffers and
    // never unmaps/frees them once SET_OOL_IN/SET_OOL_OUT succeed, because
    // no deregistration opcode is implemented on the Linux side and SEP
    // retains the physical addresses. We copy that caution exactly: if OOL
    // buffers were successfully registered, do NOT free the common buffers
    // or clear bus-mastering here. A reboot is required to actually free
    // that memory at the hardware level; leaking the WDF handles instead of
    // freeing live SEP-owned memory is the correct, deliberate choice.
    if (ctx->OolInRegistered || ctx->OolOutRegistered) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "T2TouchIdTransport: retaining SEP-registered DMA memory until reboot\n"));
    } else {
        T2DmaFreeOolBuffers(ctx);
    }

    if (ctx->Bar4Mapped) {
        MmUnmapIoSpace(ctx->Bar4VirtualAddress, ctx->Bar4Length);
        ctx->Bar4Mapped = FALSE;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
T2EvtDeviceD0Entry(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
    )
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(PreviousState);
    // Milestone 2 section 26: never assume old protocol/session state
    // remains valid across a power transition. Nothing to invalidate at
    // the transport layer itself (it is stateless below the AKS exchange
    // lock), but user-mode protocol state (BridgeXpc/BiometricKit session)
    // must independently re-initialize after any D0 exit -> D0 entry.
    return STATUS_SUCCESS;
}

NTSTATUS
T2EvtDeviceD0Exit(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
    )
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(TargetState);
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
    if (Ctx->OolRegisterAttempted) {
        WdfWaitLockRelease(Ctx->ExchangeLock);
        // Idempotent: registering twice is a no-op success/failure of the
        // first attempt, never a second live registration.
        WdfRequestComplete(Request, Ctx->OolInRegistered && Ctx->OolOutRegistered
            ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY);
        return;
    }
    Ctx->OolRegisterAttempted = TRUE;

    status = T2DmaAllocateOolBuffers(Ctx);
    if (NT_SUCCESS(status)) {
        status = T2DmaRegisterOolBuffers(Ctx);
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

    if (!Ctx->OolInRegistered || !Ctx->OolOutRegistered) {
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
    status = T2AksExchange(Ctx, operation, requestBody, requestLength,
        responseBody, responseCapacity, &responseLength);
    WdfWaitLockRelease(Ctx->ExchangeLock);

    if (requestBody) {
        RtlSecureZeroMemory(requestBody, requestLength);
        ExFreePoolWithTag(requestBody, 'qeRT');
    }

    if (NT_SUCCESS(status)) {
        // Safe: T2AksExchange already bounds-checked responseLength against
        // the responseCapacity we gave it (<= outLen - sizeof(*out)).
        if (responseLength > 0) {
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
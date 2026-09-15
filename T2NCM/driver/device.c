// SPDX-License-Identifier: GPL-2.0-only
// Device.c — miniport-mode WDFDEVICE, lifecycle state machine,
// diagnostic status snapshot. See Device.h for what left this file.

#include "Device.h"
#include "NcmProtocol.h"

static const char* T2NcmStateName(T2NCM_LIFECYCLE_STATE s)
{
    switch (s)
    {
    case T2NcmStateCreated:        return "Created";
    case T2NcmStatePrepared:       return "Prepared";
    case T2NcmStateUsbReady:       return "UsbReady";
    case T2NcmStateNcmReady:       return "NcmReady";
    case T2NcmStateNdisRegistered: return "NdisRegistered";
    case T2NcmStateRunning:        return "Running";
    case T2NcmStateStopping:       return "Stopping";
    case T2NcmStateReleased:       return "Released";
    default:                       return "?";
    }
}

BOOLEAN
T2NcmTrySetState(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ T2NCM_LIFECYCLE_STATE ExpectedCurrent,
    _In_ T2NCM_LIFECYCLE_STATE NewState
    )
{
    BOOLEAN ok = FALSE;

    WdfSpinLockAcquire(DeviceContext->StateLock);
    if (DeviceContext->State == ExpectedCurrent)
    {
        DeviceContext->State = NewState;
        ok = TRUE;
    }
    WdfSpinLockRelease(DeviceContext->StateLock);

    if (ok)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
            "T2Ncm: state %s -> %s\n",
            T2NcmStateName(ExpectedCurrent), T2NcmStateName(NewState)));
    }
    else
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
            "T2Ncm: transition expected=%s new=%s not taken (state differs)\n",
            T2NcmStateName(ExpectedCurrent), T2NcmStateName(NewState)));
    }

    return ok;
}

BOOLEAN
T2NcmIsIoAllowed(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    BOOLEAN allowed;
    WdfSpinLockAcquire(DeviceContext->StateLock);
    allowed = (DeviceContext->State == T2NcmStateUsbReady) ||
              (DeviceContext->State == T2NcmStateNcmReady) ||
              (DeviceContext->State == T2NcmStateNdisRegistered) ||
              (DeviceContext->State == T2NcmStateRunning);
    WdfSpinLockRelease(DeviceContext->StateLock);
    return allowed;
}

NTSTATUS
T2NcmDeviceCreate(
    _In_  WDFDRIVER               Driver,
    _In_  PDEVICE_OBJECT          FunctionalDeviceObject,
    _In_  PDEVICE_OBJECT          NextDeviceObject,
    _In_  PDEVICE_OBJECT          PhysicalDeviceObject,
    _Out_ WDFDEVICE*              Device,
    _Out_ PT2NCM_DEVICE_CONTEXT*  DeviceContext
    )
{
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDEVICE device = NULL;
    PT2NCM_DEVICE_CONTEXT context;

    *Device = NULL;
    *DeviceContext = NULL;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, T2NCM_DEVICE_CONTEXT);

    // WdfDeviceMiniportCreate, not WdfDeviceCreate: this wraps device
    // objects that NDIS created and owns. The resulting WDFDEVICE has no
    // PnP or power callbacks, is not the power policy owner, and has no
    // I/O queues — which is precisely what makes it impossible for this
    // driver to accidentally take power decisions back from NDIS.
    status = WdfDeviceMiniportCreate(
        Driver,
        &attributes,
        FunctionalDeviceObject,
        NextDeviceObject,
        PhysicalDeviceObject,
        &device);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfDeviceMiniportCreate failed 0x%08X\n", status));
        return status;
    }

    context = T2NcmGetDeviceContext(device);
    RtlZeroMemory(context, sizeof(*context));
    context->WdfDevice = device;
    context->State = T2NcmStateCreated;
    context->PowerState = NdisDeviceStateD0;
    context->CurrentLookahead = T2NCM_MAX_FRAME_SIZE;

    // NDIS will set the real filter via OID_GEN_CURRENT_PACKET_FILTER
    // before any traffic is expected; starting at zero (accept nothing)
    // rather than at "accept everything" means a frame indicated before
    // that OID arrives is dropped rather than leaked upward.
    context->PacketFilter = 0;

    KeInitializeEvent(&context->QuiesceEvent, NotificationEvent, FALSE);

    status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->StateLock);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfSpinLockCreate failed 0x%08X\n", status));
        WdfObjectDelete(device);
        return status;
    }

    // Work item for pushing SET_ETHERNET_PACKET_FILTER to the device
    // when the OID path runs above PASSIVE_LEVEL. Non-fatal if it
    // cannot be created: T2NcmRequestPacketFilterUpdate still applies
    // inline whenever it is called at PASSIVE_LEVEL, which is the
    // common case, and logs when it cannot.
    {
        WDF_WORKITEM_CONFIG workItemConfig;
        WDF_OBJECT_ATTRIBUTES workItemAttributes;

        WDF_WORKITEM_CONFIG_INIT(&workItemConfig, T2NcmEvtPacketFilterWorkItem);
        WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);
        workItemAttributes.ParentObject = device;

        status = WdfWorkItemCreate(&workItemConfig, &workItemAttributes,
            &context->PacketFilterWorkItem);
        if (!NT_SUCCESS(status))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: WdfWorkItemCreate (packet filter) failed 0x%08X - "
                "filter updates raised above PASSIVE_LEVEL will be skipped\n",
                status));
            context->PacketFilterWorkItem = NULL;
        }
    }

    *Device = device;
    *DeviceContext = context;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: miniport-mode WDFDEVICE created (NDIS owns PnP/power)\n"));

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------
// Diagnostic status snapshot. Everything in T2NCM_STATUS defaults to
// zero/FALSE from the RtlZeroMemory below and is only set to something
// else if the corresponding real state exists.
// ---------------------------------------------------------------------
VOID
T2NcmDeviceFillStatus(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_ PT2NCM_STATUS         Status
    )
{
    T2NCM_LIFECYCLE_STATE state;

    RtlZeroMemory(Status, sizeof(*Status));

    WdfSpinLockAcquire(DeviceContext->StateLock);
    state = DeviceContext->State;
    WdfSpinLockRelease(DeviceContext->StateLock);

    // T2NCM_LIFECYCLE_STATE (Driver.h) and T2NCM_WIRE_STATE (public.h)
    // are deliberately separate enums with matching values — assert the
    // mapping stays in sync rather than silently drifting. MSVC's C5287
    // fires on enum-vs-enum comparisons even through an explicit (int)
    // cast in C mode; that's exactly what this comparison intentionally
    // does, so silence it locally rather than restructuring the check.
#pragma warning(push)
#pragma warning(disable: 5287)
    C_ASSERT((int)T2NcmStateCreated        == (int)T2NcmWireStateCreated);
    C_ASSERT((int)T2NcmStatePrepared       == (int)T2NcmWireStatePrepared);
    C_ASSERT((int)T2NcmStateUsbReady       == (int)T2NcmWireStateUsbReady);
    C_ASSERT((int)T2NcmStateNcmReady       == (int)T2NcmWireStateNcmReady);
    C_ASSERT((int)T2NcmStateNdisRegistered == (int)T2NcmWireStateNdisRegistered);
    C_ASSERT((int)T2NcmStateRunning        == (int)T2NcmWireStateRunning);
    C_ASSERT((int)T2NcmStateStopping       == (int)T2NcmWireStateStopping);
    C_ASSERT((int)T2NcmStateReleased       == (int)T2NcmWireStateReleased);
#pragma warning(pop)

    Status->LifecycleState = (UINT32)state;

    Status->Ntb16Supported = DeviceContext->Ntb16Supported;
    Status->NtbInMaxSize   = DeviceContext->NtbInMaxSize;
    Status->NtbOutMaxSize  = DeviceContext->NtbOutMaxSize;

    Status->MacAddressValid = DeviceContext->MacAddressValid;
    Status->MacAddressIsPermanent = DeviceContext->MacAddressIsPermanent;
    if (DeviceContext->MacAddressValid)
    {
        RtlCopyMemory(Status->MacAddress, DeviceContext->PermanentMacAddress,
            sizeof(Status->MacAddress));
    }

    // Both pipes are only ever non-NULL together (set together in
    // T2NcmUsbActivateDataInterface, cleared together on its failure
    // path, in T2NcmUsbDeactivateDataInterface and in
    // T2NcmUsbReleaseHardware), so checking one would be enough — check
    // both anyway: reporting DataInterfaceActive=TRUE from a half-set
    // pair would itself be a fabricated status.
    Status->DataInterfaceActive =
        (DeviceContext->BulkInPipe != NULL) && (DeviceContext->BulkOutPipe != NULL);

    // The two halves of the inverted model, reported separately on
    // purpose: PowerState is what NDIS told us via OID_PNP_SET_POWER,
    // DataPathRunning is what MiniportPause/MiniportRestart last set.
    // A bug in the inversion shows up here as the two disagreeing —
    // e.g. DataPathRunning=TRUE while PowerState != D0 would mean
    // frames are being pushed at a suspended device.
    Status->PowerState       = (UINT32)DeviceContext->PowerState;
    Status->DataPathRunning  = (BOOLEAN)(DeviceContext->DataPathRunning != 0);
    Status->NdisAdapterReady = (DeviceContext->MiniportAdapterHandle != NULL);
    Status->OutstandingRxNbls     = (UINT32)DeviceContext->OutstandingRxNbls;
    Status->OutstandingTxRequests = (UINT32)DeviceContext->OutstandingTxRequests;

    // LONG64 counters read without a lock: RX/TX completions can only
    // ever increase them, so a torn/interleaved read is at worst a
    // slightly-stale count, never a fabricated one. The Interlocked ops
    // on the write side matter for correctness *between* concurrent
    // completions, not for this read.
    Status->RxNtbsReceived    = (UINT64)DeviceContext->RxNtbsReceived;
    Status->RxFramesParsed    = (UINT64)DeviceContext->RxFramesParsed;
    Status->RxFramesRejected  = (UINT64)DeviceContext->RxFramesRejected;
    Status->RxFramesIndicated = (UINT64)DeviceContext->RxFramesIndicated;
    Status->RxFramesFiltered  = (UINT64)DeviceContext->RxFramesFiltered;
    Status->CdcPacketFilter        = DeviceContext->CdcPacketFilter;
    Status->CdcPacketFilterApplied = DeviceContext->CdcPacketFilterApplied;
    RtlCopyMemory(Status->RxLastFrameDest, DeviceContext->RxLastFrameDest,
        sizeof(Status->RxLastFrameDest));
    RtlCopyMemory(Status->RxLastFrameSrc, DeviceContext->RxLastFrameSrc,
        sizeof(Status->RxLastFrameSrc));
    Status->RxLastFrameEtherType = DeviceContext->RxLastFrameEtherType;
    Status->RxLastFrameLength    = DeviceContext->RxLastFrameLength;

    Status->TxNtbsSent       = (UINT64)DeviceContext->TxNtbsSent;
    Status->TxFramesSent     = (UINT64)DeviceContext->TxFramesSent;
    Status->TxFramesRejected = (UINT64)DeviceContext->TxFramesRejected;
}
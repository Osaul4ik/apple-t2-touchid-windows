// SPDX-License-Identifier: GPL-2.0-only
// NdisMiniport.c — the NDIS 6.30 miniport. See NdisMiniport.h for the
// map from the old KMDF callbacks to these, and Driver.h for why the
// direction of control was inverted.

#include "NdisMiniport.h"
#include "Device.h"
#include "UsbTransport.h"
#include "NcmProtocol.h"
#include "NcmRx.h"
#include "NcmTx.h"
#include "Power.h"

#define T2NCM_VENDOR_DRIVER_VERSION  0x00020000  // 2.0
#define T2NCM_NDIS_MAJOR_VERSION     6
#define T2NCM_NDIS_MINOR_VERSION     30

// Vendor ID reported by OID_GEN_VENDOR_ID: the three-byte OUI in the
// high bytes, low byte zero. Uses the device's own permanent MAC OUI
// when there is one, so this is filled in at initialization rather than
// being a constant.
#define T2NCM_DEFAULT_VENDOR_ID      0x00FFFFFF

static const char T2NCM_VENDOR_DESCRIPTION[] = "Apple T2 USB NCM Network Adapter";

// OIDs this driver answers. NDIS handles a number of these itself for
// NDIS 6 miniports, but listing them is what makes OID_GEN_SUPPORTED_LIST
// truthful, and every one listed here has a real implementation below —
// nothing is advertised that would fall through to NOT_SUPPORTED.
static const NDIS_OID T2NcmSupportedOids[] =
{
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_LINK_SPEED,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_VENDOR_ID,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_GEN_STATISTICS,
    OID_GEN_INTERRUPT_MODERATION,
    OID_802_3_PERMANENT_ADDRESS,
    OID_802_3_CURRENT_ADDRESS,
    OID_802_3_MULTICAST_LIST,
    OID_802_3_MAXIMUM_LIST_SIZE,
    OID_802_3_RCV_ERROR_ALIGNMENT,
    OID_802_3_XMIT_ONE_COLLISION,
    OID_802_3_XMIT_MORE_COLLISIONS,
    OID_PNP_SET_POWER,
    OID_PNP_QUERY_POWER,
};

// ---------------------------------------------------------------------
// Drain bookkeeping
// ---------------------------------------------------------------------

VOID
T2NcmQuiesceCheck(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    if (DeviceContext->PauseInProgress != 0 &&
        DeviceContext->OutstandingRxNbls == 0 &&
        DeviceContext->OutstandingTxRequests == 0)
    {
        KeSetEvent(&DeviceContext->QuiesceEvent, IO_NO_INCREMENT, FALSE);
    }
}

// Waits until nothing this driver handed out is still outstanding.
//
// Written as a bounded poll rather than a single event wait on purpose.
// The event is set by whichever decrement reaches zero, but the last
// decrement can happen between this function clearing the event and
// re-reading the counters; a plain wait would then block until the next
// unrelated completion. Re-checking on a short period closes that window
// without needing a lock around every completion path, and the total
// bound means a leaked reference shows up as a logged timeout instead of
// a hung MiniportPause (which would hang the whole system power
// transition, since NDIS pauses before every Dx).
static
VOID
T2NcmWaitForDrain(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    const ULONG pollMs = 20;
    const ULONG maxWaitMs = 5000;
    ULONG waitedMs = 0;

    InterlockedExchange(&DeviceContext->PauseInProgress, 1);

    while (DeviceContext->OutstandingRxNbls != 0 ||
           DeviceContext->OutstandingTxRequests != 0)
    {
        LARGE_INTEGER interval;

        if (waitedMs >= maxWaitMs)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: drain timed out after %lums (rxNbls=%ld txReqs=%ld) — "
                "proceeding anyway; this is a reference leak, not a slow "
                "device\n", maxWaitMs,
                DeviceContext->OutstandingRxNbls,
                DeviceContext->OutstandingTxRequests));
            break;
        }

        KeClearEvent(&DeviceContext->QuiesceEvent);

        if (DeviceContext->OutstandingRxNbls == 0 &&
            DeviceContext->OutstandingTxRequests == 0)
        {
            break;
        }

        interval.QuadPart = -((LONGLONG)pollMs * 10 * 1000);
        (VOID)KeWaitForSingleObject(&DeviceContext->QuiesceEvent, Executive,
            KernelMode, FALSE, &interval);

        waitedMs += pollMs;
    }

    InterlockedExchange(&DeviceContext->PauseInProgress, 0);
}

// ---------------------------------------------------------------------
// Diagnostic control device (NdisRegisterDeviceEx)
// ---------------------------------------------------------------------

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH T2NcmDispatchCreateClose;

NTSTATUS
T2NcmDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH T2NcmDispatchDeviceControl;

NTSTATUS
T2NcmDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PT2NCM_DEVICE_CONTEXT context = g_T2NcmDiagnosticAdapter;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (context == NULL)
    {
        // No adapter initialized (halted, or mid-initialization). Say so
        // rather than returning a zeroed status struct that a tool would
        // read as "adapter present, nothing negotiated".
        status = STATUS_DEVICE_NOT_READY;
        goto Complete;
    }

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_T2NCM_GET_STATUS:
    {
        T2NCM_STATUS snapshot;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG copyLen;

        if (outLen == 0 || Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        T2NcmDeviceFillStatus(context, &snapshot);

        // Copy min(requested, sizeof) so a tool built against an older
        // public.h — which asks for a smaller struct — still gets every
        // field it knows about at the offset it expects. Fields were
        // only ever appended; see public.h.
        copyLen = (outLen < sizeof(snapshot)) ? outLen : (ULONG)sizeof(snapshot);
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &snapshot, copyLen);

        information = copyLen;
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_T2NCM_SEND_TEST_FRAME:
    {
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        if (inLen == 0 || Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Two independent gates, and both have to be open. The lifecycle
        // state says the hardware is armed; DataPathRunning says NDIS
        // has actually restarted the adapter. Injecting a frame at a
        // paused adapter would be exactly the kind of "driver decided to
        // use the hardware on its own schedule" behaviour the inverted
        // model exists to prevent.
        if (!T2NcmIsIoAllowed(context) || context->DataPathRunning == 0)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        status = T2NcmTxSendFrame(context,
            (const UCHAR*)Irp->AssociatedIrp.SystemBuffer, inLen);
        break;
    }

    default:
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: unrecognized IOCTL 0x%08X\n",
            stack->Parameters.DeviceIoControl.IoControlCode));
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static
NDIS_STATUS
T2NcmRegisterDiagnosticDevice(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    NDIS_DEVICE_OBJECT_ATTRIBUTES deviceAttributes;
    PDRIVER_DISPATCH dispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicName;
    NDIS_STATUS status;

    // Administrators and SYSTEM only. This surface can inject a raw
    // Ethernet frame onto the wire, so it is not something an
    // unprivileged process should be able to open even on a developer
    // machine.
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    RtlZeroMemory(dispatchTable, sizeof(dispatchTable));
    dispatchTable[IRP_MJ_CREATE]         = T2NcmDispatchCreateClose;
    dispatchTable[IRP_MJ_CLOSE]          = T2NcmDispatchCreateClose;
    dispatchTable[IRP_MJ_DEVICE_CONTROL] = T2NcmDispatchDeviceControl;

    RtlInitUnicodeString(&deviceName, T2NCM_NT_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicName, T2NCM_DOS_DEVICE_NAME);

    RtlZeroMemory(&deviceAttributes, sizeof(deviceAttributes));
    deviceAttributes.Header.Type     = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    deviceAttributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    deviceAttributes.Header.Size     = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);
    deviceAttributes.DeviceName      = &deviceName;
    deviceAttributes.SymbolicName    = &symbolicName;
    deviceAttributes.MajorFunctions  = &dispatchTable[0];

    deviceAttributes.DefaultSDDLString = &sddl;

    status = NdisRegisterDeviceEx(
        g_T2NcmMiniportDriverHandle,
        &deviceAttributes,
        &DeviceContext->ControlDeviceObject,
        &DeviceContext->NdisDeviceHandle);

    if (status != NDIS_STATUS_SUCCESS)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: NdisRegisterDeviceEx failed 0x%08X — continuing without "
            "the diagnostic device; the adapter itself is unaffected\n", status));
        DeviceContext->NdisDeviceHandle = NULL;
        DeviceContext->ControlDeviceObject = NULL;
    }

    return status;
}

static
VOID
T2NcmDeregisterDiagnosticDevice(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    if (DeviceContext->NdisDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(DeviceContext->NdisDeviceHandle);
        DeviceContext->NdisDeviceHandle = NULL;
        DeviceContext->ControlDeviceObject = NULL;
    }
}

// ---------------------------------------------------------------------
// MiniportSetOptions
// ---------------------------------------------------------------------

MINIPORT_SET_OPTIONS T2NcmMiniportSetOptions;

NDIS_STATUS
T2NcmMiniportSetOptions(
    _In_ NDIS_HANDLE NdisDriverHandle,
    _In_ NDIS_HANDLE DriverContext
    )
{
    UNREFERENCED_PARAMETER(NdisDriverHandle);
    UNREFERENCED_PARAMETER(DriverContext);

    // Nothing optional to register: no NDIS 6.1+ direct OID path, no
    // WDI, no PM offloads. Present because NDIS requires the handler to
    // be non-NULL, not because there is anything to opt into.
    return NDIS_STATUS_SUCCESS;
}

// ---------------------------------------------------------------------
// MiniportInitializeEx — what EvtDevicePrepareHardware and the
// hardware-bring-up half of EvtDeviceD0Entry used to do.
//
// What it deliberately does NOT do any more: start the receive engine.
// After this returns, the adapter is PAUSED. NDIS calls MiniportRestart
// when it wants frames to flow. That single change is the whole
// inversion in practice.
// ---------------------------------------------------------------------

MINIPORT_INITIALIZE T2NcmMiniportInitializeEx;

NDIS_STATUS
T2NcmMiniportInitializeEx(
    _In_ NDIS_HANDLE                    NdisMiniportHandle,
    _In_ NDIS_HANDLE                    MiniportDriverContext,
    _In_ PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters
    )
{
    NTSTATUS status;
    NDIS_STATUS ndisStatus;
    PDEVICE_OBJECT pdo = NULL;
    PDEVICE_OBJECT fdo = NULL;
    PDEVICE_OBJECT nextDeviceObject = NULL;
    WDFDEVICE device = NULL;
    PT2NCM_DEVICE_CONTEXT context = NULL;
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES registrationAttributes;
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES generalAttributes;
    NDIS_PM_CAPABILITIES pmCapabilities;
    NDIS_LINK_STATE linkState;
    NDIS_STATUS_INDICATION statusIndication;

    UNREFERENCED_PARAMETER(MiniportDriverContext);
    UNREFERENCED_PARAMETER(MiniportInitParameters);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: MiniportInitializeEx entered\n"));

    // NDIS already built the device stack; this is how a miniport gets
    // at the device objects in it so KMDF can be wrapped around them.
    NdisMGetDeviceProperty(NdisMiniportHandle, &pdo, &fdo, &nextDeviceObject,
        NULL, NULL);

    if (pdo == NULL || fdo == NULL || nextDeviceObject == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: NdisMGetDeviceProperty returned an incomplete stack\n"));
        return NDIS_STATUS_FAILURE;
    }

    status = T2NcmDeviceCreate(WdfGetDriver(), fdo, nextDeviceObject, pdo,
        &device, &context);
    if (!NT_SUCCESS(status))
    {
        return NDIS_STATUS_FAILURE;
    }

    context->MiniportAdapterHandle = NdisMiniportHandle;

    status = T2NcmUsbPrepareHardware(context);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: USB prepare failed 0x%08X\n", status));
        goto Fail;
    }

    (VOID)T2NcmTrySetState(context, T2NcmStateCreated, T2NcmStatePrepared);
    (VOID)T2NcmTrySetState(context, T2NcmStatePrepared, T2NcmStateUsbReady);

    // The MAC address is read exactly once, here, and is never re-read
    // on a power cycle — see the comment in T2NcmPowerArmHardware for
    // why a station address that can change across S3 would be worse
    // than a stale one.
    //
    // T2NcmEnsureMacAddress falls back to a deterministic, locally-
    // administered address derived from the device's ContainerID when
    // the device reports no usable MAC string (confirmed real on
    // REV_0201 hardware). MacAddressIsPermanent records which kind was
    // obtained; MacAddressValid means "usable by NDIS", not
    // "burned into hardware".
    status = T2NcmEnsureMacAddress(context);
    if (!NT_SUCCESS(status) || !context->MacAddressValid)
    {
        // Unlike the pre-NDIS milestone, this IS fatal now: NDIS cannot
        // register an 802.3 adapter with no station address, and making
        // one up here would be inventing hardware identity.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: no usable station address (0x%08X) — cannot register an "
            "Ethernet adapter\n", status));
        goto Fail;
    }

    RtlCopyMemory(context->CurrentMacAddress, context->PermanentMacAddress,
        T2NCM_MAC_LENGTH);

    status = T2NcmPowerArmHardware(context);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: hardware arm failed 0x%08X\n", status));
        goto Fail;
    }

    (VOID)T2NcmTrySetState(context, T2NcmStateUsbReady, T2NcmStateNcmReady);

    // ---- Registration attributes ----
    RtlZeroMemory(&registrationAttributes, sizeof(registrationAttributes));
    registrationAttributes.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
    registrationAttributes.Header.Revision =
        NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
    registrationAttributes.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
    registrationAttributes.MiniportAdapterContext = (NDIS_HANDLE)context;

    // NDIS_WDM: this driver calls a lower driver (the USB stack, through
    // KMDF) rather than touching hardware registers itself.
    //
    // NO_HALT_ON_SUSPEND: without it, NDIS halts the miniport on every
    // system suspend, which would tear down the USB target and the
    // WDFDEVICE and rebuild them on resume. With it, a suspend is
    // Pause -> OID_PNP_SET_POWER(Dx) -> ... -> OID_PNP_SET_POWER(D0) ->
    // Restart, which is the sequence Power.c is written against.
    registrationAttributes.AttributeFlags =
        NDIS_MINIPORT_ATTRIBUTES_NDIS_WDM |
        NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;

    // 0 = no CheckForHangEx polling. There is no hardware watchdog to
    // implement it against: a wedged NCM endpoint looks exactly like an
    // idle one from here, so a hang check could only ever guess.
    registrationAttributes.CheckForHangTimeInSeconds = 0;
    registrationAttributes.InterfaceType = NdisInterfacePNPBus;

    ndisStatus = NdisMSetMiniportAttributes(NdisMiniportHandle,
        (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&registrationAttributes);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: NdisMSetMiniportAttributes(registration) failed 0x%08X\n",
            ndisStatus));
        status = STATUS_UNSUCCESSFUL;
        goto Fail;
    }

    // ---- Power management capabilities ----
    // All zero: no Wake-on-LAN, no protocol offload, and the three
    // Min*WakeUp members left at NdisDeviceStateUnspecified, which is
    // how a miniport says "I cannot wake the system from any D-state".
    // That is the truth for this device — nothing in the T2's NCM
    // function descriptor set advertises remote wake — and saying so
    // explicitly is what lets NDIS still put the adapter in Dx rather
    // than treating it as PM-unaware and halting it.
    RtlZeroMemory(&pmCapabilities, sizeof(pmCapabilities));
    pmCapabilities.Header.Type     = NDIS_OBJECT_TYPE_DEFAULT;
    pmCapabilities.Header.Revision = NDIS_PM_CAPABILITIES_REVISION_1;
    pmCapabilities.Header.Size     = NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1;
    pmCapabilities.MinMagicPacketWakeUp = NdisDeviceStateUnspecified;
    pmCapabilities.MinPatternWakeUp     = NdisDeviceStateUnspecified;
    pmCapabilities.MinLinkChangeWakeUp  = NdisDeviceStateUnspecified;

    // ---- General attributes ----
    RtlZeroMemory(&generalAttributes, sizeof(generalAttributes));
    generalAttributes.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
    generalAttributes.Header.Revision =
        NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
    generalAttributes.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;

    generalAttributes.MediaType               = NdisMedium802_3;
    generalAttributes.PhysicalMediumType      = NdisPhysicalMediumUnspecified;
    generalAttributes.MtuSize                 = T2NCM_MTU;
    generalAttributes.MaxXmitLinkSpeed        = T2NCM_LINK_SPEED_BPS;
    generalAttributes.MaxRcvLinkSpeed         = T2NCM_LINK_SPEED_BPS;
    generalAttributes.XmitLinkSpeed           = T2NCM_LINK_SPEED_BPS;
    generalAttributes.RcvLinkSpeed            = T2NCM_LINK_SPEED_BPS;

    // The link is up for as long as the USB interface is configured:
    // there is no carrier signal to sample on a CDC-NCM function, and
    // the device being enumerated at all IS the link. Anything more
    // granular would be invented.
    generalAttributes.MediaConnectState       = MediaConnectStateConnected;
    generalAttributes.MediaDuplexState        = MediaDuplexStateFull;

    generalAttributes.LookaheadSize           = T2NCM_MAX_FRAME_SIZE;
    generalAttributes.PowerManagementCapabilitiesEx = &pmCapabilities;
    generalAttributes.MacOptions =
        NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
        NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
        NDIS_MAC_OPTION_NO_LOOPBACK;
    generalAttributes.SupportedPacketFilters =
        NDIS_PACKET_TYPE_DIRECTED |
        NDIS_PACKET_TYPE_MULTICAST |
        NDIS_PACKET_TYPE_ALL_MULTICAST |
        NDIS_PACKET_TYPE_BROADCAST |
        NDIS_PACKET_TYPE_PROMISCUOUS;
    generalAttributes.MaxMulticastListSize    = T2NCM_MAX_MULTICAST_LIST;
    generalAttributes.MacAddressLength        = T2NCM_MAC_LENGTH;
    RtlCopyMemory(generalAttributes.PermanentMacAddress,
        context->PermanentMacAddress, T2NCM_MAC_LENGTH);
    RtlCopyMemory(generalAttributes.CurrentMacAddress,
        context->CurrentMacAddress, T2NCM_MAC_LENGTH);
    generalAttributes.RecvScaleCapabilities   = NULL;
    generalAttributes.AccessType              = NET_IF_ACCESS_BROADCAST;
    generalAttributes.DirectionType           = NET_IF_DIRECTION_SENDRECEIVE;
    generalAttributes.ConnectionType          = NET_IF_CONNECTION_DEDICATED;
    generalAttributes.IfType                  = IF_TYPE_ETHERNET_CSMACD;
    generalAttributes.IfConnectorPresent      = TRUE;
    generalAttributes.SupportedStatistics =
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS |
        NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR |
        NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS;
    generalAttributes.SupportedOidList        = (PNDIS_OID)T2NcmSupportedOids;
    generalAttributes.SupportedOidListLength  = sizeof(T2NcmSupportedOids);

    ndisStatus = NdisMSetMiniportAttributes(NdisMiniportHandle,
        (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&generalAttributes);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: NdisMSetMiniportAttributes(general) failed 0x%08X\n",
            ndisStatus));
        status = STATUS_UNSUCCESSFUL;
        goto Fail;
    }

    // The NBL pool is allocated only now, after the adapter's attributes
    // are registered — NDIS wants a fully described adapter before it
    // hands out per-adapter resources, and nothing before this point
    // could have needed the pool anyway (the data path is still paused
    // and will be until MiniportRestart).
    status = T2NcmRxAllocateResources(context);
    if (!NT_SUCCESS(status))
    {
        goto Fail;
    }

    (VOID)T2NcmTrySetState(context, T2NcmStateNcmReady, T2NcmStateNdisRegistered);

    // Publish for the diagnostic device before registering it, so the
    // first IRP through the door cannot find a NULL adapter.
    g_T2NcmDiagnosticAdapter = context;
    (VOID)T2NcmRegisterDiagnosticDevice(context);

    // Report the link explicitly as well as in the attributes: NDIS uses
    // the attribute value for the adapter's initial state, and the
    // indication is what the rest of the stack watches.
    RtlZeroMemory(&linkState, sizeof(linkState));
    linkState.Header.Type     = NDIS_OBJECT_TYPE_DEFAULT;
    linkState.Header.Revision = NDIS_LINK_STATE_REVISION_1;
    linkState.Header.Size     = NDIS_SIZEOF_LINK_STATE_REVISION_1;
    linkState.MediaConnectState = MediaConnectStateConnected;
    linkState.MediaDuplexState  = MediaDuplexStateFull;
    linkState.XmitLinkSpeed     = T2NCM_LINK_SPEED_BPS;
    linkState.RcvLinkSpeed      = T2NCM_LINK_SPEED_BPS;
    linkState.PauseFunctions    = NdisPauseFunctionsUnsupported;

    RtlZeroMemory(&statusIndication, sizeof(statusIndication));
    statusIndication.Header.Type     = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    statusIndication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    statusIndication.Header.Size     = sizeof(NDIS_STATUS_INDICATION);
    statusIndication.SourceHandle    = NdisMiniportHandle;
    statusIndication.StatusCode      = NDIS_STATUS_LINK_STATE;
    statusIndication.StatusBuffer    = &linkState;
    statusIndication.StatusBufferSize = sizeof(linkState);

    NdisMIndicateStatusEx(NdisMiniportHandle, &statusIndication);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: adapter registered and PAUSED — waiting for MiniportRestart "
        "(mac=%02X:%02X:%02X:%02X:%02X:%02X permanent=%u)\n",
        context->CurrentMacAddress[0], context->CurrentMacAddress[1],
        context->CurrentMacAddress[2], context->CurrentMacAddress[3],
        context->CurrentMacAddress[4], context->CurrentMacAddress[5],
        context->MacAddressIsPermanent));

    return NDIS_STATUS_SUCCESS;

Fail:
    if (context != NULL)
    {
        // BUGFIX: mirror MiniportHaltEx's cleanup order. A failure that
        // happens after T2NcmPowerArmHardware succeeded (e.g. the
        // NdisMSetMiniportAttributes calls or T2NcmRxAllocateResources
        // below) left MI_01 switched to alt 1 with BulkInPipe/
        // BulkOutPipe bound. Without this call the alt-1 setting and
        // its pipes were never parked back to alt 0 before the
        // WDFDEVICE (and everything under it) was torn down — exactly
        // the "stranded pipe on alt 1" state UsbTransport.c's own
        // comments say must never happen, and a real source of the
        // adapter coming up in a bad state on the next attempt.
        T2NcmUsbDeactivateDataInterface(context);
        T2NcmRxFreeResources(context);
        T2NcmUsbReleaseHardware(context);
        WdfSpinLockAcquire(context->StateLock);
        context->State = T2NcmStateReleased;
        WdfSpinLockRelease(context->StateLock);
    }
    if (device != NULL)
    {
        WdfObjectDelete(device);
    }

    return NDIS_STATUS_FAILURE;
}

// ---------------------------------------------------------------------
// MiniportHaltEx — what EvtDeviceReleaseHardware used to do.
// ---------------------------------------------------------------------

MINIPORT_HALT T2NcmMiniportHaltEx;

VOID
T2NcmMiniportHaltEx(
    _In_ NDIS_HANDLE        MiniportAdapterContext,
    _In_ NDIS_HALT_ACTION   HaltAction
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: MiniportHaltEx (action=%u)\n", (ULONG)HaltAction));

    T2NcmForceSetState(context, T2NcmStateStopping);

    // NDIS guarantees the adapter is already paused here, but a
    // surprise removal can reach halt through paths where that is less
    // obvious; all of these are idempotent.
    InterlockedExchange(&context->DataPathRunning, 0);
    T2NcmRxStop(context);
    T2NcmWaitForDrain(context);

    T2NcmDeregisterDiagnosticDevice(context);
    g_T2NcmDiagnosticAdapter = NULL;

    T2NcmUsbDeactivateDataInterface(context);
    T2NcmRxFreeResources(context);
    T2NcmUsbReleaseHardware(context);

    T2NcmForceSetState(context, T2NcmStateReleased);

    context->MiniportAdapterHandle = NULL;

    // Deleting the WDFDEVICE frees the context this function is running
    // against, so nothing may touch it afterwards.
    WdfObjectDelete(context->WdfDevice);
}

// ---------------------------------------------------------------------
// MiniportPause / MiniportRestart — the new owners of the data path.
// ---------------------------------------------------------------------

MINIPORT_PAUSE T2NcmMiniportPause;

NDIS_STATUS
T2NcmMiniportPause(
    _In_ NDIS_HANDLE                       MiniportAdapterContext,
    _In_ PNDIS_MINIPORT_PAUSE_PARAMETERS   PauseParameters
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;

    UNREFERENCED_PARAMETER(PauseParameters);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: MiniportPause\n"));

    // Order matters. Close the gate first so no new indication or send
    // can start, then stop the reader, then wait for what was already in
    // flight. Doing it the other way round leaves a window where the
    // reader has stopped but an in-flight completion still indicates.
    InterlockedExchange(&context->DataPathRunning, 0);

    (VOID)T2NcmTrySetState(context, T2NcmStateRunning, T2NcmStateStopping);

    T2NcmRxStop(context);
    T2NcmWaitForDrain(context);

    // Back to NdisRegistered: the adapter still exists and the hardware
    // is still armed, it is just not moving frames.
    (VOID)T2NcmTrySetState(context, T2NcmStateStopping, T2NcmStateNdisRegistered);

    // Synchronous completion. Returning NDIS_STATUS_PENDING would mean
    // calling NdisMPauseComplete later, and there is nothing here that
    // cannot be finished inline — T2NcmWaitForDrain has already bounded
    // how long "inline" can be.
    return NDIS_STATUS_SUCCESS;
}

MINIPORT_RESTART T2NcmMiniportRestart;

NDIS_STATUS
T2NcmMiniportRestart(
    _In_ NDIS_HANDLE                       MiniportAdapterContext,
    _In_ PNDIS_MINIPORT_RESTART_PARAMETERS RestartParameters
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RestartParameters);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: MiniportRestart\n"));

    if (context->PowerState != NdisDeviceStateD0)
    {
        // Should not happen: NDIS sends OID_PNP_SET_POWER(D0) before
        // restarting. Refuse rather than drive a suspended device — if
        // this ever fires, the inverted model has been broken somewhere
        // and a loud failure is more useful than silent USB errors.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: restart requested while at power state %u — refusing\n",
            (ULONG)context->PowerState));
        return NDIS_STATUS_FAILURE;
    }

    if (context->BulkInPipe == NULL || context->BulkOutPipe == NULL)
    {
        // The control plane did not come up. T2NcmPowerArmHardware is
        // where "is the device actually ready yet" gets decided — it
        // owns its own bounded wait-for-readiness on the one control
        // transfer that can genuinely still be settling on a cold boot
        // (GET_NTB_PARAMETERS). Restart itself makes exactly one call
        // and takes whatever answer comes back; it does not loop.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: restart requested with no bulk pipes — re-arming\n"));

        status = T2NcmPowerArmHardware(context);
        if (!NT_SUCCESS(status))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: restart — re-arm failed 0x%08X\n", status));
            return NDIS_STATUS_FAILURE;
        }
    }

    // Open the gate BEFORE arming the reader: a read completion that
    // lands between WdfIoTargetStart and the flag being set would
    // otherwise be discarded as "paused" even though NDIS has asked for
    // traffic.
    InterlockedExchange(&context->DataPathRunning, 1);

    // Re-assert the device-side packet filter. T2NcmPowerArmHardware
    // already sent it after the alt-1 switch, but a restart can also
    // follow paths where the interface was re-selected in between, and
    // the device silently drops back to "forward nothing" every time
    // that happens. Cheap control transfer, removes a whole class of
    // silent-RX failure.
    if (!context->CdcPacketFilterApplied)
    {
        (VOID)T2NcmApplyPacketFilter(context);
    }

    status = T2NcmRxStart(context);
    if (!NT_SUCCESS(status))
    {
        InterlockedExchange(&context->DataPathRunning, 0);

        // Log the REAL status here instead of only the generic value
        // returned to NDIS below — this is what actually shows up as
        // the adapter's problem code (e.g. STATUS_NOT_SUPPORTED /
        // 0xC00000BB), and the previous version of this function
        // discarded it entirely, making the Device Manager / Event
        // Viewer code impossible to trace back to a specific call.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX engine did not start on restart (0x%08X)\n", status));
        return NDIS_STATUS_FAILURE;
    }

    // Restart can be reached with the lifecycle state sitting at either
    // NdisRegistered (the normal path) or NcmReady (a fast re-arm on
    // resume that never passed back through NdisRegistered) - try the
    // common case first and only fall back to the other predecessor if
    // it didn't match. Trying both unconditionally meant the second call
    // was a guaranteed no-op every single time the first one succeeded,
    // logging a spurious "not taken" trace line on every normal restart.
    if (!T2NcmTrySetState(context, T2NcmStateNdisRegistered, T2NcmStateRunning))
    {
        (VOID)T2NcmTrySetState(context, T2NcmStateNcmReady, T2NcmStateRunning);
    }

    return NDIS_STATUS_SUCCESS;
}

// ---------------------------------------------------------------------
// Data path
// ---------------------------------------------------------------------

MINIPORT_SEND_NET_BUFFER_LISTS T2NcmMiniportSendNetBufferLists;

VOID
T2NcmMiniportSendNetBufferLists(
    _In_ NDIS_HANDLE       MiniportAdapterContext,
    _In_ PNET_BUFFER_LIST  NetBufferLists,
    _In_ NDIS_PORT_NUMBER  PortNumber,
    _In_ ULONG             SendFlags
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;

    UNREFERENCED_PARAMETER(PortNumber);

    if (context->DataPathRunning == 0 ||
        context->PowerState != NdisDeviceStateD0 ||
        context->BulkOutPipe == NULL)
    {
        ULONG completeFlags = 0;
        PNET_BUFFER_LIST nbl;

        if (NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags))
        {
            NDIS_SET_SEND_COMPLETE_FLAG(completeFlags,
                NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        }

        for (nbl = NetBufferLists; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
        {
            NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_PAUSED;
            InterlockedIncrement64(&context->OutDiscards);
        }

        NdisMSendNetBufferListsComplete(context->MiniportAdapterHandle,
            NetBufferLists, completeFlags);
        return;
    }

    T2NcmTxSendNetBufferLists(context, NetBufferLists, SendFlags);
}

MINIPORT_RETURN_NET_BUFFER_LISTS T2NcmMiniportReturnNetBufferLists;

VOID
T2NcmMiniportReturnNetBufferLists(
    _In_ NDIS_HANDLE      MiniportAdapterContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG            ReturnFlags
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;

    T2NcmRxReturnNetBufferLists(context, NetBufferLists, ReturnFlags);
}

MINIPORT_CANCEL_SEND T2NcmMiniportCancelSend;

VOID
T2NcmMiniportCancelSend(
    _In_ NDIS_HANDLE MiniportAdapterContext,
    _In_ PVOID       CancelId
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(CancelId);

    // Nothing to cancel: this driver never queues NBLs. Every NET_BUFFER
    // is turned into a USB write request and submitted immediately, so
    // by the time a cancel could arrive the work is either in the USB
    // stack or already completed. Present because NDIS requires the
    // handler, not because there is a queue behind it.
}

// ---------------------------------------------------------------------
// OID handling
// ---------------------------------------------------------------------

static
NDIS_STATUS
T2NcmOidQueryCopy(
    _In_ PNDIS_OID_REQUEST Request,
    _In_reads_bytes_(Length) const VOID* Source,
    _In_ ULONG Length
    )
{
    if (Request->DATA.QUERY_INFORMATION.InformationBufferLength < Length)
    {
        Request->DATA.QUERY_INFORMATION.BytesNeeded = Length;
        Request->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }

    RtlCopyMemory(Request->DATA.QUERY_INFORMATION.InformationBuffer, Source, Length);
    Request->DATA.QUERY_INFORMATION.BytesWritten = Length;
    Request->DATA.QUERY_INFORMATION.BytesNeeded = Length;

    return NDIS_STATUS_SUCCESS;
}

static
NDIS_STATUS
T2NcmOidQuery(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNDIS_OID_REQUEST     Request
    )
{
    ULONG   genericUlong;
    ULONG64 genericUlong64;

    switch (Request->DATA.QUERY_INFORMATION.Oid)
    {
    case OID_GEN_SUPPORTED_LIST:
        return T2NcmOidQueryCopy(Request, T2NcmSupportedOids,
            sizeof(T2NcmSupportedOids));

    case OID_GEN_HARDWARE_STATUS:
        genericUlong = (DeviceContext->DataPathRunning != 0)
            ? NdisHardwareStatusReady : NdisHardwareStatusInitializing;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE:
        genericUlong = NdisMedium802_3;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_MAXIMUM_LOOKAHEAD:
        genericUlong = T2NCM_MAX_FRAME_SIZE;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_CURRENT_LOOKAHEAD:
        genericUlong = DeviceContext->CurrentLookahead;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_MAXIMUM_FRAME_SIZE:
        genericUlong = T2NCM_MTU;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_MAXIMUM_TOTAL_SIZE:
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        genericUlong = T2NCM_MAX_FRAME_SIZE;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
        // What one NTB can carry outbound, which is the real bound on
        // how much the driver can have in flight per write.
        genericUlong = DeviceContext->NtbOutMaxSize;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_RECEIVE_BUFFER_SPACE:
        genericUlong = DeviceContext->NtbInMaxSize;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_LINK_SPEED:
        // OID_GEN_LINK_SPEED is in 100 bps units, unlike the
        // NDIS_LINK_STATE fields which are in bps.
        genericUlong = (ULONG)(T2NCM_LINK_SPEED_BPS / 100ULL);
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_VENDOR_ID:
        genericUlong = DeviceContext->MacAddressIsPermanent
            ? (((ULONG)DeviceContext->PermanentMacAddress[0] << 16) |
               ((ULONG)DeviceContext->PermanentMacAddress[1] << 8)  |
                (ULONG)DeviceContext->PermanentMacAddress[2])
            : T2NCM_DEFAULT_VENDOR_ID;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_VENDOR_DESCRIPTION:
        return T2NcmOidQueryCopy(Request, T2NCM_VENDOR_DESCRIPTION,
            (ULONG)sizeof(T2NCM_VENDOR_DESCRIPTION));

    case OID_GEN_VENDOR_DRIVER_VERSION:
        genericUlong = T2NCM_VENDOR_DRIVER_VERSION;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_DRIVER_VERSION:
    {
        USHORT version = (T2NCM_NDIS_MAJOR_VERSION << 8) | T2NCM_NDIS_MINOR_VERSION;
        return T2NcmOidQueryCopy(Request, &version, sizeof(version));
    }

    case OID_GEN_MAC_OPTIONS:
        genericUlong =
            NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
            NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
            NDIS_MAC_OPTION_NO_LOOPBACK;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_MEDIA_CONNECT_STATUS:
        genericUlong = MediaConnectStateConnected;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_CURRENT_PACKET_FILTER:
        genericUlong = DeviceContext->PacketFilter;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_MAXIMUM_SEND_PACKETS:
        // No internal send queue, so there is no batching limit worth
        // advertising beyond "as many as you like".
        genericUlong = MAXULONG;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_GEN_INTERRUPT_MODERATION:
    {
        NDIS_INTERRUPT_MODERATION_PARAMETERS moderation;

        RtlZeroMemory(&moderation, sizeof(moderation));
        moderation.Header.Type     = NDIS_OBJECT_TYPE_DEFAULT;
        moderation.Header.Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
        moderation.Header.Size     =
            NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
        // Not supported, and truthfully so: this adapter has no
        // interrupt of its own — it is polled through the USB stack's
        // continuous reader.
        moderation.InterruptModeration = NdisInterruptModerationNotSupported;

        return T2NcmOidQueryCopy(Request, &moderation, sizeof(moderation));
    }

    case OID_GEN_XMIT_OK:
        genericUlong64 = (ULONG64)(DeviceContext->OutUcastPkts +
            DeviceContext->OutMulticastPkts + DeviceContext->OutBroadcastPkts);
        return T2NcmOidQueryCopy(Request, &genericUlong64, sizeof(genericUlong64));

    case OID_GEN_RCV_OK:
        genericUlong64 = (ULONG64)(DeviceContext->InUcastPkts +
            DeviceContext->InMulticastPkts + DeviceContext->InBroadcastPkts);
        return T2NcmOidQueryCopy(Request, &genericUlong64, sizeof(genericUlong64));

    case OID_GEN_STATISTICS:
    {
        NDIS_STATISTICS_INFO stats;

        RtlZeroMemory(&stats, sizeof(stats));
        stats.Header.Type     = NDIS_OBJECT_TYPE_DEFAULT;
        stats.Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
        stats.Header.Size     = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
        stats.SupportedStatistics =
            NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS |
            NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
            NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR |
            NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS;

        stats.ifHCInUcastPkts      = (ULONG64)DeviceContext->InUcastPkts;
        stats.ifHCInMulticastPkts  = (ULONG64)DeviceContext->InMulticastPkts;
        stats.ifHCInBroadcastPkts  = (ULONG64)DeviceContext->InBroadcastPkts;
        stats.ifHCInOctets         = (ULONG64)DeviceContext->InOctets;
        stats.ifInDiscards         = (ULONG64)DeviceContext->InDiscards;
        stats.ifInErrors           = (ULONG64)DeviceContext->InErrors;
        stats.ifHCOutUcastPkts     = (ULONG64)DeviceContext->OutUcastPkts;
        stats.ifHCOutMulticastPkts = (ULONG64)DeviceContext->OutMulticastPkts;
        stats.ifHCOutBroadcastPkts = (ULONG64)DeviceContext->OutBroadcastPkts;
        stats.ifHCOutOctets        = (ULONG64)DeviceContext->OutOctets;
        stats.ifOutDiscards        = (ULONG64)DeviceContext->OutDiscards;
        stats.ifOutErrors          = (ULONG64)DeviceContext->OutErrors;

        return T2NcmOidQueryCopy(Request, &stats, sizeof(stats));
    }

    case OID_802_3_PERMANENT_ADDRESS:
        return T2NcmOidQueryCopy(Request, DeviceContext->PermanentMacAddress,
            T2NCM_MAC_LENGTH);

    case OID_802_3_CURRENT_ADDRESS:
        return T2NcmOidQueryCopy(Request, DeviceContext->CurrentMacAddress,
            T2NCM_MAC_LENGTH);

    case OID_802_3_MAXIMUM_LIST_SIZE:
        genericUlong = T2NCM_MAX_MULTICAST_LIST;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    case OID_802_3_MULTICAST_LIST:
        return T2NcmOidQueryCopy(Request, DeviceContext->MulticastList,
            DeviceContext->MulticastAddressCount * T2NCM_MAC_LENGTH);

    case OID_802_3_RCV_ERROR_ALIGNMENT:
    case OID_802_3_XMIT_ONE_COLLISION:
    case OID_802_3_XMIT_MORE_COLLISIONS:
        // Genuinely always zero: there is no shared medium behind this
        // adapter to collide on and no alignment error a USB bulk
        // transfer could produce. Reported rather than refused so that
        // tools which expect the mandatory 802.3 set get an answer.
        genericUlong = 0;
        return T2NcmOidQueryCopy(Request, &genericUlong, sizeof(genericUlong));

    default:
        return NDIS_STATUS_NOT_SUPPORTED;
    }
}

static
NDIS_STATUS
T2NcmOidSet(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNDIS_OID_REQUEST     Request
    )
{
    ULONG length = Request->DATA.SET_INFORMATION.InformationBufferLength;
    PVOID buffer = Request->DATA.SET_INFORMATION.InformationBuffer;

    switch (Request->DATA.SET_INFORMATION.Oid)
    {
    case OID_GEN_CURRENT_PACKET_FILTER:
    {
        ULONG filter;

        if (length != sizeof(ULONG))
        {
            Request->DATA.SET_INFORMATION.BytesNeeded = sizeof(ULONG);
            return NDIS_STATUS_INVALID_LENGTH;
        }

        filter = *(PULONG)buffer;

        if (filter & ~(NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST |
                       NDIS_PACKET_TYPE_ALL_MULTICAST | NDIS_PACKET_TYPE_BROADCAST |
                       NDIS_PACKET_TYPE_PROMISCUOUS | NDIS_PACKET_TYPE_ALL_LOCAL))
        {
            return NDIS_STATUS_NOT_SUPPORTED;
        }

        DeviceContext->PacketFilter = filter;
        Request->DATA.SET_INFORMATION.BytesRead = sizeof(ULONG);

        // Push it to the device as well. The NDIS-level filter only
        // decides what this driver indicates upward; the CDC-level one
        // decides whether the device sends anything at all, and until
        // it is set the answer is nothing.
        T2NcmRequestPacketFilterUpdate(DeviceContext);

        return NDIS_STATUS_SUCCESS;
    }

    case OID_GEN_CURRENT_LOOKAHEAD:
    {
        if (length != sizeof(ULONG))
        {
            Request->DATA.SET_INFORMATION.BytesNeeded = sizeof(ULONG);
            return NDIS_STATUS_INVALID_LENGTH;
        }

        // Every indication carries the whole frame, so the lookahead
        // size is recorded and otherwise has no effect. Clamped rather
        // than rejected: a protocol asking for more than a frame is not
        // an error, it just cannot get more than exists.
        DeviceContext->CurrentLookahead = *(PULONG)buffer;
        if (DeviceContext->CurrentLookahead > T2NCM_MAX_FRAME_SIZE)
        {
            DeviceContext->CurrentLookahead = T2NCM_MAX_FRAME_SIZE;
        }
        Request->DATA.SET_INFORMATION.BytesRead = sizeof(ULONG);
        return NDIS_STATUS_SUCCESS;
    }

    case OID_802_3_MULTICAST_LIST:
    {
        ULONG count;

        if ((length % T2NCM_MAC_LENGTH) != 0)
        {
            return NDIS_STATUS_INVALID_LENGTH;
        }

        count = length / T2NCM_MAC_LENGTH;
        if (count > T2NCM_MAX_MULTICAST_LIST)
        {
            Request->DATA.SET_INFORMATION.BytesNeeded =
                T2NCM_MAX_MULTICAST_LIST * T2NCM_MAC_LENGTH;
            return NDIS_STATUS_MULTICAST_FULL;
        }

        // Software filtering only — the T2's NCM function has no
        // multicast filter to program, so the list is kept here and
        // applied in T2NcmRxAcceptsFrame.
        RtlZeroMemory(DeviceContext->MulticastList, sizeof(DeviceContext->MulticastList));
        if (count != 0)
        {
            RtlCopyMemory(DeviceContext->MulticastList, buffer, length);
        }
        DeviceContext->MulticastAddressCount = count;

        Request->DATA.SET_INFORMATION.BytesRead = length;

        // Going from an empty to a non-empty list (or back) changes
        // whether ALL_MULTICAST belongs in the CDC filter, so the device
        // has to be told again.
        T2NcmRequestPacketFilterUpdate(DeviceContext);

        return NDIS_STATUS_SUCCESS;
    }

    case OID_GEN_INTERRUPT_MODERATION:
        return NDIS_STATUS_INVALID_DATA;

    case OID_PNP_SET_POWER:
    {
        NDIS_DEVICE_POWER_STATE newState;

        if (length != sizeof(NDIS_DEVICE_POWER_STATE))
        {
            Request->DATA.SET_INFORMATION.BytesNeeded =
                sizeof(NDIS_DEVICE_POWER_STATE);
            return NDIS_STATUS_INVALID_LENGTH;
        }

        newState = *(PNDIS_DEVICE_POWER_STATE)buffer;
        Request->DATA.SET_INFORMATION.BytesRead = length;

        return T2NcmPowerSetDeviceState(DeviceContext, newState);
    }

    case OID_PNP_QUERY_POWER:
    {
        NDIS_DEVICE_POWER_STATE proposed;

        if (length != sizeof(NDIS_DEVICE_POWER_STATE))
        {
            Request->DATA.SET_INFORMATION.BytesNeeded =
                sizeof(NDIS_DEVICE_POWER_STATE);
            return NDIS_STATUS_INVALID_LENGTH;
        }

        proposed = *(PNDIS_DEVICE_POWER_STATE)buffer;
        Request->DATA.SET_INFORMATION.BytesRead = length;

        return T2NcmPowerQueryDeviceState(DeviceContext, proposed);
    }

    default:
        return NDIS_STATUS_NOT_SUPPORTED;
    }
}

MINIPORT_OID_REQUEST T2NcmMiniportOidRequest;

NDIS_STATUS
T2NcmMiniportOidRequest(
    _In_ NDIS_HANDLE        MiniportAdapterContext,
    _In_ PNDIS_OID_REQUEST  OidRequest
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;

    switch (OidRequest->RequestType)
    {
    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
        return T2NcmOidQuery(context, OidRequest);

    case NdisRequestSetInformation:
        return T2NcmOidSet(context, OidRequest);

    default:
        return NDIS_STATUS_NOT_SUPPORTED;
    }
}

MINIPORT_CANCEL_OID_REQUEST T2NcmMiniportCancelOidRequest;

VOID
T2NcmMiniportCancelOidRequest(
    _In_ NDIS_HANDLE MiniportAdapterContext,
    _In_ PVOID       RequestId
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(RequestId);

    // Every OID above is handled synchronously and never returns
    // NDIS_STATUS_PENDING, so there is nothing outstanding to cancel.
}

// ---------------------------------------------------------------------
// PnP events, reset, shutdown
// ---------------------------------------------------------------------

MINIPORT_DEVICE_PNP_EVENT_NOTIFY T2NcmMiniportDevicePnPEventNotify;

VOID
T2NcmMiniportDevicePnPEventNotify(
    _In_ NDIS_HANDLE           MiniportAdapterContext,
    _In_ PNET_DEVICE_PNP_EVENT NetDevicePnPEvent
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;

    switch (NetDevicePnPEvent->DevicePnPEvent)
    {
    case NdisDevicePnPEventSurpriseRemoved:
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: surprise removal\n"));

        // Close the data-path gate immediately. MiniportHaltEx will
        // follow and do the real teardown; what matters here is that no
        // further USB I/O is started against a device that is gone,
        // since every one of those would now fail and be counted as a
        // transmit error.
        InterlockedExchange(&context->DataPathRunning, 0);
        T2NcmRxStop(context);
        break;

    case NdisDevicePnPEventPowerProfileChanged:
        // Informational only (AC/battery). Nothing here is tuned by
        // power profile — and guessing at a policy would be inventing
        // behaviour the hardware never asked for.
        break;

    default:
        break;
    }
}

MINIPORT_RESET T2NcmMiniportResetEx;

NDIS_STATUS
T2NcmMiniportResetEx(
    _In_  NDIS_HANDLE MiniportAdapterContext,
    _Out_ PBOOLEAN    AddressingReset
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;
    NTSTATUS status;

    // FALSE: the station address, packet filter and multicast list are
    // all held in software here and survive a reset untouched, so NDIS
    // does not need to restore them.
    *AddressingReset = FALSE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
        "T2Ncm: MiniportResetEx — restarting the RX engine\n"));

    T2NcmRxStop(context);

    if (context->DataPathRunning == 0)
    {
        // Reset while paused: nothing to bring back up, and starting the
        // reader here would be the driver deciding on its own that
        // frames may flow again. MiniportRestart will do it.
        return NDIS_STATUS_SUCCESS;
    }

    status = T2NcmRxStart(context);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX engine did not come back after reset (0x%08X)\n", status));
        return NDIS_STATUS_FAILURE;
    }

    return NDIS_STATUS_SUCCESS;
}

MINIPORT_SHUTDOWN T2NcmMiniportShutdownEx;

VOID
T2NcmMiniportShutdownEx(
    _In_ NDIS_HANDLE          MiniportAdapterContext,
    _In_ NDIS_SHUTDOWN_ACTION ShutdownAction
    )
{
    PT2NCM_DEVICE_CONTEXT context = (PT2NCM_DEVICE_CONTEXT)MiniportAdapterContext;

    // On NdisShutdownPowerOff this can run at a raised IRQL on a
    // crashing system with no other driver guaranteed to be healthy.
    // Closing the gate is an interlocked store and is safe anywhere;
    // anything more (stopping I/O targets, waiting for drains) is not,
    // and there is nothing this device needs put into a safe state
    // before the power goes away.
    InterlockedExchange(&context->DataPathRunning, 0);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
        "T2Ncm: MiniportShutdownEx (action=%u) — data path closed\n",
        (ULONG)ShutdownAction));
}

// ---------------------------------------------------------------------
// Driver registration / unload
// ---------------------------------------------------------------------

MINIPORT_UNLOAD T2NcmMiniportDriverUnload;

VOID
T2NcmMiniportDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: MiniportDriverUnload\n"));

    if (g_T2NcmMiniportDriverHandle != NULL)
    {
        NdisMDeregisterMiniportDriver(g_T2NcmMiniportDriverHandle);
        g_T2NcmMiniportDriverHandle = NULL;
    }

    // Undo the WdfDriverCreate from DriverEntry. Required for a driver
    // created with WdfDriverInitNoDispatchOverride — WDF has no unload
    // hook of its own in that mode, because it never took the dispatch
    // table.
    WdfDriverMiniportUnload(WdfGetDriver());
}

NDIS_STATUS
T2NcmNdisRegisterDriver(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS characteristics;

    RtlZeroMemory(&characteristics, sizeof(characteristics));

    characteristics.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
    characteristics.Header.Revision =
        NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
    characteristics.Header.Size =
        NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;

    characteristics.MajorNdisVersion   = T2NCM_NDIS_MAJOR_VERSION;
    characteristics.MinorNdisVersion   = T2NCM_NDIS_MINOR_VERSION;
    characteristics.MajorDriverVersion = 2;
    characteristics.MinorDriverVersion = 0;

    characteristics.SetOptionsHandler            = T2NcmMiniportSetOptions;
    characteristics.InitializeHandlerEx          = T2NcmMiniportInitializeEx;
    characteristics.HaltHandlerEx                = T2NcmMiniportHaltEx;
    characteristics.UnloadHandler                = T2NcmMiniportDriverUnload;
    characteristics.PauseHandler                 = T2NcmMiniportPause;
    characteristics.RestartHandler               = T2NcmMiniportRestart;
    characteristics.OidRequestHandler            = T2NcmMiniportOidRequest;
    characteristics.CancelOidRequestHandler      = T2NcmMiniportCancelOidRequest;
    characteristics.SendNetBufferListsHandler    = T2NcmMiniportSendNetBufferLists;
    characteristics.ReturnNetBufferListsHandler  = T2NcmMiniportReturnNetBufferLists;
    characteristics.CancelSendHandler            = T2NcmMiniportCancelSend;
    characteristics.DevicePnPEventNotifyHandler  = T2NcmMiniportDevicePnPEventNotify;
    characteristics.ResetHandlerEx               = T2NcmMiniportResetEx;
    characteristics.ShutdownHandlerEx            = T2NcmMiniportShutdownEx;

    // CheckForHangHandlerEx deliberately left NULL — see the
    // CheckForHangTimeInSeconds comment in MiniportInitializeEx.

    return NdisMRegisterMiniportDriver(
        DriverObject,
        RegistryPath,
        NULL,
        &characteristics,
        &g_T2NcmMiniportDriverHandle);
}
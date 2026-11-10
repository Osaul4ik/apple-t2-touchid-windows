// SPDX-License-Identifier: GPL-2.0-only
// Control.c - the \\.\T2Ncm control device (NdisRegisterDeviceEx): create /
// close / cleanup and the IOCTLs of Public.h (status, test frame, tunnel peer /
// local / mode / sticky / state). Moved out of NdisMiniport.c unchanged; the
// miniport only publishes / withdraws the adapter and registers the device
// (Control.h).

#include "Control.h"
#include "Device.h"
#include "NcmTx.h"
#include "Tunnel.h"

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

// IRP_MJ_CLEANUP: the last user handle of a file object is gone. If that
// handle still owns a live transport mode that differs from the committed
// (sticky) one - i.e. its process died inside a probe phase - put the
// committed mode back, globally and on the running adapter (Tunnel.h).
_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH T2NcmDispatchCleanup;

NTSTATUS
T2NcmDispatchCleanup(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    BOOLEAN restoredTunnel = FALSE;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (T2NcmTunnelReleaseModeOwner(stack->FileObject, &restoredTunnel))
    {
        PT2NCM_DEVICE_CONTEXT context;

        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&g_T2NcmDiagnosticLock, TRUE);
        context = g_T2NcmDiagnosticAdapter;
        if (context != NULL)
        {
            // Re-read the global instead of using restoredTunnel: a SET_TRANSPORT_MODE
            // from another handle may have landed between the restore and here, and
            // the adapter must end up on whatever the driver-global mode is now.
            InterlockedExchange(&context->TunnelModeEnabled, T2NcmTunnelGetMode() ? 1 : 0);
        }
        ExReleaseResourceLite(&g_T2NcmDiagnosticLock);
        KeLeaveCriticalRegion();

        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: control handle closed while owning a probe transport mode - "
            "restored committed mode %u\n", restoredTunnel ? 1u : 0u));
    }

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
    PT2NCM_DEVICE_CONTEXT context;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    // Held shared until Complete: MiniportHaltEx clears the published
    // adapter under the exclusive lock, so the context read here cannot
    // be freed while this request is still using it.
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_T2NcmDiagnosticLock, TRUE);
    context = g_T2NcmDiagnosticAdapter;

    // Driver-global tunnel state: no adapter needed (a WUDFHost restarted
    // while the adapter is being re-initialized must still be able to read
    // the committed decision back).
    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_T2NCM_SET_TUNNEL_STICKY:
    {
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG sticky;

        if (inLen < sizeof(ULONG) || Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            goto Complete;
        }
        RtlCopyMemory(&sticky, Irp->AssociatedIrp.SystemBuffer, sizeof(ULONG));
        // The wire contract accepts exactly 0 or 1. Do not silently turn
        // malformed values into a request to disable sticky tunnel mode.
        if (sticky > 1ul)
        {
            status = STATUS_INVALID_PARAMETER;
            goto Complete;
        }
        T2NcmTunnelStickyWrite(sticky == 1ul);
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
            "T2Ncm: sticky tunnel set via IOCTL -> %u (driver memory, cleared on reboot)\n",
            (sticky == 1ul) ? 1u : 0u));
        status = STATUS_SUCCESS;
        goto Complete;
    }

    case IOCTL_T2NCM_GET_TUNNEL_STATE:
    {
        T2NCM_TUNNEL_STATE state;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (outLen < sizeof(state) || Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Complete;
        }
        state.Version = T2NCM_TUNNEL_STATE_VERSION;
        state.Sticky = T2NcmTunnelGetSticky() ? 1u : 0u;
        state.Mode = T2NcmTunnelGetMode() ? 1u : 0u;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &state, sizeof(state));
        information = sizeof(state);
        status = STATUS_SUCCESS;
        goto Complete;
    }

    default:
        break;
    }

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


    case IOCTL_T2NCM_SET_TUNNEL_PEER:
    {
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (inLen < 16 || Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        // Same rule as SET_TUNNEL_LOCAL: the tunnel only ever speaks
        // link-local (fe80::/10), so anything else is a caller bug.
        {
            const UCHAR* peerAddr = (const UCHAR*)Irp->AssociatedIrp.SystemBuffer;
            if (peerAddr[0] != 0xFE || (peerAddr[1] & 0xC0) != 0x80)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
        {
            KIRQL peerIrql;
            KeAcquireSpinLock(&context->TunnelPeerLock, &peerIrql);
            RtlCopyMemory(context->TunnelPeerIpv6, Irp->AssociatedIrp.SystemBuffer, 16);
            context->TunnelPeerIpv6Valid = TRUE;
            KeReleaseSpinLock(&context->TunnelPeerLock, peerIrql);
        }
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
            "T2Ncm: TunnelPeerIpv6 set via IOCTL (tunnel rewrite armed)\n"));
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_T2NCM_SET_TUNNEL_LOCAL:
    {
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        const UCHAR* localAddr;

        if (inLen < 16 || Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        localAddr = (const UCHAR*)Irp->AssociatedIrp.SystemBuffer;
        // Only a link-local (fe80::/10) address is ever a valid tunnel source.
        if (localAddr[0] != 0xFE || (localAddr[1] & 0xC0) != 0x80)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            KIRQL localIrql;
            KeAcquireSpinLock(&context->TunnelPeerLock, &localIrql);
            RtlCopyMemory(context->TunnelLocalIpv6, localAddr, 16);
            context->TunnelLocalIpv6Valid = TRUE;
            KeReleaseSpinLock(&context->TunnelPeerLock, localIrql);
        }
        InterlockedExchange(&context->TunnelLocalIpv6UnknownLogged, 0);
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
            "T2Ncm: TunnelLocalIpv6 set via IOCTL (real Windows link-local, no native frame needed)\n"));
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_T2NCM_SET_TRANSPORT_MODE:
    {
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG mode;

        if (inLen < sizeof(ULONG) || Irp->AssociatedIrp.SystemBuffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        RtlCopyMemory(&mode, Irp->AssociatedIrp.SystemBuffer, sizeof(ULONG));
        // Reject unknown mode values before changing either the global
        // mode or the running adapter's cached mode.
        if (mode > 1ul)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Update the driver-global mode first (this is what a later
        // MiniportInitializeEx / MiniportRestart re-seeds from, so the mode
        // survives adapter reset and sleep), then the running adapter's
        // cached copy. Plain assignment on the context field: the TX/RX
        // rewrite paths only ever read it.
        // Records this handle as the owner when the mode now differs from the
        // committed (sticky) decision, so IRP_MJ_CLEANUP can undo it if the
        // process dies before putting the committed mode back.
        T2NcmTunnelModeWrite(stack->FileObject, mode == 1ul);
        InterlockedExchange(&context->TunnelModeEnabled, mode == 1ul ? 1 : 0);

        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
            "T2Ncm: TunnelModeEnabled set live via IOCTL -> %u\n",
            context->TunnelModeEnabled ? 1u : 0u));

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
    ExReleaseResourceLite(&g_T2NcmDiagnosticLock);
    KeLeaveCriticalRegion();

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// Publishes (or, with NULL, withdraws) the adapter the diagnostic IOCTLs
// operate on. Withdrawing waits for every IOCTL that already picked the
// old pointer up, so the caller may free the context as soon as this
// returns. PASSIVE_LEVEL only.
VOID
T2NcmSetDiagnosticAdapter(
    _In_opt_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_T2NcmDiagnosticLock, TRUE);
    g_T2NcmDiagnosticAdapter = DeviceContext;
    ExReleaseResourceLite(&g_T2NcmDiagnosticLock);
    KeLeaveCriticalRegion();
}

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

    // Administrators and SYSTEM get full access. This surface can inject a
    // raw Ethernet frame onto the wire, so it is not something an
    // unprivileged process should be able to open even on a developer
    // machine.
    //
    // PLUS a deliberately WRITE-ONLY grant to LocalService (LS), which is the
    // account the T2TouchIdBio UMDF host runs as: mask 0x100082 =
    // FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE. Without it every
    // automatic IPv6->IPv4 fallback done by the service failed to arm this
    // driver (CreateFile(\\.\\T2Ncm) -> ERROR_ACCESS_DENIED), so TX frames
    // stayed bare IPv4 and the T2 dropped them; only the admin GUI could
    // arm it. No READ right, and GET_STATUS / SEND_TEST_FRAME require READ
    // (Public.h), so LS can only reach SET_TUNNEL_PEER / SET_TRANSPORT_MODE.
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100082;;;LS)");

    RtlZeroMemory(dispatchTable, sizeof(dispatchTable));
    dispatchTable[IRP_MJ_CREATE]         = T2NcmDispatchCreateClose;
    dispatchTable[IRP_MJ_CLOSE]          = T2NcmDispatchCreateClose;
    dispatchTable[IRP_MJ_CLEANUP]        = T2NcmDispatchCleanup;
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
            "T2Ncm: NdisRegisterDeviceEx failed 0x%08X - continuing without "
            "the diagnostic device; the adapter itself is unaffected\n", status));
        DeviceContext->NdisDeviceHandle = NULL;
        DeviceContext->ControlDeviceObject = NULL;
    }

    return status;
}

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

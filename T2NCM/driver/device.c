// SPDX-License-Identifier: GPL-2.0-only
// Device.c — WDFDEVICE creation, PnP/Power lifecycle state machine (Task 4).
//
// State machine (Task 4):
//   Created -> Prepared -> UsbReady -> NcmReady -> NdisRegistered -> Running
//   Running -> Stopping -> Released
// D0Exit/D0Entry cycle inside Running/UsbReady without changing the
// higher-level state — see Power.c (Task 21) once it lands; for now
// D0Entry/D0Exit only gate I/O via T2NcmIsIoAllowed().

#include "Device.h"
#include "UsbTransport.h"

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
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: REJECTED transition expected=%s actual-differs new=%s\n",
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
T2NcmEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    UNREFERENCED_PARAMETER(Driver);

    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDFDEVICE device;
    PT2NCM_DEVICE_CONTEXT context;

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDevicePrepareHardware        = T2NcmEvtDevicePrepareHardware;
    pnpPowerCallbacks.EvtDeviceReleaseHardware         = T2NcmEvtDeviceReleaseHardware;
    pnpPowerCallbacks.EvtDeviceD0Entry                 = T2NcmEvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit                  = T2NcmEvtDeviceD0Exit;
    pnpPowerCallbacks.EvtDeviceSelfManagedIoInit       = T2NcmEvtSelfManagedIoInit;
    pnpPowerCallbacks.EvtDeviceSelfManagedIoSuspend    = T2NcmEvtSelfManagedIoSuspend;
    pnpPowerCallbacks.EvtDeviceSelfManagedIoRestart    = T2NcmEvtSelfManagedIoRestart;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, T2NCM_DEVICE_CONTEXT);

    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfDeviceCreate failed 0x%08X\n", status));
        return status;
    }

    context = T2NcmGetDeviceContext(device);
    RtlZeroMemory(context, sizeof(*context));
    context->WdfDevice = device;
    context->State = T2NcmStateCreated;

    status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->StateLock);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfSpinLockCreate failed 0x%08X\n", status));
        return status;
    }

    // Task 4: default queue takes ownership of EvtIoStop so pending
    // requests are handled correctly across D0Exit/remove (Task 22).
    {
        WDF_IO_QUEUE_CONFIG queueConfig;
        WDFQUEUE queue;

        WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
        queueConfig.EvtIoStop = T2NcmEvtIoStop;

        status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
        if (!NT_SUCCESS(status))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: WdfIoQueueCreate failed 0x%08X\n", status));
            return status;
        }
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: EvtDeviceAdd OK\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmEvtDevicePrepareHardware(
    _In_ WDFDEVICE    Device,
    _In_ WDFCMRESLIST ResourcesRaw,
    _In_ WDFCMRESLIST ResourcesTranslated
    )
{
    UNREFERENCED_PARAMETER(ResourcesRaw);
    UNREFERENCED_PARAMETER(ResourcesTranslated);

    NTSTATUS status;
    PT2NCM_DEVICE_CONTEXT context = T2NcmGetDeviceContext(Device);

    // Task 6: create the WDFUSBDEVICE, select config 1, discover MI_00/MI_01.
    // Implemented in UsbTransport.c; kept out of Device.c so USB transport
    // stays a separate module per Task 1's "clean separation" requirement.
    status = T2NcmUsbPrepareHardware(context);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmUsbPrepareHardware failed 0x%08X\n", status));
        return status;
    }

    if (!T2NcmTrySetState(context, T2NcmStateCreated, T2NcmStatePrepared))
    {
        // Also legal to re-enter PrepareHardware from Released on restart;
        // handle that explicitly rather than silently accepting any state.
        if (!T2NcmTrySetState(context, T2NcmStateReleased, T2NcmStatePrepared))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: PrepareHardware called from unexpected state\n"));
            return STATUS_INVALID_DEVICE_STATE;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmEvtDeviceReleaseHardware(
    _In_ WDFDEVICE    Device,
    _In_ WDFCMRESLIST ResourcesTranslated
    )
{
    UNREFERENCED_PARAMETER(ResourcesTranslated);

    PT2NCM_DEVICE_CONTEXT context = T2NcmGetDeviceContext(Device);

    // Task 22: no USB objects may be touched after this returns. Force
    // the state to Released regardless of where we were (surprise
    // removal can arrive from any state) and let T2NcmUsbReleaseHardware
    // tear down pipes/interfaces/UsbDevice under the same lock discipline
    // T2NcmIsIoAllowed() readers use.
    WdfSpinLockAcquire(context->StateLock);
    context->State = T2NcmStateReleased;
    WdfSpinLockRelease(context->StateLock);

    T2NcmUsbReleaseHardware(context);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: ReleaseHardware -> Released\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmEvtDeviceD0Entry(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
    )
{
    UNREFERENCED_PARAMETER(PreviousState);
    PT2NCM_DEVICE_CONTEXT context = T2NcmGetDeviceContext(Device);

    // Tasks 6-12 (USB config/pipes, NCM negotiation, alt-setting switch)
    // and Task 18 (NDIS registration) plug in here in later passes; for
    // this milestone we only advance to UsbReady so I/O-allowed checks
    // and the diagnostic IOCTL (Task 25) have a real, honestly-reported
    // state instead of a fabricated one.
    (void)T2NcmTrySetState(context, T2NcmStatePrepared, T2NcmStateUsbReady);

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmEvtDeviceD0Exit(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
    )
{
    UNREFERENCED_PARAMETER(TargetState);
    PT2NCM_DEVICE_CONTEXT context = T2NcmGetDeviceContext(Device);

    // Per Task 21: stop RX/TX rearming and cancel pending USB before
    // returning. RX/TX engines don't exist yet in this milestone
    // (Tasks 15/16), so this currently only flips the gate that
    // T2NcmIsIoAllowed() checks — later passes add the actual
    // cancel/flush calls here.
    WdfSpinLockAcquire(context->StateLock);
    if (context->State != T2NcmStateReleased)
    {
        context->State = T2NcmStatePrepared;
    }
    WdfSpinLockRelease(context->StateLock);

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmEvtSelfManagedIoInit(
    _In_ WDFDEVICE Device
    )
{
    UNREFERENCED_PARAMETER(Device);
    // RX rearm loop / periodic housekeeping starts here once Task 15 lands.
    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmEvtSelfManagedIoSuspend(
    _In_ WDFDEVICE Device
    )
{
    UNREFERENCED_PARAMETER(Device);
    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmEvtSelfManagedIoRestart(
    _In_ WDFDEVICE Device
    )
{
    UNREFERENCED_PARAMETER(Device);
    return STATUS_SUCCESS;
}

VOID
T2NcmEvtIoStop(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG      ActionFlags
    )
{
    // Task 22: default behavior is correct until RX/TX engines exist —
    // WDF handles requeue/cancel for us for requests sitting in this
    // queue. Custom I/O (control transfers, NTB reads/writes) is
    // cancelled explicitly in UsbTransport.c/NcmRx.c/NcmTx.c once those
    // modules submit anything, per Task 22's "no callback may access
    // freed device context" requirement.
    UNREFERENCED_PARAMETER(Queue);

    if (ActionFlags & WdfRequestStopActionSuspend)
    {
        WdfRequestStopAcknowledge(Request, FALSE);
    }
    else if (ActionFlags & WdfRequestStopActionPurge)
    {
        WdfRequestCancelSentRequest(Request);
    }
}

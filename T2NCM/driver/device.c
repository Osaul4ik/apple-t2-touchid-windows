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

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: EvtDeviceAdd entered\n"));

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

    // Task 25: device interface for the diagnostic status IOCTL — full
    // (MI_01) role only. The stub role never negotiates anything worth
    // reporting, so it doesn't get this surface at all.
    if (!g_T2NcmStubRole)
    {
        status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_T2NCM, NULL);
        if (!NT_SUCCESS(status))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: WdfDeviceCreateDeviceInterface failed 0x%08X\n", status));
            return status;
        }

        // Task 4: default queue takes ownership of EvtIoStop so pending
        // requests are handled correctly across D0Exit/remove (Task 22).
        // Task 25: same queue also dispatches IOCTL_T2NCM_GET_STATUS —
        // it's a fast, synchronous, always-completes-immediately handler,
        // so it doesn't need a queue of its own. The stub role never
        // receives application-initiated requests at all, so it doesn't
        // need a custom queue — WDF's built-in default handling is fine.
        WDF_IO_QUEUE_CONFIG queueConfig;
        WDFQUEUE queue;

        WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
        queueConfig.EvtIoStop = T2NcmEvtIoStop;
        queueConfig.EvtIoDeviceControl = T2NcmEvtIoDeviceControl;

        status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
        if (!NT_SUCCESS(status))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: WdfIoQueueCreate failed 0x%08X\n", status));
            return status;
        }
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: EvtDeviceAdd OK (role=%s)\n", g_T2NcmStubRole ? "stub" : "full"));

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

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: EvtDevicePrepareHardware entered (role=%s)\n",
        g_T2NcmStubRole ? "stub" : "full"));

    // Task 6: create the WDFUSBDEVICE, select the interface config.
    // Implemented in UsbTransport.c; kept out of Device.c so USB transport
    // stays a separate module per Task 1's "clean separation" requirement.
    // Variant 1: two different entry points per role — see UsbTransport.h.
    status = g_T2NcmStubRole
        ? T2NcmUsbPrepareHardwareStub(context)
        : T2NcmUsbPrepareHardware(context);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: USB prepare-hardware failed 0x%08X\n", status));
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

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: EvtDevicePrepareHardware OK\n"));

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

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: EvtDeviceD0Entry entered (PreviousState=%u)\n", (ULONG)PreviousState));

    // Task 18 (NDIS registration) plugs in here in a later pass; for
    // this milestone D0Entry advances to UsbReady, then (full role only)
    // attempts the Tasks 7-12 NCM control-plane negotiation and MI_01
    // activation so I/O-allowed checks have a real, honestly-reported
    // state instead of a fabricated one. The stub role has nothing to
    // negotiate — it stops at UsbReady every time, which is fine since
    // nothing ever checks T2NcmIsIoAllowed() for it.
    (void)T2NcmTrySetState(context, T2NcmStatePrepared, T2NcmStateUsbReady);

    if (!g_T2NcmStubRole && T2NcmIsIoAllowed(context))
    {
        T2NCM_NTB_PARAMETERS ntbParams;
        NTSTATUS ncmStatus;

        // Reset every Tasks 7-12 output BEFORE attempting renegotiation.
        // Without this, a partial/failed attempt this cycle (e.g. on
        // resume from suspend) would leave stale TRUE/non-zero values
        // from a PREVIOUS successful cycle behind — the state would
        // correctly fall back to UsbReady, but Ntb16Supported,
        // MacAddressValid, and the bulk pipe handles would still read
        // as "known good" from before. Task 25's diagnostic IOCTL must
        // never report a field as confirmed when THIS cycle didn't
        // actually confirm it — that's exactly the kind of fabricated
        // status this driver's whole design is built to avoid.
        context->Ntb16Supported  = FALSE;
        context->NtbInMaxSize    = 0;
        context->NtbOutMaxSize   = 0;
        context->MacAddressValid = FALSE;
        context->BulkInPipe      = NULL;
        context->BulkOutPipe     = NULL;

        // Tasks 7-12: negotiate the CDC-NCM control plane and switch
        // MI_01 to its active alt setting. This re-runs on EVERY
        // D0Entry — cold start and resume alike — rather than only
        // once. These are all idempotent USB control transfers, so
        // that's simpler and safer than trying to distinguish
        // "first bring-up" from "resume" before Task 21's power
        // orchestration exists. A resume-fast-path (skip
        // renegotiation, verify liveness only — the same pattern
        // T2TouchIdTransport's mailbox liveness check uses) is a
        // Task 21 optimization, not a Task 7-12 correctness
        // requirement.
        //
        // Failure here is NOT fatal to D0Entry: nothing downstream
        // (NDIS registration, Task 18+) exists yet to depend on
        // NcmReady, so this logs and stays at UsbReady rather than
        // failing the whole PnP power-up and knocking the device out
        // of Device Manager on a transient negotiation failure.
        ncmStatus = T2NcmGetNtbParameters(context, &ntbParams);

        if (NT_SUCCESS(ncmStatus))
        {
            ncmStatus = T2NcmNegotiateNtbFormat(context, &ntbParams);
        }

        if (NT_SUCCESS(ncmStatus))
        {
            ncmStatus = T2NcmSetNtbInputSize(context, &ntbParams);
            if (NT_SUCCESS(ncmStatus))
            {
                context->NtbInMaxSize  = ntbParams.dwNtbInMaxSize;
                context->NtbOutMaxSize = ntbParams.dwNtbOutMaxSize;
            }
        }

        if (NT_SUCCESS(ncmStatus))
        {
            // T2NcmReadMacAddress now discovers the MAC via a string-
            // table scan (T2NcmScanForMacStringIndex in NcmProtocol.c),
            // which works from an MI_01-only binding — expected to
            // succeed on every real T2 unit. Still deliberately NOT
            // gating NcmReady on it: a firmware/revision variant whose
            // string table doesn't contain exactly one 12-hex-char
            // string would otherwise take the whole data path down with
            // it for what is, at worst, a missing permanent address.
            // MacAddressValid stays FALSE on failure — the honest,
            // "never fabricate a MAC" result this driver has always
            // required.
            NTSTATUS macStatus = T2NcmReadMacAddress(context);
            if (!NT_SUCCESS(macStatus))
            {
                T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                    "T2Ncm: permanent MAC address discovery failed (0x%08X) — "
                    "unexpected on known-good hardware; continuing without "
                    "one\n", macStatus));
            }
        }

        if (NT_SUCCESS(ncmStatus))
        {
            ncmStatus = T2NcmUsbActivateDataInterface(context);
        }

        if (NT_SUCCESS(ncmStatus))
        {
            (void)T2NcmTrySetState(context, T2NcmStateUsbReady, T2NcmStateNcmReady);
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
                "T2Ncm: NCM control-plane negotiated, MI_01 active -> NcmReady\n"));
        }
        else
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: NCM negotiation incomplete (0x%08X) — staying at UsbReady\n",
                ncmStatus));
        }
    }

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

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: EvtDeviceD0Exit entered (TargetState=%u)\n", (ULONG)TargetState));

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

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: EvtDeviceD0Exit -> Prepared (NCM control-plane will "
        "renegotiate on next D0Entry)\n"));

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

// ---------------------------------------------------------------------
// Task 25: diagnostic status IOCTL. Reports exactly what the device
// context currently holds — never a fabricated or "assumed" value.
// Everything in T2NCM_STATUS defaults to zero/FALSE from
// RtlZeroMemory(out, sizeof(*out)) and is only set to something else if
// the corresponding real state exists (e.g. MacAddress is only filled
// in when MacAddressValid is also set from the same read).
// ---------------------------------------------------------------------
static
VOID
T2NcmEvtIoDeviceControlGetStatus(
    _In_ WDFREQUEST            Request,
    _In_ PT2NCM_DEVICE_CONTEXT Context
    )
{
    NTSTATUS status;
    PT2NCM_STATUS out;
    size_t outLen;
    T2NCM_LIFECYCLE_STATE state;

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*out), (PVOID*)&out, &outLen);
    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);
        return;
    }

    // WdfRequestRetrieveOutputBuffer's success contract guarantees outLen
    // >= the MinimumRequiredSize (sizeof(*out)) passed in above; the
    // KMDF header's SAL doesn't express that tie, so /analyze can't
    // derive it on its own — restated explicitly (same pattern
    // T2TouchIdTransport's GetStatus handler uses).
    _Analysis_assume_(outLen >= sizeof(*out));
    RtlZeroMemory(out, sizeof(*out));

    WdfSpinLockAcquire(Context->StateLock);
    state = Context->State;
    WdfSpinLockRelease(Context->StateLock);

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

    out->LifecycleState = (UINT32)state;

    // Tasks 7-11. Read without the state lock — these fields are only
    // ever written from D0Entry on the PASSIVE_LEVEL power thread, and a
    // torn read here is at worst one IOCTL reporting a value from just
    // before/after a negotiation pass, never a fabricated one.
    out->Ntb16Supported = Context->Ntb16Supported;
    out->NtbInMaxSize   = Context->NtbInMaxSize;
    out->NtbOutMaxSize  = Context->NtbOutMaxSize;

    // Task 8.
    out->MacAddressValid = Context->MacAddressValid;
    if (Context->MacAddressValid)
    {
        RtlCopyMemory(out->MacAddress, Context->PermanentMacAddress, sizeof(out->MacAddress));
    }

    // Task 12 — both pipes are only ever non-NULL together (set together
    // in T2NcmUsbActivateDataInterface, cleared together on its failure
    // path and in T2NcmUsbReleaseHardware), so checking one is enough,
    // but check both anyway: reporting DataInterfaceActive=TRUE from a
    // half-set pair would itself be a fabricated status.
    out->DataInterfaceActive =
        (Context->BulkInPipe != NULL) && (Context->BulkOutPipe != NULL);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: IOCTL_T2NCM_GET_STATUS -> state=%u ntb16=%u inMax=%u outMax=%u "
        "macValid=%u mac=%02X:%02X:%02X:%02X:%02X:%02X dataActive=%u\n",
        out->LifecycleState, out->Ntb16Supported, out->NtbInMaxSize, out->NtbOutMaxSize,
        out->MacAddressValid,
        out->MacAddress[0], out->MacAddress[1], out->MacAddress[2],
        out->MacAddress[3], out->MacAddress[4], out->MacAddress[5],
        out->DataInterfaceActive));

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(*out));
}

VOID
T2NcmEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
    )
{
    PT2NCM_DEVICE_CONTEXT context = T2NcmGetDeviceContext(WdfIoQueueGetDevice(Queue));

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode)
    {
    case IOCTL_T2NCM_GET_STATUS:
        T2NcmEvtIoDeviceControlGetStatus(Request, context);
        break;

    default:
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: unrecognized IOCTL 0x%08X\n", IoControlCode));
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        break;
    }
}
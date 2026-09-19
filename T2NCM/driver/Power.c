// SPDX-License-Identifier: GPL-2.0-only
// Power.c — see Power.h for the model. Short version: NDIS owns the
// power policy, this file only moves the hardware.

#include "Power.h"
#include "Device.h"
#include "UsbTransport.h"
#include "NcmProtocol.h"
#include "NcmRx.h"

// ---------------------------------------------------------------------
// Cold-boot readiness wait for GET_NTB_PARAMETERS.
//
// On real hardware the T2's NCM control plane can still be settling
// when this runs right after a from-cold MiniportInitializeEx —
// bridgeOS/SEP have their own bring-up sequence that isn't synchronized
// with when Windows decides the USB function is enumerated. There is no
// notification for "the NCM function has finished initializing"; the
// CDC-NCM spec's interrupt-pipe notifications (NETWORK_CONNECTION etc.,
// read by the separate T2NcmCtrl.sys on MI_00) are about physical link
// state, not this. The only real signal is the answer to the request
// itself, so waiting for readiness here necessarily means asking again —
// the difference from a blind loop is WHERE that asking happens (this
// one call, not the whole Restart/re-arm sequence) and THAT it only
// re-asks when the failure actually looks like "not ready yet".
//
// A transient status is a low-level USB condition consistent with a
// function that hasn't attached to the endpoint yet — STALL/timeout/not-
// ready style failures the class request can hit before bridgeOS has
// wired the NCM handler up. STATUS_DEVICE_PROTOCOL_ERROR is deliberately
// EXCLUDED: that means the device answered with a well-formed but
// nonsensical response (T2NcmGetNtbParameters already validated it), which
// is a real incompatibility, not a timing race — retrying it would just
// burn the whole budget for nothing.
static
BOOLEAN
T2NcmIsTransientArmStatus(
    _In_ NTSTATUS Status
    )
{
    switch (Status)
    {
    case STATUS_IO_TIMEOUT:
    case STATUS_DEVICE_NOT_READY:
    case STATUS_DEVICE_BUSY:
    case STATUS_DEVICE_DATA_ERROR:
    case STATUS_UNSUCCESSFUL:      // generic STALL/PID-error mapping
        return TRUE;
    default:
        return FALSE;
    }
}

#define T2NCM_ARM_READY_BUDGET_MS      800
#define T2NCM_ARM_READY_INITIAL_MS     20
#define T2NCM_ARM_READY_MAX_STEP_MS    150

static
NTSTATUS
T2NcmGetNtbParametersWaitReady(
    _In_  PT2NCM_DEVICE_CONTEXT   DeviceContext,
    _Out_ PT2NCM_NTB_PARAMETERS   Parameters
    )
{
    NTSTATUS status;
    ULONG elapsedMs = 0;
    ULONG stepMs = T2NCM_ARM_READY_INITIAL_MS;
    ULONG attempt = 0;

    for (;;)
    {
        attempt++;
        status = T2NcmGetNtbParameters(DeviceContext, Parameters);
        if (NT_SUCCESS(status))
        {
            if (attempt > 1)
            {
                T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                    "T2Ncm: GET_NTB_PARAMETERS succeeded after %lu attempt(s), "
                    "~%lu ms of waiting for the control plane to settle\n",
                    attempt, elapsedMs));
            }
            return STATUS_SUCCESS;
        }

        if (!T2NcmIsTransientArmStatus(status) ||
            elapsedMs + stepMs > T2NCM_ARM_READY_BUDGET_MS)
        {
            // Either a real (non-timing) failure, or the budget is
            // spent — stop asking and let the caller treat this as a
            // genuine failure rather than retrying forever.
            if (attempt > 1)
            {
                T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                    "T2Ncm: GET_NTB_PARAMETERS gave up after %lu attempt(s) "
                    "(~%lu ms), last status 0x%08X\n",
                    attempt, elapsedMs, status));
            }
            return status;
        }

        {
            LARGE_INTEGER delay;

            delay.QuadPart = -((LONGLONG)stepMs * 10000);
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }

        elapsedMs += stepMs;
        stepMs *= 2;
        if (stepMs > T2NCM_ARM_READY_MAX_STEP_MS)
        {
            stepMs = T2NCM_ARM_READY_MAX_STEP_MS;
        }
    }
}

NTSTATUS
T2NcmPowerArmHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    NTSTATUS status;

    // Fast re-arm: NtbParametersCached means a PRIOR arm on this same
    // physical device already confirmed GET_NTB_PARAMETERS, format
    // negotiation and SET_NTB_INPUT_SIZE, and DeviceContext still holds
    // those values (T2NcmPowerQuiesceHardware does not touch them - see
    // below). Every D0 re-entry after S3/selective-suspend/any other
    // brief power dip otherwise spent several sequential control
    // transfers — GET_NTB_PARAMETERS, NTB16 negotiation,
    // SET_NTB_INPUT_SIZE, THEN the alt-setting switch — with MI_01
    // sitting on alt 0 (no bulk endpoints at all) for the whole
    // sequence. Anything the far side sends during that window has no
    // pipe to land on; skipping straight to the alt-1 switch cuts that
    // window down to the one control transfer that cannot be skipped.
    // A failed fast re-arm falls back to the full slow path below on the
    // NEXT arm attempt (see the Unwind block) rather than retrying here,
    // so this function never loops.
    // Defensive: any re-arm (fast or slow path below) is about to call
    // WdfUsbInterfaceSelectSetting, which hands back BRAND NEW pipe
    // objects — the old WDFUSBPIPE handles this device's continuous
    // reader (if one is still configured against them) become invalid
    // the moment that happens. T2NcmRxStart's own RxStarted flag is only
    // cleared by MiniportPause -> T2NcmRxStop, so a second arm reachable
    // without an intervening Pause (a stray/duplicate D0 power
    // indication, a retry from MiniportRestart, a surprise-removal
    // recovery path, etc.) would otherwise leave the reader silently
    // orphaned on a pipe that no longer exists rather than reconfigured
    // on the new one. T2NcmRxStop is idempotent, so this costs nothing
    // on the normal path where nothing was running.
    T2NcmRxStop(DeviceContext);

    if (DeviceContext->NtbParametersCached)
    {
        status = T2NcmUsbActivateDataInterface(DeviceContext);
        if (NT_SUCCESS(status))
        {
            (VOID)T2NcmApplyPacketFilter(DeviceContext);

            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
                "T2Ncm: hardware fast-armed (NTB params reused: ntbIn=%lu "
                "ntbOut=%lu), MI_01 on alt %u\n",
                DeviceContext->NtbInMaxSize, DeviceContext->NtbOutMaxSize,
                T2NCM_DATA_ALT_ACTIVE));

            return STATUS_SUCCESS;
        }

        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: fast re-arm's alt-1 activation failed 0x%08X — "
            "invalidating cached NTB parameters, next arm attempt takes "
            "the full slow path\n", status));

        // Do not trust these values again without re-confirming them.
        DeviceContext->NtbParametersCached = FALSE;
        return status;
    }

    {
    T2NCM_NTB_PARAMETERS ntbParams;

    // Reset every negotiated output BEFORE attempting (re)negotiation.
    // Without this, a partial/failed attempt this cycle would leave
    // stale TRUE/non-zero values from a PREVIOUS successful cycle
    // behind — the lifecycle state would correctly fall back to
    // UsbReady, but Ntb16Supported, MacAddressValid and the bulk pipe
    // handles would still read as "known good" from before. Nothing in
    // this driver may report a field as confirmed when THIS cycle did
    // not confirm it.
    DeviceContext->Ntb16Supported         = FALSE;
    DeviceContext->NtbInMaxSize           = 0;
    DeviceContext->NtbOutMaxSize          = 0;
    DeviceContext->NdpOutDivisor          = 0;
    DeviceContext->NdpOutPayloadRemainder = 0;
    DeviceContext->NdpOutAlignment        = 0;
    DeviceContext->NtbOutMaxDatagrams     = 0;
    DeviceContext->BulkInPipe             = NULL;
    DeviceContext->BulkOutPipe            = NULL;
    DeviceContext->RxReaderConfigured     = FALSE;

    // The MAC address is deliberately NOT reset here. It is read once at
    // first bring-up and is a property of the physical device, not of
    // the current power cycle — and NDIS has already published it as the
    // adapter's station address. Re-deriving it on resume could only
    // either produce the same answer or produce a different one, and a
    // NIC whose MAC changes across S3 is a worse failure than a stale
    // one. MiniportInitializeEx owns that read; see NdisMiniport.c.

    status = T2NcmGetNtbParametersWaitReady(DeviceContext, &ntbParams);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: GET_NTB_PARAMETERS failed 0x%08X\n", status));
        return status;
    }

    status = T2NcmNegotiateNtbFormat(DeviceContext, &ntbParams);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: NTB16 format negotiation failed 0x%08X\n", status));
        return status;
    }

    status = T2NcmSetNtbInputSize(DeviceContext, &ntbParams);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: SET_NTB_INPUT_SIZE failed 0x%08X\n", status));
        return status;
    }

    DeviceContext->NtbInMaxSize           = ntbParams.dwNtbInMaxSize;
    DeviceContext->NtbOutMaxSize          = ntbParams.dwNtbOutMaxSize;
    DeviceContext->NdpOutDivisor          = ntbParams.wNdpOutDivisor;
    DeviceContext->NdpOutPayloadRemainder = ntbParams.wNdpOutPayloadRemainder;
    DeviceContext->NdpOutAlignment        = ntbParams.wNdpOutAlignment;
    DeviceContext->NtbOutMaxDatagrams     = ntbParams.wNtbOutMaxDatagrams;

    // Confirmed for this physical device — trusted on every subsequent
    // D0 re-entry until/unless a fast re-arm's activation fails above.
    DeviceContext->NtbParametersCached    = TRUE;

    status = T2NcmUsbActivateDataInterface(DeviceContext);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: MI_01 alt-1 activation failed 0x%08X\n", status));
        return status;
    }

    // MUST come after the alt-1 switch: SET_INTERFACE resets the
    // device's packet filter to zero, i.e. "forward nothing to the
    // host". Without this the adapter transmits fine and receives
    // literally zero bytes - which is exactly what it did before this
    // call existed. Not fatal on failure: the control plane is
    // otherwise up, the failure is logged loudly by
    // T2NcmSetEthernetPacketFilter, and the NDIS packet-filter OID will
    // retry it as soon as the stack sets a filter.
    (VOID)T2NcmApplyPacketFilter(DeviceContext);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: hardware armed — ntbIn=%lu ntbOut=%lu, MI_01 on alt %u\n",
        DeviceContext->NtbInMaxSize, DeviceContext->NtbOutMaxSize,
        T2NCM_DATA_ALT_ACTIVE));

    return STATUS_SUCCESS;
    }
}

VOID
T2NcmPowerQuiesceHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    // Belt and braces. NDIS has already paused the miniport before any
    // Dx transition reaches us, so RX is stopped and every indication
    // and send is drained by the time we get here. T2NcmRxStop is
    // idempotent, so calling it again costs one branch and removes any
    // dependency on that ordering holding in a surprise-removal path.
    T2NcmRxStop(DeviceContext);

    // Park MI_01 on its zero-endpoint idle setting. The bulk pipe
    // objects belong to the alt-1 setting and must not be used again
    // until T2NcmPowerArmHardware re-selects it, so drop the cached
    // handles in the same step rather than leaving the send path with
    // pointers to pipes that are no longer configured.
    T2NcmUsbDeactivateDataInterface(DeviceContext);
}

NDIS_STATUS
T2NcmPowerSetDeviceState(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ NDIS_DEVICE_POWER_STATE NewState
    )
{
    NDIS_DEVICE_POWER_STATE previous = DeviceContext->PowerState;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: OID_PNP_SET_POWER %u -> %u\n",
        (ULONG)previous, (ULONG)NewState));

    if (NewState == NdisDeviceStateD0)
    {
        NTSTATUS status;

        DeviceContext->PowerState = NdisDeviceStateD0;

        if (previous == NdisDeviceStateD0)
        {
            // NDIS does not normally send a redundant D0, but treating
            // it as a no-op is cheaper and safer than re-running a
            // control-plane negotiation underneath a live data path.
            return NDIS_STATUS_SUCCESS;
        }

        status = T2NcmPowerArmHardware(DeviceContext);
        if (NT_SUCCESS(status))
        {
            // Post-suspend state can be Prepared (a fresh cold-boot-style
            // re-negotiation) or UsbReady (nothing dropped the negotiated
            // NTB parameters) - try the more common Prepared case first
            // and only fall back if it didn't match, same reasoning as
            // MiniportRestart's NdisRegistered/NcmReady pair.
            if (!T2NcmTrySetState(DeviceContext, T2NcmStatePrepared, T2NcmStateNcmReady))
            {
                (void)T2NcmTrySetState(DeviceContext, T2NcmStateUsbReady, T2NcmStateNcmReady);
            }
        }
        else
        {
            // Stay at UsbReady and report the power transition as
            // successful anyway. Failing a D0 transition would leave the
            // device stack stuck mid-resume; an adapter that comes back
            // without a working control plane is recoverable (disable/
            // enable, or replug), a wedged S3 resume is not.
            (void)T2NcmTrySetState(DeviceContext, T2NcmStatePrepared, T2NcmStateUsbReady);
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: D0 re-arm failed 0x%08X — adapter will have no data "
                "path until it is reinitialized; reporting the power "
                "transition as successful regardless\n", status));
        }

        // Deliberately NOT starting RX here, and deliberately NOT
        // touching DataPathRunning: MiniportRestart owns that and NDIS
        // will call it immediately after this returns. See Power.h.
        return NDIS_STATUS_SUCCESS;
    }

    // ---- Any low-power state ----
    DeviceContext->PowerState = NewState;

    T2NcmPowerQuiesceHardware(DeviceContext);

    // Drop back to Prepared: the USB target and the WDFDEVICE survive a
    // D-state transition, the negotiated control plane does not. This is
    // the honest state to report from the diagnostic surface while
    // suspended — NcmReady would claim a negotiated NTB geometry that no
    // longer describes anything.
    WdfSpinLockAcquire(DeviceContext->StateLock);
    if (DeviceContext->State != T2NcmStateReleased)
    {
        DeviceContext->State = T2NcmStatePrepared;
    }
    WdfSpinLockRelease(DeviceContext->StateLock);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: quiesced for low-power state %u (MI_01 parked on alt %u)\n",
        (ULONG)NewState, T2NCM_DATA_ALT_IDLE));

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
T2NcmPowerQueryDeviceState(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ NDIS_DEVICE_POWER_STATE ProposedState
    )
{
    UNREFERENCED_PARAMETER(DeviceContext);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: OID_PNP_QUERY_POWER(%u) -> allowed\n", (ULONG)ProposedState));

    return NDIS_STATUS_SUCCESS;
}
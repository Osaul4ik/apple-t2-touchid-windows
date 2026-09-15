// SPDX-License-Identifier: GPL-2.0-only
// Power.c — see Power.h for the model. Short version: NDIS owns the
// power policy, this file only moves the hardware.

#include "Power.h"
#include "Device.h"
#include "UsbTransport.h"
#include "NcmProtocol.h"
#include "NcmRx.h"

NTSTATUS
T2NcmPowerArmHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    T2NCM_NTB_PARAMETERS ntbParams;
    NTSTATUS status;

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

    // The MAC address is deliberately NOT reset here. It is read once at
    // first bring-up and is a property of the physical device, not of
    // the current power cycle — and NDIS has already published it as the
    // adapter's station address. Re-deriving it on resume could only
    // either produce the same answer or produce a different one, and a
    // NIC whose MAC changes across S3 is a worse failure than a stale
    // one. MiniportInitializeEx owns that read; see NdisMiniport.c.

    status = T2NcmGetNtbParameters(DeviceContext, &ntbParams);
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
            (void)T2NcmTrySetState(DeviceContext, T2NcmStatePrepared, T2NcmStateNcmReady);
            (void)T2NcmTrySetState(DeviceContext, T2NcmStateUsbReady, T2NcmStateNcmReady);
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
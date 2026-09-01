// SPDX-License-Identifier: GPL-2.0-only
// NcmProtocol.c — Tasks 7-11 (NCM control layer). Deliberately left as
// explicit STATUS_NOT_IMPLEMENTED in this milestone, per the task list's
// own sequencing rule ("do not attempt to implement USB, NCM, and NDIS
// simultaneously in one change"). UsbTransport.c (Tasks 5-6) must reach
// Task 25's diagnostic milestone first. Filled in the next pass.

#include "NcmProtocol.h"

NTSTATUS
T2NcmGetNtbParameters(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_ PT2NCM_NTB_PARAMETERS Parameters
    )
{
    UNREFERENCED_PARAMETER(DeviceContext);
    RtlZeroMemory(Parameters, sizeof(*Parameters));
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
T2NcmNegotiateNtbFormat(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ const T2NCM_NTB_PARAMETERS* Parameters
    )
{
    UNREFERENCED_PARAMETER(DeviceContext);
    UNREFERENCED_PARAMETER(Parameters);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
T2NcmSetNtbInputSize(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ const T2NCM_NTB_PARAMETERS* Parameters
    )
{
    UNREFERENCED_PARAMETER(DeviceContext);
    UNREFERENCED_PARAMETER(Parameters);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
T2NcmReadMacAddress(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    // Task 8: must fail explicitly, never fabricate a MAC.
    DeviceContext->MacAddressValid = FALSE;
    return STATUS_NOT_IMPLEMENTED;
}

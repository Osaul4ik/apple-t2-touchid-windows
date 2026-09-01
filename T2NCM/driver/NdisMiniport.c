// SPDX-License-Identifier: GPL-2.0-only
// NdisMiniport.c — Tasks 18-20, not yet implemented in this milestone.
#include "NdisMiniport.h"

NTSTATUS T2NcmNdisRegister(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext)
{
    UNREFERENCED_PARAMETER(DeviceContext);
    return STATUS_NOT_IMPLEMENTED;
}

VOID T2NcmNdisDeregister(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext)
{
    UNREFERENCED_PARAMETER(DeviceContext);
}

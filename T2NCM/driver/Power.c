// SPDX-License-Identifier: GPL-2.0-only
// Power.c — Task 21, not yet wired in (see Power.h). Device.c's D0Entry/
// D0Exit handle the minimal state transition directly for this milestone.
#include "Power.h"

NTSTATUS T2NcmPowerEnterD0(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext)
{
    UNREFERENCED_PARAMETER(DeviceContext);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS T2NcmPowerExitD0(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext)
{
    UNREFERENCED_PARAMETER(DeviceContext);
    return STATUS_NOT_IMPLEMENTED;
}

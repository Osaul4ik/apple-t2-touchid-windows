// SPDX-License-Identifier: GPL-2.0-only
// Control.h - the \\.\T2Ncm control device (Control.c), as the miniport uses it.
#pragma once

#include "NdisMiniport.h"

// Publishes (or, with NULL, withdraws) the adapter the IOCTLs operate on.
// Withdrawing waits for every IOCTL that already picked the old pointer up, so the
// caller may free the context as soon as this returns. PASSIVE_LEVEL only.
VOID
T2NcmSetDiagnosticAdapter(
    _In_opt_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Creates \\.\T2Ncm (SDDL in Control.c). A failure is logged and leaves the
// adapter itself unaffected.
NDIS_STATUS
T2NcmRegisterDiagnosticDevice(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

VOID
T2NcmDeregisterDiagnosticDevice(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

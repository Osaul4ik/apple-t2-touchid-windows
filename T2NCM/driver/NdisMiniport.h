// SPDX-License-Identifier: GPL-2.0-only
// NdisMiniport.h — NDIS 6 miniport entry points (Tasks 18-20). Not yet
// implemented — registration happens only after Task 25's diagnostic
// milestone (USB+NCM control plane proven) succeeds, per the task list's
// sequencing rule.
#pragma once
#include "Driver.h"

NTSTATUS T2NcmNdisRegister(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);
VOID     T2NcmNdisDeregister(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);

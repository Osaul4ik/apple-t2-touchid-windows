// SPDX-License-Identifier: GPL-2.0-only
// Power.h — D0Entry/D0Exit orchestration once RX/TX/NDIS exist (Task 21).
// Device.c currently inlines the minimal D0Entry/D0Exit state transition;
// this module takes over the RX/TX stop-and-flush / re-init sequencing
// once NcmRx/NcmTx/NdisMiniport are implemented.
#pragma once
#include "Driver.h"

NTSTATUS T2NcmPowerEnterD0(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);
NTSTATUS T2NcmPowerExitD0(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);

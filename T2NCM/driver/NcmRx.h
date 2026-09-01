// SPDX-License-Identifier: GPL-2.0-only
// NcmRx.h — NTB16 RX parser + bulk-IN engine (Tasks 14-15). Not yet
// implemented — see NcmProtocol.c header comment for sequencing rationale.
#pragma once
#include "Driver.h"

NTSTATUS T2NcmRxStart(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);
VOID     T2NcmRxStop(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);

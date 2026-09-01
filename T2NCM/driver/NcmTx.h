// SPDX-License-Identifier: GPL-2.0-only
// NcmTx.h — NTB16 TX builder + bulk-OUT engine (Tasks 13,16). Not yet
// implemented — see NcmProtocol.c header comment for sequencing rationale.
#pragma once
#include "Driver.h"

NTSTATUS T2NcmTxStart(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);
VOID     T2NcmTxStop(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);

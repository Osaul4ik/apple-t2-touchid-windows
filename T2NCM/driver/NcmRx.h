// SPDX-License-Identifier: GPL-2.0-only
// NcmRx.h — NTB16 RX parser + bulk-IN continuous reader + NDIS receive
// indication.
//
// Ownership under the inverted power model (Driver.h):
//   T2NcmRxStart / T2NcmRxStop are called ONLY from MiniportRestart /
//   MiniportPause (and, defensively, from the halt and quiesce paths).
//   They are NOT called from a D0Entry/D0Exit — this driver has none.
//   Nothing else in the driver may start or stop the receive engine.
#pragma once
#include "Driver.h"

// Allocates the NET_BUFFER_LIST pool used for receive indications.
// Called from MiniportInitializeEx before the adapter is registered;
// the pool outlives individual pause/restart cycles so that a restart
// never has to allocate before it can accept traffic.
NTSTATUS
T2NcmRxAllocateResources(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Frees what T2NcmRxAllocateResources allocated. Called from
// MiniportHaltEx, after the data path is stopped and every indicated
// NBL has been returned. Idempotent.
VOID
T2NcmRxFreeResources(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Configures a continuous reader on DeviceContext->BulkInPipe (buffer
// size = the already-negotiated NtbInMaxSize, rounded up to the pipe's
// MaximumPacketSize) and starts it. Call only after
// T2NcmUsbActivateDataInterface has switched the data interface to alt 1
// and populated BulkInPipe.
//
// Idempotent: a second call while already started is a no-op success.
NTSTATUS
T2NcmRxStart(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Stops the continuous reader and waits for in-flight reads to
// complete. Idempotent — safe to call when RX was never started, or
// twice in a row (surprise removal followed by an explicit pause).
//
// Note what this does NOT do: it does not wait for already-indicated
// NBLs to come back. That drain belongs to MiniportPause, which is the
// only caller that has to guarantee it before returning to NDIS.
VOID
T2NcmRxStop(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// MiniportReturnNetBufferLists: NDIS handing back NBLs this driver
// indicated. Frees the per-frame MDL and buffer, returns the NBL to the
// pool, and releases the outstanding-indication reference that
// MiniportPause waits on.
VOID
T2NcmRxReturnNetBufferLists(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNET_BUFFER_LIST      NetBufferLists,
    _In_ ULONG                 ReturnFlags
    );
// SPDX-License-Identifier: GPL-2.0-only
// NcmRx.h — NTB16 RX parser + bulk-IN continuous reader (Tasks 14-15).
//
// Frames are validated, counted, and snapshotted into the device
// context for IOCTL_T2NCM_GET_STATUS — NOT yet indicated up to NDIS,
// because NdisMiniport.c (Tasks 18-20) doesn't exist yet. This mirrors
// Task 25's rule for the control plane: prove the layer below is
// parsing real device traffic correctly before anything is built on
// top of it that would make a parsing bug harder to isolate.
#pragma once
#include "Driver.h"

// Configures a continuous reader on DeviceContext->BulkInPipe (buffer
// size = the already-negotiated NtbInMaxSize) and starts it. Call only
// after T2NcmUsbActivateDataInterface has switched the data interface
// to alt 1 and populated BulkInPipe — this does not select the
// interface or validate the pipe itself.
//
// Idempotent: a second call while already started is a no-op success,
// matching T2NcmUsbReleaseHardware's tolerance for redundant
// start/stop pairs across PnP/power transitions.
NTSTATUS
T2NcmRxStart(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Stops the continuous reader and waits for in-flight reads to
// complete. Idempotent — safe to call when RX was never started (e.g.
// D0Exit firing before NCM negotiation ever reached UsbReady) or twice
// in a row (surprise-remove followed by an explicit D0Exit).
VOID
T2NcmRxStop(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );
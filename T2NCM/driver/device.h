// SPDX-License-Identifier: GPL-2.0-only
// Device.h — PnP/Power lifecycle (Task 4).

#pragma once

#include "Driver.h"

EVT_WDF_DEVICE_PREPARE_HARDWARE          T2NcmEvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE          T2NcmEvtDeviceReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY                  T2NcmEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT                   T2NcmEvtDeviceD0Exit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT      T2NcmEvtSelfManagedIoInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_SUSPEND   T2NcmEvtSelfManagedIoSuspend;
EVT_WDF_DEVICE_SELF_MANAGED_IO_RESTART   T2NcmEvtSelfManagedIoRestart;
EVT_WDF_IO_QUEUE_IO_STOP                 T2NcmEvtIoStop;

// ----------------------------------------------------------------------
// Explicit state-machine transition helper (Task 4 requirement: "all
// transitions must be explicit"). Every EvtDevice*/EvtSelfManagedIo*
// callback in Device.c goes through this instead of writing
// context->State directly, so illegal transitions (e.g. issuing USB I/O
// after Stopping) are caught in one place rather than scattered checks.
// ----------------------------------------------------------------------
BOOLEAN
T2NcmTrySetState(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ T2NCM_LIFECYCLE_STATE ExpectedCurrent,
    _In_ T2NCM_LIFECYCLE_STATE NewState
    );

// Returns TRUE if USB/NDIS I/O may currently be submitted (i.e. we are
// not in Stopping/Released/Created/Prepared). Every I/O path (RX rearm,
// TX submit, NCM control transfer) must check this under StateLock
// before touching UsbDevice/pipes, per Task 22 ("no callback may access
// freed device context").
BOOLEAN
T2NcmIsIoAllowed(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

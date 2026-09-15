// SPDX-License-Identifier: GPL-2.0-only
// Device.h — miniport-mode WDFDEVICE creation, the lifecycle state
// machine, and the diagnostic IOCTL handlers.
//
// What used to be here and is NOT any more: EvtDevicePrepareHardware,
// EvtDeviceReleaseHardware, EvtDeviceD0Entry, EvtDeviceD0Exit,
// EvtDeviceSelfManagedIo*, and the WDF I/O queue. None of them can
// exist on a WdfDeviceMiniportCreate device — it is not a power policy
// owner, WDF does not own the dispatch table (Driver.c creates the
// driver with WdfDriverInitNoDispatchOverride), and so no PnP, power or
// I/O IRP ever reaches the framework. Their jobs moved to the NDIS
// entry points in NdisMiniport.c and to Power.c. See the
// POWER-MANAGEMENT INVERSION block at the top of Driver.h.

#pragma once

#include "Driver.h"

// Creates the miniport-mode WDFDEVICE over the device objects NDIS hands
// MiniportInitializeEx, attaches T2NCM_DEVICE_CONTEXT to it, and
// initializes the parts of that context that are not hardware-derived
// (locks, quiesce event, packet filter defaults).
//
// FunctionalDeviceObject/NextDeviceObject/PhysicalDeviceObject come from
// NdisMGetDeviceProperty. The framework does not attach the FDO to the
// stack here — NDIS already did that — it only wraps what exists.
NTSTATUS
T2NcmDeviceCreate(
    _In_  WDFDRIVER               Driver,
    _In_  PDEVICE_OBJECT          FunctionalDeviceObject,
    _In_  PDEVICE_OBJECT          NextDeviceObject,
    _In_  PDEVICE_OBJECT          PhysicalDeviceObject,
    _Out_ WDFDEVICE*              Device,
    _Out_ PT2NCM_DEVICE_CONTEXT*  DeviceContext
    );

// ----------------------------------------------------------------------
// Explicit state-machine transition helper. Every caller goes through
// this instead of writing context->State directly, so illegal
// transitions are caught in one place rather than scattered checks.
// ----------------------------------------------------------------------
BOOLEAN
T2NcmTrySetState(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ T2NCM_LIFECYCLE_STATE ExpectedCurrent,
    _In_ T2NCM_LIFECYCLE_STATE NewState
    );

// Returns TRUE if USB I/O may currently be submitted (i.e. the hardware
// is armed and we are not in Stopping/Released/Created/Prepared). This
// is a HARDWARE readiness question, not a data-path one — whether frames
// may flow is DataPathRunning, owned by MiniportPause/MiniportRestart.
// Both have to be true before anything is put on the wire.
BOOLEAN
T2NcmIsIoAllowed(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Fills a T2NCM_STATUS (public.h) from the current device context.
// Reports exactly what the context holds — never a fabricated or
// "assumed" value. Called from the diagnostic control device's
// IRP_MJ_DEVICE_CONTROL dispatch in NdisMiniport.c.
VOID
T2NcmDeviceFillStatus(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_ PT2NCM_STATUS         Status
    );
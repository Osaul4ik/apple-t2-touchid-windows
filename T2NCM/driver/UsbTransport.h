// SPDX-License-Identifier: GPL-2.0-only
// UsbTransport.h — USB configuration, interface/pipe discovery.
//
// Called from NdisMiniport.c (MiniportInitializeEx / MiniportHaltEx) and
// Power.c, NOT from WDF PnP callbacks — this driver has none. The
// WDFDEVICE these functions run against was created with
// WdfDeviceMiniportCreate and is not a power policy owner; see the
// POWER-MANAGEMENT INVERSION block at the top of Driver.h.
//
// The MI_00 "stub role" entry point that used to live here is gone: the
// MI_00 claim is now a separate binary (CtrlStub.c / T2NcmCtrl.sys),
// because an NDIS miniport and a classic KMDF PnP driver cannot share
// one DriverEntry.

#pragma once

#include "Driver.h"

// Creates the WDFUSBDEVICE against the miniport-mode WDFDEVICE and
// selects the single-interface configuration, storing the resulting
// interface handle in the device context. This PDO exposes exactly one
// interface to itself (whatever its real bInterfaceNumber — MI_01 in
// practice), starting on alt 0 with zero endpoints per the descriptor
// dump. No USB I/O is issued here beyond the standard SELECT_CONFIGURATION
// control transfer WDF itself performs.
NTSTATUS
T2NcmUsbPrepareHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Tears down the cached pipe/interface/device handles. Safe to call more
// than once (idempotent) since surprise removal can reach
// MiniportHaltEx from partially-initialized states.
VOID
T2NcmUsbReleaseHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Switches the data interface from alt 0 (idle, 0 endpoints) to alt 1
// (bulk IN/OUT). Only to be called after NCM control-plane negotiation
// succeeds. Re-validates both bulk pipes after the switch and unwinds
// back to alt 0 on any failure.
NTSTATUS
T2NcmUsbActivateDataInterface(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Switches the data interface back to alt 0 and drops the cached bulk
// pipe handles. Used when quiescing for a low-power state (Power.c) and
// on halt. Idempotent; a no-op when the interface was never activated.
// Callers must have stopped the RX engine and drained outstanding sends
// first — this does not do it for them.
VOID
T2NcmUsbDeactivateDataInterface(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );
// SPDX-License-Identifier: GPL-2.0-only
// UsbTransport.h — USB configuration, interface/pipe discovery (Tasks 5-6).
//
// Two prepare-hardware entry points, one per role (Driver.h/g_T2NcmStubRole):
// T2NcmUsbPrepareHardware for the full/MI_01 instance, T2NcmUsbPrepareHardwareStub
// for the MI_00 stub instance. Device.c picks which one to call.

#pragma once

#include "Driver.h"

// Called from EvtDevicePrepareHardware (full/MI_01 role only). Creates the
// WDFUSBDEVICE, selects the single-interface configuration, and stores
// the resulting interface handle in the device context. This PDO exposes
// exactly one interface to itself (whatever its real bInterfaceNumber —
// MI_01 in practice), starting on alt 0 with zero endpoints per the
// descriptor dump. No USB I/O is issued here beyond the standard
// SELECT_CONFIGURATION control transfer WDF itself performs (Task 6:
// "No USB I/O should happen before configuration succeeds").
NTSTATUS
T2NcmUsbPrepareHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Called from EvtDevicePrepareHardware (MI_00 stub role only). Creates
// the WDFUSBDEVICE and selects the single-interface configuration —
// nothing else. No pipe discovery, no control-plane negotiation: this
// exists purely so MI_00 has a working driver bound to it (Code 28/31
// avoidance), not to do any NCM function. Deliberately does not touch
// DeviceContext->DataInterface/BulkIn/OutPipe.
NTSTATUS
T2NcmUsbPrepareHardwareStub(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Called from EvtDeviceReleaseHardware (both roles). Tears down pipe/
// interface/device handles. Safe to call more than once (idempotent)
// since surprise removal can invoke ReleaseHardware from
// partially-initialized states, and safe on the stub role where these
// fields were never set in the first place.
VOID
T2NcmUsbReleaseHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Switches the data interface from alt 0 (idle, 0 endpoints) to alt 1
// (bulk IN/OUT), per Task 12. Only to be called after NCM control-plane
// negotiation (Tasks 7-11) succeeds, and only in the full/MI_01 role.
// Re-validates both bulk pipes after the switch and unwinds back to
// alt 0 on any failure.
NTSTATUS
T2NcmUsbActivateDataInterface(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );
// SPDX-License-Identifier: GPL-2.0-only
// UsbTransport.h — USB configuration, interface/pipe discovery (Tasks 5-6).

#pragma once

#include "Driver.h"

// Called from EvtDevicePrepareHardware. Creates the WDFUSBDEVICE, selects
// configuration 1, discovers MI_00 (control, interrupt IN) and MI_01
// (data, starts on alt 0 with zero endpoints per the descriptor dump),
// and stores pipe handles in the device context. No USB I/O is issued
// here beyond the standard SELECT_CONFIGURATION/SELECT_INTERFACE control
// transfers WDF itself performs (Task 6: "No USB I/O should happen
// before configuration succeeds").
NTSTATUS
T2NcmUsbPrepareHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Called from EvtDeviceReleaseHardware. Tears down pipe/interface/device
// handles. Safe to call more than once (idempotent) since surprise
// removal can invoke ReleaseHardware from partially-initialized states.
VOID
T2NcmUsbReleaseHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Switches MI_01 from alt 0 (idle, 0 endpoints) to alt 1 (bulk IN/OUT),
// per Task 12. Only to be called after NCM control-plane negotiation
// (Tasks 7-11) succeeds. Re-validates both bulk pipes after the switch
// and unwinds back to alt 0 on any failure.
NTSTATUS
T2NcmUsbActivateDataInterface(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

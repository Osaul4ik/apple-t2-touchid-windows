// SPDX-License-Identifier: GPL-2.0-only
// NdisMiniport.h — every NDIS entry point this driver exposes.
//
// This file is the top of the driver now. Under the inverted model
// (Driver.h) NDIS owns PnP and power, so the callbacks declared in
// NdisMiniport.c are the only places the driver is ever entered from
// the system: there is no EvtDeviceAdd, no D0Entry, no D0Exit and no
// WDF I/O queue anywhere in T2Ncm.sys.
//
// Mapping from the pre-inversion KMDF design, for anyone reading the
// git history:
//
//   EvtDevicePrepareHardware + EvtDeviceD0Entry  -> MiniportInitializeEx
//   EvtDeviceD0Entry's "start RX"                -> MiniportRestart
//   EvtDeviceD0Exit's "stop RX"                  -> MiniportPause
//   EvtDeviceD0Exit's "go to Dx"                 -> OID_PNP_SET_POWER (Power.c)
//   EvtDeviceReleaseHardware                     -> MiniportHaltEx
//   EvtDeviceSelfManagedIo*                      -> (nothing; NDIS covers it)
//   WdfDeviceCreateDeviceInterface + IO queue    -> NdisMRegisterDeviceEx
#pragma once
#include "Driver.h"

// Called once from DriverEntry, after WdfDriverCreate. Fills in the
// NDIS_MINIPORT_DRIVER_CHARACTERISTICS and registers them.
NDIS_STATUS
T2NcmNdisRegisterDriver(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

// Signals the quiesce event if a pause is in progress and both drain
// counters have reached zero. Called from every place that decrements
// one of them (RX return, TX completion) — see MiniportPause for why
// the wait is written the way it is.
VOID
T2NcmQuiesceCheck(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );
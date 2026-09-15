// SPDX-License-Identifier: GPL-2.0-only
// Power.h — the D-state half of the inverted power model.
//
// There are no WDF D0Entry/D0Exit callbacks in this driver. A WDFDEVICE
// created with WdfDeviceMiniportCreate is not a power policy owner and
// gets no PnP/power callbacks at all; NDIS is the power policy owner for
// the adapter. Every device power transition therefore arrives here, and
// only here, as OID_PNP_SET_POWER from NdisMiniport.c's OID handler.
//
// Ordering guaranteed by NDIS (this is what the driver is allowed to
// rely on, and why none of the functions below touch the data path
// start/stop flags themselves):
//
//   going down:   MiniportPause  -> OID_PNP_SET_POWER(Dx)
//   coming up:    OID_PNP_SET_POWER(D0) -> MiniportRestart
//
// So by the time T2NcmPowerSetDeviceState sees a Dx, the RX engine is
// already stopped and all indications/sends are already drained by
// MiniportPause. And when it sees D0, it must leave the data path
// stopped — MiniportRestart is what starts it, a moment later.
//
// That split is the inversion in one sentence: power code moves the
// *hardware* between states, NDIS moves the *data path*.
#pragma once
#include "Driver.h"

// Handles an OID_PNP_SET_POWER set request. NdisDeviceStateD0 re-arms
// the hardware (re-negotiates the NCM control plane and puts MI_01 back
// on alt 1 if it was parked); anything else quiesces it (parks MI_01 on
// alt 0, its zero-endpoint idle setting, so the device is not asked to
// hold bulk endpoints open across a suspend).
//
// Never fails the transition for a hardware reason. A miniport that
// fails OID_PNP_SET_POWER blocks the system power transition, which is
// a far worse outcome than an adapter that comes back with no link;
// failures are logged, the lifecycle state is left honest (it falls
// back to UsbReady rather than claiming NcmReady), and NDIS is told the
// power transition succeeded.
NDIS_STATUS
T2NcmPowerSetDeviceState(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ NDIS_DEVICE_POWER_STATE NewState
    );

// Handles OID_PNP_QUERY_POWER. Always succeeds: this adapter has no
// pending work it could not abandon and no wake capability to protect,
// so there is never a reason to veto a proposed transition.
NDIS_STATUS
T2NcmPowerQueryDeviceState(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ NDIS_DEVICE_POWER_STATE ProposedState
    );

// Brings the NCM control plane up and activates MI_01's alt 1. Shared by
// MiniportInitializeEx (first bring-up) and T2NcmPowerSetDeviceState(D0)
// (resume) so that there is exactly ONE implementation of "make the
// hardware ready", rather than the pre-inversion arrangement where
// D0Entry held a copy of the bring-up sequence that initialization then
// had to stay in sync with.
//
// Does NOT start the RX engine and does NOT touch DataPathRunning.
NTSTATUS
T2NcmPowerArmHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Parks MI_01 on alt 0. Assumes the caller has already ensured the data
// path is stopped (MiniportPause, or MiniportHaltEx). Idempotent and
// safe to call when the interface was never activated.
VOID
T2NcmPowerQuiesceHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );
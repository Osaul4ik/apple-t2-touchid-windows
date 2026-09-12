// SPDX-License-Identifier: GPL-2.0-only
// Driver.h
// T2Ncm.sys — KMDF+NDIS6 USB CDC-NCM function driver for the Apple T2.
//
// Real hardware showed MI_00 (NCM Control) and MI_01 (NCM Data) enumerate
// as TWO INDEPENDENT PDOs under usbccgp (no Interface Association
// Descriptor grouping them) — WdfUsbTargetDeviceGetInterface(UsbDevice, 1)
// returned NULL from a WDFUSBDEVICE created against MI_00's own PDO,
// confirming a single WDFUSBDEVICE object can never see both interfaces.
// The original "one driver instance spans both interfaces" design
// (docs/T2Ncm-Architecture.md) doesn't work as written. Fix ("Variant 1"):
// this SAME .sys binary loads under TWO different service names, gated by
// g_T2NcmStubRole (set in DriverEntry from RegistryPath):
//   - "T2Ncm"         binds MI_01 (NCM Data) — full NCM function: control-
//                      plane negotiation (NcmProtocol.c; class requests are
//                      addressed by wIndex over the shared EP0, so they
//                      don't need MI_00's own interface object), bulk I/O,
//                      eventual NDIS miniport.
//   - "T2NcmCtrlStub" binds MI_00 (NCM Control) — does nothing but claim
//                      the PDO and handle PnP/power cleanly, so Windows
//                      doesn't show it as an unclaimed Code-28/31 device
//                      and it doesn't block system sleep. MI_00's
//                      interrupt-notification pipe (0x81) is not read by
//                      either role in this milestone — dropped as part of
//                      this fix, not yet reinstated.
//
// Module layout (Task 1/2):
//   Driver.c        DriverEntry / WDF driver object / role detection
//   Device.c        PnP/Power callbacks, lifecycle state machine (Task 4),
//                    diagnostic IOCTL_T2NCM_GET_STATUS (Task 25, public.h,
//                    full role only)
//   UsbTransport.c  USB target/pipe/descriptor discovery (Tasks 5-6, 12)
//   NcmProtocol.c   NCM control-plane (GET_NTB_PARAMETERS, format neg.) (Tasks 7-11)
//   NcmRx.c         NTB16 RX parser + bulk-IN engine (Tasks 14-15)
//   NcmTx.c         NTB16 TX builder + bulk-OUT engine (Tasks 13,16)
//   NdisMiniport.c  NDIS 6 miniport entry points (Tasks 18-20)
//   Power.c         D0Entry/D0Exit orchestration (Task 21)

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>
#include <usb.h>
#include <usbdlib.h>
#include <wdfusb.h>

// ndis.h itself uses nameless struct/union extensions and trips C4201 at
// /W4; with /WX that becomes a hard error (C2220) even though we didn't
// write the offending code. This is Microsoft's own header, not ours —
// scope the suppression tightly to just this include rather than
// disabling C4201 project-wide.
#pragma warning(push)
#pragma warning(disable: 4201)
#include <ndis.h>
#pragma warning(pop)

#include "public.h"

// ---- Logging ----
// Reuses the T2TouchIdTransport convention (see driver/T2TouchIdTransport/driver.h):
// DbgPrintEx, not KdPrintEx, because KdPrintEx compiles to nothing when
// DBG=0 (Release), and this driver ships test-signed Release builds.
#define T2NCM_LOG(_x_) DbgPrintEx _x_
#define T2NCM_DPFLTR_ID DPFLTR_IHVDRIVER_ID

// ---- Device identity (VERIFIED FROM SOURCE: USBPcap descriptor dump) ----
#define T2NCM_VID           0x05ACu
#define T2NCM_PID           0x8233u
#define T2NCM_REV           0x0201u

// ---- Interface roles ----
// T2NCM_CONTROL_IFACE_NUM is only ever used as a wIndex value in
// NcmProtocol.c's SETUP packets — control transfers addressed by
// interface number go over the shared EP0 regardless of which PDO this
// driver instance is actually bound to, so it does NOT require owning
// MI_00's own WDFUSBINTERFACE object (see Driver.h's top comment).
#define T2NCM_CONTROL_IFACE_NUM   0   // MI_00 — addressed by wIndex only
#define T2NCM_DATA_IFACE_NUM      1   // MI_01 — this driver's real bInterfaceNumber
#define T2NCM_DATA_ALT_IDLE       0   // Alt 0 — 0 endpoints
#define T2NCM_DATA_ALT_ACTIVE     1   // Alt 1 — bulk IN/OUT

// ---- Expected endpoint addresses (VERIFIED FROM SOURCE, discovered
// dynamically per Task 5 — these are cross-checks, not hard-coded truth) ----
#define T2NCM_EXPECTED_BULK_IN_EP   0x82u
#define T2NCM_EXPECTED_BULK_OUT_EP  0x01u

// ---- CDC/NCM class constants ----
#define T2NCM_CLASS_CDC_CONTROL     0x02u
#define T2NCM_SUBCLASS_NCM          0x0Du
#define T2NCM_CLASS_CDC_DATA        0x0Au

// ---- Pool tag (NcmProtocol.c string-descriptor reads) ----
#define T2NCM_POOL_TAG              ((ULONG)'TNcm')

// ---- Lifecycle states (Task 4) ----
// All transitions are explicit — see Device.c T2NcmSetState().
typedef enum _T2NCM_LIFECYCLE_STATE
{
    T2NcmStateCreated = 0,
    T2NcmStatePrepared,
    T2NcmStateUsbReady,
    T2NcmStateNcmReady,
    T2NcmStateNdisRegistered,
    T2NcmStateRunning,
    T2NcmStateStopping,
    T2NcmStateReleased,
} T2NCM_LIFECYCLE_STATE;

// ---- Device context ----
typedef struct _T2NCM_DEVICE_CONTEXT
{
    WDFDEVICE           WdfDevice;
    WDFUSBDEVICE        UsbDevice;
    WDFUSBINTERFACE     DataInterface;      // this PDO's own interface (MI_01 in full role)

    WDFUSBPIPE          BulkInPipe;         // 0x82 (alt 1)
    WDFUSBPIPE          BulkOutPipe;        // 0x01 (alt 1)

    T2NCM_LIFECYCLE_STATE State;
    WDFSPINLOCK          StateLock;

    UCHAR                PermanentMacAddress[6];
    BOOLEAN              MacAddressValid;

    NDIS_HANDLE          NdisMiniportHandle;
    NDIS_HANDLE          NdisMiniportAdapterHandle;

    // Populated by NcmProtocol.c after GET_NTB_PARAMETERS (Task 9)
    BOOLEAN              Ntb16Supported;
    ULONG                NtbInMaxSize;
    ULONG                NtbOutMaxSize;

} T2NCM_DEVICE_CONTEXT, *PT2NCM_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T2NCM_DEVICE_CONTEXT, T2NcmGetDeviceContext)

// Set once in DriverEntry (Driver.c) from RegistryPath — TRUE for the
// "T2NcmCtrlStub" service (MI_00), FALSE for "T2Ncm" (MI_01, full
// function). Each service name loads this binary as its own independent
// driver-object image instance, so this global never gets shared or
// raced between the two roles even when both are loaded at once.
extern BOOLEAN g_T2NcmStubRole;

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD T2NcmEvtDeviceAdd;
// SPDX-License-Identifier: GPL-2.0-only
// Driver.h
// T2Ncm.sys — KMDF+NDIS6 USB CDC-NCM function driver for the Apple T2
// NCM control interface (MI_00), driving the paired data interface
// (MI_01) directly. Replaces the failed inbox-UsbNcm.sys rebind attempt
// documented in docs/T2Ncm-Architecture.md.
//
// Module layout (Task 1/2):
//   Driver.c        DriverEntry / WDF driver object
//   Device.c        PnP/Power callbacks, lifecycle state machine (Task 4)
//   UsbTransport.c  USB target/pipe/descriptor discovery (Tasks 5-6)
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
#include <ndis.h>

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
#define T2NCM_CONTROL_IFACE_NUM   0   // MI_00
#define T2NCM_DATA_IFACE_NUM      1   // MI_01
#define T2NCM_DATA_ALT_IDLE       0   // MI_01 Alt 0 — 0 endpoints
#define T2NCM_DATA_ALT_ACTIVE     1   // MI_01 Alt 1 — bulk IN/OUT

// ---- Expected endpoint addresses (VERIFIED FROM SOURCE, discovered
// dynamically per Task 5 — these are cross-checks, not hard-coded truth) ----
#define T2NCM_EXPECTED_INT_IN_EP    0x81u
#define T2NCM_EXPECTED_BULK_IN_EP   0x82u
#define T2NCM_EXPECTED_BULK_OUT_EP  0x01u

// ---- CDC/NCM class constants ----
#define T2NCM_CLASS_CDC_CONTROL     0x02u
#define T2NCM_SUBCLASS_NCM          0x0Du
#define T2NCM_CLASS_CDC_DATA        0x0Au

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
    WDFUSBINTERFACE     ControlInterface;   // MI_00
    WDFUSBINTERFACE     DataInterface;      // MI_01

    WDFUSBPIPE          InterruptInPipe;    // 0x81 (MI_00)
    WDFUSBPIPE          BulkInPipe;         // 0x82 (MI_01 alt 1)
    WDFUSBPIPE          BulkOutPipe;        // 0x01 (MI_01 alt 1)

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

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD T2NcmEvtDeviceAdd;

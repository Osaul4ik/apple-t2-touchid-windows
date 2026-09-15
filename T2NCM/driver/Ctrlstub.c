// SPDX-License-Identifier: GPL-2.0-only
// CtrlStub.c — T2NcmCtrl.sys, a SEPARATE binary from T2Ncm.sys.
//
// Claims MI_00 (the Apple T2's CDC-NCM control interface) and does
// nothing else: no NCM negotiation, no endpoints read, no I/O surface.
// It exists so MI_00 is not left as an unclaimed device (Device Manager
// Code 28/31) and so it participates in PnP and power like any other
// device rather than sitting there un-power-managed.
//
// WHY THIS IS ITS OWN BINARY (it used to be a role inside T2Ncm.sys,
// selected by reading RegistryPath in DriverEntry):
//
// T2Ncm.sys is now an NDIS miniport whose DriverEntry must call
// WdfDriverCreate with WdfDriverInitNoDispatchOverride and then hand the
// driver object to NDIS. This stub is the opposite: a classic KMDF
// function driver that has to OWN its dispatch table so it can receive
// PnP and power IRPs for MI_00. One DriverEntry cannot be both, and a
// DriverEntry that picked between them by service name would still be a
// single image with a single entry point shared by two service entries —
// which is exactly the kind of thing that works until it doesn't.
//
// Two source files, two projects, two .sys files, two INFs, no shared
// mutable globals. The cost is one extra 20 KB binary.
//
// NOTE ON POWER: this driver is a normal power policy owner for MI_00,
// unlike T2Ncm.sys where NDIS owns power. That is correct and not an
// inconsistency — MI_00 is not a network adapter, it is just a USB
// interface that needs an owner. Its D0Entry/D0Exit are deliberately
// empty and never block, so the stub can never be the reason a system
// suspend is delayed.

#include <ntddk.h>
#include <wdf.h>
#include <usb.h>
#include <usbdlib.h>
#include <wdfusb.h>

#define T2NCMCTRL_LOG(_x_) DbgPrintEx _x_
#define T2NCMCTRL_DPFLTR_ID DPFLTR_IHVDRIVER_ID

typedef struct _T2NCMCTRL_CONTEXT
{
    WDFUSBDEVICE UsbDevice;
} T2NCMCTRL_CONTEXT, *PT2NCMCTRL_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T2NCMCTRL_CONTEXT, T2NcmCtrlGetContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD T2NcmCtrlEvtDeviceAdd;
EVT_WDF_DEVICE_PREPARE_HARDWARE T2NcmCtrlEvtDevicePrepareHardware;
EVT_WDF_DEVICE_D0_ENTRY T2NcmCtrlEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT T2NcmCtrlEvtDeviceD0Exit;

NTSTATUS
T2NcmCtrlEvtDevicePrepareHardware(
    _In_ WDFDEVICE    Device,
    _In_ WDFCMRESLIST ResourcesRaw,
    _In_ WDFCMRESLIST ResourcesTranslated
    )
{
    NTSTATUS status;
    PT2NCMCTRL_CONTEXT context = T2NcmCtrlGetContext(Device);
    WDF_USB_DEVICE_CREATE_CONFIG createConfig;
    WDF_USB_DEVICE_SELECT_CONFIG_PARAMS configParams;

    UNREFERENCED_PARAMETER(ResourcesRaw);
    UNREFERENCED_PARAMETER(ResourcesTranslated);

    WDF_USB_DEVICE_CREATE_CONFIG_INIT(&createConfig, USBD_CLIENT_CONTRACT_VERSION_602);

    status = WdfUsbTargetDeviceCreateWithParameters(
        Device, &createConfig, WDF_NO_OBJECT_ATTRIBUTES, &context->UsbDevice);
    if (!NT_SUCCESS(status))
    {
        T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2NcmCtrl: WdfUsbTargetDeviceCreateWithParameters failed 0x%08X\n",
            status));
        return status;
    }

    // MI_00 has exactly one interface with one alt setting — claim it and
    // stop. The interrupt notification endpoint (0x81) is deliberately
    // not read: nothing consumes NCM notifications yet, and opening a
    // pipe this driver would never service would be worse than leaving
    // it alone.
    WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_INIT_SINGLE_INTERFACE(&configParams);

    status = WdfUsbTargetDeviceSelectConfig(
        context->UsbDevice, WDF_NO_OBJECT_ATTRIBUTES, &configParams);
    if (!NT_SUCCESS(status))
    {
        T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2NcmCtrl: WdfUsbTargetDeviceSelectConfig failed 0x%08X\n", status));
        return status;
    }

    T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2NcmCtrl: MI_00 claimed and idle\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmCtrlEvtDeviceD0Entry(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
    )
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(PreviousState);
    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmCtrlEvtDeviceD0Exit(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
    )
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(TargetState);
    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmCtrlEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDFDEVICE device;

    UNREFERENCED_PARAMETER(Driver);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDevicePrepareHardware = T2NcmCtrlEvtDevicePrepareHardware;
    pnpPowerCallbacks.EvtDeviceD0Entry         = T2NcmCtrlEvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit          = T2NcmCtrlEvtDeviceD0Exit;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, T2NCMCTRL_CONTEXT);

    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status))
    {
        T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2NcmCtrl: WdfDeviceCreate failed 0x%08X\n", status));
        return status;
    }

    // No device interface and no I/O queue on purpose: this driver has
    // no surface anyone should be able to open.
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;

    T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2NcmCtrl: DriverEntry\n"));

    WDF_DRIVER_CONFIG_INIT(&config, T2NcmCtrlEvtDeviceAdd);

    return WdfDriverCreate(
        DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}
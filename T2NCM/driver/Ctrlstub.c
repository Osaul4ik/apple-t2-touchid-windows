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
    WDFUSBINTERFACE ControlInterface;
    WDFUSBPIPE   NotificationPipe;   // EP 0x81, interrupt IN
} T2NCMCTRL_CONTEXT, *PT2NCMCTRL_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T2NCMCTRL_CONTEXT, T2NcmCtrlGetContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD T2NcmCtrlEvtDeviceAdd;
EVT_WDF_DEVICE_PREPARE_HARDWARE T2NcmCtrlEvtDevicePrepareHardware;
EVT_WDF_DEVICE_D0_ENTRY T2NcmCtrlEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT T2NcmCtrlEvtDeviceD0Exit;


// ---------------------------------------------------------------------
// Notification endpoint (EP 0x81, interrupt IN)
//
// CHANGED: this used to be left alone on the grounds that nothing
// consumes NCM notifications. That reasoning was wrong in one important
// way - the device does not know nobody is listening. A CDC function
// that has a NETWORK_CONNECTION or CONNECTION_SPEED_CHANGE notification
// queued and no host reading its interrupt endpoint can sit on it, and
// some implementations gate the data path behind having delivered it.
// Draining the endpoint costs one standing read and removes that as a
// possible reason for a silent receive path.
//
// The notifications themselves are still not acted on: link state for
// this adapter is "the USB interface is configured" (see the
// MediaConnectState comment in T2Ncm.sys's NdisMiniport.c), and
// inventing a link-state policy from notifications this driver has
// never actually observed would be guessing. They are logged and
// discarded.
// ---------------------------------------------------------------------
#define T2NCMCTRL_NOTIFY_BUFFER_SIZE 64u

EVT_WDF_USB_READER_COMPLETION_ROUTINE T2NcmCtrlEvtNotificationRead;

VOID
T2NcmCtrlEvtNotificationRead(
    _In_ WDFUSBPIPE Pipe,
    _In_ WDFMEMORY  Buffer,
    _In_ size_t     NumBytesTransferred,
    _In_ WDFCONTEXT Context
    )
{
    const UCHAR* bytes;

    UNREFERENCED_PARAMETER(Pipe);
    UNREFERENCED_PARAMETER(Context);

    if (NumBytesTransferred < 2)
    {
        return;
    }

    bytes = (const UCHAR*)WdfMemoryGetBuffer(Buffer, NULL);
    if (bytes == NULL)
    {
        return;
    }

    // bmRequestType, bNotificationCode - enough to identify which
    // notification arrived without pretending to decode a payload this
    // driver has no confirmed layout for.
    T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2NcmCtrl: notification bmRequestType=0x%02X code=0x%02X len=%Iu "
        "(drained, not acted on)\n",
        bytes[0], bytes[1], NumBytesTransferred));
}

EVT_WDF_USB_READERS_FAILED T2NcmCtrlEvtNotificationFailed;

BOOLEAN
T2NcmCtrlEvtNotificationFailed(
    _In_ WDFUSBPIPE  Pipe,
    _In_ NTSTATUS    Status,
    _In_ USBD_STATUS UsbdStatus
    )
{
    UNREFERENCED_PARAMETER(Pipe);

    T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
        "T2NcmCtrl: notification reader stopped (status=0x%08X usbd=0x%08X)\n",
        Status, UsbdStatus));

    // FALSE: do not let the framework reset the pipe and retry forever
    // on a device that has gone away. Same reasoning as T2Ncm.sys's
    // bulk-IN reader.
    return FALSE;
}

static
VOID
T2NcmCtrlStartNotificationReader(
    _In_ WDFDEVICE Device
    )
{
    PT2NCMCTRL_CONTEXT context = T2NcmCtrlGetContext(Device);
    WDF_USB_CONTINUOUS_READER_CONFIG readerConfig;
    UCHAR count;
    UCHAR i;
    NTSTATUS status;

    if (context->ControlInterface == NULL)
    {
        return;
    }

    count = WdfUsbInterfaceGetNumConfiguredPipes(context->ControlInterface);

    for (i = 0; i < count; i++)
    {
        WDF_USB_PIPE_INFORMATION pipeInfo;
        WDFUSBPIPE pipe;

        WDF_USB_PIPE_INFORMATION_INIT(&pipeInfo);
        pipe = WdfUsbInterfaceGetConfiguredPipe(context->ControlInterface, i, &pipeInfo);
        if (pipe == NULL)
        {
            continue;
        }

        if (WdfUsbPipeTypeInterrupt == pipeInfo.PipeType &&
            WdfUsbTargetPipeIsInEndpoint(pipe))
        {
            context->NotificationPipe = pipe;
            break;
        }
    }

    if (context->NotificationPipe == NULL)
    {
        // Not an error worth failing start over - MI_00 without an
        // interrupt endpoint just means there is nothing to drain.
        T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2NcmCtrl: no interrupt IN endpoint on MI_00\n"));
        return;
    }

    WDF_USB_CONTINUOUS_READER_CONFIG_INIT(
        &readerConfig,
        T2NcmCtrlEvtNotificationRead,
        context,
        T2NCMCTRL_NOTIFY_BUFFER_SIZE);
    readerConfig.EvtUsbTargetPipeReadersFailed = T2NcmCtrlEvtNotificationFailed;
    readerConfig.NumPendingReads = 2;

    status = WdfUsbTargetPipeConfigContinuousReader(
        context->NotificationPipe, &readerConfig);
    if (!NT_SUCCESS(status))
    {
        T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2NcmCtrl: WdfUsbTargetPipeConfigContinuousReader failed 0x%08X\n",
            status));
        context->NotificationPipe = NULL;
        return;
    }

    status = WdfIoTargetStart(
        WdfUsbTargetPipeGetIoTarget(context->NotificationPipe));
    if (!NT_SUCCESS(status))
    {
        T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2NcmCtrl: WdfIoTargetStart (notification) failed 0x%08X\n",
            status));
        return;
    }

    T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2NcmCtrl: notification reader started on MI_00\n"));
}

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

    // EvtDevicePrepareHardware runs again if PnP stops and restarts this
    // device (resource rebalance, driver update). The WDFUSBDEVICE is a
    // child of the WDFDEVICE and survives that, so it is created only the
    // first time - a second create would leak/duplicate the USB target.
    // SelectConfig below IS repeated on every start: the USB stack may
    // reconfigure the device, which hands back new interface/pipe objects,
    // so the pipe cached from the previous start is dropped here.
    context->NotificationPipe = NULL;
    context->ControlInterface = NULL;

    if (context->UsbDevice == NULL)
    {
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
    }

    // MI_00 has exactly one interface with one alt setting.
    WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_INIT_SINGLE_INTERFACE(&configParams);

    status = WdfUsbTargetDeviceSelectConfig(
        context->UsbDevice, WDF_NO_OBJECT_ATTRIBUTES, &configParams);
    if (!NT_SUCCESS(status))
    {
        T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2NcmCtrl: WdfUsbTargetDeviceSelectConfig failed 0x%08X\n", status));
        return status;
    }

    context->ControlInterface = configParams.Types.SingleInterface.ConfiguredUsbInterface;

    // Drain the notification endpoint - see the comment block above.
    T2NcmCtrlStartNotificationReader(Device);

    T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2NcmCtrl: MI_00 claimed\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmCtrlEvtDeviceD0Entry(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
    )
{
    PT2NCMCTRL_CONTEXT context = T2NcmCtrlGetContext(Device);

    UNREFERENCED_PARAMETER(PreviousState);

    // WDF stops power-managed USB pipe targets on D0Exit, so the
    // notification reader has to be restarted here. Deliberately never
    // fails the power transition over it: draining notifications is a
    // precaution, not a requirement, and blocking a resume for it would
    // be a worse bug than the one it guards against.
    if (context->NotificationPipe != NULL)
    {
        NTSTATUS status = WdfIoTargetStart(
            WdfUsbTargetPipeGetIoTarget(context->NotificationPipe));
        if (!NT_SUCCESS(status))
        {
            T2NCMCTRL_LOG((T2NCMCTRL_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2NcmCtrl: restarting notification reader failed 0x%08X\n",
                status));
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmCtrlEvtDeviceD0Exit(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
    )
{
    PT2NCMCTRL_CONTEXT context = T2NcmCtrlGetContext(Device);

    UNREFERENCED_PARAMETER(TargetState);

    if (context->NotificationPipe != NULL)
    {
        WdfIoTargetStop(
            WdfUsbTargetPipeGetIoTarget(context->NotificationPipe),
            WdfIoTargetCancelSentIo);
    }

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
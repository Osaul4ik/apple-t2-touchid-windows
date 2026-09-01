// SPDX-License-Identifier: GPL-2.0-only
// UsbTransport.c
//
// Task 5/6: descriptor-driven discovery. Endpoint addresses are never
// assumed — T2NCM_EXPECTED_*_EP in Driver.h are cross-checks logged on
// mismatch, not the discovery mechanism itself. This lets the same
// driver bind a T2 revision whose endpoint addresses differ without a
// code change, per Task 5's explicit requirement.

#include "UsbTransport.h"

static
NTSTATUS
T2NcmFindPipeByDirectionAndType(
    _In_  WDFUSBINTERFACE  UsbInterface,
    _In_  UCHAR            SettingIndex,
    _In_  WDF_USB_PIPE_TYPE ExpectedType,
    _In_  BOOLEAN          WantIn,
    _Out_ WDFUSBPIPE*      Pipe
    )
{
    UCHAR pipeCount = WdfUsbInterfaceGetNumConfiguredPipes(UsbInterface, SettingIndex);

    for (UCHAR i = 0; i < pipeCount; i++)
    {
        WDF_USB_PIPE_INFORMATION pipeInfo;
        WDF_USB_PIPE_INFORMATION_INIT(&pipeInfo);

        WDFUSBPIPE candidate = WdfUsbInterfaceGetConfiguredPipe(
            UsbInterface, SettingIndex, i, &pipeInfo);

        if (candidate == NULL)
        {
            continue;
        }

        BOOLEAN isIn = WDF_USB_PIPE_TYPE_ISOCHRONOUS != pipeInfo.PipeType &&
                        WdfUsbTargetPipeIsInEndpoint(candidate);

        if (pipeInfo.PipeType == ExpectedType && isIn == WantIn)
        {
            *Pipe = candidate;
            return STATUS_SUCCESS;
        }
    }

    *Pipe = NULL;
    return STATUS_NOT_FOUND;
}

NTSTATUS
T2NcmUsbPrepareHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    NTSTATUS status;
    WDF_USB_DEVICE_CREATE_CONFIG createConfig;
    WDF_USB_DEVICE_SELECT_CONFIG_PARAMS configParams;
    WDFUSBPIPE pipe;

    WDF_USB_DEVICE_CREATE_CONFIG_INIT(&createConfig, USBD_CLIENT_CONTRACT_VERSION_602);

    status = WdfUsbTargetDeviceCreateWithParameters(
        DeviceContext->WdfDevice,
        &createConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &DeviceContext->UsbDevice);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfUsbTargetDeviceCreateWithParameters failed 0x%08X\n", status));
        return status;
    }

    // Task 6: select configuration 1 with BOTH interfaces (MI_00 default
    // setting, MI_01 explicitly on alt 0 — "idle" — until NCM negotiation
    // completes and Task 12 switches it to alt 1). Do NOT assume a
    // pre-existing UsbNcm configuration is already selected.
    WDF_USB_INTERFACE_SETTING_PAIR settingPairs[2];
    settingPairs[0].SettingIndex = 0; // MI_00 has only one setting
    settingPairs[1].SettingIndex = T2NCM_DATA_ALT_IDLE;

    WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_INIT_MULTIPLE_INTERFACES(
        &configParams, 2, settingPairs);

    status = WdfUsbTargetDeviceSelectConfig(
        DeviceContext->UsbDevice, WDF_NO_OBJECT_ATTRIBUTES, &configParams);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfUsbTargetDeviceSelectConfig failed 0x%08X\n", status));
        return status;
    }

    if (configParams.Types.MultiInterface.NumberOfInterfaces != 2)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: expected 2 interfaces, got %u\n",
            configParams.Types.MultiInterface.NumberOfInterfaces));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    DeviceContext->ControlInterface =
        configParams.Types.MultiInterface.Pairs[0].UsbInterface;
    DeviceContext->DataInterface =
        configParams.Types.MultiInterface.Pairs[1].UsbInterface;

    // Task 5: discover the interrupt IN pipe on MI_00 dynamically.
    status = T2NcmFindPipeByDirectionAndType(
        DeviceContext->ControlInterface, 0, WdfUsbPipeTypeInterrupt, TRUE, &pipe);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: MI_00 interrupt IN pipe not found: 0x%08X\n", status));
        return status;
    }
    DeviceContext->InterruptInPipe = pipe;

    {
        WDF_USB_PIPE_INFORMATION info;
        WDF_USB_PIPE_INFORMATION_INIT(&info);
        WdfUsbTargetPipeGetInformation(pipe, &info);
        if (info.EndpointAddress != T2NCM_EXPECTED_INT_IN_EP)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: MI_00 interrupt EP is 0x%02X, not the 0x%02X seen on the "
                "reference revision — continuing, discovery is authoritative\n",
                info.EndpointAddress, T2NCM_EXPECTED_INT_IN_EP));
        }
    }

    // MI_01 alt 0 has zero endpoints by design (idle state) — bulk pipes
    // are only enumerated after Task 12 switches to alt 1. Nothing more
    // to discover here yet.

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: USB configuration selected, MI_00/MI_01 interfaces bound\n"));

    return STATUS_SUCCESS;
}

VOID
T2NcmUsbReleaseHardware(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    // WDFUSBDEVICE and its child interface/pipe objects are parented to
    // WdfDevice and are torn down by the framework on device removal;
    // this function exists as the single place that clears the cached
    // handles so no later callback can dereference a stale pipe object
    // (Task 22).
    DeviceContext->InterruptInPipe = NULL;
    DeviceContext->BulkInPipe = NULL;
    DeviceContext->BulkOutPipe = NULL;
    DeviceContext->ControlInterface = NULL;
    DeviceContext->DataInterface = NULL;
    DeviceContext->UsbDevice = NULL;
}

NTSTATUS
T2NcmUsbActivateDataInterface(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    // Task 12 — implemented once NCM control-plane negotiation (Tasks
    // 7-11, NcmProtocol.c) exists to gate this call. Left as an explicit
    // not-implemented status rather than a silent stub so the Task 25
    // diagnostic IOCTL reports real state, not a fabricated success.
    UNREFERENCED_PARAMETER(DeviceContext);
    return STATUS_NOT_IMPLEMENTED;
}

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
    _In_  WDF_USB_PIPE_TYPE ExpectedType,
    _In_  BOOLEAN          WantIn,
    _Out_ WDFUSBPIPE*      Pipe
    )
{
    // KMDF 1.15's WdfUsbInterfaceGetNumConfiguredPipes/GetConfiguredPipe
    // don't take an alternate-setting parameter at all — they report
    // pipes for whichever setting is CURRENTLY selected on UsbInterface
    // (via WdfUsbTargetDeviceSelectConfig or WdfUsbInterfaceSelectSetting).
    // Precondition: the caller has already made the desired setting
    // current before calling this helper.
    UCHAR pipeCount = WdfUsbInterfaceGetNumConfiguredPipes(UsbInterface);

    for (UCHAR i = 0; i < pipeCount; i++)
    {
        WDF_USB_PIPE_INFORMATION pipeInfo;
        WDF_USB_PIPE_INFORMATION_INIT(&pipeInfo);

        WDFUSBPIPE candidate = WdfUsbInterfaceGetConfiguredPipe(
            UsbInterface, i, &pipeInfo);

        if (candidate == NULL)
        {
            continue;
        }

        BOOLEAN isIn = WdfUsbPipeTypeIsochronous != pipeInfo.PipeType &&
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
    //
    // WDF_USB_INTERFACE_SETTING_PAIR.UsbInterface is an OUTPUT field —
    // WDF fills it in on success. Zero the array first: an uninitialized
    // stack UsbInterface here is garbage, not NULL, and
    // WdfUsbTargetDeviceSelectConfig validates it on input for the
    // multi-interface case — garbage there fails the whole call with
    // STATUS_INVALID_PARAMETER (0xC000000D), which cost real bring-up
    // time to track down on hardware. Never leave a WDF out-param
    // uninitialized on entry again.
    WDF_USB_INTERFACE_SETTING_PAIR settingPairs[2];
    RtlZeroMemory(settingPairs, sizeof(settingPairs));
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

    // Task 6: this KMDF version's WDF_USB_DEVICE_SELECT_CONFIG_PARAMS
    // doesn't echo the interface count back (no NumberOfInterfaces
    // field on Types.MultiInterface here) — the real per-interface
    // confirmation is that WDF filled in both Pairs[].UsbInterface
    // handles. WdfUsbTargetDeviceSelectConfig succeeding should
    // guarantee this, but never assume — check both explicitly rather
    // than dereferencing a handle we didn't verify.
    if (settingPairs[0].UsbInterface == NULL || settingPairs[1].UsbInterface == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfUsbTargetDeviceSelectConfig succeeded but left an interface "
            "handle NULL (MI_00=%p, MI_01=%p)\n",
            settingPairs[0].UsbInterface, settingPairs[1].UsbInterface));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    DeviceContext->ControlInterface = settingPairs[0].UsbInterface;
    DeviceContext->DataInterface    = settingPairs[1].UsbInterface;

    // Task 5: discover the interrupt IN pipe on MI_00 dynamically. MI_00
    // has only one setting (0), already made current by the
    // WdfUsbTargetDeviceSelectConfig call above.
    status = T2NcmFindPipeByDirectionAndType(
        DeviceContext->ControlInterface, WdfUsbPipeTypeInterrupt, TRUE, &pipe);
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

static
NTSTATUS
T2NcmUsbSelectDataAltSetting(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ UCHAR                 SettingIndex
    )
{
    WDF_USB_INTERFACE_SELECT_SETTING_PARAMS params;

    WDF_USB_INTERFACE_SELECT_SETTING_PARAMS_INIT_SETTING(&params, SettingIndex);

    return WdfUsbInterfaceSelectSetting(
        DeviceContext->DataInterface, WDF_NO_OBJECT_ATTRIBUTES, &params);
}

NTSTATUS
T2NcmUsbActivateDataInterface(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    NTSTATUS status;
    WDFUSBPIPE bulkIn = NULL;
    WDFUSBPIPE bulkOut = NULL;

    // Task 12: only reachable once NCM control-plane negotiation (Tasks
    // 7-11) has already succeeded — callers (Device.c) are responsible
    // for that ordering.
    status = T2NcmUsbSelectDataAltSetting(DeviceContext, T2NCM_DATA_ALT_ACTIVE);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: MI_01 SelectSetting(alt %u) failed 0x%08X\n",
            T2NCM_DATA_ALT_ACTIVE, status));
        return status;
    }

    // T2NcmUsbSelectDataAltSetting above already made alt 1 the
    // interface's current setting, so the pipe queries below reflect it.
    status = T2NcmFindPipeByDirectionAndType(
        DeviceContext->DataInterface,
        WdfUsbPipeTypeBulk, TRUE, &bulkIn);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: MI_01 bulk IN pipe not found on alt %u: 0x%08X\n",
            T2NCM_DATA_ALT_ACTIVE, status));
        goto Unwind;
    }

    status = T2NcmFindPipeByDirectionAndType(
        DeviceContext->DataInterface,
        WdfUsbPipeTypeBulk, FALSE, &bulkOut);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: MI_01 bulk OUT pipe not found on alt %u: 0x%08X\n",
            T2NCM_DATA_ALT_ACTIVE, status));
        goto Unwind;
    }

    // Cross-check against the reference revision's endpoint addresses —
    // same "log, don't fail" discipline as the MI_00 interrupt pipe in
    // T2NcmUsbPrepareHardware. Discovery above is authoritative.
    {
        WDF_USB_PIPE_INFORMATION info;

        WDF_USB_PIPE_INFORMATION_INIT(&info);
        WdfUsbTargetPipeGetInformation(bulkIn, &info);
        if (info.EndpointAddress != T2NCM_EXPECTED_BULK_IN_EP)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: MI_01 bulk IN EP is 0x%02X, not the 0x%02X seen on the "
                "reference revision — continuing, discovery is authoritative\n",
                info.EndpointAddress, T2NCM_EXPECTED_BULK_IN_EP));
        }

        WDF_USB_PIPE_INFORMATION_INIT(&info);
        WdfUsbTargetPipeGetInformation(bulkOut, &info);
        if (info.EndpointAddress != T2NCM_EXPECTED_BULK_OUT_EP)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: MI_01 bulk OUT EP is 0x%02X, not the 0x%02X seen on the "
                "reference revision — continuing, discovery is authoritative\n",
                info.EndpointAddress, T2NCM_EXPECTED_BULK_OUT_EP));
        }
    }

    DeviceContext->BulkInPipe = bulkIn;
    DeviceContext->BulkOutPipe = bulkOut;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: MI_01 switched to alt %u, bulk IN/OUT pipes bound\n",
        T2NCM_DATA_ALT_ACTIVE));

    return STATUS_SUCCESS;

Unwind:
    // Leave MI_01 in a known state (idle alt 0) rather than stranded on
    // alt 1 with pipes we failed to fully discover. If even the unwind
    // fails, log it loudly — Task 22 requires the device context never
    // hold a pipe handle we didn't validate, so BulkIn/OutPipe stay NULL
    // either way.
    {
        NTSTATUS unwindStatus =
            T2NcmUsbSelectDataAltSetting(DeviceContext, T2NCM_DATA_ALT_IDLE);
        if (!NT_SUCCESS(unwindStatus))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: unwind to alt %u after failed activation ALSO failed "
                "0x%08X — MI_01 alt-setting state is now unknown\n",
                T2NCM_DATA_ALT_IDLE, unwindStatus));
        }
    }

    DeviceContext->BulkInPipe = NULL;
    DeviceContext->BulkOutPipe = NULL;

    return status;
}
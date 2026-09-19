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

    // Variant 1 (see Driver.h top comment): real hardware showed MI_00
    // and MI_01 are two INDEPENDENT PDOs, not one IAD-grouped function —
    // WdfUsbTargetDeviceGetInterface(UsbDevice, 1) came back NULL from a
    // WDFUSBDEVICE created against MI_00's PDO. This driver instance now
    // binds directly to MI_01's own PDO, which exposes exactly ONE
    // interface to itself — a plain single-interface select-config is
    // all that's needed, no WDF_USB_INTERFACE_SETTING_PAIR array, no
    // pre-fetched interface handles.
    WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_INIT_SINGLE_INTERFACE(&configParams);

    status = WdfUsbTargetDeviceSelectConfig(
        DeviceContext->UsbDevice, WDF_NO_OBJECT_ATTRIBUTES, &configParams);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfUsbTargetDeviceSelectConfig failed 0x%08X\n", status));
        return status;
    }

    // Index 0 here means "this PDO's own, only interface" (WDF's
    // interface array is scoped to what this specific WDFUSBDEVICE
    // exposes, not the composite device's full interface list) — it
    // resolves to MI_01 regardless of MI_01's real bInterfaceNumber (1).
    DeviceContext->DataInterface = WdfUsbTargetDeviceGetInterface(DeviceContext->UsbDevice, 0);

    if (DeviceContext->DataInterface == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfUsbTargetDeviceGetInterface(0) returned NULL after a "
            "successful SelectConfig - should not happen\n"));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    // Alt 0 has zero endpoints by design (idle state) — bulk pipes are
    // only enumerated after Task 12 switches to alt 1. Control-plane
    // requests to MI_00 (GET_NTB_PARAMETERS etc., NcmProtocol.c) go over
    // this same UsbDevice's shared control endpoint (EP0), addressed by
    // wIndex=T2NCM_CONTROL_IFACE_NUM — that's a device-level resource,
    // not an interface-level one, so it doesn't require owning MI_00's
    // own interface object (which this driver instance never has).
    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: USB configuration selected, MI_01 interface bound "
        "(control-plane reaches MI_00 via shared EP0)\n"));

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
    // (Task 22). Harmless no-op for fields the stub role never set.
    DeviceContext->BulkInPipe = NULL;
    DeviceContext->BulkOutPipe = NULL;
    DeviceContext->DataInterface = NULL;
    DeviceContext->UsbDevice = NULL;
    DeviceContext->RxReaderConfigured = FALSE;
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
                "reference revision - continuing, discovery is authoritative\n",
                info.EndpointAddress, T2NCM_EXPECTED_BULK_IN_EP));
        }

        WDF_USB_PIPE_INFORMATION_INIT(&info);
        WdfUsbTargetPipeGetInformation(bulkOut, &info);
        if (info.EndpointAddress != T2NCM_EXPECTED_BULK_OUT_EP)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: MI_01 bulk OUT EP is 0x%02X, not the 0x%02X seen on the "
                "reference revision - continuing, discovery is authoritative\n",
                info.EndpointAddress, T2NCM_EXPECTED_BULK_OUT_EP));
        }
    }

    DeviceContext->BulkInPipe = bulkIn;
    DeviceContext->BulkOutPipe = bulkOut;

    // WdfUsbInterfaceSelectSetting above just handed back a brand-new
    // WDFUSBPIPE for BulkInPipe (a fresh alt-1 selection always does,
    // per WDF) — any continuous-reader configuration T2NcmRxStart put on
    // the PREVIOUS pipe object does not carry over. Clear the flag so
    // the next T2NcmRxStart reconfigures it instead of calling
    // WdfIoTargetStart on a pipe that was never configured.
    DeviceContext->RxReaderConfigured = FALSE;

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
                "0x%08X - MI_01 alt-setting state is now unknown\n",
                T2NCM_DATA_ALT_IDLE, unwindStatus));
        }
    }

    DeviceContext->BulkInPipe = NULL;
    DeviceContext->BulkOutPipe = NULL;
    DeviceContext->RxReaderConfigured = FALSE;

    return status;
}
VOID
T2NcmUsbDeactivateDataInterface(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    NTSTATUS status;

    // Drop the cached pipe handles FIRST. The pipe objects belong to the
    // alt-1 setting and stop being valid targets the moment alt 0 is
    // selected; clearing them before the SET_INTERFACE means the send
    // path can never observe a window where BulkOutPipe is non-NULL but
    // the interface underneath it has already been torn down.
    DeviceContext->BulkInPipe = NULL;
    DeviceContext->BulkOutPipe = NULL;
    DeviceContext->RxReaderConfigured = FALSE;

    // The device clears its Ethernet packet filter on SET_INTERFACE, so
    // whatever was pushed for the previous alt-1 activation is gone the
    // moment this runs. Record that, so nothing later mistakes a stale
    // CdcPacketFilter value for a filter the device is actually holding.
    DeviceContext->CdcPacketFilterApplied = FALSE;

    if (DeviceContext->DataInterface == NULL)
    {
        return; // never activated, or already released
    }

    status = T2NcmUsbSelectDataAltSetting(DeviceContext, T2NCM_DATA_ALT_IDLE);
    if (!NT_SUCCESS(status))
    {
        // Not fatal, and deliberately not escalated: the caller is on a
        // power-down or halt path where there is nothing useful to do
        // with a failure, and refusing to proceed would be worse than
        // leaving the device on alt 1. Logged because a device that
        // cannot be parked on alt 0 is a real finding for the next
        // hardware session.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: parking MI_01 on alt %u failed 0x%08X - continuing\n",
            T2NCM_DATA_ALT_IDLE, status));
        return;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: MI_01 parked on alt %u\n", T2NCM_DATA_ALT_IDLE));
}
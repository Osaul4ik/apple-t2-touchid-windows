// SPDX-License-Identifier: GPL-2.0-only
// Driver.cpp - DriverEntry + EvtDeviceAdd for the WBDI UMDF skeleton.
// initguid.h must come BEFORE the header that DEFINE_GUIDs
// GUID_DEVINTERFACE_BIOMETRIC_READER (winbio_ioctl.h, pulled in by
// Internal.h): without INITGUID that header only *declares* the GUID and the
// link fails with LNK2001. Exactly one .cpp of the driver does this; a second
// one would be harmless (DECLSPEC_SELECTANY) but pointless.
#include <initguid.h>
#include "Internal.h"

void T2BioLog(_In_z_ const char* fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    if (SUCCEEDED(StringCchVPrintfA(buf, ARRAYSIZE(buf), fmt, ap))) {
        OutputDebugStringA("T2TouchIdBio: ");
        OutputDebugStringA(buf);
        OutputDebugStringA("\n");
    }
    va_end(ap);
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                                _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, T2BioEvtDeviceAdd);

    const NTSTATUS status = WdfDriverCreate(DriverObject, RegistryPath,
                                            WDF_NO_OBJECT_ATTRIBUTES, &config,
                                            WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        T2BioLog("WdfDriverCreate failed 0x%08x", status);
    }
    return status;
}

extern "C" NTSTATUS T2BioEvtDeviceAdd(_In_ WDFDRIVER Driver,
                                      _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);

    WDFDEVICE device = nullptr;
    NTSTATUS status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        T2BioLog("WdfDeviceCreate failed 0x%08x", status);
        return status;
    }

    // This interface GUID is what WinBio's sensor discovery looks for.
    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_BIOMETRIC_READER, nullptr);
    if (!NT_SUCCESS(status)) {
        T2BioLog("WdfDeviceCreateDeviceInterface failed 0x%08x", status);
        return status;
    }

    // Parallel dispatch on purpose: the later CAPTURE_DATA will stay pending
    // for a long time (lock-screen wait, design doc 9.4) and GET_SENSOR_STATUS /
    // cancel must still get through while it does.
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = T2BioEvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        T2BioLog("WdfIoQueueCreate failed 0x%08x", status);
    }
    return status;
}
// SPDX-License-Identifier: GPL-2.0-only
// Driver.cpp - DriverEntry + EvtDeviceAdd for the WBDI UMDF skeleton.
// initguid.h must come BEFORE the header that DEFINE_GUIDs
// GUID_DEVINTERFACE_BIOMETRIC_READER (winbio_ioctl.h, pulled in by
// Internal.h): without INITGUID that header only *declares* the GUID and the
// link fails with LNK2001. Exactly one .cpp of the driver does this; a second
// one would be harmless (DECLSPEC_SELECTANY) but pointless.
#include <initguid.h>
#include "Internal.h"

// DebugView: run as Administrator, Capture -> Capture Global Win32 (WUDFHost.exe
// is a LocalService process in session 0). Filter: T2TouchId*  - the engine
// adapter (wbiosrvc) uses the "T2TouchIdEngine:" prefix, this driver
// "T2TouchIdBio:". One OutputDebugString call per line so lines from parallel
// IOCTL threads do not interleave.
void T2BioLog(_In_z_ const char* fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    const HRESULT fmtHr = StringCchVPrintfA(buf, ARRAYSIZE(buf), fmt, ap);
    va_end(ap);
    if (FAILED(fmtHr)) {
        return;
    }
    char line[400];
    if (SUCCEEDED(StringCchPrintfA(line, ARRAYSIZE(line), "T2TouchIdBio: [%lu:%lu] %s\n",
                                   static_cast<unsigned long>(GetCurrentProcessId()),
                                   static_cast<unsigned long>(GetCurrentThreadId()), buf))) {
        OutputDebugStringA(line);
    }
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                                _In_ PUNICODE_STRING RegistryPath)
{
    T2BioLog("DriverEntry (UMDF %d.%d)", UMDF_VERSION_MAJOR, UMDF_VERSION_MINOR);

    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, T2BioEvtDeviceAdd);

    const NTSTATUS status = WdfDriverCreate(DriverObject, RegistryPath,
                                            WDF_NO_OBJECT_ATTRIBUTES, &config,
                                            WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        T2BioLog("WdfDriverCreate failed 0x%08x", status);
    } else {
        T2BioLog("DriverEntry ok");
    }
    return status;
}

extern "C" NTSTATUS T2BioEvtDeviceAdd(_In_ WDFDRIVER Driver,
                                      _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);
    T2BioLog("EvtDeviceAdd");

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
    } else {
        T2BioLog("EvtDeviceAdd ok: biometric interface + parallel IOCTL queue created");
    }
    return status;
}
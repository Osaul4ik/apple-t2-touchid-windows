// SPDX-License-Identifier: GPL-2.0-only
// Driver.cpp - DriverEntry + EvtDeviceAdd for the WBDI UMDF skeleton.
// GUID_DEVINTERFACE_BIOMETRIC_READER is instantiated by Internal.h itself,
// which scopes INITGUID tightly around just <winbio_ioctl.h> (see the
// comment there for why it must NOT be left on across <windows.h>/<wdf.h>).
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
    config.EvtDriverUnload = T2BioEvtDriverUnload;

    const NTSTATUS status = WdfDriverCreate(DriverObject, RegistryPath,
                                            WDF_NO_OBJECT_ATTRIBUTES, &config,
                                            WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        T2BioLog("WdfDriverCreate failed 0x%08x", status);
        return status;
    }
    // Process-wide (not per-device) - see Queue.cpp's OnSuspendResume header
    // comment for why EvtIoStop alone is not enough for this driver's
    // root-enumerated device. Registered once here rather than in
    // EvtDeviceAdd since it does not depend on the device at all.
    T2BioRegisterSuspendResumeNotification();
    T2BioLog("DriverEntry ok");
    return status;
}

extern "C" VOID T2BioEvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    T2BioUnregisterSuspendResumeNotification();
    T2BioLog("EvtDriverUnload ok");
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
    // Required precisely because CAPTURE_DATA can be the long-pending
    // request above: this power-managed queue's default (no EvtIoStop) is
    // to block device D0Exit until that request completes on its own, which
    // for CAPTURE_DATA(verify) means "until a touch or CancelIoEx" - a
    // system sleep triggers neither. See T2BioEvtIoStop in Queue.cpp.
    queueConfig.EvtIoStop = T2BioEvtIoStop;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        T2BioLog("WdfIoQueueCreate failed 0x%08x", status);
    } else {
        T2BioLog("EvtDeviceAdd ok: biometric interface + parallel IOCTL queue created, EvtIoStop wired");
    }
    return status;
}
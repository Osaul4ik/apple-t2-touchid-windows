// SPDX-License-Identifier: GPL-2.0-only
// Driver.c — DriverEntry / WDF driver object creation / role detection.

#include "Driver.h"
#include "Device.h"

BOOLEAN g_T2NcmStubRole = FALSE;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: DriverEntry entered\n"));

    // Variant 1 fix: this same binary is registered under two service
    // names in the INF ("T2Ncm" on MI_01, "T2NcmCtrlStub" on MI_00) —
    // RegistryPath's service-key name is how one .sys tells which PDO
    // it's being loaded for. RegistryPath->Buffer is guaranteed
    // null-terminated for this specific I/O-manager-supplied parameter,
    // so a plain wcsstr is safe here.
    g_T2NcmStubRole = (wcsstr(RegistryPath->Buffer, L"\\T2NcmCtrlStub") != NULL);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: role = %s\n", g_T2NcmStubRole ? "MI_00 stub" : "MI_01 full"));

    WDF_DRIVER_CONFIG_INIT(&config, T2NcmEvtDeviceAdd);

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfDriverCreate failed 0x%08X\n", status));
        return status;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: DriverEntry OK\n"));

    return STATUS_SUCCESS;
}
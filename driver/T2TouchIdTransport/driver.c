// SPDX-License-Identifier: GPL-2.0-only
// driver.c
#include "driver.h"

// Cached copy of HKLM\SOFTWARE\T2TouchId\Logging\Transport (see driver.h).
volatile LONG g_T2LogEnabled = 0;

// Re-reads the logging switch. PASSIVE_LEVEL only (Zw registry calls); a
// missing key/value, a wrong type or any failure leaves logging OFF.
VOID
T2LogRefresh(VOID)
{
    UNICODE_STRING keyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\T2TouchId\\Logging");
    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"Transport");
    OBJECT_ATTRIBUTES attrs;
    HANDLE key = NULL;
    ULONG buf[(sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG) + sizeof(ULONG) - 1) / sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
    ULONG resultLength = 0;
    LONG enabled = 0;

    InitializeObjectAttributes(&attrs, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&key, KEY_QUERY_VALUE, &attrs))) {
        if (NT_SUCCESS(ZwQueryValueKey(key, &valueName, KeyValuePartialInformation,
                                       info, sizeof(buf), &resultLength)) &&
            info->Type == REG_DWORD && info->DataLength == sizeof(ULONG)) {
            enabled = (*(PULONG)info->Data != 0) ? 1 : 0;
        }
        ZwClose(key);
    }
    InterlockedExchange(&g_T2LogEnabled, enabled);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    T2LogRefresh();

    WDF_DRIVER_CONFIG_INIT(&config, T2EvtDeviceAdd);
    config.DriverPoolTag = 'diT2'; // "T2id" reversed, distinguishes our pool allocs in !pooltag

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE);

    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: WdfDriverCreate failed 0x%x\n", status));
    }

    return status;
}
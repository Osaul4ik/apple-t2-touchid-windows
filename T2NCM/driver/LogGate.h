// SPDX-License-Identifier: GPL-2.0-only
// LogGate.h - registry switch for T2Ncm.sys and T2NcmCtrl.sys DebugView logging.
//
// HKLM\SOFTWARE\T2TouchId\Logging\Ncm (DWORD, set by the SepVault GUI
// "T2NCM" switch). Missing key/value, wrong type or any failure = OFF.
// Same scheme as T2TouchIdTransport (driver/T2TouchIdTransport/driver.h):
// the value is read here at PASSIVE_LEVEL only and cached by the caller in
// a volatile global, because the log macros also run at DISPATCH_LEVEL
// where the registry cannot be touched.
//
// Included by exactly two translation units (driver.c, Ctrlstub.c), each of
// which uses it - so the static __inline function never goes unreferenced.

#pragma once

#include <ntddk.h>

static __inline LONG
T2NcmReadLogSwitch(VOID)
{
    UNICODE_STRING keyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\T2TouchId\\Logging");
    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"Ncm");
    OBJECT_ATTRIBUTES attrs;
    HANDLE key = NULL;
    ULONG buf[(sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG) + sizeof(ULONG) - 1) / sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
    ULONG resultLength = 0;
    LONG enabled = 0;

    InitializeObjectAttributes(&attrs, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&key, KEY_QUERY_VALUE, &attrs)))
    {
        if (NT_SUCCESS(ZwQueryValueKey(key, &valueName, KeyValuePartialInformation,
                                       info, sizeof(buf), &resultLength)) &&
            info->Type == REG_DWORD && info->DataLength == sizeof(ULONG))
        {
            enabled = (*(PULONG)info->Data != 0) ? 1 : 0;
        }
        ZwClose(key);
    }
    return enabled;
}
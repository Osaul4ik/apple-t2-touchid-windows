// SPDX-License-Identifier: GPL-2.0-only
// Driver.c — DriverEntry.
//
// Two things happen here, in this order, and the order matters:
//
//  1. WdfDriverCreate with WdfDriverInitNoDispatchOverride and no
//     EvtDeviceAdd. This is KMDF's documented "miniport mode": the
//     framework does NOT hook the driver object's MajorFunction table,
//     does NOT install an AddDevice routine, and therefore never sees a
//     PnP or power IRP. It exists solely so that NdisMiniport.c can call
//     WdfDeviceMiniportCreate and then use WDFUSBDEVICE/WDFUSBPIPE to
//     talk to MI_01. KMDF is a USB client library here, nothing more.
//
//  2. NdisMRegisterMiniportDriver. From this call onward NDIS owns the
//     device stack, the PnP lifetime and — the point of this revision —
//     the power policy. See the POWER-MANAGEMENT INVERSION block at the
//     top of Driver.h.
//
// If step 2 fails, step 1 must be undone with WdfDriverMiniportUnload
// before returning, because a no-dispatch-override WDF driver object has
// no unload path of its own that the I/O manager would reach.

#include "Driver.h"
#include "NdisMiniport.h"

NDIS_HANDLE g_T2NcmMiniportDriverHandle = NULL;
PT2NCM_DEVICE_CONTEXT volatile g_T2NcmDiagnosticAdapter = NULL;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    NDIS_STATUS ndisStatus;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER wdfDriver = NULL;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: DriverEntry entered (NDIS miniport, NDIS-owned power)\n"));

    // WDF_NO_EVENT_CALLBACK for EvtDriverDeviceAdd: with
    // WdfDriverInitNoDispatchOverride the framework would reject a
    // non-NULL one anyway, since it has no AddDevice to call it from.
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNoDispatchOverride;

    // DriverPoolTag is purely a debugging aid — it makes WDF's own
    // allocations for this driver identifiable in a pool dump alongside
    // the T2NCM_POOL_TAG allocations the driver makes directly.
    config.DriverPoolTag = T2NCM_POOL_TAG;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &wdfDriver);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfDriverCreate (miniport mode) failed 0x%08X\n", status));
        return status;
    }

    ndisStatus = T2NcmNdisRegisterDriver(DriverObject, RegistryPath);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: NdisMRegisterMiniportDriver failed 0x%08X\n", ndisStatus));

        // Undo step 1. WdfDriverMiniportUnload is the documented teardown
        // for a driver created with WdfDriverInitNoDispatchOverride — a
        // plain WdfObjectDelete is not correct here.
        WdfDriverMiniportUnload(wdfDriver);
        return (NTSTATUS)ndisStatus;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: DriverEntry OK - NDIS is the power policy owner\n"));

    return STATUS_SUCCESS;
}
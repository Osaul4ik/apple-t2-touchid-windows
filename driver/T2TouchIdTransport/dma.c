// dma.c
//
// OOL buffers via WDF common buffer. Logical address
// (WdfCommonBufferGetAlignedLogicalAddress) is what SEP must receive —
// never MmGetPhysicalAddress on the VA. After host writes to OOL_IN the
// caller flushes CPU caches (see T2AksFlushForDevice in akstore.c).

#include "driver.h"

NTSTATUS
T2DmaAllocateOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    WDF_DMA_ENABLER_CONFIG dmaConfig;
    PHYSICAL_ADDRESS systemPaIn, systemPaOut;

    // Prefer 32-bit packet profile so OOL stays in lower 4GB when possible.
    // AddressWidthOverride is used when the WDK headers expose it.
    WDF_DMA_ENABLER_CONFIG_INIT(&dmaConfig, WdfDmaProfilePacket, T2_SEP_OOL_SIZE);
#if defined(WDF_DMA_ENABLER_CONFIG_SIZE_V2) || (defined(WDK_NTDDI_VERSION) && (WDK_NTDDI_VERSION >= NTDDI_WIN10))
    dmaConfig.AddressWidthOverride = 32;
#endif

    status = WdfDmaEnablerCreate(Ctx->Device, &dmaConfig, WDF_NO_OBJECT_ATTRIBUTES, &Ctx->DmaEnabler);
    if (!NT_SUCCESS(status)) {
        // Fallback: plain packet profile without width override.
        WDF_DMA_ENABLER_CONFIG_INIT(&dmaConfig, WdfDmaProfilePacket, T2_SEP_OOL_SIZE);
        status = WdfDmaEnablerCreate(Ctx->Device, &dmaConfig, WDF_NO_OBJECT_ATTRIBUTES, &Ctx->DmaEnabler);
    }
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: WdfDmaEnablerCreate failed, status=0x%x\n", status));
        return status;
    }

    status = WdfCommonBufferCreate(Ctx->DmaEnabler, T2_SEP_OOL_SIZE,
        WDF_NO_OBJECT_ATTRIBUTES, &Ctx->OolInBuffer);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: WdfCommonBufferCreate(OolIn) failed, status=0x%x\n", status));
        return status;
    }

    status = WdfCommonBufferCreate(Ctx->DmaEnabler, T2_SEP_OOL_SIZE,
        WDF_NO_OBJECT_ATTRIBUTES, &Ctx->OolOutBuffer);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: WdfCommonBufferCreate(OolOut) failed, status=0x%x\n", status));
        return status;
    }

    Ctx->OolInVa = WdfCommonBufferGetAlignedVirtualAddress(Ctx->OolInBuffer);
    Ctx->OolOutVa = WdfCommonBufferGetAlignedVirtualAddress(Ctx->OolOutBuffer);
    // LOGICAL / bus address — this is what must be given to SEP.
    Ctx->OolInPa = WdfCommonBufferGetAlignedLogicalAddress(Ctx->OolInBuffer);
    Ctx->OolOutPa = WdfCommonBufferGetAlignedLogicalAddress(Ctx->OolOutBuffer);

    // Diagnostic: compare system PA vs logical. If they differ, IOMMU is
    // translating and the old MmGetPhysicalAddress path was wrong.
    systemPaIn = MmGetPhysicalAddress(Ctx->OolInVa);
    systemPaOut = MmGetPhysicalAddress(Ctx->OolOutVa);

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: OOL IN  VA=%p SystemPA=0x%llx Logical=0x%llx%s\n",
        Ctx->OolInVa, systemPaIn.QuadPart, Ctx->OolInPa.QuadPart,
        (systemPaIn.QuadPart != Ctx->OolInPa.QuadPart) ? " [IOMMU TRANSLATED]" : ""));
    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: OOL OUT VA=%p SystemPA=0x%llx Logical=0x%llx%s\n",
        Ctx->OolOutVa, systemPaOut.QuadPart, Ctx->OolOutPa.QuadPart,
        (systemPaOut.QuadPart != Ctx->OolOutPa.QuadPart) ? " [IOMMU TRANSLATED]" : ""));

    if ((Ctx->OolInPa.QuadPart & (PAGE_SIZE - 1)) != 0 ||
        (Ctx->OolOutPa.QuadPart & (PAGE_SIZE - 1)) != 0) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: OOL logical addresses not page-aligned "
            "(in=0x%llx out=0x%llx)\n",
            Ctx->OolInPa.QuadPart, Ctx->OolOutPa.QuadPart));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Ctx->OolInVa, T2_SEP_OOL_SIZE);
    RtlZeroMemory(Ctx->OolOutVa, T2_SEP_OOL_SIZE);

    return STATUS_SUCCESS;
}

NTSTATUS
T2DmaRegisterOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;

    if (Ctx->OolInVa == NULL || Ctx->OolOutVa == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = T2EnablePciBusMaster(Ctx->Device);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: T2EnablePciBusMaster failed, status=0x%x\n", status));
        return status;
    }

    // Pass LOGICAL addresses to SEP — never system PA.
    status = T2SepControl(Ctx, T2_SEP_CMSG_SET_OOL_IN, 1, Ctx->OolInPa, T2_SEP_OOL_SIZE);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: SET_OOL_IN failed, status=0x%x\n", status));
        return status;
    }
    Ctx->OolInRegistered = TRUE;

    status = T2SepControl(Ctx, T2_SEP_CMSG_SET_OOL_OUT, 2, Ctx->OolOutPa, T2_SEP_OOL_SIZE);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: OOL input registered but output "
            "registration failed, status=0x%x; reboot before retry\n", status));
        return status;
    }
    Ctx->OolOutRegistered = TRUE;

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: registered 16 KiB endpoint-7 OOL "
        "(logical in=0x%llx out=0x%llx)\n",
        Ctx->OolInPa.QuadPart, Ctx->OolOutPa.QuadPart));
    return STATUS_SUCCESS;
}

VOID
T2DmaFreeOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    if (Ctx->OolOutBuffer) {
        WdfObjectDelete(Ctx->OolOutBuffer);
        Ctx->OolOutBuffer = NULL;
        Ctx->OolOutVa = NULL;
        Ctx->OolOutPa.QuadPart = 0;
    }
    if (Ctx->OolInBuffer) {
        WdfObjectDelete(Ctx->OolInBuffer);
        Ctx->OolInBuffer = NULL;
        Ctx->OolInVa = NULL;
        Ctx->OolInPa.QuadPart = 0;
    }
    if (Ctx->DmaEnabler) {
        WdfObjectDelete(Ctx->DmaEnabler);
        Ctx->DmaEnabler = NULL;
    }
}

// dma.c
//
// Non-cached contiguous OOL buffers for endpoint-7 AppleKeyStore DMA.
// VERIFIED FROM SOURCE sizing/masks (driver.h). Allocation deliberately
// mirrors Linux dma_alloc_coherent: MmNonCached so SEP always sees host
// stores without a cache flush. WDF common buffers (write-back) caused
// silent EP7 timeouts even with correct V1/V2 wire layout.

#include "driver.h"

NTSTATUS
T2DmaAllocateOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    PHYSICAL_ADDRESS low, high, boundary;

    low.QuadPart = 0;
    // 44-bit DMA limit (T2_SEP_DMA_BITS) — same constraint as Linux
    // dma_set_mask_and_coherent(DMA_BIT_MASK(44)).
    high.QuadPart = (1ULL << T2_SEP_DMA_BITS) - 1;
    boundary.QuadPart = 0;

    Ctx->OolInVa = MmAllocateContiguousMemorySpecifyCache(
        T2_SEP_OOL_SIZE, low, high, boundary, MmNonCached);
    if (Ctx->OolInVa == NULL) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: MmAllocateContiguousMemorySpecifyCache(OolIn) failed\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Ctx->OolInPa = MmGetPhysicalAddress(Ctx->OolInVa);

    Ctx->OolOutVa = MmAllocateContiguousMemorySpecifyCache(
        T2_SEP_OOL_SIZE, low, high, boundary, MmNonCached);
    if (Ctx->OolOutVa == NULL) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: MmAllocateContiguousMemorySpecifyCache(OolOut) failed\n"));
        MmFreeContiguousMemorySpecifyCache(Ctx->OolInVa, T2_SEP_OOL_SIZE, MmNonCached);
        Ctx->OolInVa = NULL;
        Ctx->OolInPa.QuadPart = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Ctx->OolOutPa = MmGetPhysicalAddress(Ctx->OolOutVa);

    // Page-aligned check (SEP control message shifts by PAGE_SHIFT).
    if ((Ctx->OolInPa.QuadPart & (PAGE_SIZE - 1)) != 0 ||
        (Ctx->OolOutPa.QuadPart & (PAGE_SIZE - 1)) != 0) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: OOL buffers not page-aligned (in=0x%llx out=0x%llx)\n",
            Ctx->OolInPa.QuadPart, Ctx->OolOutPa.QuadPart));
        T2DmaFreeOolBuffers(Ctx);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Ctx->OolInVa, T2_SEP_OOL_SIZE);
    RtlZeroMemory(Ctx->OolOutVa, T2_SEP_OOL_SIZE);

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: allocated non-cached OOL buffers inPA=0x%llx outPA=0x%llx\n",
        Ctx->OolInPa.QuadPart, Ctx->OolOutPa.QuadPart));
    return STATUS_SUCCESS;
}

NTSTATUS
T2DmaRegisterOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;

    if (Ctx->OolInVa == NULL || Ctx->OolOutVa == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Linux calls pci_set_master before SET_OOL_*.
    status = T2EnablePciBusMaster(Ctx->Device);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: T2EnablePciBusMaster failed, status=0x%x\n", status));
        return status;
    }

    status = T2SepControl(Ctx, T2_SEP_CMSG_SET_OOL_IN, 1, Ctx->OolInPa, T2_SEP_OOL_SIZE);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: SET_OOL_IN failed, status=0x%x\n", status));
        return status;
    }
    Ctx->OolInRegistered = TRUE;

    status = T2SepControl(Ctx, T2_SEP_CMSG_SET_OOL_OUT, 2, Ctx->OolOutPa, T2_SEP_OOL_SIZE);
    if (!NT_SUCCESS(status)) {
        // VERIFIED FROM SOURCE (Milestone 1, "Pinning"): once OOL_IN
        // registration succeeds, SEP retains that physical address.
        // Do not free; reboot clears SEP's view. Leave OolInRegistered=TRUE.
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: OOL input registered but output "
            "registration failed, status=0x%x; reboot before retry\n", status));
        return status;
    }
    Ctx->OolOutRegistered = TRUE;

    T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: registered 16 KiB endpoint-7 OOL input/output buffers "
        "(non-cached, inPA=0x%llx outPA=0x%llx)\n",
        Ctx->OolInPa.QuadPart, Ctx->OolOutPa.QuadPart));
    return STATUS_SUCCESS;
}

VOID
T2DmaFreeOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    // Only ever called when neither buffer was successfully registered
    // with SEP (see T2EvtDeviceReleaseHardware) - safe to free.
    if (Ctx->OolOutVa) {
        MmFreeContiguousMemorySpecifyCache(Ctx->OolOutVa, T2_SEP_OOL_SIZE, MmNonCached);
        Ctx->OolOutVa = NULL;
        Ctx->OolOutPa.QuadPart = 0;
    }
    if (Ctx->OolInVa) {
        MmFreeContiguousMemorySpecifyCache(Ctx->OolInVa, T2_SEP_OOL_SIZE, MmNonCached);
        Ctx->OolInVa = NULL;
        Ctx->OolInPa.QuadPart = 0;
    }
}

// dma.c
//
// KMDF common-buffer allocation for the two 16 KiB endpoint-7 OOL buffers,
// and their registration with SEP over endpoint 0 (SET_OOL_IN / SET_OOL_OUT).
// Sizes/masks VERIFIED FROM SOURCE (driver.h). The 44-bit DMA mask and the
// exact allocator behavior on this specific chipset are VERIFIED ON WINDOWS
// pending — Milestone 0/1 explicitly flagged "do not assume Windows
// IOMMU/DMA configuration is identical to Linux"; this code asks WDF for
// a 44-bit-capable profile but must be checked against real
// WdfDmaEnablerCreate results on the target machine (see
// docs/milestone-2-hardware-results.md).

#include "driver.h"

NTSTATUS
T2DmaAllocateOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    WDF_DMA_ENABLER_CONFIG dmaConfig;

    // WDF_DMA_PROFILE_ScatterGather64 is the closest stock profile; the
    // OOL buffers are single contiguous common buffers, not scatter-gather
    // lists, but WdfCommonBufferCreate still requires an enabler. If real
    // hardware testing shows the 44-bit mask needs an explicit
    // DEVICE_DESCRIPTION.MaximumLength / DmaAddressWidth override, adjust
    // here — flagged, not guessed silently.
    WDF_DMA_ENABLER_CONFIG_INIT(&dmaConfig, WdfDmaProfilePacket64, T2_SEP_OOL_SIZE);
    status = WdfDmaEnablerCreate(Ctx->Device, &dmaConfig, WDF_NO_OBJECT_ATTRIBUTES, &Ctx->DmaEnabler);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfCommonBufferCreate(Ctx->DmaEnabler, T2_SEP_OOL_SIZE,
        WDF_NO_OBJECT_ATTRIBUTES, &Ctx->OolInBuffer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfCommonBufferCreate(Ctx->DmaEnabler, T2_SEP_OOL_SIZE,
        WDF_NO_OBJECT_ATTRIBUTES, &Ctx->OolOutBuffer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(WdfCommonBufferGetAlignedVirtualAddress(Ctx->OolInBuffer), T2_SEP_OOL_SIZE);
    RtlZeroMemory(WdfCommonBufferGetAlignedVirtualAddress(Ctx->OolOutBuffer), T2_SEP_OOL_SIZE);

    return STATUS_SUCCESS;
}

NTSTATUS
T2DmaRegisterOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    PHYSICAL_ADDRESS oolInDma = WdfCommonBufferGetAlignedLogicalAddress(Ctx->OolInBuffer);
    PHYSICAL_ADDRESS oolOutDma = WdfCommonBufferGetAlignedLogicalAddress(Ctx->OolOutBuffer);

    status = T2SepControl(Ctx, T2_SEP_CMSG_SET_OOL_IN, 1, oolInDma, T2_SEP_OOL_SIZE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Ctx->OolInRegistered = TRUE;

    status = T2SepControl(Ctx, T2_SEP_CMSG_SET_OOL_OUT, 2, oolOutDma, T2_SEP_OOL_SIZE);
    if (!NT_SUCCESS(status)) {
        // VERIFIED FROM SOURCE (Milestone 1, "Pinning"): once OOL_IN
        // registration succeeds, SEP retains that physical address
        // regardless of what happens next. Do not free or reuse the
        // common buffer even though OUT registration failed - only a
        // reboot clears SEP's view of it. Leave OolInRegistered = TRUE so
        // T2EvtDeviceReleaseHardware knows to leak, not free.
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: OOL input registered but output "
            "registration failed; reboot before retry\n"));
        return status;
    }
    Ctx->OolOutRegistered = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "T2TouchIdTransport: registered 16 KiB endpoint-7 OOL input/output buffers\n"));
    return STATUS_SUCCESS;
}

VOID
T2DmaFreeOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx)
{
    // Only ever called when neither buffer was successfully registered
    // with SEP (see T2EvtDeviceReleaseHardware) - safe to free.
    if (Ctx->OolOutBuffer) {
        WdfObjectDelete(Ctx->OolOutBuffer);
        Ctx->OolOutBuffer = NULL;
    }
    if (Ctx->OolInBuffer) {
        WdfObjectDelete(Ctx->OolInBuffer);
        Ctx->OolInBuffer = NULL;
    }
    if (Ctx->DmaEnabler) {
        WdfObjectDelete(Ctx->DmaEnabler);
        Ctx->DmaEnabler = NULL;
    }
}

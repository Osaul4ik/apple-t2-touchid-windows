// SPDX-License-Identifier: GPL-2.0-only
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

    // VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux, t2_sep_transport.c
    // probe): Linux calls dma_set_mask_and_coherent(DMA_BIT_MASK(44)) —
    // the SAME T2_SEP_DMA_BITS (44) that T2SepControl already enforces on
    // the logical address it's given (see mailbox.c). There is no 32-bit
    // restriction in that source at all: word[1] carries dma>>12, which
    // only needs to fit a 32-bit register if dma<2^44, not dma<2^32. A
    // prior version of this function forced AddressWidthOverride=32
    // ("prefer 32-bit... so OOL stays in lower 4GB") — that was a
    // self-imposed constraint with no protocol or Linux-source basis, and
    // diverges from the reference driver's actual DMA mask.
    // VERIFIED (learn.microsoft.com/.../ns-wdfdmaenabler-_wdf_dma_enabler_config):
    // AddressWidthOverride accepts 0 (defer to Profile) or any value from
    // 24 to 63 — 32 is not a ceiling, so requesting 44 directly here is
    // valid and matches Linux's mask exactly, rather than approximating it.
    WDF_DMA_ENABLER_CONFIG_INIT(&dmaConfig, WdfDmaProfilePacket, T2_SEP_OOL_SIZE);
#if defined(WDF_DMA_ENABLER_CONFIG_SIZE_V2) || (defined(WDK_NTDDI_VERSION) && (WDK_NTDDI_VERSION >= NTDDI_WIN10))
    dmaConfig.AddressWidthOverride = T2_SEP_DMA_BITS; // 44 — matches Linux's DMA_BIT_MASK(44), not an arbitrary 32
#endif

    status = WdfDmaEnablerCreate(Ctx->Device, &dmaConfig, WDF_NO_OBJECT_ATTRIBUTES, &Ctx->DmaEnabler);
    if (!NT_SUCCESS(status)) {
        // Fallback: plain packet profile without width override. Same
        // rollback-safety reasoning as before — nothing SEP-visible has
        // happened yet, so a second, unconstrained attempt is safe.
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
        // Milestone 2B §5: nothing beyond DmaEnabler exists yet - roll it
        // back so a subsequent retry starts from a clean slate instead of
        // leaking a DmaEnabler across attempts.
        T2DmaFreeOolBuffers(Ctx);
        return status;
    }

    status = WdfCommonBufferCreate(Ctx->DmaEnabler, T2_SEP_OOL_SIZE,
        WDF_NO_OBJECT_ATTRIBUTES, &Ctx->OolOutBuffer);
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: WdfCommonBufferCreate(OolOut) failed, status=0x%x\n", status));
        // Milestone 2B §5: OolInBuffer + DmaEnabler were allocated above -
        // neither has been shown to SEP yet (registration is a separate
        // step), so both are fully rollback-safe here.
        T2DmaFreeOolBuffers(Ctx);
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
        // Milestone 2B §5: still nothing SEP-visible - roll back so the
        // caller sees a clean HardwareReady-retryable failure, not a leaked
        // pair of common buffers.
        T2DmaFreeOolBuffers(Ctx);
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
        // Milestone 2B §5: SEP was never contacted - the caller (device.c)
        // is responsible for freeing the still-allocated OOL buffers and
        // returning to a retryable state, since OolInRegistered/
        // OolOutRegistered are both still FALSE here.
        return status;
    }

    // Pass LOGICAL addresses to SEP — never system PA.
    BOOLEAN sentIn = FALSE;
    status = T2SepControl(Ctx, T2_SEP_CMSG_SET_OOL_IN, 1, Ctx->OolInPa, T2_SEP_OOL_SIZE, &sentIn);
    if (sentIn) {
        // Sticky/permanent for this device context regardless of the
        // outcome below - see OolSepMayKnowAddress in driver.h. The
        // doorbell rang; SEP may already have the address even if the
        // status check right below says this call "failed".
        Ctx->OolSepMayKnowAddress = TRUE;
    }
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: SET_OOL_IN failed, status=0x%x (sentToDevice=%d)\n",
            status, sentIn));
        // Milestone 2B §5: only genuinely safe to treat as fully
        // recoverable/retryable when sentIn is FALSE (message never left
        // this host - e.g. bus-master enable failed, or the outbox-full
        // wait itself timed out before anything was written). If sentIn is
        // TRUE, OolSepMayKnowAddress above is what now keeps this from
        // being freed/retried even though OolInRegistered stays FALSE.
        return status;
    }
    Ctx->OolInRegistered = TRUE;

    BOOLEAN sentOut = FALSE;
    status = T2SepControl(Ctx, T2_SEP_CMSG_SET_OOL_OUT, 2, Ctx->OolOutPa, T2_SEP_OOL_SIZE, &sentOut);
    if (sentOut) {
        Ctx->OolSepMayKnowAddress = TRUE;
    }
    if (!NT_SUCCESS(status)) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: OOL input registered but output "
            "registration failed, status=0x%x (sentToDevice=%d); SEP now holds "
            "the OOL_IN logical address (0x%llx) and no deregistration opcode "
            "exists (Milestone 1 §3) - deliberately NOT freeing OolInBuffer/"
            "DmaEnabler, this device context is now terminal until reboot\n",
            status, sentOut, Ctx->OolInPa.QuadPart));
        // Milestone 2B §5/§7: OolInRegistered (confirmed) and
        // OolSepMayKnowAddress (set above, unconditionally sticky) both
        // independently keep device.c from treating this as retryable.
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
    // Defense-in-depth: every call site is expected to have already
    // checked OolSepMayKnowAddress (see driver.h) before calling this, but
    // refuse here too rather than trust that every future call site gets
    // it right. Freeing this memory while SEP might still land a DMA write
    // into the OOL_IN/OOL_OUT logical address would hand that physical
    // memory to something else while SEP could still be writing to it.
    if (Ctx->OolSepMayKnowAddress) {
        T2_LOG((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "T2TouchIdTransport: T2DmaFreeOolBuffers called while "
            "OolSepMayKnowAddress is set - refusing to free (bug at call site)\n"));
        return;
    }

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
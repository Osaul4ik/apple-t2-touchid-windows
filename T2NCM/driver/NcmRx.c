// SPDX-License-Identifier: GPL-2.0-only
// NcmRx.c — NTB16 RX parser + bulk-IN continuous reader (Tasks 14-15).
//
// See NcmRx.h for the "diagnostic only, no NDIS indication yet" scope
// of this milestone.

#include "NcmRx.h"

// ---- NTB16 / NDP16 wire structures (USB CDC-NCM 1.20 §3.2-3.3),
// little-endian, packed exactly as the device sends them — same
// pshpack1/poppack convention as T2NCM_WIRE_NTB_PARAMETERS in
// NcmProtocol.c. ----
#include <pshpack1.h>
typedef struct _T2NCM_WIRE_NTH16
{
    ULONG  dwSignature;      // 'NCMH', 0x484D434E on the wire (LE)
    USHORT wHeaderLength;    // must be 12 for NTH16
    USHORT wSequence;
    USHORT wBlockLength;     // total NTB length, including this header
    USHORT wNdpIndex;        // byte offset from NTB start to first NDP16
} T2NCM_WIRE_NTH16;

typedef struct _T2NCM_WIRE_NDP16_ENTRY
{
    USHORT wDatagramIndex;   // 0 (paired with length 0) marks the
                              // required terminator entry
    USHORT wDatagramLength;
} T2NCM_WIRE_NDP16_ENTRY;

typedef struct _T2NCM_WIRE_NDP16
{
    ULONG  dwSignature;      // 'NCM0' (no CRC, no IPS), 0x304D434E (LE)
    USHORT wLength;          // this NDP16's length, header + entries
    USHORT wNextNdpIndex;    // 0 if this is the last NDP16 in the NTB
    // followed by (wLength-8)/4 T2NCM_WIRE_NDP16_ENTRY entries, the
    // last of which is the zero/zero terminator
} T2NCM_WIRE_NDP16;
#include <poppack.h>

#define T2NCM_NTH16_SIGNATURE       0x484D434Eu  // "NCMH"
#define T2NCM_NDP16_SIGNATURE_NOCRC 0x304D434Eu  // "NCM0" — the only
    // datagram-pointer variant handled this milestone. NCM also
    // defines a CRC variant ("NCM1") and IPS-over-NCM subtypes; adding
    // those needs real capture evidence the T2 sends them, per this
    // driver's "never guess a wire format" rule (NcmProtocol.c's
    // history with the MAC string is exactly the failure mode that
    // rule exists to avoid).
#define T2NCM_NTH16_HEADER_LENGTH   12u
#define T2NCM_NDP16_HEADER_LENGTH   8u
#define T2NCM_ETHERNET_HEADER_LEN   14u  // dest(6) + src(6) + ethertype(2)

// Number of concurrently outstanding bulk-IN reads. Small and fixed —
// this is a diagnostic-only RX path (nothing yet consumes the frames),
// so there's no throughput target to tune for; it only needs enough
// depth that the pipe is never starved between one completion and the
// next read being requeued.
#define T2NCM_RX_PENDING_READS      4u

static
VOID
T2NcmRxParseNtb(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(Length) const UCHAR* Buffer,
    _In_ size_t Length
    )
{
    T2NCM_WIRE_NTH16 nth;
    T2NCM_WIRE_NDP16 ndp;
    ULONG blockLength;
    ULONG ndpOffset;
    ULONG ndpLength;
    ULONG entryCount;
    ULONG framesThisNtb = 0;

    InterlockedIncrement64(&DeviceContext->RxNtbsReceived);

    if (Length < sizeof(T2NCM_WIRE_NTH16))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTB shorter than NTH16 (%Iu bytes) — dropping\n", Length));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    // Buffer may not be naturally aligned for these field widths —
    // copy into a local struct rather than casting Buffer directly,
    // same reasoning as T2NCM_WIRE_NTB_PARAMETERS's handling in
    // NcmProtocol.c.
    RtlCopyMemory(&nth, Buffer, sizeof(nth));

    if (nth.dwSignature != T2NCM_NTH16_SIGNATURE)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTH16 signature mismatch (0x%08X) — dropping NTB\n",
            nth.dwSignature));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    if (nth.wHeaderLength != T2NCM_NTH16_HEADER_LENGTH)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTH16 wHeaderLength=%u (expected %u) — dropping NTB\n",
            nth.wHeaderLength, T2NCM_NTH16_HEADER_LENGTH));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    // Never trust the device's own length field over what USB actually
    // delivered — blockLength must fit inside Length, not just be
    // internally self-consistent.
    blockLength = nth.wBlockLength;
    if (blockLength < sizeof(T2NCM_WIRE_NTH16) || blockLength > Length)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX NTH16 wBlockLength=%u out of bounds (received %Iu) — "
            "dropping NTB\n", blockLength, Length));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    if (DeviceContext->NtbInMaxSize != 0 && blockLength > DeviceContext->NtbInMaxSize)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTB blockLength=%u exceeds negotiated NtbInMaxSize=%lu — "
            "dropping NTB\n", blockLength, DeviceContext->NtbInMaxSize));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    ndpOffset = nth.wNdpIndex;
    if (ndpOffset < sizeof(T2NCM_WIRE_NTH16) ||
        ndpOffset + T2NCM_NDP16_HEADER_LENGTH > blockLength)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX NDP16 offset %u out of bounds (block=%u) — dropping NTB\n",
            ndpOffset, blockLength));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    RtlCopyMemory(&ndp, Buffer + ndpOffset, sizeof(ndp));

    if (ndp.dwSignature != T2NCM_NDP16_SIGNATURE_NOCRC)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NDP16 signature 0x%08X not the handled NCM0 variant — "
            "dropping NTB\n", ndp.dwSignature));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    ndpLength = ndp.wLength;
    if (ndpLength < T2NCM_NDP16_HEADER_LENGTH ||
        ndpOffset + ndpLength > blockLength ||
        ((ndpLength - T2NCM_NDP16_HEADER_LENGTH) % sizeof(T2NCM_WIRE_NDP16_ENTRY)) != 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX NDP16 wLength=%u invalid/out of bounds (block=%u) — "
            "dropping NTB\n", ndpLength, blockLength));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    // Explicit cast: (ULONG - unsigned literal) / sizeof(...) promotes to
    // size_t before the divide, and entryCount is intentionally ULONG
    // (bounded by ndpLength, which is a USHORT-derived value that can
    // never need more than 32 bits) — /W4 flags the implicit narrowing
    // on assignment even though it can't actually lose data here.
    entryCount = (ULONG)((ndpLength - T2NCM_NDP16_HEADER_LENGTH) / sizeof(T2NCM_WIRE_NDP16_ENTRY));

    for (ULONG i = 0; i < entryCount; i++)
    {
        T2NCM_WIRE_NDP16_ENTRY entry;
        // Same explicit-narrowing note as entryCount above: the whole
        // expression promotes to size_t via sizeof(), then back to
        // ULONG, which can never truncate given entryCount's own bound.
        ULONG entryOffset = (ULONG)(ndpOffset + T2NCM_NDP16_HEADER_LENGTH +
                             (i * sizeof(T2NCM_WIRE_NDP16_ENTRY)));

        RtlCopyMemory(&entry, Buffer + entryOffset, sizeof(entry));

        if (entry.wDatagramIndex == 0 && entry.wDatagramLength == 0)
        {
            break; // required terminator — not an error, just the end
        }

        if (entry.wDatagramIndex < sizeof(T2NCM_WIRE_NTH16) ||
            (ULONG)entry.wDatagramIndex + entry.wDatagramLength > blockLength)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: RX datagram entry %u out of bounds (index=%u len=%u "
                "block=%u) — skipping this datagram only\n",
                i, entry.wDatagramIndex, entry.wDatagramLength, blockLength));
            InterlockedIncrement64(&DeviceContext->RxFramesRejected);
            continue;
        }

        if (entry.wDatagramLength < T2NCM_ETHERNET_HEADER_LEN)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: RX datagram entry %u too short for an Ethernet "
                "header (len=%u) — skipping this datagram only\n",
                i, entry.wDatagramLength));
            InterlockedIncrement64(&DeviceContext->RxFramesRejected);
            continue;
        }

        {
            const UCHAR* frame = Buffer + entry.wDatagramIndex;

            // Task 18-20 (NDIS) will indicate `frame`/entry.wDatagramLength
            // up via NdisMIndicateReceiveNetBufferLists from right here.
            // Until then: snapshot it for IOCTL_T2NCM_GET_STATUS only.
            RtlCopyMemory(DeviceContext->RxLastFrameDest, frame, 6);
            RtlCopyMemory(DeviceContext->RxLastFrameSrc, frame + 6, 6);
            DeviceContext->RxLastFrameEtherType =
                (USHORT)((frame[12] << 8) | frame[13]); // network byte order
            DeviceContext->RxLastFrameLength = entry.wDatagramLength;
        }

        InterlockedIncrement64(&DeviceContext->RxFramesParsed);
        framesThisNtb++;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_TRACE_LEVEL,
        "T2Ncm: RX NTB seq=%u block=%u frames=%lu\n",
        nth.wSequence, blockLength, framesThisNtb));
}

EVT_WDF_USB_READER_COMPLETION_ROUTINE T2NcmEvtRxReadComplete;

VOID
T2NcmEvtRxReadComplete(
    _In_ WDFUSBPIPE  Pipe,
    _In_ WDFMEMORY   Buffer,
    _In_ size_t      NumBytesTransferred,
    _In_ WDFCONTEXT  Context
    )
{
    PT2NCM_DEVICE_CONTEXT deviceContext = (PT2NCM_DEVICE_CONTEXT)Context;
    const UCHAR* buffer;

    UNREFERENCED_PARAMETER(Pipe);

    if (NumBytesTransferred == 0)
    {
        // A legitimate zero-length packet (NCM/USB ZLP framing), not an
        // error — nothing to parse.
        return;
    }

    buffer = (const UCHAR*)WdfMemoryGetBuffer(Buffer, NULL);
    if (buffer == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX read completion had a NULL buffer — dropping\n"));
        InterlockedIncrement64(&deviceContext->RxFramesRejected);
        return;
    }

    T2NcmRxParseNtb(deviceContext, buffer, NumBytesTransferred);
}

EVT_WDF_USB_READERS_FAILED T2NcmEvtRxReadersFailed;

VOID
T2NcmEvtRxReadersFailed(
    _In_    WDFUSBPIPE Pipe,
    _In_    NTSTATUS   Status,
    _In_    USBD_STATUS UsbdStatus
    )
{
    UNREFERENCED_PARAMETER(Pipe);

    // KMDF stops requeuing reads on this pipe once the continuous
    // reader gives up (repeated failures, e.g. device unplugged mid-
    // transfer). Nothing to recover here — EvtDeviceReleaseHardware/
    // the next PrepareHardware pass rebuilds the pipe from scratch.
    // Logged, not treated as fatal to the whole device: TX and the
    // control plane may still be fine.
    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
        "T2Ncm: RX continuous reader stopped itself (status=0x%08X, "
        "usbdStatus=0x%08X) — bulk-IN reads will not resume until the "
        "next PrepareHardware\n", Status, UsbdStatus));
}

NTSTATUS
T2NcmRxStart(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    WDF_USB_CONTINUOUS_READER_CONFIG readerConfig;
    NTSTATUS status;

    if (DeviceContext->RxStarted)
    {
        return STATUS_SUCCESS; // idempotent, see NcmRx.h
    }

    if (DeviceContext->BulkInPipe == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmRxStart called with no BulkInPipe — "
            "T2NcmUsbActivateDataInterface must succeed first\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (DeviceContext->NtbInMaxSize == 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmRxStart called with NtbInMaxSize=0 — "
            "GET_NTB_PARAMETERS must succeed first\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    WDF_USB_CONTINUOUS_READER_CONFIG_INIT(
        &readerConfig,
        T2NcmEvtRxReadComplete,
        DeviceContext,
        DeviceContext->NtbInMaxSize);

    readerConfig.EvtUsbTargetPipeReadersFailed = T2NcmEvtRxReadersFailed;
    readerConfig.NumPendingReads = T2NCM_RX_PENDING_READS;

    status = WdfUsbTargetPipeConfigContinuousReader(
        DeviceContext->BulkInPipe, &readerConfig);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfUsbTargetPipeConfigContinuousReader failed (0x%08X)\n",
            status));
        return status;
    }

    status = WdfIoTargetStart(WdfUsbTargetPipeGetIoTarget(DeviceContext->BulkInPipe));
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfIoTargetStart(BulkInPipe) failed (0x%08X)\n", status));
        return status;
    }

    DeviceContext->RxStarted = TRUE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: RX continuous reader started (bufferSize=%lu, pendingReads=%u)\n",
        DeviceContext->NtbInMaxSize, T2NCM_RX_PENDING_READS));

    return STATUS_SUCCESS;
}

VOID
T2NcmRxStop(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    if (!DeviceContext->RxStarted)
    {
        return; // idempotent, see NcmRx.h
    }

    // WdfIoTargetStop's default action (WdfIoTargetCancelSentIo) cancels
    // outstanding reads and waits for their completions to run before
    // returning — safe to call from D0Exit/ReleaseHardware without a
    // separate drain step.
    WdfIoTargetStop(
        WdfUsbTargetPipeGetIoTarget(DeviceContext->BulkInPipe),
        WdfIoTargetCancelSentIo);

    DeviceContext->RxStarted = FALSE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: RX continuous reader stopped\n"));
}
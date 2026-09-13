// SPDX-License-Identifier: GPL-2.0-only
// NcmTx.c — NTB16 TX builder + bulk-OUT engine (Tasks 13, 16).
//
// See NcmTx.h for scope. This is the mirror image of NcmRx.c's parser:
// there we validated everything the device claims because it isn't
// trustworthy; here we CONTROL every offset, so the discipline is
// instead "never emit a field the device's negotiated geometry didn't
// ask for" — no fixed layout assumptions, no guessed padding.

#include "NcmTx.h"

// ---- NTB16 / NDP16 wire structures — intentionally re-declared here
// rather than shared with NcmRx.c, matching this codebase's existing
// per-file wire-struct convention (see T2NCM_WIRE_NTB_PARAMETERS in
// NcmProtocol.c, which isn't shared either). Field layout must stay
// identical to NcmRx.c's copy since both describe the same wire
// format. ----
#include <pshpack1.h>
typedef struct _T2NCM_WIRE_NTH16_TX
{
    ULONG  dwSignature;
    USHORT wHeaderLength;
    USHORT wSequence;
    USHORT wBlockLength;
    USHORT wNdpIndex;
} T2NCM_WIRE_NTH16_TX;

typedef struct _T2NCM_WIRE_NDP16_ENTRY_TX
{
    USHORT wDatagramIndex;
    USHORT wDatagramLength;
} T2NCM_WIRE_NDP16_ENTRY_TX;

typedef struct _T2NCM_WIRE_NDP16_TX
{
    ULONG  dwSignature;
    USHORT wLength;
    USHORT wNextNdpIndex;
} T2NCM_WIRE_NDP16_TX;
#include <poppack.h>

#define T2NCM_TX_NTH16_SIGNATURE   0x484D434Eu  // "NCMH"
#define T2NCM_TX_NDP16_SIGNATURE   0x304D434Eu  // "NCM0" — no CRC, no IPS;
    // the only variant this driver has ever seen the T2 use (NcmRx.c
    // parses the same signature back out of real RX traffic).
#define T2NCM_TX_NTH16_LEN         12u
#define T2NCM_TX_NDP16_HEADER_LEN  8u
#define T2NCM_TX_NDP16_ENTRY_LEN   4u
#define T2NCM_TX_MIN_ETHERNET_FRAME 14u  // dest(6)+src(6)+ethertype(2)
#define T2NCM_TX_MAX_ETHERNET_FRAME 1514u // untagged Ethernet II, 1500
    // MTU + 14-byte header. No jumbo-frame support this milestone —
    // that needs MTU negotiation to land with Task 18-20's NDIS
    // registration, which is also what would ever let a frame this
    // large be generated in the first place today (nothing above
    // IOCTL_T2NCM_SEND_TEST_FRAME exists yet to originate one).

// wNTH16/wNDP16's own fields are all USHORT — a block/offset that
// doesn't fit is a wire-format ceiling, not a soft NtbOutMaxSize
// concern, so it's checked independently of that (which is a ULONG
// and could in principle be negotiated larger than 0xFFFF).
#define T2NCM_TX_MAX_WIRE_OFFSET   0xFFFFu

static
ULONG
T2NcmRoundUpToAlignment(
    _In_ ULONG Value,
    _In_ ULONG Alignment
    )
{
    // Alignment is guaranteed a nonzero power of two by
    // T2NcmValidateNdpGeometry (NcmProtocol.c) before it's ever stored
    // in the device context — the bitmask form only works because of
    // that guarantee.
    return (Value + Alignment - 1) & ~(Alignment - 1);
}

static
ULONG
T2NcmRoundUpToCongruence(
    _In_ ULONG Value,
    _In_ ULONG Divisor,
    _In_ ULONG Remainder
    )
{
    // Smallest X >= Value with X % Divisor == Remainder. Divisor
    // guaranteed nonzero and Remainder < Divisor, same source as above.
    ULONG currentRemainder = Value % Divisor;

    if (currentRemainder <= Remainder)
    {
        return Value + (Remainder - currentRemainder);
    }
    return Value + (Divisor - currentRemainder) + Remainder;
}

NTSTATUS
T2NcmTxSendFrame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength
    )
{
    ULONG ndpOffset;
    ULONG ndpLength;
    ULONG datagramOffset;
    ULONG blockLength;
    PUCHAR buffer;
    T2NCM_WIRE_NTH16_TX nth;
    T2NCM_WIRE_NDP16_TX ndp;
    T2NCM_WIRE_NDP16_ENTRY_TX entries[2];
    WDF_MEMORY_DESCRIPTOR memDesc;
    ULONG bytesWritten = 0;
    NTSTATUS status;

    if (DeviceContext->BulkOutPipe == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmTxSendFrame called with no BulkOutPipe — "
            "T2NcmUsbActivateDataInterface must succeed first\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (DeviceContext->NtbOutMaxSize == 0 ||
        DeviceContext->NdpOutDivisor == 0 ||
        DeviceContext->NdpOutAlignment == 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmTxSendFrame called before NTB OUT geometry was "
            "negotiated — GET_NTB_PARAMETERS must succeed first\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (FrameLength < T2NCM_TX_MIN_ETHERNET_FRAME ||
        FrameLength > T2NCM_TX_MAX_ETHERNET_FRAME)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: TX frame length %lu outside [%u,%u] — rejecting\n",
            FrameLength, T2NCM_TX_MIN_ETHERNET_FRAME, T2NCM_TX_MAX_ETHERNET_FRAME));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return STATUS_INVALID_PARAMETER;
    }

    // Layout: NTH16, then NDP16 (aligned per NdpOutAlignment), then the
    // one datagram (placed per NdpOutDivisor/PayloadRemainder) — the
    // conventional NCM ordering, not one this device is known to
    // require, but nothing observed on real RX traffic (NcmRx.c) or in
    // the spec suggests the device cares about order as long as the
    // offsets it's told are honored.
    ndpOffset = T2NcmRoundUpToAlignment(T2NCM_TX_NTH16_LEN, DeviceContext->NdpOutAlignment);
    ndpLength = T2NCM_TX_NDP16_HEADER_LEN + (2u * T2NCM_TX_NDP16_ENTRY_LEN); // one real entry + terminator
    datagramOffset = T2NcmRoundUpToCongruence(
        ndpOffset + ndpLength, DeviceContext->NdpOutDivisor, DeviceContext->NdpOutPayloadRemainder);
    blockLength = datagramOffset + FrameLength;

    if (ndpOffset > T2NCM_TX_MAX_WIRE_OFFSET ||
        datagramOffset > T2NCM_TX_MAX_WIRE_OFFSET ||
        blockLength > T2NCM_TX_MAX_WIRE_OFFSET)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: TX layout (ndp=%lu datagram=%lu block=%lu) exceeds "
            "NTH16/NDP16's 16-bit offset fields — rejecting\n",
            ndpOffset, datagramOffset, blockLength));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return STATUS_INVALID_PARAMETER;
    }

    if (blockLength > DeviceContext->NtbOutMaxSize)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: TX blockLength=%lu exceeds negotiated NtbOutMaxSize=%lu "
            "— rejecting\n", blockLength, DeviceContext->NtbOutMaxSize));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return STATUS_INVALID_PARAMETER;
    }

    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, blockLength, T2NCM_POOL_TAG);
    if (buffer == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: TX buffer allocation failed (%lu bytes)\n", blockLength));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Zero the whole buffer first — the gaps between NTH16/NDP16/the
    // datagram (padding introduced by alignment/divisor rounding) must
    // never carry stale pool contents onto the wire.
    RtlZeroMemory(buffer, blockLength);

    nth.dwSignature   = T2NCM_TX_NTH16_SIGNATURE;
    nth.wHeaderLength = (USHORT)T2NCM_TX_NTH16_LEN;
    nth.wSequence     = DeviceContext->TxSequence++; // see driver.h: not
                                                       // Interlocked, this
                                                       // milestone only
                                                       // reaches here
                                                       // sequentially
    nth.wBlockLength  = (USHORT)blockLength;
    nth.wNdpIndex     = (USHORT)ndpOffset;
    RtlCopyMemory(buffer, &nth, sizeof(nth));

    ndp.dwSignature   = T2NCM_TX_NDP16_SIGNATURE;
    ndp.wLength       = (USHORT)ndpLength;
    ndp.wNextNdpIndex = 0; // only one NDP16 in this NTB
    RtlCopyMemory(buffer + ndpOffset, &ndp, sizeof(ndp));

    entries[0].wDatagramIndex  = (USHORT)datagramOffset;
    entries[0].wDatagramLength = (USHORT)FrameLength;
    entries[1].wDatagramIndex  = 0; // required zero/zero terminator
    entries[1].wDatagramLength = 0;
    RtlCopyMemory(buffer + ndpOffset + T2NCM_TX_NDP16_HEADER_LEN, entries, sizeof(entries));

    RtlCopyMemory(buffer + datagramOffset, Frame, FrameLength);

    WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&memDesc, buffer, blockLength);

    // Synchronous: this milestone's only caller is
    // IOCTL_T2NCM_SEND_TEST_FRAME, dispatched from the device's
    // sequential default queue at PASSIVE_LEVEL — there's no NDIS
    // MiniportSendNetBufferLists yet that would need this off an async,
    // possibly-DISPATCH_LEVEL path. Passing Request=NULL lets WDF
    // allocate and manage a one-shot internal request for this single
    // call, which is the documented pattern when the caller has no
    // request object of its own to reuse.
    status = WdfUsbTargetPipeWriteSynchronously(
        DeviceContext->BulkOutPipe, NULL, NULL, &memDesc, &bytesWritten);

    ExFreePoolWithTag(buffer, T2NCM_POOL_TAG);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: TX WdfUsbTargetPipeWriteSynchronously failed (0x%08X)\n",
            status));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return status;
    }

    if (bytesWritten != blockLength)
    {
        // A successful status with a short transfer would mean the
        // device only got part of the NTB — never treat that as "sent".
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: TX short write (%lu of %lu bytes) despite success "
            "status — treating as failed\n", bytesWritten, blockLength));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedIncrement64(&DeviceContext->TxNtbsSent);
    InterlockedIncrement64(&DeviceContext->TxFramesSent);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: TX NTB seq=%u block=%lu frameLen=%lu sent\n",
        nth.wSequence, blockLength, FrameLength));

    return STATUS_SUCCESS;
}
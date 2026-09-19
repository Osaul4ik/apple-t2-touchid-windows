// SPDX-License-Identifier: GPL-2.0-only
// NcmTx.c — NTB16 TX builder + bulk-OUT engine.
//
// This is the mirror image of NcmRx.c's parser: there we validated
// everything the device claims because it isn't trustworthy; here we
// CONTROL every offset, so the discipline is instead "never emit a field
// the device's negotiated geometry didn't ask for" — no fixed layout
// assumptions, no guessed padding.

#include "NcmTx.h"
#include "Device.h"
#include "NdisMiniport.h"

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
#define T2NCM_TX_MAX_ETHERNET_FRAME T2NCM_MAX_FRAME_SIZE // 1514, no jumbo

// NTH16/NDP16's own fields are all USHORT — a block/offset that doesn't
// fit is a wire-format ceiling, not a soft NtbOutMaxSize concern, so
// it's checked independently of that (which is a ULONG and could in
// principle be negotiated larger than 0xFFFF).
#define T2NCM_TX_MAX_WIRE_OFFSET   0xFFFFu

// Per-request bookkeeping for the asynchronous NBL path. Lives in the
// WDFREQUEST's own context so the completion routine needs no lookup
// and nothing has to be freed on a lost-request path.
typedef struct _T2NCM_TX_REQUEST_CONTEXT
{
    PT2NCM_DEVICE_CONTEXT DeviceContext;
    PNET_BUFFER_LIST      NetBufferList;
    PUCHAR                Buffer;
    ULONG                 BlockLength;
    ULONG                 FrameLength;
} T2NCM_TX_REQUEST_CONTEXT, *PT2NCM_TX_REQUEST_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T2NCM_TX_REQUEST_CONTEXT, T2NcmGetTxRequestContext)

// NBL->MiniportReserved[0] holds the count of NET_BUFFERs from that NBL
// still in flight. The NBL is completed to NDIS by whichever write
// completion drops it to zero. MiniportReserved is documented as
// miniport-owned scratch for exactly this.
#define T2NCM_TX_NBL_PENDING(_nbl) \
    (*(volatile LONG*)&((_nbl)->MiniportReserved[0]))

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

// Computes where the NDP16 and the single datagram have to sit for this
// device's negotiated OUT geometry. Pure arithmetic and validation — no
// allocation, no side effects — so both the NBL path and the diagnostic
// path can use it before deciding whether the frame is sendable at all.
static
NTSTATUS
T2NcmTxComputeLayout(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_  ULONG  FrameLength,
    _Out_ PULONG NdpOffset,
    _Out_ PULONG NdpLength,
    _Out_ PULONG DatagramOffset,
    _Out_ PULONG BlockLength
    )
{
    ULONG ndpOffset;
    ULONG ndpLength;
    ULONG datagramOffset;
    ULONG blockLength;

    *NdpOffset = 0;
    *NdpLength = 0;
    *DatagramOffset = 0;
    *BlockLength = 0;

    if (DeviceContext->NtbOutMaxSize == 0 ||
        DeviceContext->NdpOutDivisor == 0 ||
        DeviceContext->NdpOutAlignment == 0)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (FrameLength < T2NCM_TX_MIN_ETHERNET_FRAME ||
        FrameLength > T2NCM_TX_MAX_ETHERNET_FRAME)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // Layout: NTH16, then NDP16 (aligned per NdpOutAlignment), then the
    // one datagram (placed per NdpOutDivisor/PayloadRemainder) — the
    // conventional NCM ordering. Nothing observed on real RX traffic
    // (NcmRx.c) or in the spec suggests the device cares about order as
    // long as the offsets it's told are honored.
    ndpOffset = T2NcmRoundUpToAlignment(T2NCM_TX_NTH16_LEN, DeviceContext->NdpOutAlignment);
    ndpLength = T2NCM_TX_NDP16_HEADER_LEN + (2u * T2NCM_TX_NDP16_ENTRY_LEN); // one real entry + terminator
    datagramOffset = T2NcmRoundUpToCongruence(
        ndpOffset + ndpLength, DeviceContext->NdpOutDivisor,
        DeviceContext->NdpOutPayloadRemainder);
    blockLength = datagramOffset + FrameLength;

    if (ndpOffset > T2NCM_TX_MAX_WIRE_OFFSET ||
        datagramOffset > T2NCM_TX_MAX_WIRE_OFFSET ||
        blockLength > T2NCM_TX_MAX_WIRE_OFFSET)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (blockLength > DeviceContext->NtbOutMaxSize)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *NdpOffset = ndpOffset;
    *NdpLength = ndpLength;
    *DatagramOffset = datagramOffset;
    *BlockLength = blockLength;

    return STATUS_SUCCESS;
}

// Writes NTH16 + NDP16 + the two datagram entries into an
// already-zeroed buffer. The datagram payload itself is copied in by
// the caller, which knows where its bytes come from (a flat pointer for
// the diagnostic path, an MDL chain for the NBL path).
static
USHORT
T2NcmTxWriteHeaders(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_writes_bytes_(BlockLength) PUCHAR Buffer,
    _In_ ULONG NdpOffset,
    _In_ ULONG NdpLength,
    _In_ ULONG DatagramOffset,
    _In_ ULONG FrameLength,
    _In_ ULONG BlockLength
    )
{
    T2NCM_WIRE_NTH16_TX nth;
    T2NCM_WIRE_NDP16_TX ndp;
    T2NCM_WIRE_NDP16_ENTRY_TX entries[2];
    USHORT sequence;

    // Interlocked now: MiniportSendNetBufferLists can run concurrently
    // on several CPUs. wSequence only has to be non-repeating within a
    // reasonable window per the NCM spec, so a wrapping 16-bit
    // truncation of a 32-bit counter is fine.
    sequence = (USHORT)(InterlockedIncrement(&DeviceContext->TxSequence) & 0xFFFF);

    nth.dwSignature   = T2NCM_TX_NTH16_SIGNATURE;
    nth.wHeaderLength = (USHORT)T2NCM_TX_NTH16_LEN;
    nth.wSequence     = sequence;
    nth.wBlockLength  = (USHORT)BlockLength;
    nth.wNdpIndex     = (USHORT)NdpOffset;
    RtlCopyMemory(Buffer, &nth, sizeof(nth));

    ndp.dwSignature   = T2NCM_TX_NDP16_SIGNATURE;
    ndp.wLength       = (USHORT)NdpLength;
    ndp.wNextNdpIndex = 0; // only one NDP16 in this NTB
    RtlCopyMemory(Buffer + NdpOffset, &ndp, sizeof(ndp));

    entries[0].wDatagramIndex  = (USHORT)DatagramOffset;
    entries[0].wDatagramLength = (USHORT)FrameLength;
    entries[1].wDatagramIndex  = 0; // required zero/zero terminator
    entries[1].wDatagramLength = 0;
    RtlCopyMemory(Buffer + NdpOffset + T2NCM_TX_NDP16_HEADER_LEN, entries, sizeof(entries));

    return sequence;
}

static
VOID
T2NcmTxCountFrame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(T2NCM_MAC_LENGTH) const UCHAR* Destination,
    _In_ ULONG FrameLength
    )
{
    InterlockedAdd64(&DeviceContext->OutOctets, (LONG64)FrameLength);

    if (Destination[0] & 0x01)
    {
        if (Destination[0] == 0xFF && Destination[1] == 0xFF && Destination[2] == 0xFF &&
            Destination[3] == 0xFF && Destination[4] == 0xFF && Destination[5] == 0xFF)
        {
            InterlockedIncrement64(&DeviceContext->OutBroadcastPkts);
        }
        else
        {
            InterlockedIncrement64(&DeviceContext->OutMulticastPkts);
        }
    }
    else
    {
        InterlockedIncrement64(&DeviceContext->OutUcastPkts);
    }
}

// ---------------------------------------------------------------------
// Asynchronous NBL path
// ---------------------------------------------------------------------

// Completes one NET_BUFFER's worth of work against its parent NBL, and
// completes the NBL to NDIS if it was the last one outstanding.
static
VOID
T2NcmTxCompleteNetBuffer(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNET_BUFFER_LIST      Nbl,
    _In_ NDIS_STATUS           Status
    )
{
    // First failure wins: once an NBL is marked failed it stays failed,
    // because reporting success for a partially-sent NBL would be worse
    // than reporting a failure for a partially-successful one.
    if (Status != NDIS_STATUS_SUCCESS)
    {
        NET_BUFFER_LIST_STATUS(Nbl) = Status;
    }

    if (InterlockedDecrement(&T2NCM_TX_NBL_PENDING(Nbl)) == 0)
    {
        ULONG completeFlags = 0;

        if (KeGetCurrentIrql() == DISPATCH_LEVEL)
        {
            NDIS_SET_SEND_COMPLETE_FLAG(completeFlags,
                NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        }

        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
        NdisMSendNetBufferListsComplete(
            DeviceContext->MiniportAdapterHandle, Nbl, completeFlags);
    }
}

EVT_WDF_REQUEST_COMPLETION_ROUTINE T2NcmEvtTxWriteComplete;

VOID
T2NcmEvtTxWriteComplete(
    _In_ WDFREQUEST                     Request,
    _In_ WDFIOTARGET                    Target,
    _In_ PWDF_REQUEST_COMPLETION_PARAMS Params,
    _In_ WDFCONTEXT                     Context
    )
{
    PT2NCM_TX_REQUEST_CONTEXT requestContext = (PT2NCM_TX_REQUEST_CONTEXT)Context;
    PT2NCM_DEVICE_CONTEXT deviceContext = requestContext->DeviceContext;
    NTSTATUS status = Params->IoStatus.Status;
    size_t written = Params->Parameters.Usb.Completion->Parameters.PipeWrite.Length;
    NDIS_STATUS ndisStatus;

    UNREFERENCED_PARAMETER(Target);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: TX write failed 0x%08X\n", status));
        InterlockedIncrement64(&deviceContext->TxFramesRejected);
        InterlockedIncrement64(&deviceContext->OutErrors);
        ndisStatus = NDIS_STATUS_FAILURE;
    }
    else if (written != requestContext->BlockLength)
    {
        // A successful status with a short transfer would mean the
        // device only got part of the NTB — never treat that as "sent".
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: TX short write (%Iu of %lu bytes) despite success "
            "status - treating as failed\n", written, requestContext->BlockLength));
        InterlockedIncrement64(&deviceContext->TxFramesRejected);
        InterlockedIncrement64(&deviceContext->OutErrors);
        ndisStatus = NDIS_STATUS_FAILURE;
    }
    else
    {
        InterlockedIncrement64(&deviceContext->TxNtbsSent);
        InterlockedIncrement64(&deviceContext->TxFramesSent);
        T2NcmTxCountFrame(deviceContext, requestContext->Buffer +
            (requestContext->BlockLength - requestContext->FrameLength),
            requestContext->FrameLength);
        ndisStatus = NDIS_STATUS_SUCCESS;
    }

    T2NcmTxCompleteNetBuffer(deviceContext, requestContext->NetBufferList, ndisStatus);

    ExFreePoolWithTag(requestContext->Buffer, T2NCM_TX_POOL_TAG);

    // The WDFMEMORY is parented to the request, so deleting the request
    // releases it too.
    WdfObjectDelete(Request);

    InterlockedDecrement(&deviceContext->OutstandingTxRequests);
    T2NcmQuiesceCheck(deviceContext);
}

// Builds and submits one NTB for one NET_BUFFER. On any failure the
// caller's NBL reference for this NET_BUFFER is released here, so the
// caller never has to unwind.
static
VOID
T2NcmTxSubmitNetBuffer(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNET_BUFFER_LIST      Nbl,
    _In_ PNET_BUFFER           NetBuffer
    )
{
    NTSTATUS status;
    ULONG frameLength;
    ULONG ndpOffset, ndpLength, datagramOffset, blockLength;
    PUCHAR buffer = NULL;
    PVOID frameData;
    WDFREQUEST request = NULL;
    WDFMEMORY memory = NULL;
    WDF_OBJECT_ATTRIBUTES attributes;
    PT2NCM_TX_REQUEST_CONTEXT requestContext;
    BOOLEAN sent;

    frameLength = NET_BUFFER_DATA_LENGTH(NetBuffer);

    status = T2NcmTxComputeLayout(DeviceContext, frameLength,
        &ndpOffset, &ndpLength, &datagramOffset, &blockLength);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: TX layout rejected frame of %lu bytes (0x%08X)\n",
            frameLength, status));
        goto Fail;
    }

    // POOL_FLAG_NON_PAGED: this path can run at DISPATCH_LEVEL.
    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, blockLength, T2NCM_TX_POOL_TAG);
    if (buffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }

    // Zero the whole buffer first — the gaps between NTH16/NDP16/the
    // datagram (padding introduced by alignment/divisor rounding) must
    // never carry stale pool contents onto the wire. ExAllocatePool2
    // already zeroes, but the guarantee is worth stating where the
    // padding is created rather than relying on an allocator detail.
    RtlZeroMemory(buffer, blockLength);

    (VOID)T2NcmTxWriteHeaders(DeviceContext, buffer, ndpOffset, ndpLength,
        datagramOffset, frameLength, blockLength);

    // NdisGetDataBuffer flattens the MDL chain for us when it has to:
    // given a storage pointer it either returns a pointer to already-
    // contiguous data or copies into storage and returns that. Passing
    // the NTB's own datagram slot as storage means the common
    // (contiguous) case still costs one copy and the fragmented case
    // costs exactly the same one.
    frameData = NdisGetDataBuffer(NetBuffer, frameLength,
        buffer + datagramOffset, 1, 0);
    if (frameData == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }
    if (frameData != (PVOID)(buffer + datagramOffset))
    {
        RtlCopyMemory(buffer + datagramOffset, frameData, frameLength);
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, T2NCM_TX_REQUEST_CONTEXT);
    attributes.ParentObject = DeviceContext->WdfDevice;

    status = WdfRequestCreate(&attributes,
        WdfUsbTargetPipeGetIoTarget(DeviceContext->BulkOutPipe), &request);
    if (!NT_SUCCESS(status))
    {
        goto Fail;
    }

    requestContext = T2NcmGetTxRequestContext(request);
    requestContext->DeviceContext = DeviceContext;
    requestContext->NetBufferList = Nbl;
    requestContext->Buffer        = buffer;
    requestContext->BlockLength   = blockLength;
    requestContext->FrameLength   = frameLength;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = request;

    // Preallocated rather than WdfMemoryCreate: the buffer already
    // exists and is already non-paged, and WdfMemoryCreatePreallocated
    // is callable at DISPATCH_LEVEL without a pool-type argument to get
    // wrong.
    status = WdfMemoryCreatePreallocated(&attributes, buffer, blockLength, &memory);
    if (!NT_SUCCESS(status))
    {
        goto Fail;
    }

    status = WdfUsbTargetPipeFormatRequestForWrite(
        DeviceContext->BulkOutPipe, request, memory, NULL);
    if (!NT_SUCCESS(status))
    {
        goto Fail;
    }

    WdfRequestSetCompletionRoutine(request, T2NcmEvtTxWriteComplete, requestContext);

    // Count the request as outstanding BEFORE sending: the completion
    // can run before WdfRequestSend returns, and a decrement against a
    // count that had not been taken yet would let MiniportPause see
    // zero while a write was still in flight.
    InterlockedIncrement(&DeviceContext->OutstandingTxRequests);

    sent = WdfRequestSend(request,
        WdfUsbTargetPipeGetIoTarget(DeviceContext->BulkOutPipe),
        WDF_NO_SEND_OPTIONS);

    if (!sent)
    {
        status = WdfRequestGetStatus(request);
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfRequestSend (bulk OUT) failed 0x%08X\n", status));

        InterlockedDecrement(&DeviceContext->OutstandingTxRequests);
        T2NcmQuiesceCheck(DeviceContext);
        goto Fail;
    }

    return; // completion routine owns everything from here

Fail:
    if (request != NULL)
    {
        WdfObjectDelete(request);  // also releases the parented WDFMEMORY
    }
    if (buffer != NULL)
    {
        ExFreePoolWithTag(buffer, T2NCM_TX_POOL_TAG);
    }

    InterlockedIncrement64(&DeviceContext->TxFramesRejected);
    InterlockedIncrement64(&DeviceContext->OutDiscards);

    T2NcmTxCompleteNetBuffer(DeviceContext, Nbl, NDIS_STATUS_FAILURE);
}

VOID
T2NcmTxSendNetBufferLists(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNET_BUFFER_LIST      NetBufferLists,
    _In_ ULONG                 SendFlags
    )
{
    PNET_BUFFER_LIST nbl = NetBufferLists;

    UNREFERENCED_PARAMETER(SendFlags);

    while (nbl != NULL)
    {
        PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(nbl);
        PNET_BUFFER netBuffer;
        LONG netBufferCount = 0;

        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SUCCESS;

        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(nbl);
             netBuffer != NULL;
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer))
        {
            netBufferCount++;
        }

        if (netBufferCount == 0)
        {
            // An NBL with no NET_BUFFERs has nothing to send; complete
            // it as success rather than inventing a failure for it.
            ULONG completeFlags = 0;
            if (KeGetCurrentIrql() == DISPATCH_LEVEL)
            {
                NDIS_SET_SEND_COMPLETE_FLAG(completeFlags,
                    NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
            }
            NdisMSendNetBufferListsComplete(
                DeviceContext->MiniportAdapterHandle, nbl, completeFlags);
            nbl = next;
            continue;
        }

        // Take one extra reference for the duration of the submit loop
        // so that a completion arriving between two submits cannot
        // complete the NBL out from under the loop; released at the
        // bottom via T2NcmTxCompleteNetBuffer.
        T2NCM_TX_NBL_PENDING(nbl) = netBufferCount + 1;

        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(nbl);
             netBuffer != NULL;
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer))
        {
            T2NcmTxSubmitNetBuffer(DeviceContext, nbl, netBuffer);
        }

        T2NcmTxCompleteNetBuffer(DeviceContext, nbl, NDIS_STATUS_SUCCESS);

        nbl = next;
    }
}

// ---------------------------------------------------------------------
// Synchronous diagnostic path (IOCTL_T2NCM_SEND_TEST_FRAME)
// ---------------------------------------------------------------------

NTSTATUS
T2NcmTxSendFrame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength
    )
{
    ULONG ndpOffset, ndpLength, datagramOffset, blockLength;
    PUCHAR buffer;
    WDF_MEMORY_DESCRIPTOR memDesc;
    ULONG bytesWritten = 0;
    USHORT sequence;
    NTSTATUS status;

    if (DeviceContext->BulkOutPipe == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmTxSendFrame called with no BulkOutPipe - the data "
            "interface must be active first\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = T2NcmTxComputeLayout(DeviceContext, FrameLength,
        &ndpOffset, &ndpLength, &datagramOffset, &blockLength);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: TX layout rejected diagnostic frame of %lu bytes "
            "(0x%08X)\n", FrameLength, status));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return status;
    }

    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, blockLength, T2NCM_TX_POOL_TAG);
    if (buffer == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: TX buffer allocation failed (%lu bytes)\n", blockLength));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, blockLength);

    sequence = T2NcmTxWriteHeaders(DeviceContext, buffer, ndpOffset, ndpLength,
        datagramOffset, FrameLength, blockLength);

    RtlCopyMemory(buffer + datagramOffset, Frame, FrameLength);

    WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&memDesc, buffer, blockLength);

    // Synchronous is correct HERE and only here: the caller is the
    // diagnostic IOCTL dispatch, at PASSIVE_LEVEL, with no NDIS send
    // path involved. Passing Request=NULL lets WDF allocate and manage a
    // one-shot internal request for this single call.
    status = WdfUsbTargetPipeWriteSynchronously(
        DeviceContext->BulkOutPipe, NULL, NULL, &memDesc, &bytesWritten);

    ExFreePoolWithTag(buffer, T2NCM_TX_POOL_TAG);

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
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: TX short write (%lu of %lu bytes) despite success "
            "status - treating as failed\n", bytesWritten, blockLength));
        InterlockedIncrement64(&DeviceContext->TxFramesRejected);
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedIncrement64(&DeviceContext->TxNtbsSent);
    InterlockedIncrement64(&DeviceContext->TxFramesSent);
    T2NcmTxCountFrame(DeviceContext, Frame, FrameLength);

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: TX NTB seq=%u block=%lu frameLen=%lu sent\n",
        sequence, blockLength, FrameLength));

    return STATUS_SUCCESS;
}
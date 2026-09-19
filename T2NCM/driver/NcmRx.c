// SPDX-License-Identifier: GPL-2.0-only
// NcmRx.c — NTB16 RX parser + bulk-IN continuous reader + NDIS receive
// indication.
//
// The parser half is unchanged from the pre-NDIS milestone and keeps its
// discipline: nothing the device claims about its own buffer is trusted
// unless it also fits inside what USB actually delivered. What is new is
// the tail of the loop — each accepted datagram is now copied into an
// NBL and indicated to NDIS instead of only bumping a counter.
//
// Copy, not zero-copy, on purpose: the continuous reader owns its buffer
// and re-arms the read as soon as the completion returns, so the NTB is
// gone the moment this function exits. Handing NDIS an MDL over the
// reader's own buffer would mean the receive path could not be re-armed
// until the protocol stack was done with the frame, which is a far worse
// trade than one memcpy per frame on a 480 Mbit/s link.

#include "NcmRx.h"
#include "Device.h"
#include "NdisMiniport.h"

// ---- NTB16 / NDP16 wire structures (USB CDC-NCM 1.20 3.2-3.3),
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
    // datagram-pointer variant handled. NCM also defines a CRC variant
    // ("NCM1") and IPS-over-NCM subtypes; adding those needs real
    // capture evidence the T2 sends them, per this driver's "never
    // guess a wire format" rule.
#define T2NCM_NTH16_HEADER_LENGTH   12u
#define T2NCM_NDP16_HEADER_LENGTH   8u
#define T2NCM_ETHERNET_HEADER_LEN   14u  // dest(6) + src(6) + ethertype(2)

// Number of concurrently outstanding bulk-IN reads. Enough depth that
// the pipe is never starved between one completion and the next read
// being requeued, small enough that a paused adapter is not holding a
// large amount of pinned pool.
#define T2NCM_RX_PENDING_READS      4u

// Upper bound on frames indicated in a single NdisMIndicateReceive-
// NetBufferLists call. An NTB can in principle carry hundreds of
// datagrams; batching them all into one indication is fine, but the
// chain is built on the stack-walked list below and this keeps the
// per-NTB work bounded if a device ever reports an absurd entry count.
#define T2NCM_RX_MAX_BATCH          64u

// Per-NBL bookkeeping. NBLs come from a pool created with a context
// area of this size, so the frame buffer and its MDL can be found again
// in MiniportReturnNetBufferLists without a side table.
typedef struct _T2NCM_RX_NBL_CONTEXT
{
    PMDL   Mdl;
    PUCHAR Buffer;
    ULONG  Length;
} T2NCM_RX_NBL_CONTEXT, *PT2NCM_RX_NBL_CONTEXT;

NTSTATUS
T2NcmRxAllocateResources(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    NET_BUFFER_LIST_POOL_PARAMETERS poolParams;

    if (DeviceContext->RxNblPool != NULL)
    {
        return STATUS_SUCCESS; // idempotent
    }

    RtlZeroMemory(&poolParams, sizeof(poolParams));
    poolParams.Header.Type        = NDIS_OBJECT_TYPE_DEFAULT;
    poolParams.Header.Revision    = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParams.Header.Size        = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParams.ProtocolId         = NDIS_PROTOCOL_ID_DEFAULT;
    poolParams.fAllocateNetBuffer = TRUE;
    poolParams.ContextSize        = sizeof(T2NCM_RX_NBL_CONTEXT);
    poolParams.PoolTag            = T2NCM_RX_POOL_TAG;
    poolParams.DataSize           = 0;   // MDL supplied per allocation

    DeviceContext->RxNblPool = NdisAllocateNetBufferListPool(
        DeviceContext->MiniportAdapterHandle, &poolParams);

    if (DeviceContext->RxNblPool == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: NdisAllocateNetBufferListPool failed\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

VOID
T2NcmRxFreeResources(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    if (DeviceContext->RxNblPool != NULL)
    {
        // Caller contract (NcmRx.h): every indicated NBL has already
        // been returned. Freeing a pool with outstanding allocations is
        // a bugcheck, so this is not defensive-coded around — it would
        // only hide a real drain failure that MiniportPause/HaltEx
        // should have caught first.
        NdisFreeNetBufferListPool(DeviceContext->RxNblPool);
        DeviceContext->RxNblPool = NULL;
    }
}

// Returns TRUE if the current packet filter says this destination MAC
// should be delivered upward. The T2's NCM function has no hardware
// filter to program, so it sends whatever it sends and the filtering
// has to happen here — an adapter that ignores OID_GEN_CURRENT_PACKET_
// FILTER and indicates everything would leak traffic to protocols that
// explicitly asked not to see it.
static
BOOLEAN
T2NcmRxAcceptsFrame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(T2NCM_MAC_LENGTH) const UCHAR* Destination
    )
{
    ULONG filter = DeviceContext->PacketFilter;

    if (filter & NDIS_PACKET_TYPE_PROMISCUOUS)
    {
        return TRUE;
    }

    // Broadcast: all six bytes 0xFF.
    if (Destination[0] == 0xFF && Destination[1] == 0xFF && Destination[2] == 0xFF &&
        Destination[3] == 0xFF && Destination[4] == 0xFF && Destination[5] == 0xFF)
    {
        return (filter & NDIS_PACKET_TYPE_BROADCAST) != 0;
    }

    // Group bit set = multicast (broadcast already handled above).
    if (Destination[0] & 0x01)
    {
        if (filter & NDIS_PACKET_TYPE_ALL_MULTICAST)
        {
            return TRUE;
        }
        if ((filter & NDIS_PACKET_TYPE_MULTICAST) == 0)
        {
            return FALSE;
        }
        for (ULONG i = 0; i < DeviceContext->MulticastAddressCount; i++)
        {
            if (RtlCompareMemory(DeviceContext->MulticastList[i], Destination,
                    T2NCM_MAC_LENGTH) == T2NCM_MAC_LENGTH)
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    // Unicast.
    if (filter & NDIS_PACKET_TYPE_ALL_LOCAL)
    {
        return TRUE;
    }
    if ((filter & NDIS_PACKET_TYPE_DIRECTED) == 0)
    {
        return FALSE;
    }

    if (RtlCompareMemory(DeviceContext->CurrentMacAddress, Destination,
            T2NCM_MAC_LENGTH) == T2NCM_MAC_LENGTH)
    {
        return TRUE;
    }

    // Accept unicast addressed to somebody else ONLY when the station
    // address was not read from the device. On real REV_0201 hardware
    // the string table is empty, so there is no iMACAddress and the
    // adapter runs on a generated locally-administered address that the
    // T2 was never told about - it can and does address frames to a
    // different unicast address, and matching on ours would silently
    // drop every one of them. The link is point to point with exactly
    // one peer, so there is no other station whose traffic this could
    // be. When the address IS the device's own (MacAddressIsPermanent),
    // this relaxation is off and normal directed filtering applies.
    return !DeviceContext->MacAddressIsPermanent;
}

// Copies one datagram into a fresh NBL. Returns NULL on any allocation
// failure — the caller counts that as a discard rather than retrying,
// because the NTB buffer is about to be recycled by the reader anyway.
static
PNET_BUFFER_LIST
T2NcmRxBuildNbl(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(Length) const UCHAR* Frame,
    _In_ ULONG Length
    )
{
    PNET_BUFFER_LIST nbl;
    PT2NCM_RX_NBL_CONTEXT nblContext;
    PUCHAR buffer;
    PMDL mdl;

    buffer = (PUCHAR)NdisAllocateMemoryWithTagPriority(
        DeviceContext->MiniportAdapterHandle, Length, T2NCM_RX_POOL_TAG,
        NormalPoolPriority);
    if (buffer == NULL)
    {
        return NULL;
    }

    RtlCopyMemory(buffer, Frame, Length);

    mdl = NdisAllocateMdl(DeviceContext->MiniportAdapterHandle, buffer, Length);
    if (mdl == NULL)
    {
        NdisFreeMemory(buffer, 0, 0);
        return NULL;
    }

    nbl = NdisAllocateNetBufferAndNetBufferList(
        DeviceContext->RxNblPool,
        sizeof(T2NCM_RX_NBL_CONTEXT),  // ContextSize
        0,                              // ContextBackFill
        mdl,
        0,                              // DataOffset
        Length);
    if (nbl == NULL)
    {
        NdisFreeMdl(mdl);
        NdisFreeMemory(buffer, 0, 0);
        return NULL;
    }

    nblContext = (PT2NCM_RX_NBL_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    nblContext->Mdl    = mdl;
    nblContext->Buffer = buffer;
    nblContext->Length = Length;

    nbl->SourceHandle = DeviceContext->MiniportAdapterHandle;
    NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SUCCESS;

    return nbl;
}

VOID
T2NcmRxReturnNetBufferLists(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNET_BUFFER_LIST      NetBufferLists,
    _In_ ULONG                 ReturnFlags
    )
{
    PNET_BUFFER_LIST nbl = NetBufferLists;
    LONG returned = 0;

    UNREFERENCED_PARAMETER(ReturnFlags);

    while (nbl != NULL)
    {
        PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(nbl);
        PT2NCM_RX_NBL_CONTEXT nblContext =
            (PT2NCM_RX_NBL_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

        if (nblContext->Mdl != NULL)
        {
            NdisFreeMdl(nblContext->Mdl);
        }
        if (nblContext->Buffer != NULL)
        {
            NdisFreeMemory(nblContext->Buffer, 0, 0);
        }

        NdisFreeNetBufferList(nbl);
        returned++;

        nbl = next;
    }

    if (returned != 0)
    {
        InterlockedAdd(&DeviceContext->OutstandingRxNbls, -returned);

        // A pause that was waiting on this drain has to be woken by
        // whichever decrement reaches zero — see T2NcmQuiesceCheck.
        T2NcmQuiesceCheck(DeviceContext);
    }
}

static
VOID
T2NcmRxParseNtb(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(Length) const UCHAR* Buffer,
    _In_ size_t Length,
    _In_ BOOLEAN AtDispatchLevel
    )
{
    T2NCM_WIRE_NTH16 nth;
    T2NCM_WIRE_NDP16 ndp;
    ULONG blockLength;
    ULONG ndpOffset;
    ULONG ndpLength;
    ULONG entryCount;
    ULONG framesThisNtb = 0;
    PNET_BUFFER_LIST nblHead = NULL;
    PNET_BUFFER_LIST nblTail = NULL;

    InterlockedIncrement64(&DeviceContext->RxNtbsReceived);

    if (Length < sizeof(T2NCM_WIRE_NTH16))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTB shorter than NTH16 (%Iu bytes) — dropping\n", Length));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    // Buffer may not be naturally aligned for these field widths —
    // copy into a local struct rather than casting Buffer directly.
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

    for (ULONG i = 0; i < entryCount && framesThisNtb < T2NCM_RX_MAX_BATCH; i++)
    {
        T2NCM_WIRE_NDP16_ENTRY entry;
        // Same explicit-narrowing note as entryCount above.
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
            InterlockedIncrement64(&DeviceContext->InErrors);
            continue;
        }

        if (entry.wDatagramLength < T2NCM_ETHERNET_HEADER_LEN ||
            entry.wDatagramLength > T2NCM_MAX_FRAME_SIZE)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: RX datagram entry %u length %u outside [%u,%u] — "
                "skipping this datagram only\n",
                i, entry.wDatagramLength, T2NCM_ETHERNET_HEADER_LEN,
                T2NCM_MAX_FRAME_SIZE));
            InterlockedIncrement64(&DeviceContext->RxFramesRejected);
            InterlockedIncrement64(&DeviceContext->InErrors);
            continue;
        }

        {
            const UCHAR* frame = Buffer + entry.wDatagramIndex;
            PNET_BUFFER_LIST nbl;

            // Diagnostic snapshot, kept from the pre-NDIS milestone: it
            // is still the quickest way to tell "the parser is fine and
            // NDIS is dropping them" apart from "nothing is arriving".
            RtlCopyMemory(DeviceContext->RxLastFrameDest, frame, 6);
            RtlCopyMemory(DeviceContext->RxLastFrameSrc, frame + 6, 6);
            DeviceContext->RxLastFrameEtherType =
                (USHORT)((frame[12] << 8) | frame[13]); // network byte order
            DeviceContext->RxLastFrameLength = entry.wDatagramLength;

            InterlockedIncrement64(&DeviceContext->RxFramesParsed);

            if (!T2NcmRxAcceptsFrame(DeviceContext, frame))
            {
                InterlockedIncrement64(&DeviceContext->RxFramesFiltered);
                // Filtered out by OID_GEN_CURRENT_PACKET_FILTER. Not an
                // error and not a discard in the NDIS statistics sense —
                // the frame was never ours to deliver.
                continue;
            }

            nbl = T2NcmRxBuildNbl(DeviceContext, frame, entry.wDatagramLength);
            if (nbl == NULL)
            {
                InterlockedIncrement64(&DeviceContext->InDiscards);
                continue;
            }

            if (nblHead == NULL)
            {
                nblHead = nbl;
            }
            else
            {
                NET_BUFFER_LIST_NEXT_NBL(nblTail) = nbl;
            }
            nblTail = nbl;
            NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

            InterlockedAdd64(&DeviceContext->InOctets, (LONG64)entry.wDatagramLength);
            if (frame[0] & 0x01)
            {
                if (frame[0] == 0xFF && frame[1] == 0xFF && frame[2] == 0xFF &&
                    frame[3] == 0xFF && frame[4] == 0xFF && frame[5] == 0xFF)
                {
                    InterlockedIncrement64(&DeviceContext->InBroadcastPkts);
                }
                else
                {
                    InterlockedIncrement64(&DeviceContext->InMulticastPkts);
                }
            }
            else
            {
                InterlockedIncrement64(&DeviceContext->InUcastPkts);
            }

            framesThisNtb++;
        }
    }

    if (nblHead != NULL)
    {
        ULONG indicateFlags = 0;

        if (AtDispatchLevel)
        {
            NDIS_SET_RECEIVE_FLAG(indicateFlags, NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
        }

        // Take the outstanding-indication references BEFORE indicating.
        // NDIS is entitled to call MiniportReturnNetBufferLists from
        // inside this call on the same thread, so a reference taken
        // afterwards could be taken against a count that has already
        // gone negative.
        InterlockedAdd(&DeviceContext->OutstandingRxNbls, (LONG)framesThisNtb);
        InterlockedAdd64(&DeviceContext->RxFramesIndicated, (LONG64)framesThisNtb);

        NdisMIndicateReceiveNetBufferLists(
            DeviceContext->MiniportAdapterHandle,
            nblHead,
            NDIS_DEFAULT_PORT_NUMBER,
            framesThisNtb,
            indicateFlags);
    }

    // Per-NTB success trace deliberately removed (16.09.2026) - this ran on
    // every received NTB, i.e. continuously during any active traffic, and
    // flooded the debug output ("T2Ncm: RX NTB seq=... block=... frames=...").
    // RxNtbsReceived/RxFramesIndicated (incremented above/below) already give
    // the same information for diagnostics without per-packet spam; the
    // drop/error paths above keep their own T2NCM_LOG calls since those are
    // rare by construction.
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

    // The data-path gate. MiniportPause has already stopped the reader
    // by the time it returns, but a completion that was already in
    // flight can still land here afterwards; indicating from it would
    // hand NDIS a frame on a paused adapter, which is exactly what
    // pause means it must not receive. Cheap volatile read, checked on
    // every completion rather than assumed from the stop ordering.
    if (deviceContext->DataPathRunning == 0)
    {
        InterlockedIncrement64(&deviceContext->RxNtbsReceived);
        InterlockedIncrement64(&deviceContext->InDiscards);
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

    T2NcmRxParseNtb(deviceContext, buffer, NumBytesTransferred,
        (BOOLEAN)(KeGetCurrentIrql() == DISPATCH_LEVEL));
}

EVT_WDF_USB_READERS_FAILED T2NcmEvtRxReadersFailed;

BOOLEAN
T2NcmEvtRxReadersFailed(
    _In_    WDFUSBPIPE Pipe,
    _In_    NTSTATUS   Status,
    _In_    USBD_STATUS UsbdStatus
    )
{
    UNREFERENCED_PARAMETER(Pipe);

    // Returning FALSE: don't let the framework reset the pipe and
    // restart the reader on its own. An unbounded auto-restart loop on a
    // device that is actually gone (unplugged) is worse than stopping,
    // and under the inverted model the recovery path is NDIS's to drive
    // — a reset request or a halt/reinitialize — not a retry loop
    // hidden inside the read engine.
    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
        "T2Ncm: RX continuous reader stopped itself (status=0x%08X, "
        "usbdStatus=0x%08X) — bulk-IN reads will not resume until the "
        "adapter is restarted\n", Status, UsbdStatus));

    return FALSE;
}

NTSTATUS
T2NcmRxStart(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    WDF_USB_CONTINUOUS_READER_CONFIG readerConfig;
    WDF_USB_PIPE_INFORMATION pipeInfo;
    ULONG maxPacketSize;
    ULONG readerBufferSize;
    BOOLEAN reused;
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

    // WdfUsbTargetPipeConfigContinuousReader requires TransferLength to
    // be a multiple of the pipe's MaximumPacketSize (STATUS_INVALID_
    // BUFFER_SIZE otherwise — confirmed on real hardware: negotiated
    // NtbInMaxSize=32764 is NOT a multiple of the bulk endpoint's
    // 512-byte MaximumPacketSize). The device's own NtbInMaxSize is a
    // content-size limit, not a USB transfer-chunking one, so rounding
    // the READ buffer up to the next multiple is correct — it only
    // changes how much slack the last packet of a transfer can have,
    // never what T2NcmRxParseNtb is allowed to trust (that still
    // validates against the actual NumBytesTransferred, not this
    // buffer size).
    WDF_USB_PIPE_INFORMATION_INIT(&pipeInfo);
    WdfUsbTargetPipeGetInformation(DeviceContext->BulkInPipe, &pipeInfo);

    maxPacketSize = pipeInfo.MaximumPacketSize;
    if (maxPacketSize == 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: BulkInPipe reports MaximumPacketSize=0 — cannot size "
            "the continuous reader buffer\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Computed unconditionally (cheap arithmetic, no WDF call) so the
    // trailing log line below always has a real value, whether or not
    // this call actually reconfigures the reader.
    readerBufferSize =
        ((DeviceContext->NtbInMaxSize + maxPacketSize - 1) / maxPacketSize) * maxPacketSize;

    // WdfUsbTargetPipeConfigContinuousReader may be called only ONCE for
    // a given pipe object — calling it again on a pipe that already has
    // a continuous reader configured fails with STATUS_INVALID_DEVICE_
    // STATE (0xC0000184), confirmed on hardware. A plain NDIS Pause ->
    // Restart cycle (T2NcmMiniportPause/T2NcmMiniportRestart) does not
    // touch the USB alt setting and so keeps the exact same BulkInPipe
    // object across the cycle; only WdfIoTargetStop/Start should run
    // then. Only actually reconfigure when BulkInPipe is a pipe object
    // this function has not configured yet (fresh bring-up, or after
    // T2NcmUsbActivateDataInterface handed back a brand-new pipe on
    // re-arm — see driver.h and Power.c).
    if (!DeviceContext->RxReaderConfigured)
    {
        reused = FALSE;

        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
            "T2Ncm: T2NcmRxStart configuring continuous reader on a new "
            "pipe object (ntbMax=%lu, bufferSize=%lu, maxPacketSize=%lu)\n",
            DeviceContext->NtbInMaxSize, readerBufferSize, maxPacketSize));

        WDF_USB_CONTINUOUS_READER_CONFIG_INIT(
            &readerConfig,
            T2NcmEvtRxReadComplete,
            DeviceContext,
            readerBufferSize);

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

        DeviceContext->RxReaderConfigured = TRUE;
    }
    else
    {
        reused = TRUE;

        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
            "T2Ncm: T2NcmRxStart reusing existing reader config on the same "
            "pipe object (Pause/Restart cycle) — WdfIoTargetStart only\n"));
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
        "T2Ncm: RX continuous reader started (ntbMax=%lu, bufferSize=%lu, "
        "maxPacketSize=%lu, pendingReads=%u, reused=%u)\n",
        DeviceContext->NtbInMaxSize, readerBufferSize, maxPacketSize,
        T2NCM_RX_PENDING_READS, (ULONG)reused));

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
    // returning, so nothing races the pipe teardown that follows on a
    // halt path.
    WdfIoTargetStop(
        WdfUsbTargetPipeGetIoTarget(DeviceContext->BulkInPipe),
        WdfIoTargetCancelSentIo);

    DeviceContext->RxStarted = FALSE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: RX continuous reader stopped\n"));
}
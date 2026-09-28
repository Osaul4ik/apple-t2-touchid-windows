// SPDX-License-Identifier: GPL-2.0-only
// NcmRx.c — NTB16 RX parser + bulk-IN read loop + NDIS receive
// indication.
//
// The parser half is unchanged from the pre-NDIS milestone and keeps its
// discipline: nothing the device claims about its own buffer is trusted
// unless it also fits inside what USB actually delivered. What is new is
// the tail of the loop — each accepted datagram is now copied into an
// NBL and indicated to NDIS instead of only bumping a counter.
//
// Copy, not zero-copy, on purpose: the read loop owns its buffer and
// re-arms the read as soon as the completion returns, so the NTB is
// gone the moment this function exits. Handing NDIS an MDL over the
// reader's own buffer would mean the receive path could not be re-armed
// until the protocol stack was done with the frame, which is a far worse
// trade than one memcpy per frame on a 480 Mbit/s link.

#include "NcmRx.h"
#include "Tunnel.h"
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

// Number of concurrently outstanding bulk-IN reads (must not exceed
// T2NCM_RX_MAX_READ_SLOTS in driver.h). Enough depth that
// the pipe is never starved between one completion and the next read
// being requeued, small enough that a paused adapter is not holding a
// large amount of pinned pool.
#define T2NCM_RX_PENDING_READS      4u

// Upper bound on frames handed to NDIS in a single NdisMIndicateReceive-
// NetBufferLists call. An NTB can carry hundreds of datagrams, so the
// parser flushes a full batch and keeps going - the cap bounds the size
// of one indication, it must never bound how many datagrams of an NTB
// get delivered.
#define T2NCM_RX_MAX_BATCH          64u

// Upper bound on NDP16s followed in one NTB (wNextNdpIndex chain).
#define T2NCM_RX_MAX_NDPS           8u

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
        // Freeing a pool with outstanding allocations is a bugcheck.
        // MiniportPause/HaltEx must drain first; if a drain timed out
        // and left OutstandingRxNbls > 0, refuse the free rather than
        // crash — the pool leaks until unload, which is recoverable,
        // unlike a bugcheck on Halt during surprise-remove.
        LONG outstanding = InterlockedCompareExchange(
            (LONG volatile *)&DeviceContext->OutstandingRxNbls, 0, 0);
        if (outstanding != 0)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: T2NcmRxFreeResources skipped - %ld NBLs still outstanding "
                "(drain timed out?); leaving pool alive to avoid bugcheck\n",
                outstanding));
            return;
        }
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
    ULONG filter = T2NcmReadPacketFilter(DeviceContext);

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
        {
            BOOLEAN found = FALSE;
            KIRQL oldIrql;

            // The list is rewritten by OID_802_3_MULTICAST_LIST on another
            // CPU; see MulticastLock in driver.h.
            KeAcquireSpinLock(&DeviceContext->MulticastLock, &oldIrql);
            for (ULONG i = 0; i < DeviceContext->MulticastAddressCount; i++)
            {
                if (RtlCompareMemory(DeviceContext->MulticastList[i], Destination,
                        T2NCM_MAC_LENGTH) == T2NCM_MAC_LENGTH)
                {
                    found = TRUE;
                    break;
                }
            }
            KeReleaseSpinLock(&DeviceContext->MulticastLock, oldIrql);

            return found;
        }
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

    if (RtlCompareMemory(DeviceContext->PermanentMacAddress, Destination,
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

// Hands one chain of already-built NBLs to NDIS. Takes the outstanding-
// indication references BEFORE indicating: NDIS is entitled to call
// MiniportReturnNetBufferLists from inside this call on the same thread,
// so a reference taken afterwards could be taken against a count that
// has already gone negative.
static
VOID
T2NcmRxIndicateBatch(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNET_BUFFER_LIST      NblHead,
    _In_ ULONG                 NblCount,
    _In_ BOOLEAN               AtDispatchLevel
    )
{
    ULONG indicateFlags = 0;

    if (AtDispatchLevel)
    {
        NDIS_SET_RECEIVE_FLAG(indicateFlags, NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
    }

    InterlockedAdd(&DeviceContext->OutstandingRxNbls, (LONG)NblCount);
    InterlockedAdd64(&DeviceContext->RxFramesIndicated, (LONG64)NblCount);

    NdisMIndicateReceiveNetBufferLists(
        DeviceContext->MiniportAdapterHandle,
        NblHead,
        NDIS_DEFAULT_PORT_NUMBER,
        NblCount,
        indicateFlags);
}

// Validates one NDP16 against what USB actually delivered and reports how
// many datagram entries it holds. Returns FALSE (after logging and
// counting the rejection) if the NDP16 cannot be trusted, in which case
// the caller stops walking the chain but still delivers whatever earlier
// NDP16s already produced.
static
BOOLEAN
T2NcmRxReadNdp(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(BlockLength) const UCHAR* Buffer,
    _In_  ULONG BlockLength,
    _In_  ULONG NdpOffset,
    _Out_ T2NCM_WIRE_NDP16* Ndp,
    _Out_ PULONG EntryCount
    )
{
    ULONG ndpLength;

    // Defined on EVERY path, including the FALSE returns: the caller only
    // reads them after a TRUE return, but an _Out_ parameter that some
    // path leaves unwritten is exactly what PREfast (C6101) rejects.
    RtlZeroMemory(Ndp, sizeof(*Ndp));
    *EntryCount = 0;

    if (NdpOffset < sizeof(T2NCM_WIRE_NTH16) ||
        NdpOffset + T2NCM_NDP16_HEADER_LENGTH > BlockLength)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX NDP16 offset %u out of bounds (block=%u) - dropping NDP\n",
            NdpOffset, BlockLength));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return FALSE;
    }

    RtlCopyMemory(Ndp, Buffer + NdpOffset, sizeof(*Ndp));

    if (Ndp->dwSignature != T2NCM_NDP16_SIGNATURE_NOCRC)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NDP16 signature 0x%08X not the handled NCM0 variant - "
            "dropping NDP\n", Ndp->dwSignature));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return FALSE;
    }

    ndpLength = Ndp->wLength;
    if (ndpLength < T2NCM_NDP16_HEADER_LENGTH ||
        NdpOffset + ndpLength > BlockLength ||
        ((ndpLength - T2NCM_NDP16_HEADER_LENGTH) % sizeof(T2NCM_WIRE_NDP16_ENTRY)) != 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX NDP16 wLength=%u invalid/out of bounds (block=%u) - "
            "dropping NDP\n", ndpLength, BlockLength));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return FALSE;
    }

    // Explicit cast: (ULONG - unsigned literal) / sizeof(...) promotes to
    // size_t before the divide, and the count is intentionally ULONG
    // (bounded by ndpLength, a USHORT-derived value) - /W4 flags the
    // implicit narrowing on assignment even though nothing can be lost.
    *EntryCount = (ULONG)((ndpLength - T2NCM_NDP16_HEADER_LENGTH) / sizeof(T2NCM_WIRE_NDP16_ENTRY));

    return TRUE;
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
    ULONG entryCount;
    ULONG framesThisNtb = 0;
    PNET_BUFFER_LIST nblHead = NULL;
    PNET_BUFFER_LIST nblTail = NULL;

    InterlockedIncrement64(&DeviceContext->RxNtbsReceived);

    if (Length < sizeof(T2NCM_WIRE_NTH16))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTB shorter than NTH16 (%Iu bytes) - dropping\n", Length));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    // Buffer may not be naturally aligned for these field widths —
    // copy into a local struct rather than casting Buffer directly.
    RtlCopyMemory(&nth, Buffer, sizeof(nth));

    if (nth.dwSignature != T2NCM_NTH16_SIGNATURE)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTH16 signature mismatch (0x%08X) - dropping NTB\n",
            nth.dwSignature));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    if (nth.wHeaderLength != T2NCM_NTH16_HEADER_LENGTH)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTH16 wHeaderLength=%u (expected %u) - dropping NTB\n",
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
            "T2Ncm: RX NTH16 wBlockLength=%u out of bounds (received %Iu) - "
            "dropping NTB\n", blockLength, Length));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    if (DeviceContext->NtbInMaxSize != 0 && blockLength > DeviceContext->NtbInMaxSize)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: RX NTB blockLength=%u exceeds negotiated NtbInMaxSize=%lu - "
            "dropping NTB\n", blockLength, DeviceContext->NtbInMaxSize));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    ndpOffset = nth.wNdpIndex;

    // An NTB may carry a chain of NDP16s (wNextNdpIndex != 0). Walk all of
    // them - stopping after the first would silently drop every datagram
    // described by the later ones. The chain is bounded, and each link has
    // to move strictly forward, so a malformed device cannot loop it.
    for (ULONG ndpCount = 0; ndpCount < T2NCM_RX_MAX_NDPS; ndpCount++)
    {
        if (!T2NcmRxReadNdp(DeviceContext, Buffer, blockLength, ndpOffset,
                &ndp, &entryCount))
        {
            break; // logged and counted inside; keep what was parsed so far
        }

        for (ULONG i = 0; i < entryCount; i++)
        {
            T2NCM_WIRE_NDP16_ENTRY entry;
            // Explicit narrowing, same reasoning as the entry count in
            // T2NcmRxReadNdp.
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
                    "block=%u) - skipping this datagram only\n",
                    i, entry.wDatagramIndex, entry.wDatagramLength, blockLength));
                InterlockedIncrement64(&DeviceContext->RxFramesRejected);
                InterlockedIncrement64(&DeviceContext->InErrors);
                continue;
            }

            if (entry.wDatagramLength < T2NCM_ETHERNET_HEADER_LEN ||
                entry.wDatagramLength > T2NCM_MAX_FRAME_SIZE)
            {
                T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                    "T2Ncm: RX datagram entry %u length %u outside [%u,%u] - "
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
                UCHAR tunFrame[T2NCM_MAX_FRAME_SIZE];
                ULONG tunLen = entry.wDatagramLength;
                const UCHAR* deliver = frame;

                if (tunLen <= sizeof(tunFrame))
                {
                    RtlCopyMemory(tunFrame, frame, tunLen);
                    if (T2NcmTunnelRewriteRxIpv6ToIpv4(DeviceContext, tunFrame, &tunLen))
                    {
                        deliver = tunFrame;
                    }
                    else
                    {
                        tunLen = entry.wDatagramLength;
                        deliver = frame;
                    }
                }

                // Diagnostic snapshot, kept from the pre-NDIS milestone: it
                // is still the quickest way to tell "the parser is fine and
                // NDIS is dropping them" apart from "nothing is arriving".
                RtlCopyMemory(DeviceContext->RxLastFrameDest, deliver, 6);
                RtlCopyMemory(DeviceContext->RxLastFrameSrc, deliver + 6, 6);
                DeviceContext->RxLastFrameEtherType =
                    (USHORT)((deliver[12] << 8) | deliver[13]); // network byte order
                DeviceContext->RxLastFrameLength = (tunLen > 0xFFFFu) ? (USHORT)0xFFFF : (USHORT)tunLen;

                InterlockedIncrement64(&DeviceContext->RxFramesParsed);

                if (!T2NcmRxAcceptsFrame(DeviceContext, deliver))
                {
                    InterlockedIncrement64(&DeviceContext->RxFramesFiltered);
                    // Filtered out by OID_GEN_CURRENT_PACKET_FILTER. Not an
                    // error and not a discard in the NDIS statistics sense —
                    // the frame was never ours to deliver.
                    continue;
                }

                nbl = T2NcmRxBuildNbl(DeviceContext, deliver, tunLen);
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

                InterlockedAdd64(&DeviceContext->InOctets, (LONG64)tunLen);
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

                if (framesThisNtb == T2NCM_RX_MAX_BATCH)
                {
                    // Full batch: indicate it and start a new chain instead
                    // of abandoning the rest of the NTB's datagrams.
                    T2NcmRxIndicateBatch(DeviceContext, nblHead, framesThisNtb,
                        AtDispatchLevel);
                    nblHead = NULL;
                    nblTail = NULL;
                    framesThisNtb = 0;
                }
            }
        }

        if (ndp.wNextNdpIndex == 0)
        {
            break; // last NDP16 in this NTB
        }

        if (ndp.wNextNdpIndex <= ndpOffset)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm: RX NDP16 wNextNdpIndex=%u does not advance past %u - "
                "ignoring the rest of the chain\n",
                ndp.wNextNdpIndex, ndpOffset));
            InterlockedIncrement64(&DeviceContext->RxFramesRejected);
            break;
        }

        ndpOffset = ndp.wNextNdpIndex;
    }

    if (nblHead != NULL)
    {
        T2NcmRxIndicateBatch(DeviceContext, nblHead, framesThisNtb,
            AtDispatchLevel);
    }

    // Per-NTB success trace deliberately removed (16.09.2026) - this ran on
    // every received NTB, i.e. continuously during any active traffic, and
    // flooded the debug output ("T2Ncm: RX NTB seq=... block=... frames=...").
    // RxNtbsReceived/RxFramesIndicated (incremented above/below) already give
    // the same information for diagnostics without per-packet spam; the
    // drop/error paths above keep their own T2NCM_LOG calls since those are
    // rare by construction.
}

// ---------------------------------------------------------------------
// Bulk-IN read engine.
//
// This is a hand-rolled request loop, NOT WdfUsbTargetPipeConfigContinuous-
// Reader. The framework's continuous reader recovers from a failed read by
// queueing a work item that calls FxUsbPipeContinuousReader::CancelRepeaters
// and cancels every sibling read - including reads that WdfIoTargetStop
// (CancelSentIo) had just cancelled itself. On this hardware AppleUSBVHCI
// completes a cancelled read with STATUS_UNSUCCESSFUL (0xC0000001) instead
// of STATUS_CANCELLED, so every stop looked like a failed read to WDF, the
// recovery work item ran, and its second IoCancelIrp reached VHCI's
// EvtIoCanceledOnQueue for an IRP VHCI had already completed: IoFreeMdl
// ran twice and the kernel heap bugchecked (0x13A, arg1 0x11, pool tag
// 'Mdl_', AppleUSBVHCI+0x1d5de in the dump).
//
// The loop below never cancels anything on its own. A read that completes
// with an error is simply not re-sent, and the only cancel a request ever
// sees is the single one WdfIoTargetStop issues from T2NcmRxStop.
//
// Ownership rules:
//   * RxReadRequests[] holds T2NCM_RX_PENDING_READS WDFREQUESTs, created
//     against the CURRENT bulk-IN pipe's I/O target in T2NcmRxStart and
//     deleted in T2NcmRxStop. A request never outlives the pipe object it
//     was created for (alt-setting re-selection replaces the pipe).
//   * RxReadsRunning is the gate: a completion re-sends its request only
//     while it is 1. T2NcmRxStop clears it before stopping the target.
//   * RxReadsOutstanding counts requests owned by the USB stack or by a
//     completion routine. A resend takes its own count BEFORE the
//     completing routine drops the old one, so the count never touches 0
//     while the loop is alive; T2NcmRxStop waits for 0 before deleting.
// ---------------------------------------------------------------------

#define T2NCM_RX_STOP_DRAIN_POLL_MS     10u
#define T2NCM_RX_STOP_DRAIN_TIMEOUT_MS  5000u

C_ASSERT(T2NCM_RX_PENDING_READS <= T2NCM_RX_MAX_READ_SLOTS);

typedef struct _T2NCM_RX_READ_CONTEXT
{
    PT2NCM_DEVICE_CONTEXT DeviceContext;
    WDFMEMORY             Memory;   // parented to the request
} T2NCM_RX_READ_CONTEXT, *PT2NCM_RX_READ_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T2NCM_RX_READ_CONTEXT, T2NcmGetRxReadContext)

EVT_WDF_REQUEST_COMPLETION_ROUTINE T2NcmEvtRxReadComplete;

// Formats and sends one read. On FALSE the request is NOT in flight and
// no outstanding count is held for it.
static
BOOLEAN
T2NcmRxSubmitRead(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST            Request
    )
{
    PT2NCM_RX_READ_CONTEXT readContext = T2NcmGetRxReadContext(Request);
    NTSTATUS status;

    status = WdfUsbTargetPipeFormatRequestForRead(
        DeviceContext->RxPipe, Request, readContext->Memory, NULL);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX FormatRequestForRead failed (0x%08X)\n", status));
        return FALSE;
    }

    WdfRequestSetCompletionRoutine(Request, T2NcmEvtRxReadComplete, readContext);

    // Count BEFORE sending: the completion can run before WdfRequestSend
    // returns, and T2NcmRxStop must never see 0 while a read is in flight.
    InterlockedIncrement(&DeviceContext->RxReadsOutstanding);

    if (!WdfRequestSend(Request,
            WdfUsbTargetPipeGetIoTarget(DeviceContext->RxPipe),
            WDF_NO_SEND_OPTIONS))
    {
        status = WdfRequestGetStatus(Request);
        InterlockedDecrement(&DeviceContext->RxReadsOutstanding);

        // A resend racing T2NcmRxStop lands on a stopped target and fails
        // here; that is the expected, quiet way for the loop to end.
        if (DeviceContext->RxReadsRunning != 0)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: RX WdfRequestSend failed (0x%08X) - read not re-armed\n",
                status));
        }
        return FALSE;
    }

    return TRUE;
}

// One completed bulk-IN transfer that succeeded: gate checks, then hand
// the NTB to the parser. Same rules as the old continuous-reader callback.
static
VOID
T2NcmRxHandleRead(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PT2NCM_RX_READ_CONTEXT ReadContext,
    _In_ size_t NumBytesTransferred
    )
{
    const UCHAR* buffer;

    if (NumBytesTransferred == 0)
    {
        // A legitimate zero-length packet (NCM/USB ZLP framing), not an
        // error - nothing to parse.
        return;
    }

    // The data-path gate. MiniportPause has already stopped the reader
    // by the time it returns, but a completion that was already in
    // flight can still land here afterwards; indicating from it would
    // hand NDIS a frame on a paused adapter, which is exactly what
    // pause means it must not receive. Cheap volatile read, checked on
    // every completion rather than assumed from the stop ordering.
    if (DeviceContext->DataPathRunning == 0)
    {
        InterlockedIncrement64(&DeviceContext->RxNtbsReceived);
        InterlockedIncrement64(&DeviceContext->InDiscards);
        return;
    }

    buffer = (const UCHAR*)WdfMemoryGetBuffer(ReadContext->Memory, NULL);
    if (buffer == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX read completion had a NULL buffer - dropping\n"));
        InterlockedIncrement64(&DeviceContext->RxFramesRejected);
        return;
    }

    T2NcmRxParseNtb(DeviceContext, buffer, NumBytesTransferred,
        (BOOLEAN)(KeGetCurrentIrql() == DISPATCH_LEVEL));
}

VOID
T2NcmEvtRxReadComplete(
    _In_ WDFREQUEST                     Request,
    _In_ WDFIOTARGET                    Target,
    _In_ PWDF_REQUEST_COMPLETION_PARAMS Params,
    _In_ WDFCONTEXT                     Context
    )
{
    PT2NCM_RX_READ_CONTEXT readContext = (PT2NCM_RX_READ_CONTEXT)Context;
    PT2NCM_DEVICE_CONTEXT deviceContext = readContext->DeviceContext;
    NTSTATUS status = Params->IoStatus.Status;

    UNREFERENCED_PARAMETER(Target);

    if (NT_SUCCESS(status))
    {
        T2NcmRxHandleRead(deviceContext, readContext,
            Params->Parameters.Usb.Completion->Parameters.PipeRead.Length);

        if (deviceContext->RxReadsRunning != 0)
        {
            WDF_REQUEST_REUSE_PARAMS reuse;

            WDF_REQUEST_REUSE_PARAMS_INIT(&reuse,
                WDF_REQUEST_REUSE_NO_FLAGS, STATUS_SUCCESS);

            status = WdfRequestReuse(Request, &reuse);
            if (NT_SUCCESS(status))
            {
                // Takes its own outstanding count before ours is dropped
                // below. Failure is logged inside and simply retires
                // this slot.
                (VOID)T2NcmRxSubmitRead(deviceContext, Request);
            }
            else
            {
                T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                    "T2Ncm: RX WdfRequestReuse failed (0x%08X) - read not re-armed\n",
                    status));
            }
        }
    }
    else if (deviceContext->RxReadsRunning != 0)
    {
        // A genuine failure while the loop is supposed to be running. The
        // slot is retired (no resend); the other slots keep running, and
        // if the device is really gone they all end up here. Recovery is
        // NDIS's to drive (reset, or halt/reinitialize), same policy the
        // old EvtReadersFailed=FALSE expressed.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RX bulk-IN read failed (status=0x%08X) - slot retired, "
            "not re-armed until the adapter is restarted\n", status));
        InterlockedIncrement64(&deviceContext->InErrors);
    }
    // else: a stop is in progress and this is the cancelled read coming
    // back. AppleUSBVHCI reports that as 0xC0000001, which is expected
    // here and deliberately neither logged nor counted.

    InterlockedDecrement(&deviceContext->RxReadsOutstanding);
}

static
VOID
T2NcmRxDeleteReadRequests(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    ULONG i;

    for (i = 0; i < T2NCM_RX_MAX_READ_SLOTS; i++)
    {
        if (DeviceContext->RxReadRequests[i] != NULL)
        {
            // Also releases the parented WDFMEMORY.
            WdfObjectDelete(DeviceContext->RxReadRequests[i]);
            DeviceContext->RxReadRequests[i] = NULL;
        }
    }
}

// Shared by T2NcmRxStop and the failure path of T2NcmRxStart. PASSIVE_LEVEL
// only (WdfIoTargetStop with CancelSentIo, and a sleeping drain wait).
static
VOID
T2NcmRxTeardownReads(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    ULONG waitedMs = 0;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    // Close the gate first so a completion racing the stop does not queue
    // a fresh read; one that slips through anyway fails on the stopped
    // target inside T2NcmRxSubmitRead.
    InterlockedExchange(&DeviceContext->RxReadsRunning, 0);

    if (DeviceContext->RxPipe != NULL)
    {
        // The ONLY cancel this engine ever issues.
        WdfIoTargetStop(
            WdfUsbTargetPipeGetIoTarget(DeviceContext->RxPipe),
            WdfIoTargetCancelSentIo);
    }

    // Wait until no request is owned by the USB stack or a completion
    // routine. Deleting a request that is still in flight is a bugcheck,
    // so on timeout the requests are leaked instead (T2NcmRxStart refuses
    // to run over a non-zero count).
    while (InterlockedCompareExchange(
               (LONG volatile *)&DeviceContext->RxReadsOutstanding, 0, 0) != 0)
    {
        LARGE_INTEGER delay;

        if (waitedMs >= T2NCM_RX_STOP_DRAIN_TIMEOUT_MS)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: RX stop timed out with %ld read(s) still outstanding - "
                "leaking the read requests rather than deleting them in flight\n",
                DeviceContext->RxReadsOutstanding));
            return;
        }

        delay.QuadPart = -((LONGLONG)T2NCM_RX_STOP_DRAIN_POLL_MS * 10000);
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        waitedMs += T2NCM_RX_STOP_DRAIN_POLL_MS;
    }

    T2NcmRxDeleteReadRequests(DeviceContext);
    DeviceContext->RxPipe = NULL;
}

NTSTATUS
T2NcmRxStart(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    WDF_USB_PIPE_INFORMATION pipeInfo;
    ULONG maxPacketSize;
    ULONG readBufferSize;
    ULONG i;
    NTSTATUS status;

    if (DeviceContext->RxStarted)
    {
        return STATUS_SUCCESS; // idempotent, see NcmRx.h
    }

    if (DeviceContext->BulkInPipe == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmRxStart called with no BulkInPipe - "
            "T2NcmUsbActivateDataInterface must succeed first\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (DeviceContext->NtbInMaxSize == 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmRxStart called with NtbInMaxSize=0 - "
            "GET_NTB_PARAMETERS must succeed first\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    // A previous stop that timed out left requests in flight; starting a
    // second set on top of them would orphan them.
    if (InterlockedCompareExchange(
            (LONG volatile *)&DeviceContext->RxReadsOutstanding, 0, 0) != 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: T2NcmRxStart refused - %ld read(s) from a previous "
            "run are still outstanding\n", DeviceContext->RxReadsOutstanding));
        return STATUS_DEVICE_BUSY;
    }

    // Idle leftovers (a stop that finished draining always deletes them,
    // but be explicit that nothing stale is ever reused).
    T2NcmRxDeleteReadRequests(DeviceContext);

    // The read buffer must be a multiple of the pipe's MaximumPacketSize
    // (WdfUsbTargetPipeFormatRequestForRead rejects it otherwise -
    // confirmed on real hardware: negotiated NtbInMaxSize=32764 is NOT a
    // multiple of the bulk endpoint's 512-byte MaximumPacketSize). The
    // device's own NtbInMaxSize is a content-size limit, not a USB
    // transfer-chunking one, so rounding the READ buffer up to the next
    // multiple is correct - it only changes how much slack the last packet
    // of a transfer can have, never what T2NcmRxParseNtb is allowed to
    // trust (that still validates against the actual bytes transferred,
    // not this buffer size).
    WDF_USB_PIPE_INFORMATION_INIT(&pipeInfo);
    WdfUsbTargetPipeGetInformation(DeviceContext->BulkInPipe, &pipeInfo);

    maxPacketSize = pipeInfo.MaximumPacketSize;
    if (maxPacketSize == 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: BulkInPipe reports MaximumPacketSize=0 - cannot size "
            "the read buffers\n"));
        return STATUS_INVALID_DEVICE_STATE;
    }

    readBufferSize =
        ((DeviceContext->NtbInMaxSize + maxPacketSize - 1) / maxPacketSize) * maxPacketSize;

    DeviceContext->RxPipe = DeviceContext->BulkInPipe;
    DeviceContext->RxReadBufferSize = readBufferSize;

    // Pipe I/O targets are stopped after a stop and must be started
    // again; a fresh pipe object after an alt-setting switch needs it too.
    status = WdfIoTargetStart(WdfUsbTargetPipeGetIoTarget(DeviceContext->RxPipe));
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: WdfIoTargetStart(BulkInPipe) failed (0x%08X)\n", status));
        DeviceContext->RxPipe = NULL;
        return status;
    }

    for (i = 0; i < T2NCM_RX_PENDING_READS; i++)
    {
        WDF_OBJECT_ATTRIBUTES attributes;
        WDFREQUEST request = NULL;
        WDFMEMORY memory = NULL;
        PT2NCM_RX_READ_CONTEXT readContext;

        WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, T2NCM_RX_READ_CONTEXT);
        attributes.ParentObject = DeviceContext->WdfDevice;

        status = WdfRequestCreate(&attributes,
            WdfUsbTargetPipeGetIoTarget(DeviceContext->RxPipe), &request);
        if (!NT_SUCCESS(status))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: WdfRequestCreate (bulk-IN read %lu) failed (0x%08X)\n",
                i, status));
            goto Fail;
        }

        // Stored before anything else can fail, so Fail: deletes it.
        DeviceContext->RxReadRequests[i] = request;

        WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
        attributes.ParentObject = request;

        status = WdfMemoryCreate(&attributes, NonPagedPoolNx, T2NCM_RX_POOL_TAG,
            readBufferSize, &memory, NULL);
        if (!NT_SUCCESS(status))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: WdfMemoryCreate (bulk-IN read %lu, %lu bytes) failed (0x%08X)\n",
                i, readBufferSize, status));
            goto Fail;
        }

        readContext = T2NcmGetRxReadContext(request);
        readContext->DeviceContext = DeviceContext;
        readContext->Memory        = memory;
    }

    // Open the gate before the first send: a completion can arrive before
    // the loop below has submitted every slot.
    InterlockedExchange(&DeviceContext->RxReadsRunning, 1);

    for (i = 0; i < T2NCM_RX_PENDING_READS; i++)
    {
        if (!T2NcmRxSubmitRead(DeviceContext, DeviceContext->RxReadRequests[i]))
        {
            status = STATUS_UNSUCCESSFUL;
            goto Fail;
        }
    }

    DeviceContext->RxStarted = TRUE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: RX read loop started (ntbMax=%lu, bufferSize=%lu, "
        "maxPacketSize=%lu, pendingReads=%u)\n",
        DeviceContext->NtbInMaxSize, readBufferSize, maxPacketSize,
        T2NCM_RX_PENDING_READS));

    return STATUS_SUCCESS;

Fail:
    // Cancels whatever did get sent, waits for it, deletes every slot.
    T2NcmRxTeardownReads(DeviceContext);
    return status;
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

    // Cancels outstanding reads (once - nothing else cancels them), waits
    // for every completion routine to finish, and only then deletes the
    // requests, so nothing races the pipe teardown that follows on a halt
    // path.
    T2NcmRxTeardownReads(DeviceContext);

    DeviceContext->RxStarted = FALSE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: RX read loop stopped\n"));
}
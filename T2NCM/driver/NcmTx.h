// SPDX-License-Identifier: GPL-2.0-only
// NcmTx.h — NTB16 TX builder + bulk-OUT engine.
//
// Two entry points, one wire format:
//
//   T2NcmTxSendNetBufferLists  the real path. Called by
//       MiniportSendNetBufferLists, possibly at DISPATCH_LEVEL and
//       possibly on several CPUs at once, so everything it does is
//       asynchronous — WdfRequestSend with a completion routine, never
//       WdfUsbTargetPipeWriteSynchronously.
//
//   T2NcmTxSendFrame           the diagnostic path, kept from the
//       pre-NDIS milestone. Synchronous, PASSIVE_LEVEL only, one raw
//       Ethernet frame from IOCTL_T2NCM_SEND_TEST_FRAME. Still useful
//       for putting a known frame on the wire without involving the
//       TCP/IP stack at all when bringing the adapter up on hardware.
//
// Both honor the device's negotiated NdpOutDivisor/PayloadRemainder/
// Alignment geometry rather than assuming a fixed layout — those values
// came from GET_NTB_PARAMETERS specifically to tell the host where the
// device's OUT direction requires things to sit.
//
// Neither checks whether the data path is allowed to run; that gate
// belongs to the caller (MiniportSendNetBufferLists checks
// DataPathRunning, the IOCTL handler checks the lifecycle state),
// because only the caller knows how to report a refusal.
#pragma once
#include "Driver.h"

// Sends a chain of NBLs. Takes ownership of the chain: every NBL is
// completed through NdisMSendNetBufferListsComplete exactly once, either
// here (immediate refusal) or from the bulk-OUT write completion.
//
// One NTB per NET_BUFFER, single datagram each. Batching several
// datagrams into one NTB is legal and would cut per-frame USB overhead,
// but it also means one failed write drops several frames and needs a
// per-NTB refcount across NBLs; that optimization is worth doing only
// once there is real throughput data from hardware to justify it.
VOID
T2NcmTxSendNetBufferLists(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ PNET_BUFFER_LIST      NetBufferLists,
    _In_ ULONG                 SendFlags
    );

// Wraps Frame in a single-datagram NTB16 and writes it to
// DeviceContext->BulkOutPipe synchronously. PASSIVE_LEVEL only.
//
// Frame must be a complete Ethernet II frame (dest+src+ethertype+
// payload, no FCS) between 14 and 1514 bytes.
NTSTATUS
T2NcmTxSendFrame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength
    );
// SPDX-License-Identifier: GPL-2.0-only
// IPv4 tunnel mode: host stack uses 169.254/16 TCP; on the USB wire the T2
// still speaks IPv6 link-local. Rewrite Ethernet+IP(+TCP) headers in place
// (TX expands by 20 bytes, RX shrinks by 20).
#pragma once

#include "driver.h"

// Registry: HKLM\SOFTWARE\T2TouchId\Network\TransportMode = 1 enables tunnel.
BOOLEAN T2NcmTunnelModeEnabled(VOID);

// Learn peer IPv6 from an inbound IPv6 frame (source address).
VOID T2NcmTunnelNotePeerFromIpv6Frame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength
    );

// TX: if tunnel on and frame is IPv4 TCP/UDP to 169.254/16, rewrite to IPv6.
// *FrameLength in/out; Buffer must have room for +20 bytes (IPv6 header delta).
// Returns TRUE if frame was rewritten (or left unchanged as non-candidate).
BOOLEAN T2NcmTunnelRewriteTxIpv4ToIpv6(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Inout_updates_bytes_(BufferCapacity) PUCHAR Frame,
    _Inout_ PULONG FrameLength,
    _In_ ULONG BufferCapacity
    );

// RX: if tunnel on and frame is IPv6 TCP/UDP, rewrite to IPv4 toward 169.254.
// Frame buffer may shrink; *FrameLength updated.
BOOLEAN T2NcmTunnelRewriteRxIpv6ToIpv4(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Inout_updates_bytes_(*FrameLength) PUCHAR Frame,
    _Inout_ PULONG FrameLength
    );


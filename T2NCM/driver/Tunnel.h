// SPDX-License-Identifier: GPL-2.0-only
// IPv4 tunnel mode: host stack uses 169.254/16 TCP; on the USB wire the T2
// still speaks IPv6 link-local. Rewrite Ethernet+IP(+TCP) headers in place
// (TX expands by 20 bytes, RX shrinks by 20).
//
// Tunnel mode is held in driver memory (see Tunnel.c); the driver does not read
// the registry for it. TX/RX DPC paths only read the cached
// DeviceContext->TunnelModeEnabled.
#pragma once

#include "driver.h"

// Driver-global tunnel mode (survives adapter re-init; cleared by reboot).
VOID    T2NcmTunnelSetMode(_In_ BOOLEAN Enabled);
BOOLEAN T2NcmTunnelGetMode(VOID);

// Driver-global sticky-tunnel flag (userspace's committed decision, see
// IOCTL_T2NCM_SET_TUNNEL_STICKY). Stored only; cleared by reboot.
VOID    T2NcmTunnelSetSticky(_In_ BOOLEAN Sticky);
BOOLEAN T2NcmTunnelGetSticky(VOID);

// Mode ownership. Userspace flips the live mode away from the committed
// (sticky) decision only for the duration of one probe phase (TransportPhase,
// TransportMode.h) and puts it back when the phase ends. A process that dies
// in the middle of that phase (GUI timeout kill, crash, WUDFHost restart)
// used to leave the driver in the probe's mode for every later user
// ("sticky=0 mode=1"). The handle that moved the live mode away from the
// committed one is now its owner; when that handle is cleaned up while still
// the owner, the driver restores the committed mode by itself.
//   ModeWrite   - under the mode lock: set the global live mode and record /
//                 clear the owner (owner = FileObject when Enabled != sticky).
//   StickyWrite - set the committed flag; a live mode that now equals it has
//                 no owner any more.
//   ReleaseModeOwner - IRP_MJ_CLEANUP: when FileObject still owns the live
//                 mode, set it back to the committed value and return TRUE
//                 with *RestoredTunnel = that value.
VOID    T2NcmTunnelModeWrite(_In_opt_ PFILE_OBJECT FileObject, _In_ BOOLEAN Enabled);
VOID    T2NcmTunnelStickyWrite(_In_ BOOLEAN Sticky);
BOOLEAN T2NcmTunnelReleaseModeOwner(_In_opt_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN RestoredTunnel);

// Copy the driver-global mode into a (re)created DeviceContext.
// Called from InitializeEx / Restart.
VOID T2NcmTunnelRefreshMode(_In_ PT2NCM_DEVICE_CONTEXT DeviceContext);

// TX: if tunnel on and frame is IPv4 TCP/UDP to 169.254/16, rewrite to IPv6.
BOOLEAN T2NcmTunnelRewriteTxIpv4ToIpv6(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Inout_updates_bytes_(BufferCapacity) PUCHAR Frame,
    _Inout_ PULONG FrameLength,
    _In_ ULONG BufferCapacity
    );

// Validate non-TCP/UDP IPv6 directly in the NTB buffer; never modifies it.
BOOLEAN T2NcmTunnelValidateRxIpv6Passthrough(
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength
    );

// RX: if tunnel on and frame is IPv6 TCP/UDP, rewrite to IPv4 toward 169.254.
BOOLEAN T2NcmTunnelRewriteRxIpv6ToIpv4(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Inout_updates_bytes_(*FrameLength) PUCHAR Frame,
    _Inout_ PULONG FrameLength,
    _In_ BOOLEAN TunnelModeSnapshot
    );

VOID T2NcmTunnelNotePeerFromIpv6Frame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength
    );

// TX: if Frame is a native (already-IPv6, not synthesized by us) outbound
// frame, remember its source address as Windows' real link-local address
// on this adapter. Called from T2NcmTunnelRewriteTxIpv4ToIpv6 on every
// outbound frame that isn't the 169.254/16 IPv4 traffic that function
// rewrites, so it costs nothing extra on the IPv4-tunnel path.
VOID T2NcmTunnelNoteLocalFromIpv6Frame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength
    );

// TX: given the host's own outbound 169.254/16 frame BEFORE rewrite,
// remember its IPv4 source address as Windows' real APIPA address on
// this adapter. Called from T2NcmTunnelRewriteTxIpv4ToIpv6 once the
// frame has already been identified as IPv4-to-169.254/16, so it costs
// nothing on any other path.
VOID T2NcmTunnelNoteLocalFromIpv4Frame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(4) const UCHAR* SrcIpv4
    );
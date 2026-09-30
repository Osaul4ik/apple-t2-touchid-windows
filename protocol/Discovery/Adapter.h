// SPDX-License-Identifier: GPL-2.0-only
// Adapter.h — T2 NCM local interface + peer (T2) link-local for RemoteXPC.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <string>
#include <vector>
#include <cstdint>

namespace t2::discovery {

// Where NcmEndpoint::peerLinkLocal came from. NeighborTable is the only
// automatic source — a real BridgeOS-owned entry seen answering on the
// link (Windows IPv6 Neighbor Discovery), not a guess about what its
// address might be. There is no automatic fallback: if the neighbor
// table has nothing usable yet, the peer is None and the caller must
// wait, prompt traffic (a ping to ff02::1 populates the table), or use
// --host.
enum class PeerSource {
    None,
    NeighborTable,
    ManualOverride,
    // Persisted from the last time the neighbor table had it. Only used when
    // the table is empty (IPv6 ND blocked by VPN/WFP) so the IPv4-tunnel
    // fallback still has a target after a cold boot.
    LastKnown,
};

struct NcmEndpoint {
    unsigned long ifIndex = 0;
    in6_addr localLinkLocal{};
    // Destination: T2 peer (NOT the Windows host address on the adapter).
    in6_addr peerLinkLocal{};
    PeerSource peerSource = PeerSource::None;
    unsigned char mac[6]{};
    bool hasMac = false;
    // IPv6 is bound to the adapter (Ipv6IfIndex != 0). False = the IPv6 component
    // is unchecked/removed: native IPv6 cannot work, only the tunnel can.
    bool ipv6Bound = true;
    std::wstring friendlyName;
    std::wstring description;
};

// resolvePeer=false skips the (potentially ~550 ms) peer lookup: used by the
// connect path, which runs the readiness gate first (a ping sourced from a
// Tentative link-local address goes nowhere) and resolves the peer afterwards.
std::vector<NcmEndpoint> FindT2NcmEndpoints(bool resolvePeer = true);
bool GetEndpointByIfIndex(unsigned long ifIndex, NcmEndpoint* out);

// ---- Step A of the connect sequence: readiness gate (architecture v2, 6.A) ----
enum class GateResult {
    Ready,          // link-local Preferred (or IPv6 not needed), peer resolved
    V6Unavailable,  // IPv6 unbound / no link-local 1.5 s after link up: skip native
    TimedOut,       // link-local still Tentative after maxMs; go on anyway
    Cancelled,
};

// Waits (bounded, cancel-aware) for the preconditions of any probe: a non-
// Tentative link-local on the adapter, then a resolved peer. It is a precondition
// check, NOT a probe - it never draws a conclusion about the transport, except
// the local fact "this adapter has no usable IPv6" (V6Unavailable, per Generation).
// Also notices NCM re-enumeration (new ifIndex/MAC) and a changed peer and bumps
// the transport Generation. On return *ep has the peer resolved when one exists.
GateResult RunReadinessGate(NcmEndpoint* ep, void* cancelEvent, unsigned maxMs = 3000);

// Peer resolution order: neighbor table -> persisted last-known peer (unless
// distrusted) -> multicast ping + poll (only when `allowPing`) -> persisted peer
// even if distrusted. The ping runs whenever the table AND the persisted peer give
// nothing, in native and tunnel mode alike. Updates ep->peerLinkLocal/peerSource.
bool ResolveT2Peer(NcmEndpoint* ep, bool allowPing = true);
bool ParseIpv6(const char* text, in6_addr* out);

// Looks up the real T2 peer via the Windows IPv6 neighbor table
// (GetIpNetTable2) for the given interface. Only a neighbor whose state
// is Reachable, Stale, Delay or Probe is considered a candidate —
// Incomplete and Unreachable are excluded because the address behind
// them was never confirmed to answer, and any address seen as
// Permanent (the multicast/solicited-node entries Windows always
// carries — ff02::1, ff02::1:ffXX:XXXX, etc.) is excluded as well.
// Among several qualifying candidates the most confirmed state wins:
// Reachable > Stale > Delay > Probe.
//
// Returns false, leaving *out untouched, if no such neighbor exists yet
// — this can legitimately happen before any multicast traffic (e.g. an
// ff02::1 ping) has had a chance to populate the table.
// outMac (optional): if the winning neighbor-table row already carries a
// full 6-byte link-layer address, it's copied here and *outHaveMac is set
// true - lets a caller that's about to look the MAC up again (e.g.
// PersistPeer's LookupPeerMac) skip a second full GetIpNetTable2 walk for
// the row this call already read. *outHaveMac is always written when
// outMac is non-null (false on any path that didn't get a MAC, including
// FindNeighborPeer returning false at all).
bool FindNeighborPeer(unsigned long ifIndex, in6_addr* out,
                       unsigned char outMac[6] = nullptr, bool* outHaveMac = nullptr);

std::string FormatLinkLocal(const in6_addr& addr, unsigned long scopeId);

} // namespace t2::discovery
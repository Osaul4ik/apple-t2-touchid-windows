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
};

struct NcmEndpoint {
    unsigned long ifIndex = 0;
    in6_addr localLinkLocal{};
    // Destination: T2 peer (NOT the Windows host address on the adapter).
    in6_addr peerLinkLocal{};
    PeerSource peerSource = PeerSource::None;
    unsigned char mac[6]{};
    bool hasMac = false;
    std::wstring friendlyName;
    std::wstring description;
};

std::vector<NcmEndpoint> FindT2NcmEndpoints();
bool GetEndpointByIfIndex(unsigned long ifIndex, NcmEndpoint* out);
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
bool FindNeighborPeer(unsigned long ifIndex, in6_addr* out);

std::string FormatLinkLocal(const in6_addr& addr, unsigned long scopeId);

} // namespace t2::discovery
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

struct NcmEndpoint {
    unsigned long ifIndex = 0;
    in6_addr localLinkLocal{};
    // Destination: T2 peer (NOT the Windows host address on the adapter).
    in6_addr peerLinkLocal{};
    bool peerDerivedFromMac = false;
    unsigned char mac[6]{};
    bool hasMac = false;
    std::wstring friendlyName;
    std::wstring description;
    std::wstring adapterName;
};

std::vector<NcmEndpoint> FindT2NcmEndpoints();
bool GetEndpointByIfIndex(unsigned long ifIndex, NcmEndpoint* out);
bool ParseIpv6(const char* text, in6_addr* out);
in6_addr LinkLocalFromMac(const unsigned char mac[6]);
std::string FormatLinkLocal(const in6_addr& addr, unsigned long scopeId);

} // namespace t2::discovery

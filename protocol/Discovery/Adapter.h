// SPDX-License-Identifier: GPL-2.0-only
// Adapter.h — locate the T2 CDC-NCM IPv6 link-local endpoint on Windows.
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
    // ifIndex used as IPv6 scope_id for fe80:: addresses.
    unsigned long ifIndex = 0;
    in6_addr linkLocal{};
    std::wstring friendlyName;
    std::wstring description;
    std::wstring adapterName; // e.g. "Ethernet 2"
};

// Finds adapters that look like the Apple T2 NCM function:
//   - IPv6 link-local present and Preferred
//   - description/friendly name contains "T2" / "NCM" / "UsbNcm", OR
//   - caller can pass an explicit ifIndex override
// Returns empty vector if none found (never invents a success).
std::vector<NcmEndpoint> FindT2NcmEndpoints();

// Resolve a single endpoint by ifIndex (e.g. 27 from Get-NetIPAddress).
// Returns false if that interface has no Preferred fe80:: address.
bool GetEndpointByIfIndex(unsigned long ifIndex, NcmEndpoint* out);

std::string FormatLinkLocal(const in6_addr& addr, unsigned long scopeId);

} // namespace t2::discovery

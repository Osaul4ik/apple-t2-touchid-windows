// SPDX-License-Identifier: GPL-2.0-only
// Adapter.cpp
#include "Adapter.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace t2::discovery {
namespace {

bool LooksLikeT2Ncm(const std::wstring& description, const std::wstring& friendly) {
    auto has = [](const std::wstring& s, const wchar_t* needle) {
        return s.find(needle) != std::wstring::npos;
    };
    // Match project INF friendly name and common inbox strings.
    if (has(description, L"T2") && has(description, L"NCM")) return true;
    if (has(friendly, L"T2") && has(friendly, L"NCM")) return true;
    if (has(description, L"UsbNcm") || has(friendly, L"UsbNcm")) return true;
    if (has(description, L"Apple T2 USB NCM") || has(friendly, L"Apple T2 USB NCM")) return true;
    return false;
}

std::wstring NarrowToWide(const char* s) {
    if (!s) return {};
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, s, -1, out.data(), n);
    return out;
}

} // namespace

std::string FormatLinkLocal(const in6_addr& addr, unsigned long scopeId) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (!InetNtopA(AF_INET6, &addr, buf, sizeof(buf))) {
        return {};
    }
    std::string s(buf);
    s.push_back('%');
    s += std::to_string(scopeId);
    return s;
}

bool GetEndpointByIfIndex(unsigned long ifIndex, NcmEndpoint* out) {
    if (!out || ifIndex == 0) return false;

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
        return false;
    }
    std::vector<uint8_t> buf(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, addrs, &size) != NO_ERROR) {
        return false;
    }

    for (auto* a = addrs; a; a = a->Next) {
        if (a->Ipv6IfIndex != ifIndex && a->IfIndex != ifIndex) continue;

        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET6) continue;
            auto* sa = reinterpret_cast<sockaddr_in6*>(u->Address.lpSockaddr);
            // fe80::/10 link-local
            if (sa->sin6_addr.u.Byte[0] != 0xFE || (sa->sin6_addr.u.Byte[1] & 0xC0) != 0x80) {
                continue;
            }
            // DadState Preferred == 4 (IpDadStatePreferred)
            if (u->DadState != IpDadStatePreferred) continue;

            out->ifIndex = a->Ipv6IfIndex ? a->Ipv6IfIndex : a->IfIndex;
            out->linkLocal = sa->sin6_addr;
            out->friendlyName = a->FriendlyName ? a->FriendlyName : L"";
            out->description = a->Description ? a->Description : L"";
            out->adapterName = a->AdapterName ? NarrowToWide(a->AdapterName) : L"";
            return true;
        }
    }
    return false;
}

std::vector<NcmEndpoint> FindT2NcmEndpoints() {
    std::vector<NcmEndpoint> result;

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
        return result;
    }
    std::vector<uint8_t> buf(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, addrs, &size) != NO_ERROR) {
        return result;
    }

    for (auto* a = addrs; a; a = a->Next) {
        std::wstring friendly = a->FriendlyName ? a->FriendlyName : L"";
        std::wstring description = a->Description ? a->Description : L"";
        if (!LooksLikeT2Ncm(description, friendly)) continue;

        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET6) continue;
            auto* sa = reinterpret_cast<sockaddr_in6*>(u->Address.lpSockaddr);
            if (sa->sin6_addr.u.Byte[0] != 0xFE || (sa->sin6_addr.u.Byte[1] & 0xC0) != 0x80) continue;
            if (u->DadState != IpDadStatePreferred) continue;

            NcmEndpoint ep;
            ep.ifIndex = a->Ipv6IfIndex ? a->Ipv6IfIndex : a->IfIndex;
            ep.linkLocal = sa->sin6_addr;
            ep.friendlyName = friendly;
            ep.description = description;
            ep.adapterName = a->AdapterName ? NarrowToWide(a->AdapterName) : L"";
            result.push_back(ep);
            break; // one link-local per adapter is enough
        }
    }
    return result;
}

} // namespace t2::discovery

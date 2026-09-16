// SPDX-License-Identifier: GPL-2.0-only
#include "Adapter.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace t2::discovery {
namespace {

// Nudges the T2 to answer by sending one ICMPv6 echo to the all-nodes
// multicast address on this interface — the exact manual workaround an
// operator has to reach for today ("try pinging ff02::1%<ifIndex>").
// This shells out to the system ping.exe (rather than driving raw ICMPv6
// via Icmp6SendEcho2, whose reply-capture semantics for a *multicast*
// destination are the fragile part) — we don't need to parse *our* copy
// of the reply, we only need Windows' own IPv6 stack to observe the T2's
// unicast reply on the wire, which is what actually populates the
// neighbor table entry FindNeighborPeer reads afterwards.
bool PromptPeerViaMulticastPing(unsigned long ifIndex, unsigned timeoutMs) {
    if (ifIndex == 0) return false;

    wchar_t cmd[128];
    _snwprintf_s(cmd, _TRUNCATE, L"ping.exe -6 -n 1 -w %u ff02::1%%%lu",
                 timeoutMs, ifIndex);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};

    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, timeoutMs + 1000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool LooksLikeT2Ncm(const std::wstring& description, const std::wstring& friendly) {
    auto has = [](const std::wstring& s, const wchar_t* needle) {
        return s.find(needle) != std::wstring::npos;
    };
    if (has(description, L"T2") && has(description, L"NCM")) return true;
    if (has(friendly, L"T2") && has(friendly, L"NCM")) return true;
    if (has(description, L"UsbNcm") || has(friendly, L"UsbNcm")) return true;
    if (has(description, L"Apple T2 USB NCM") || has(friendly, L"Apple T2 USB NCM"))
        return true;
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

bool IsLinkLocal(const in6_addr& a) {
    return a.u.Byte[0] == 0xFE && (a.u.Byte[1] & 0xC0) == 0x80;
}

// IPv6 multicast addresses (ff00::/8) always start with 0xFF. Windows
// keeps solicited-node and well-known multicast entries in the same
// neighbor table as real neighbors (see the ff02::... rows netsh
// prints as "Permanent"), so this is checked independently of the
// State filter below rather than relying solely on Permanent meaning
// "multicast" — the two happen to coincide today but nothing pins that.
bool IsMulticast(const in6_addr& a) {
    return a.u.Byte[0] == 0xFF;
}

// Higher is more confirmed. Anything not listed here (Incomplete,
// Unreachable, Permanent, Media, and any future state) returns 0 and is
// excluded by IsAcceptableNeighborState below.
int NeighborStatePriority(NL_NEIGHBOR_STATE state) {
    switch (state) {
        case NlnsReachable: return 4;
        case NlnsStale:     return 3;
        case NlnsDelay:     return 2;
        case NlnsProbe:     return 1;
        default:            return 0;
    }
}

bool IsAcceptableNeighborState(NL_NEIGHBOR_STATE state) {
    return NeighborStatePriority(state) > 0;
}

bool FillFromAdapter(IP_ADAPTER_ADDRESSES* a, NcmEndpoint* out) {
    out->ifIndex = a->Ipv6IfIndex ? a->Ipv6IfIndex : a->IfIndex;
    out->friendlyName = a->FriendlyName ? a->FriendlyName : L"";
    out->description = a->Description ? a->Description : L"";
    out->adapterName = a->AdapterName ? NarrowToWide(a->AdapterName) : L"";

    if (a->PhysicalAddressLength >= 6) {
        std::memcpy(out->mac, a->PhysicalAddress, 6);
        out->hasMac = true;
    }

    bool gotLocal = false;
    for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
        if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET6)
            continue;
        auto* sa = reinterpret_cast<sockaddr_in6*>(u->Address.lpSockaddr);
        if (!IsLinkLocal(sa->sin6_addr)) continue;
        if (u->DadState != IpDadStatePreferred) continue;
        out->localLinkLocal = sa->sin6_addr;
        gotLocal = true;
        break;
    }

    // Real discovery, not derivation: look up whatever the Windows IPv6
    // neighbor table actually confirmed on this interface. If nothing
    // qualifies yet, send the one-off ff02::1 multicast ping ourselves
    // (an operator would otherwise have to do this by hand every time)
    // and check the neighbor table once more before giving up — still
    // left as PeerSource::None (peerLinkLocal stays zeroed) if that
    // retry also comes up empty, so the caller can fall back to --host.
    if (gotLocal) {
        in6_addr peer{};
        if (FindNeighborPeer(out->ifIndex, &peer)) {
            out->peerLinkLocal = peer;
            out->peerSource = PeerSource::NeighborTable;
        } else {
            PromptPeerViaMulticastPing(out->ifIndex, 300);
            Sleep(250);
            if (FindNeighborPeer(out->ifIndex, &peer)) {
                out->peerLinkLocal = peer;
                out->peerSource = PeerSource::NeighborTable;
            }
        }
    }

    return gotLocal && out->hasMac;
}

} // namespace

bool FindNeighborPeer(unsigned long ifIndex, in6_addr* out) {
    if (!out || ifIndex == 0) return false;

    PMIB_IPNET_TABLE2 table = nullptr;
    if (GetIpNetTable2(AF_INET6, &table) != NO_ERROR || table == nullptr) {
        return false;
    }

    bool found = false;
    int bestPriority = 0;
    in6_addr best{};

    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPNET_ROW2& row = table->Table[i];

        if (row.InterfaceIndex != ifIndex) continue;
        if (row.Address.si_family != AF_INET6) continue;

        const in6_addr& addr = row.Address.Ipv6.sin6_addr;
        if (!IsLinkLocal(addr)) continue;
        if (IsMulticast(addr)) continue;
        if (!IsAcceptableNeighborState(row.State)) continue;

        int priority = NeighborStatePriority(row.State);
        if (!found || priority > bestPriority) {
            found = true;
            bestPriority = priority;
            best = addr;
        }
    }

    FreeMibTable(table);

    if (found) {
        *out = best;
    }
    return found;
}

in6_addr LinkLocalFromMac(const unsigned char mac[6]) {
    in6_addr a{};
    a.u.Byte[0] = 0xFE;
    a.u.Byte[1] = 0x80;
    a.u.Byte[8] = static_cast<unsigned char>(mac[0] ^ 0x02);
    a.u.Byte[9] = mac[1];
    a.u.Byte[10] = mac[2];
    a.u.Byte[11] = 0xFF;
    a.u.Byte[12] = 0xFE;
    a.u.Byte[13] = mac[3];
    a.u.Byte[14] = mac[4];
    a.u.Byte[15] = mac[5];
    return a;
}

bool ParseIpv6(const char* text, in6_addr* out) {
    if (!text || !out) return false;
    return InetPtonA(AF_INET6, text, out) == 1;
}

std::string FormatLinkLocal(const in6_addr& addr, unsigned long scopeId) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (!InetNtopA(AF_INET6, &addr, buf, sizeof(buf))) return {};
    std::string s(buf);
    s.push_back('%');
    s += std::to_string(scopeId);
    return s;
}

std::vector<NcmEndpoint> FindT2NcmEndpoints() {
    std::vector<NcmEndpoint> result;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, nullptr, &size) !=
        ERROR_BUFFER_OVERFLOW)
        return result;
    std::vector<uint8_t> buf(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, addrs, &size) != NO_ERROR)
        return result;

    for (auto* a = addrs; a; a = a->Next) {
        std::wstring friendly = a->FriendlyName ? a->FriendlyName : L"";
        std::wstring description = a->Description ? a->Description : L"";
        if (!LooksLikeT2Ncm(description, friendly)) continue;
        NcmEndpoint ep;
        if (!FillFromAdapter(a, &ep)) continue;
        result.push_back(ep);
    }
    return result;
}

bool GetEndpointByIfIndex(unsigned long ifIndex, NcmEndpoint* out) {
    if (!out || ifIndex == 0) return false;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, nullptr, &size) !=
        ERROR_BUFFER_OVERFLOW)
        return false;
    std::vector<uint8_t> buf(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_INET6, flags, nullptr, addrs, &size) != NO_ERROR)
        return false;

    for (auto* a = addrs; a; a = a->Next) {
        unsigned long idx = a->Ipv6IfIndex ? a->Ipv6IfIndex : a->IfIndex;
        if (idx != ifIndex && a->IfIndex != ifIndex) continue;
        return FillFromAdapter(a, out);
    }
    return false;
}

} // namespace t2::discovery
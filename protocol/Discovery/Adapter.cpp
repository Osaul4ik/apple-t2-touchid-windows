// SPDX-License-Identifier: GPL-2.0-only
#include "Adapter.h"
#include "../BridgeXpc/TransportMode.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <mutex>

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

// Best-effort: remember the confirmed peer (fe80 + MAC) so a later cold boot
// with IPv6 ND blocked still has a tunnel target. May fail silently when the
// caller lacks HKLM write access (UMDF host) - then the CLI/GUI run persists it.
void PersistPeer(unsigned long ifIndex, const in6_addr& peer) {
    UCHAR mac[6]{};
    const bool haveMac = t2::transport::LookupPeerMac(ifIndex, peer, mac);
    t2::transport::PublishTunnelPeer(peer, haveMac ? mac : nullptr);
}

// Same as PersistPeer, but for a caller that already has the MAC in hand
// (from the same neighbor-table row FindNeighborPeer just read) - skips
// the redundant second GetIpNetTable2 walk LookupPeerMac would otherwise
// do to re-find a row we were just looking at.
void PersistPeerWithMac(unsigned long ifIndex, const in6_addr& peer,
                         const unsigned char* mac, bool haveMac) {
    if (haveMac) {
        t2::transport::PublishTunnelPeer(peer, mac);
    } else {
        PersistPeer(ifIndex, peer); // fall back to the full lookup
    }
}

bool FillFromAdapter(IP_ADAPTER_ADDRESSES* a, NcmEndpoint* out, bool resolvePeer) {
    out->ifIndex = a->Ipv6IfIndex ? a->Ipv6IfIndex : a->IfIndex;
    out->ipv6Bound = (a->Ipv6IfIndex != 0);
    out->friendlyName = a->FriendlyName ? a->FriendlyName : L"";
    out->description = a->Description ? a->Description : L"";

    if (a->PhysicalAddressLength >= 6) {
        std::memcpy(out->mac, a->PhysicalAddress, 6);
        out->hasMac = true;
    }

    // COLD-BOOT FIX: this used to REQUIRE a Preferred link-local address and
    // dropped the whole endpoint otherwise. Right after boot the address is
    // still Tentative (DAD ~1s), and with IPv6 disabled/filtered it may not
    // exist at all - in both cases discovery returned nothing and the IPv4
    // tunnel fallback never got a chance. localLinkLocal is informational
    // only, so: prefer a Preferred one, else any link-local, else derive it
    // from the adapter MAC. The endpoint is valid as long as the MAC exists.
    bool gotLocal = false;
    bool gotPreferred = false;
    for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
        if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET6)
            continue;
        auto* sa = reinterpret_cast<sockaddr_in6*>(u->Address.lpSockaddr);
        if (!IsLinkLocal(sa->sin6_addr)) continue;
        const bool preferred = (u->DadState == IpDadStatePreferred);
        if (gotPreferred || (gotLocal && !preferred)) continue;
        out->localLinkLocal = sa->sin6_addr;
        gotLocal = true;
        gotPreferred = preferred;
    }
    if (!gotLocal && out->hasMac) {
        in6_addr d{};
        d.u.Byte[0] = 0xFE; d.u.Byte[1] = 0x80;
        d.u.Byte[8] = out->mac[0] ^ 0x02; d.u.Byte[9] = out->mac[1]; d.u.Byte[10] = out->mac[2];
        d.u.Byte[11] = 0xFF; d.u.Byte[12] = 0xFE;
        d.u.Byte[13] = out->mac[3]; d.u.Byte[14] = out->mac[4]; d.u.Byte[15] = out->mac[5];
        out->localLinkLocal = d;
        gotLocal = true;
    }

    // Real discovery, not derivation: the peer is whatever the Windows IPv6
    // neighbor table confirmed (or, failing that, the persisted last-known peer).
    // See ResolveT2Peer for the order. Callers on the connect path pass
    // resolvePeer=false and resolve after the readiness gate instead.
    if (gotLocal && resolvePeer) {
        ResolveT2Peer(out, out->ipv6Bound);
    }

    return gotLocal && out->hasMac;
}

} // namespace

bool ResolveT2Peer(NcmEndpoint* out, bool allowPing) {
    if (!out || out->ifIndex == 0) return false;
    in6_addr peer{};
    unsigned char neighborMac[6]{};
    bool haveNeighborMac = false;
    out->peerSource = PeerSource::None;
    out->peerLinkLocal = in6_addr{};
    if (FindNeighborPeer(out->ifIndex, &peer, neighborMac, &haveNeighborMac)) {
        out->peerLinkLocal = peer;
        out->peerSource = PeerSource::NeighborTable;
        PersistPeerWithMac(out->ifIndex, peer, neighborMac, haveNeighborMac);
        return true;
    }
    // Neighbor table has no T2 entry (cold boot, resume, or a VPN/WFP dropping ND).
    //  1. last-known peer persisted from a good session - free, and right unless
    //     the machine was paired with another T2 or the T2 changed address. Trusted
    //     in native AND tunnel mode until two silent attempts in a row distrust it
    //     (TransportMode.h NotePathSilent); the old code trusted it forever in
    //     tunnel mode;
    //  2. multicast ping + neighbor-table poll (~550 ms worst case, spawns
    //     ping.exe) - whenever 1 gave nothing, regardless of the tunnel flag;
    //  3. the persisted peer even if distrusted: ND/ICMPv6 is dropped, so a stale
    //     guess still beats no target for the IPv4-tunnel attempt.
    const bool trustPersisted = !t2::transport::ConsumePersistedPeerDistrust();
    in6_addr saved{};
    const bool haveSaved = t2::transport::ReadPersistedPeer(&saved, nullptr, nullptr);
    if (haveSaved && trustPersisted) {
        out->peerLinkLocal = saved;
        out->peerSource = PeerSource::LastKnown;
        return true;
    }
    if (allowPing) {
        // The ping still gets its full timeout; only the wait for the neighbor
        // table is responsive (10 ms polling instead of a blind sleep).
        PromptPeerViaMulticastPing(out->ifIndex, 300);
        const int kPeerPollIntervalMs = 10;
        const int kPeerPollBudgetMs = 250;
        for (int waited = 0; waited < kPeerPollBudgetMs; waited += kPeerPollIntervalMs) {
            unsigned char pollMac[6]{};
            bool havePollMac = false;
            if (FindNeighborPeer(out->ifIndex, &peer, pollMac, &havePollMac)) {
                out->peerLinkLocal = peer;
                out->peerSource = PeerSource::NeighborTable;
                PersistPeerWithMac(out->ifIndex, peer, pollMac, havePollMac);
                return true;
            }
            Sleep(kPeerPollIntervalMs);
        }
    }
    if (haveSaved) {
        out->peerLinkLocal = saved;
        out->peerSource = PeerSource::LastKnown;
        return true;
    }
    return false;
}

bool FindNeighborPeer(unsigned long ifIndex, in6_addr* out,
                       unsigned char outMac[6], bool* outHaveMac) {
    if (outHaveMac) *outHaveMac = false;
    if (!out || ifIndex == 0) return false;

    PMIB_IPNET_TABLE2 table = nullptr;
    if (GetIpNetTable2(AF_INET6, &table) != NO_ERROR || table == nullptr) {
        return false;
    }

    bool found = false;
    int bestPriority = 0;
    in6_addr best{};
    unsigned char bestMac[6]{};
    bool bestHaveMac = false;

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
            // Capture the MAC from this same row while we're here - saves
            // a caller (PersistPeer) from walking the whole table again
            // moments later just to look up the identical row.
            bestHaveMac = row.PhysicalAddressLength >= 6;
            if (bestHaveMac) {
                std::memcpy(bestMac, row.PhysicalAddress, 6);
            }
        }
    }

    FreeMibTable(table);

    if (found) {
        *out = best;
        if (outMac && outHaveMac && bestHaveMac) {
            std::memcpy(outMac, bestMac, 6);
            *outHaveMac = true;
        }
    }
    return found;
}

// ---- Readiness gate (architecture v2, section 6 step A) ----------------------
namespace {

enum class LinkLocalState { None, Tentative, Preferred };

// State of the adapter's link-local IPv6 address straight from the IP stack
// (never touches the wire, so it works while a VPN/WFP drops all IPv6).
LinkLocalState QueryLinkLocalState(unsigned long ifIndex) {
    PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
    if (GetUnicastIpAddressTable(AF_INET6, &table) != NO_ERROR || !table) {
        return LinkLocalState::None;
    }
    LinkLocalState st = LinkLocalState::None;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        if (row.InterfaceIndex != ifIndex || row.Address.si_family != AF_INET6) continue;
        if (!IsLinkLocal(row.Address.Ipv6.sin6_addr)) continue;
        if (row.DadState == IpDadStatePreferred || row.DadState == IpDadStateDeprecated) {
            st = LinkLocalState::Preferred;
            break;
        }
        if (row.DadState == IpDadStateTentative) st = LinkLocalState::Tentative;
        // Invalid / Duplicate: not usable, ignored.
    }
    FreeMibTable(table);
    return st;
}

bool IsInterfaceOperUp(unsigned long ifIndex) {
    MIB_IF_ROW2 row{};
    row.InterfaceIndex = ifIndex;
    if (GetIfEntry2(&row) != NO_ERROR) return false;
    return row.OperStatus == IfOperStatusUp;
}

// Sleeps up to `ms`, returning true early when the cancel event fires.
bool SleepOrCancel(void* cancelEvent, DWORD ms) {
    if (cancelEvent) return WaitForSingleObject(static_cast<HANDLE>(cancelEvent), ms) == 0;
    Sleep(ms);
    return false;
}

// Identity of the NCM adapter / T2 peer last seen by the gate. A change means the
// T2 re-enumerated or changed address: Generation moves, so committed tunnel,
// V6Unavailable and the port-scan progress are all dropped (sections 3 and 7).
std::mutex g_identityMu;
struct Identity {
    bool valid = false;
    unsigned long ifIndex = 0;
    unsigned char mac[6]{};
    bool peerValid = false;
    in6_addr peer{};
} g_identity;

void NoteAdapterIdentity(const NcmEndpoint& ep) {
    std::lock_guard<std::mutex> lock(g_identityMu);
    const bool sameMac = ep.hasMac && g_identity.valid &&
                         std::memcmp(g_identity.mac, ep.mac, 6) == 0;
    if (g_identity.valid && (g_identity.ifIndex != ep.ifIndex || !sameMac)) {
        t2::transport::BumpGeneration(L"NCM adapter re-registered (ifIndex/MAC changed)");
        g_identity.peerValid = false;
    }
    g_identity.valid = true;
    g_identity.ifIndex = ep.ifIndex;
    if (ep.hasMac) std::memcpy(g_identity.mac, ep.mac, 6);
}

void NotePeerIdentity(const NcmEndpoint& ep) {
    if (ep.peerSource == PeerSource::None) return;
    std::lock_guard<std::mutex> lock(g_identityMu);
    if (g_identity.peerValid &&
        std::memcmp(&g_identity.peer, &ep.peerLinkLocal, sizeof(in6_addr)) != 0) {
        t2::transport::BumpGeneration(L"T2 peer address changed");
    }
    g_identity.peerValid = true;
    g_identity.peer = ep.peerLinkLocal;
}

} // namespace

GateResult RunReadinessGate(NcmEndpoint* ep, void* cancelEvent, unsigned maxMs) {
    if (!ep || ep->ifIndex == 0) return GateResult::TimedOut;
    NoteAdapterIdentity(*ep);

    const ULONGLONG t0 = GetTickCount64();
    GateResult result = GateResult::Ready;
    constexpr ULONGLONG kNoAddressMs = 1500;  // no link-local this long after link-up => IPv6 unusable
    constexpr DWORD kPollMs = 25;

    if (!ep->ipv6Bound) {
        // IPv6 component unbound on the adapter: nothing to wait for, native is impossible.
        t2::transport::MarkV6Unavailable();
        result = GateResult::V6Unavailable;
    } else if (!t2::transport::IsV6Unavailable()) {
        // (When V6Unavailable is already set for this Generation the wait is not repeated.)
        for (;;) {
            if (cancelEvent &&
                WaitForSingleObject(static_cast<HANDLE>(cancelEvent), 0) == 0) {
                return GateResult::Cancelled;
            }
            const LinkLocalState st = QueryLinkLocalState(ep->ifIndex);
            const ULONGLONG waited = GetTickCount64() - t0;
            if (st == LinkLocalState::Preferred) break;
            if (st == LinkLocalState::None && waited >= kNoAddressMs && IsInterfaceOperUp(ep->ifIndex)) {
                t2::transport::MarkV6Unavailable();
                result = GateResult::V6Unavailable;
                T2_LOG("discovery", L"readiness gate: no link-local IPv6 %llu ms after link up - "
                       L"V6Unavailable for this Generation (native skipped)",
                       static_cast<unsigned long long>(waited));
                break;
            }
            if (waited >= maxMs) {
                result = GateResult::TimedOut;
                T2_LOG("discovery", L"readiness gate: link-local still %s after %llu ms - continuing",
                       st == LinkLocalState::Tentative ? L"Tentative" : L"missing",
                       static_cast<unsigned long long>(waited));
                break;
            }
            if (SleepOrCancel(cancelEvent, kPollMs)) return GateResult::Cancelled;
        }
    } else {
        result = GateResult::V6Unavailable;
    }

    // Peer: resolved only now that the address is usable (a ping from a Tentative
    // source goes nowhere). Ping is pointless without IPv6 on the adapter.
    if (ep->peerSource == PeerSource::None) {
        ResolveT2Peer(ep, result != GateResult::V6Unavailable);
    }
    NotePeerIdentity(*ep);
    T2_LOG("discovery", L"readiness gate: %s in %llu ms, peer source=%d gen=%llu",
           result == GateResult::Ready ? L"ready"
               : result == GateResult::V6Unavailable ? L"V6Unavailable" : L"timed out",
           static_cast<unsigned long long>(GetTickCount64() - t0),
           static_cast<int>(ep->peerSource),
           static_cast<unsigned long long>(t2::transport::CurrentGeneration()));
    return result;
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

std::vector<NcmEndpoint> FindT2NcmEndpoints(bool resolvePeer) {
    std::vector<NcmEndpoint> result;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    // AF_UNSPEC (was AF_INET6): with the IPv6 component unbound on the T2 adapter
    // the AF_INET6 query omits it entirely, discovery found "no T2 adapter" and
    // the IPv4 tunnel - the one thing that still works there - never got a chance.
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &size) !=
        ERROR_BUFFER_OVERFLOW)
        return result;
    std::vector<uint8_t> buf(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size) != NO_ERROR)
        return result;

    // OPTIMIZATION: GetAdaptersAddresses returns adapters in binding
    // order, and an active VPN client commonly forces its own virtual
    // adapter to the front of that order (for kill-switch / tunnel
    // priority). T2 NCM, brought up later by a USB plug event, ends up
    // toward the end. Walking front-to-back meant every VPN/virtual
    // adapter got checked — and any that happened to also pass
    // LooksLikeT2Ncm would start its (blocking) ping/poll — before we
    // ever reached the real one. The list is singly-linked (no Prev),
    // so reversing means collecting pointers first, then walking that
    // back to front.
    std::vector<IP_ADAPTER_ADDRESSES*> ordered;
    for (auto* a = addrs; a; a = a->Next) {
        ordered.push_back(a);
    }

    for (auto it = ordered.rbegin(); it != ordered.rend(); ++it) {
        IP_ADAPTER_ADDRESSES* a = *it;
        std::wstring friendly = a->FriendlyName ? a->FriendlyName : L"";
        std::wstring description = a->Description ? a->Description : L"";
        if (!LooksLikeT2Ncm(description, friendly)) continue;
        NcmEndpoint ep;
        if (!FillFromAdapter(a, &ep, resolvePeer)) continue;
        result.push_back(ep);
    }
    return result;
}

bool GetEndpointByIfIndex(unsigned long ifIndex, NcmEndpoint* out) {
    if (!out || ifIndex == 0) return false;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &size) !=
        ERROR_BUFFER_OVERFLOW)
        return false;
    std::vector<uint8_t> buf(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size) != NO_ERROR)
        return false;

    for (auto* a = addrs; a; a = a->Next) {
        unsigned long idx = a->Ipv6IfIndex ? a->Ipv6IfIndex : a->IfIndex;
        if (idx != ifIndex && a->IfIndex != ifIndex) continue;
        return FillFromAdapter(a, out, true);
    }
    return false;
}

} // namespace t2::discovery
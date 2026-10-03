// SPDX-License-Identifier: GPL-2.0-only
// TransportMode — Native IPv6 (default) vs IPv4 tunnel for Cisco/WFP that
// drops all IPv6 before the packet reaches T2Ncm. When tunnel is on,
// userspace uses AF_INET to a link-local IPv4 mapped from the T2 fe80
// address; T2Ncm.sys rewrites IPv4↔IPv6 on the wire (T2 still speaks IPv6).
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// Guarded on _WINIOCTL_: this only needs to run for a standalone consumer
// where WIN32_LEAN_AND_MEAN (set above) kept <windows.h> from pulling in
// <winioctl.h> at all. If something earlier in this translation unit already
// included <winioctl.h> - e.g. driver/T2TouchIdTransport/public.h, reached
// via protocol/AppleKeyStore/Client.h - _WINIOCTL_ is already set and the
// CTL_CODE/FILE_DEVICE_UNKNOWN macros this file needs are already available,
// so re-including here would add nothing. It would, however, re-run
// winioctl.h's GUID_DEVINTERFACE_* block, which sits OUTSIDE that guard and
// re-executes on every textual inclusion regardless: if INITGUID happened to
// be active during an earlier inclusion in this TU (as it is inside
// public.h, to instantiate its own custom GUID), that block's DEFINE_GUID
// stays in "instantiate" mode for the rest of the file, and a further
// inclusion here would redefine GUID_DEVINTERFACE_DISK and friends a second
// time -> C2374 "redefinition; multiple initialization".
#ifndef _WINIOCTL_
#include <winioctl.h>
#endif
#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <vector>
#include "Log.h"
#include "Winsock.h"

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Advapi32.lib")

namespace t2::transport {

inline constexpr wchar_t kNetworkRegPath[] = L"SOFTWARE\\T2TouchId\\Network";
inline constexpr wchar_t kPeerIpv6Value[] = L"PeerIpv6";
inline constexpr wchar_t kPeerMacValue[] = L"PeerMac";

// ---- Transport selection: Native IPv6 vs IPv4 tunnel -------------------
//
// There is no manual override: no GUI/CLI "force IPv4" and no permanent-IPv4 setting.
//
//  1. AUTO-SWITCH (persistent setting, default ON): HKLM\...\Network\AutoSwitch
//     (DWORD, missing == 1). Policy (owned by BridgeDiscovery):
//       - default transport = Native IPv6;
//       - on native TCP-level failure → one recovery multicast ping (ff02::1) to
//         re-reveal the T2 peer (same prompt used at cold start);
//       - if that single recovery attempt fails → fall to the IPv4 tunnel;
//       - when off, only Native IPv6 is used.
//
//  2. STICKY TUNNEL (until reboot): set only when a switch to the tunnel SUCCEEDED
//     (a tunnel handshake worked), never on a mere native failure. The source of
//     truth is T2Ncm.sys MEMORY (IOCTL_T2NCM_SET_TUNNEL_STICKY / GET_TUNNEL_STATE,
//     a driver global): it survives a WUDFHost restart, an adapter re-init and
//     sleep, and a reboot (or driver unload) clears it. Each process seeds its
//     in-process copy from the driver once (EnsureStickySeededFromDriver) and
//     pushes every change back. No registry. After it is set there is NO way back
//     to native IPv6 until reboot. The next cold boot starts from Native IPv6 again
//     and switches to the tunnel only if IPv6 is blocked.
//     An older T2Ncm.sys without those IOCTLs: the in-process flag alone (the
//     pre-IOCTL behaviour), logged once.
//
//  The BridgeXPC port itself is NOT transport state: it is the same port on both
//  transports and lives only in the registry (Discovery/PortCache.h).
//
// CONNECT ARCHITECTURE v2 (CONNECT_ARCHITECTURE_v2.md) adds, in this file:
//  * Generation (section 3): scan progress / V6Unavailable are tied to a counter that
//    moves on real resume / NCM re-enumeration / peer change (the sticky tunnel is not).
//  * PathEvidence (section 4): a connect attempt is Positive / Silent / Refused /
//    LocalError; only Positive proves a path, LocalError proves nothing.
//  * TransportPhase (sections 11, 12): cross-process mutex + RAII mode scope, so the
//    driver mode equals the committed mode whenever a phase ends, and no other
//    process can flip it in the middle of a probe/scan.
//
// Native and tunnel are mutually exclusive at the driver level: while T2Ncm.sys has
// TunnelModeEnabled set it rewrites EVERY inbound IPv6 TCP/UDP frame to IPv4
// (Tunnel.c, T2NcmTunnelRewriteRxIpv6ToIpv4), so a native SYN-ACK would never reach
// the IPv6 stack. That is why the two paths are tried one after the other.
inline constexpr wchar_t kAutoSwitchValue[] = L"AutoSwitch";                    // under kNetworkRegPath, persistent

enum class TransportMode : DWORD {
    NativeIpv6 = 0,
    Ipv4Tunnel = 1,
};

// Registry reads are cached for a short TTL: IsTunnelModeActive() sits on hot
// paths (PortScan::ProbePort calls it once per probed port - up to 16384 times
// per scan - and used to open/query/close the key every time).
struct CachedDword {
    std::atomic<ULONGLONG> at{0};
    std::atomic<DWORD> val{0};
};
inline DWORD ReadDwordCached(CachedDword& c, const wchar_t* subKey, const wchar_t* name,
                             DWORD def, ULONGLONG ttlMs) {
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG last = c.at.load(std::memory_order_relaxed);
    if (last != 0 && now - last < ttlMs) return c.val.load(std::memory_order_relaxed);
    DWORD v = def;
    DWORD cb = sizeof(v);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, subKey, name, RRF_RT_REG_DWORD,
                     nullptr, &v, &cb) != ERROR_SUCCESS) {
        v = def; // missing key/value or no read access: fail to the default
    }
    c.val.store(v, std::memory_order_relaxed);
    c.at.store(now, std::memory_order_relaxed);
    return v;
}

inline bool IsAutoSwitchEnabled() {
    static CachedDword c;
    return ReadDwordCached(c, kNetworkRegPath, kAutoSwitchValue, 1, 1000) != 0;
}

// ---- Generation (architecture v2, section 3) -----------------------------
// Starts at 1 in every process (process start IS a new generation). Bumped on
// real Sx suspend/resume (BumpRealSuspendGeneration), when the NCM adapter
// re-registers with another ifIndex/MAC and when the T2 peer address changes.
// Value 0 is reserved for "never set".
inline std::atomic<ULONGLONG>& GenerationCounter() {
    static std::atomic<ULONGLONG> g{1};
    return g;
}
inline ULONGLONG CurrentGeneration() { return GenerationCounter().load(std::memory_order_acquire); }
inline ULONGLONG BumpGeneration(const wchar_t* why) {
    const ULONGLONG n = GenerationCounter().fetch_add(1, std::memory_order_acq_rel) + 1;
    T2_LOG("transport", L"Generation -> %llu (%s)", static_cast<unsigned long long>(n),
           why ? why : L"?");
    return n;
}

// Committed auto-tunnel: in-process copy of the driver's sticky flag (see 2.).
// Sticky-until-reboot: once the automatic switch to the IPv4 tunnel happened, it stays.
// It is NOT tied to the Generation (resume / NCM re-enumeration / peer change do not
// undo it) and there is no way back to native IPv6 until reboot.
inline std::atomic<bool> g_autoTunnel{false};
inline std::atomic<ULONGLONG> g_autoTunnelGen{0};

// Defined further down (they need the shared T2Ncm control handle).
inline void EnsureStickySeededFromDriver();
inline bool PushTunnelStickyToDriver(bool on);

inline bool IsAutoTunnelCommitted() {
    EnsureStickySeededFromDriver(); // one IOCTL per process, then a relaxed load
    return g_autoTunnel.load(std::memory_order_relaxed);
}

// Attempt-scoped transport override: -1 none, 0 native, 1 tunnel. Set by
// TransportPhase while an attempt probes a transport that is NOT (yet)
// committed. This replaces the old "provisional tunnel" (CommitAutoTunnel(true)
// followed by a rollback): nothing is committed until a handshake succeeded,
// and the override disappears on every exit path (RAII), including cancel.
inline std::atomic<int>& TransportOverride() {
    static std::atomic<int> o{-1};
    return o;
}

// THE query for "which transport is active right now" (discovery budgets,
// port scan, RemoteXPC and Connection all read this).
inline bool IsTunnelModeActive() {
    const int ov = TransportOverride().load(std::memory_order_relaxed);
    if (ov >= 0) return ov == 1;
    return IsAutoTunnelCommitted();
}

// IPv6 unusable on the T2 adapter for this Generation (unbound, or no
// link-local address 1.5 s after the link came up). Native is not attempted.
inline std::atomic<ULONGLONG> g_v6UnavailableGen{0};
inline void MarkV6Unavailable() { g_v6UnavailableGen.store(CurrentGeneration(), std::memory_order_relaxed); }
inline void ClearV6Unavailable() { g_v6UnavailableGen.store(0, std::memory_order_relaxed); }
inline bool IsV6Unavailable() {
    return g_v6UnavailableGen.load(std::memory_order_relaxed) == CurrentGeneration();
}

// ---- Path evidence (architecture v2, section 4) ---------------------------
enum class PathEvidence {
    Positive,   // SYN-ACK / HELO: the path works
    Silent,     // nothing came back inside the budget
    LocalError, // local problem (no route/address/MAC) - says nothing about the path
    Refused,    // RST; a proof of the path only if assumption A0 holds
    Blocked,    // WSAEACCES on connect: a local WFP block filter (VPN kill-switch) -
                // the path is known dead at once, no need to wait for a timeout
};
// A0 [HW]: the T2 answers a SYN to a closed port with RST. Unconfirmed, so the
// default is "not proof"; flip HKLM\SOFTWARE\T2TouchId\Network\RstIsProof=1
// after the hardware test (section 16, step 0).
inline bool IsRstProof() {
    static CachedDword c;
    return ReadDwordCached(c, kNetworkRegPath, L"RstIsProof", 0, 1000) != 0;
}
inline bool IsPositiveEvidence(PathEvidence e) {
    return e == PathEvidence::Positive || (e == PathEvidence::Refused && IsRstProof());
}
inline PathEvidence ClassifyWsaError(int wsa) {
    switch (wsa) {
        case 0:                return PathEvidence::Positive;
        case WSAECONNREFUSED:  return PathEvidence::Refused;
        case WSAENETUNREACH:
        case WSAENETDOWN:
        case WSAEADDRNOTAVAIL:
        case WSAEAFNOSUPPORT:  return PathEvidence::LocalError;
        // WSAEACCES is what a WFP block filter (VPN kill-switch) returns on connect():
        // that IS the blocked-path case the tunnel exists for, not a local fault.
        case WSAEACCES:        return PathEvidence::Blocked;
        default:               return PathEvidence::Silent; // timeout, host unreachable, aborted...
    }
}

// Unlock / resume: a stale "IPv6 unavailable" verdict must not survive it. There is no
// return from the sticky tunnel to native IPv6 (until reboot), so nothing else to do.
inline void RequestNativeReprobe() { ClearV6Unavailable(); }

// ---- adaptive native connect budget -------------------------------------
// A healthy T2 link-local peer answers a SYN in single-digit ms (field logs:
// whole socket+connect+HELO = 13-16 ms). A blocked path never answers, so the
// only cost of "is IPv6 dead?" is how long we wait before deciding. The wait
// is 4x the smoothed successful connect time, clamped to [60, 250] ms; 150 ms
// before anything has been measured. It only bounds the TCP handshake; HELO
// keeps the caller's full timeout.
inline std::atomic<DWORD> g_nativeEmaMs{0};
inline std::chrono::milliseconds NativeConnectBudget(std::chrono::milliseconds cap) {
    const DWORD ema = g_nativeEmaMs.load(std::memory_order_relaxed);
    long long ms = (ema == 0) ? 150 : static_cast<long long>(ema) * 4 + 30;
    if (ms < 60) ms = 60;
    if (ms > 250) ms = 250;
    if (cap.count() < ms) ms = cap.count();
    return std::chrono::milliseconds(ms);
}
// Native TCP handshake completed: the IPv6 path works. Clears auto-tunnel.
inline void RecordNativeSuccess(ULONGLONG tcpMs) {
    const DWORD old = g_nativeEmaMs.load(std::memory_order_relaxed);
    DWORD next = (old == 0) ? static_cast<DWORD>(tcpMs) : static_cast<DWORD>((old * 3 + tcpMs) / 4);
    if (next == 0) next = 1;
    g_nativeEmaMs.store(next, std::memory_order_relaxed);
    EnsureStickySeededFromDriver();
    if (g_autoTunnel.exchange(false, std::memory_order_relaxed)) {
        PushTunnelStickyToDriver(false);
    }
    ClearV6Unavailable(); // a native handshake just worked
}
// Tunnel handshake completed after native failed: sticky until reboot (driver
// memory + in-process copy). Independent of Generation. on=false only when
// auto-switch was turned off.
inline void CommitAutoTunnel(bool on) {
    EnsureStickySeededFromDriver();
    const bool was = g_autoTunnel.exchange(on, std::memory_order_relaxed);
    if (on) g_autoTunnelGen.store(CurrentGeneration(), std::memory_order_relaxed);
    if (was != on) PushTunnelStickyToDriver(on);
}

// ---- persisted-peer trust -----------------------------------------------
// Adapter.cpp uses the last-known T2 peer straight away when the neighbor
// table is empty (skipping the ~550 ms ping + poll). If a connect to that
// guessed peer then fails, this flag makes the NEXT discovery do the full
// ping-based lookup once instead of trusting it again.
inline std::atomic<bool> g_persistedPeerDistrusted{false};
inline void DistrustPersistedPeer() { g_persistedPeerDistrusted.store(true, std::memory_order_relaxed); }
inline bool ConsumePersistedPeerDistrust() { return g_persistedPeerDistrusted.exchange(false, std::memory_order_relaxed); }

// Standalone path probe: a throwaway TCP SYN at the T2 peer's IPv6 link-local
// address, bounded by `timeout`, classified as PathEvidence (section 4):
//   handshake completed        -> Positive
//   RST (WSAECONNREFUSED)      -> Refused (a proof only if RstIsProof, see A0)
//   nothing within `timeout`   -> Silent
//   no route / address / etc.  -> LocalError (says nothing about the path)
// Only meaningful while T2Ncm is in native mode (tunnel mode rewrites replies).
// `port` should be the cached BridgeXPC port: port 1 is only usable once A0 is
// confirmed on hardware.
inline PathEvidence ProbeNativePath(const in6_addr& peer6, unsigned long ifIndex, uint16_t port,
                                    std::chrono::milliseconds timeout, ULONGLONG* outMs = nullptr) {
    const ULONGLONG t0 = GetTickCount64();
    auto done = [&](PathEvidence e) {
        if (outMs) *outMs = GetTickCount64() - t0;
        return e;
    };
    if (!t2::EnsureWinsock()) return done(PathEvidence::LocalError);
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return done(PathEvidence::LocalError);

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = peer6;
    addr.sin6_scope_id = ifIndex;

    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);
    PathEvidence ev = PathEvidence::Silent;
    const int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        ev = PathEvidence::Positive;
    } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
        ev = ClassifyWsaError(WSAGetLastError()); // immediate failure
    } else {
        fd_set writeSet, errSet;
        FD_ZERO(&writeSet);
        FD_ZERO(&errSet);
        FD_SET(s, &writeSet);
        FD_SET(s, &errSet);
        timeval tv{};
        tv.tv_sec = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
        const int sel = select(0, nullptr, &writeSet, &errSet, &tv);
        if (sel > 0 && (FD_ISSET(s, &writeSet) || FD_ISSET(s, &errSet))) {
            int err = 0;
            int errLen = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errLen);
            ev = ClassifyWsaError(err);
        }
        // sel <= 0: nothing came back within `timeout` -> Silent.
    }
    closesocket(s);
    return done(ev);
}

inline in_addr MapPeerToIpv4(const in6_addr& peer6) {
    unsigned a = peer6.s6_addr[14];
    unsigned b = peer6.s6_addr[15];
    if (a == 0) a = 1;
    if (a == 255) a = 254;
    if (b == 0) b = 1;
    if (b == 255) b = 254;
    a = (a + peer6.s6_addr[13]) % 254;
    if (a == 0) a = 1;
    in_addr out{};
    out.S_un.S_un_b.s_b1 = 169;
    out.S_un.S_un_b.s_b2 = 254;
    out.S_un.S_un_b.s_b3 = static_cast<UCHAR>(a);
    out.S_un.S_un_b.s_b4 = static_cast<UCHAR>(b);
    return out;
}

inline bool IsTunnelMappedIpv4(const in_addr& a) {
    return a.S_un.S_un_b.s_b1 == 169 && a.S_un.S_un_b.s_b2 == 254;
}

// Publish peer fe80 (+ optional MAC) for T2Ncm.sys (read at PASSIVE refresh).
inline void PublishTunnelPeer(const in6_addr& peer6, const UCHAR mac[6] /*nullable*/) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kNetworkRegPath, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }
    RegSetValueExW(key, kPeerIpv6Value, 0, REG_BINARY,
                   reinterpret_cast<const BYTE*>(&peer6), sizeof(peer6));
    if (mac) {
        RegSetValueExW(key, kPeerMacValue, 0, REG_BINARY, mac, 6);
    }
    RegCloseKey(key);
}

// Last-known peer (fe80 + MAC) persisted by PublishTunnelPeer. Lets discovery
// and the tunnel keep working after a cold boot when the IPv6 neighbor table
// is still empty because a VPN/WFP drops the ff02::1 ping and Neighbor
// Discovery (the exact case the IPv4 tunnel exists for).
inline bool ReadPersistedPeer(in6_addr* peer6, UCHAR mac[6], bool* haveMac) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kNetworkRegPath, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return false;
    }
    DWORD type = 0, cb = sizeof(in6_addr);
    bool ok = RegQueryValueExW(key, kPeerIpv6Value, nullptr, &type,
                               reinterpret_cast<LPBYTE>(peer6), &cb) == ERROR_SUCCESS &&
              type == REG_BINARY && cb == sizeof(in6_addr);
    if (ok && haveMac && mac) {
        cb = 6;
        type = 0;
        *haveMac = RegQueryValueExW(key, kPeerMacValue, nullptr, &type,
                                    mac, &cb) == ERROR_SUCCESS &&
                   type == REG_BINARY && cb == 6;
    }
    RegCloseKey(key);
    return ok;
}

// Look up peer MAC from the IPv6 neighbor table (same entry as discovery).
inline bool LookupPeerMac(unsigned long ifIndex, const in6_addr& peer6, UCHAR outMac[6]) {
    PMIB_IPNET_TABLE2 table = nullptr;
    if (GetIpNetTable2(AF_INET6, &table) != NO_ERROR || !table) {
        return false;
    }
    bool found = false;
    UCHAR anyMac[6]{};
    bool any = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& e = table->Table[i];
        if (e.InterfaceIndex != ifIndex) continue;
        if (e.Address.si_family != AF_INET6) continue;
        if (e.PhysicalAddressLength < 6) continue;
        // Skip multicast/solicited-node style permanent junk: need a real MAC.
        if (e.PhysicalAddress[0] & 0x01) continue;
        if (!any) {
            std::memcpy(anyMac, e.PhysicalAddress, 6);
            any = true;
        }
        if (std::memcmp(&e.Address.Ipv6.sin6_addr, &peer6, sizeof(in6_addr)) == 0) {
            std::memcpy(outMac, e.PhysicalAddress, 6);
            found = true;
            break;
        }
    }
    FreeMibTable(table);
    if (!found && any) {
        std::memcpy(outMac, anyMac, 6);
        found = true;
    }
    return found;
}

// Static neighbor so TCP SYN is not stuck on ARP for 169.254.x.y.
inline void EnsureTunnelIpv4Neighbor(unsigned long ifIndex, const in_addr& peer4,
                                     const UCHAR mac[6]) {
    MIB_IPNET_ROW2 row{};
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr = peer4;
    row.InterfaceIndex = ifIndex;
    std::memcpy(row.PhysicalAddress, mac, 6);
    row.PhysicalAddressLength = 6;
    row.State = NlnsPermanent;
    // CreateIpNetEntry2 only succeeds for a row that doesn't exist yet. In
    // tunnel mode the row for 169.254.a.b almost always already exists by
    // the time this runs — either a leftover Permanent entry from an
    // earlier session with a now-stale MAC (T2 rebooted, link-layer
    // address changed), or an Incomplete/Unreachable row Windows' own ARP
    // left behind before PrepareTunnelPeer ever ran. Create then returns
    // ERROR_OBJECT_ALREADY_EXISTS and — this was the bug — the old code
    // treated that as "nothing to do" and left the stale/incomplete row in
    // place, so every SYN to that address kept going nowhere. Any failure
    // to create (ALREADY_EXISTS included) must fall through to Set, which
    // overwrites the existing row's state and MAC unconditionally.
    const DWORD c = CreateIpNetEntry2(&row);
    const bool createdFresh = (c == NO_ERROR);
    DWORD setResult = NO_ERROR;
    if (!createdFresh) {
        setResult = SetIpNetEntry2(&row);
    }
    T2_LOG("tunnel", L"ARP neighbor %u.%u.%u.%u -> %02X-%02X-%02X-%02X-%02X-%02X "
           L"ifIndex=%lu: %s (create=%lu%s)",
           peer4.S_un.S_un_b.s_b1, peer4.S_un.S_un_b.s_b2,
           peer4.S_un.S_un_b.s_b3, peer4.S_un.S_un_b.s_b4,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           ifIndex,
           createdFresh ? L"created"
                        : (setResult == NO_ERROR ? L"updated existing row"
                                                  : L"UPDATE FAILED"),
           c,
           createdFresh ? L"" : (setResult == NO_ERROR ? L", set=OK" : L", set FAILED"));
}


// Push peer fe80 into T2Ncm.sys so TX rewrite works immediately (no RX wait).

// ---- Sleep / Dx gate -------------------------------------------------
// Set by Bio OnSuspendResume(PBT_APMSUSPEND). While true, all T2Ncm control
// IOCTLs (mode + peer) are skipped: the miniport is paused / in D3 and live
// IOCTLs during that window are what the post-sleep log storm showed
// (TunnelPeerIpv6 x5 between MiniportPause and D0Entry).
inline std::atomic<bool>& TransportIoSuspendedFlag() {
    static std::atomic<bool> s{false};
    return s;
}
inline void SetTransportIoSuspended(bool suspended) {
    TransportIoSuspendedFlag().store(suspended, std::memory_order_release);
}
inline bool IsTransportIoSuspended() {
    return TransportIoSuspendedFlag().load(std::memory_order_acquire);
}

// Last mode we successfully pushed — avoid 0↔1 thrash when callers
// (Connect, LockRefresh, every-4th) all re-push the same value.
inline std::atomic<int>& LastPushedModeFlag() {
    static std::atomic<int> s{-1}; // -1 unknown, 0 native, 1 tunnel
    return s;
}

// Dedupe TunnelPeer IOCTL: port scan pushed same peer 15–20x per CAPTURE.
struct LastPushedPeerState {
    std::mutex mu;
    in6_addr peer{};
    bool valid = false;
};
inline LastPushedPeerState& LastPushedPeer() {
    static LastPushedPeerState s;
    return s;
}
// Dedupe for the local (Windows-side) link-local push, same idea as
// LastPushedPeer above.
struct LastPushedLocalState {
    std::mutex mu;
    in6_addr local{};
    bool valid = false;
};
inline LastPushedLocalState& LastPushedLocal() {
    static LastPushedLocalState s;
    return s;
}
inline void ClearLastPushedLocal() {
    std::lock_guard<std::mutex> lock(LastPushedLocal().mu);
    LastPushedLocal().valid = false;
}
inline bool IsSameAsLastPushedLocal(const in6_addr& a) {
    std::lock_guard<std::mutex> lock(LastPushedLocal().mu);
    return LastPushedLocal().valid &&
           std::memcmp(&LastPushedLocal().local, &a, sizeof(in6_addr)) == 0;
}
inline void RememberLastPushedLocal(const in6_addr& a) {
    std::lock_guard<std::mutex> lock(LastPushedLocal().mu);
    LastPushedLocal().local = a;
    LastPushedLocal().valid = true;
}

// Cache of "have we already ensured the static ARP neighbor for this
// tunnel peer" - separate from LastPushedPeer (that one only dedupes the
// IOCTL to the driver, not the neighbor-table syscalls below it).
// PrepareTunnelPeer's LookupPeerMac(GetIpNetTable2) + EnsureTunnelIpv4Neighbor
// (CreateIpNetEntry2/SetIpNetEntry2) are the two heaviest synchronous calls
// in the whole tunnel Connect() path - a full neighbor-table walk plus a
// kernel IP helper round-trip - and previously ran unconditionally on
// EVERY Connect(), even the common case of the same peer as last time
// (e.g. a lock-screen retry loop). Skipping them when nothing changed
// removes that cost from the tunnel's steady-state per-attempt latency.
struct ArpPrepCacheState {
    std::mutex mu;
    in6_addr peer{};
    bool valid = false;
};
inline ArpPrepCacheState& ArpPrepCache() {
    static ArpPrepCacheState s;
    return s;
}
inline bool IsArpAlreadyPrepared(const in6_addr& peer6) {
    std::lock_guard<std::mutex> lock(ArpPrepCache().mu);
    return ArpPrepCache().valid &&
           std::memcmp(&ArpPrepCache().peer, &peer6, sizeof(in6_addr)) == 0;
}
inline void RememberArpPrepared(const in6_addr& peer6) {
    std::lock_guard<std::mutex> lock(ArpPrepCache().mu);
    ArpPrepCache().peer = peer6;
    ArpPrepCache().valid = true;
}
inline void ClearLastPushedPeer() {
    std::lock_guard<std::mutex> lock(LastPushedPeer().mu);
    LastPushedPeer().valid = false;
}
inline bool IsSameAsLastPushedPeer(const in6_addr& peer6) {
    std::lock_guard<std::mutex> lock(LastPushedPeer().mu);
    return LastPushedPeer().valid &&
           std::memcmp(&LastPushedPeer().peer, &peer6, sizeof(in6_addr)) == 0;
}
inline void RememberLastPushedPeer(const in6_addr& peer6) {
    std::lock_guard<std::mutex> lock(LastPushedPeer().mu);
    LastPushedPeer().peer = peer6;
    LastPushedPeer().valid = true;
}

// Call whenever a tunnel connect actually FAILS (TCP connect or HELO
// timeout) - forces the next PrepareTunnelPeer to redo the full
// lookup+ARP-set instead of trusting a neighbor entry that may itself be
// the reason the connect just failed (T2 rebooted/re-addressed mid-lock,
// stale MAC in the neighbor table). Also clears the IOCTL-dedupe caches
// for the same reason - a failed connect means "don't trust what we
// think is already armed in the driver either".
inline void InvalidateTunnelPrepCache() {
    {
        std::lock_guard<std::mutex> lock(ArpPrepCache().mu);
        ArpPrepCache().valid = false;
    }
    ClearLastPushedPeer();
    ClearLastPushedLocal();
    LastPushedModeFlag().store(-1, std::memory_order_relaxed);
}

// Real Sx suspend generation (NOT screen-lock). Bio bumps this only on
// PBT_APMSUSPEND so Connect settle does not fire on every WTS_SESSION_LOCK.
inline std::atomic<ULONGLONG>& RealSuspendGeneration() {
    static std::atomic<ULONGLONG> s{0};
    return s;
}
inline void BumpRealSuspendGeneration() {
    RealSuspendGeneration().fetch_add(1, std::memory_order_acq_rel);
    BumpGeneration(L"real Sx suspend/resume"); // committed tunnel, V6Unavailable, scan progress start over
}
inline ULONGLONG GetRealSuspendGeneration() {
    return RealSuspendGeneration().load(std::memory_order_acquire);
}

// ---- Shared \\.\T2Ncm control handle (lease-counted) ---------------------
//
// Every push below used to CreateFileW + DeviceIoControl + CloseHandle on its own,
// so one Connect()/scan phase (mode + peer + local) paid for three opens.
// A T2NcmControlLease keeps ONE handle alive for as long as at least one lease
// exists in the process; the last lease to go closes it. TransportPhase and
// PrepareTunnelPeer hold a lease for their duration, so all pushes inside share a
// single handle. A push made outside any lease takes a lease for the duration of
// that one call - i.e. exactly the old open/IOCTL/close behaviour.
//
// Deliberately NOT a process-lifetime handle: an idle open handle on the control
// device would pin T2Ncm.sys and make a driver update / Disable-NetAdapter /
// tools\remove-t2-drivers.bat need a reboot. With leases the handle exists only
// while a phase is actually running. The handle is opened lazily by the first
// IOCTL, not by the lease itself.
struct T2NcmControlState {
    std::mutex mu;
    HANDLE h = INVALID_HANDLE_VALUE;
    unsigned refs = 0;
};
inline T2NcmControlState& T2NcmControl() {
    static T2NcmControlState s;
    return s;
}

class T2NcmControlLease {
public:
    T2NcmControlLease() {
        auto& s = T2NcmControl();
        std::lock_guard<std::mutex> lock(s.mu);
        ++s.refs;
    }
    ~T2NcmControlLease() {
        auto& s = T2NcmControl();
        std::lock_guard<std::mutex> lock(s.mu);
        if (--s.refs == 0 && s.h != INVALID_HANDLE_VALUE) {
            CloseHandle(s.h);
            s.h = INVALID_HANDLE_VALUE;
        }
    }
    T2NcmControlLease(const T2NcmControlLease&) = delete;
    T2NcmControlLease& operator=(const T2NcmControlLease&) = delete;
};

struct T2NcmIoctlResult {
    bool  ok = false;
    bool  openFailed = false; // open failure is already logged by T2NcmControlIoctl
    DWORD err = 0;            // GetLastError of the failing call (0 when ok)
};

// Errors that mean "this handle no longer refers to a live control device"
// (driver unloaded / re-created while the handle was cached). Anything else -
// notably ERROR_INVALID_FUNCTION from an older T2Ncm.sys - is a real answer and
// must reach the caller unchanged.
inline bool IsStaleControlHandleError(DWORD e) {
    return e == ERROR_INVALID_HANDLE || e == ERROR_DEVICE_REMOVED ||
           e == ERROR_NO_SUCH_DEVICE || e == ERROR_DEV_NOT_EXIST ||
           e == ERROR_DEVICE_NOT_CONNECTED;
}

// One IOCTL on the shared handle. FILE_WRITE_DATA only (not GENERIC_WRITE): the
// control device grants LocalService exactly that (see NdisMiniport.c SDDL);
// GENERIC_WRITE also asks for WRITE_ATTRIBUTES/EA/APPEND and would be denied for
// the service. A stale cached handle is dropped and the IOCTL retried once on a
// fresh open.
inline T2NcmIoctlResult T2NcmControlIoctl(const wchar_t* who, DWORD code,
                                          LPVOID in, DWORD inSize,
                                          LPVOID out = nullptr, DWORD outSize = 0,
                                          DWORD* outReturned = nullptr) {
    T2NcmControlLease lease; // keeps the handle open for the duration of this call at least
    auto& s = T2NcmControl();
    T2NcmIoctlResult r;
    for (int attempt = 0; attempt < 2; ++attempt) {
        HANDLE h;
        {
            std::lock_guard<std::mutex> lock(s.mu);
            if (s.h == INVALID_HANDLE_VALUE) {
                s.h = CreateFileW(L"\\\\.\\T2Ncm", FILE_WRITE_DATA,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (s.h == INVALID_HANDLE_VALUE) {
                    r.openFailed = true;
                    r.err = GetLastError();
                    T2_LOG("tunnel", L"%s: could not open \\\\.\\T2Ncm "
                           L"(GetLastError=%lu) - driver not loaded, or (5) access denied",
                           who, r.err);
                    return r;
                }
            }
            h = s.h;
        }
        DWORD returned = 0;
        if (DeviceIoControl(h, code, in, inSize, out, outSize, &returned, nullptr)) {
            if (outReturned) *outReturned = returned;
            r.ok = true;
            r.err = 0;
            return r;
        }
        r.err = GetLastError();
        if (attempt == 0 && IsStaleControlHandleError(r.err)) {
            std::lock_guard<std::mutex> lock(s.mu);
            if (s.h == h) { // nobody replaced it meanwhile
                CloseHandle(s.h);
                s.h = INVALID_HANDLE_VALUE;
            }
            continue; // retry once on a fresh open
        }
        break;
    }
    return r;
}

inline bool PushTunnelPeerToDriver(const in6_addr& peer6) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PushTunnelPeerToDriver: skipped (system suspending / Dx)");
        return false;
    }
    if (IsSameAsLastPushedPeer(peer6)) {
        return true; // already armed — kill port-scan IOCTL storm
    }
    const DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"PushTunnelPeerToDriver", code,
                                                 (LPVOID)&peer6, (DWORD)sizeof(peer6));
    if (r.openFailed) {
        return false;
    }
    if (!r.ok) {
        T2_LOG("tunnel", L"PushTunnelPeerToDriver: IOCTL failed, GetLastError=%lu", r.err);
        return false;
    }
    RememberLastPushedPeer(peer6);
    return true;
}

// ---- Sticky tunnel flag in T2Ncm.sys memory (see 2. at the top) ------------
// Same CTL_CODEs as T2NCM/driver/Public.h (hand-rolled, like 0x902/0x903 here).
// Both are FILE_WRITE_ACCESS: the control device hands LocalService a write-only
// handle, and the I/O manager checks only the access the code requires, so the
// GET still returns its METHOD_BUFFERED output to the UMDF host.
inline constexpr DWORD kIoctlSetTunnelSticky =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_WRITE_ACCESS);
inline constexpr DWORD kIoctlGetTunnelState =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_WRITE_ACCESS);
struct T2NcmTunnelStateWire { // == T2NCM_TUNNEL_STATE (Public.h)
    ULONG Version;
    ULONG Sticky;
    ULONG Mode;
};
// 0 = not seeded yet, 1 = seeded from the driver, 2 = the driver has no such
// IOCTL or is not reachable (in-process flag only).
inline std::atomic<int>& StickySeedState() {
    static std::atomic<int> s{0};
    return s;
}
inline std::mutex& StickySeedMutex() {
    static std::mutex m;
    return m;
}

inline bool ReadTunnelStateFromDriver(T2NcmTunnelStateWire* out, DWORD* err) {
    T2NcmTunnelStateWire st{};
    DWORD returned = 0;
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"GetTunnelState", kIoctlGetTunnelState,
                                                 nullptr, 0, &st, sizeof(st), &returned);
    if (err) *err = r.err;
    if (!r.ok || returned < sizeof(st)) return false;
    *out = st;
    return true;
}

// Seeds g_autoTunnel from the driver once per process. A restarted WUDFHost thus
// stays on the tunnel the previous instance committed to (no native retry, no
// mode-0 push into a driver that is supposed to stay in tunnel mode). Not marked
// done while the system is suspending: the next call retries.
inline void EnsureStickySeededFromDriver() {
    if (StickySeedState().load(std::memory_order_acquire) != 0) return;
    if (IsTransportIoSuspended()) return;
    std::lock_guard<std::mutex> lock(StickySeedMutex());
    if (StickySeedState().load(std::memory_order_relaxed) != 0) return;
    T2NcmTunnelStateWire st{};
    DWORD err = 0;
    if (ReadTunnelStateFromDriver(&st, &err)) {
        if (st.Sticky != 0) {
            g_autoTunnel.store(true, std::memory_order_relaxed);
            g_autoTunnelGen.store(CurrentGeneration(), std::memory_order_relaxed);
        }
        T2_LOG("transport", L"sticky tunnel seeded from T2Ncm memory: sticky=%lu mode=%lu",
               st.Sticky, st.Mode);
        StickySeedState().store(1, std::memory_order_release);
        return;
    }
    T2_LOG("transport", L"T2Ncm GET_TUNNEL_STATE unavailable (GetLastError=%lu%s) - sticky "
           L"tunnel kept in this process only", err,
           err == ERROR_INVALID_FUNCTION ? L", older T2Ncm.sys" : L"");
    StickySeedState().store(2, std::memory_order_release);
}

inline bool PushTunnelStickyToDriver(bool on) {
    if (StickySeedState().load(std::memory_order_acquire) == 2) return false; // no IOCTL
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PushTunnelStickyToDriver: skipped (system suspending / Dx)");
        return false;
    }
    ULONG v = on ? 1ul : 0ul;
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"PushTunnelStickyToDriver", kIoctlSetTunnelSticky,
                                                 &v, sizeof(v));
    if (!r.ok) {
        if (!r.openFailed) {
            T2_LOG("tunnel", L"PushTunnelStickyToDriver: IOCTL failed, GetLastError=%lu", r.err);
        }
        return false;
    }
    T2_LOG("tunnel", L"PushTunnelStickyToDriver: sticky tunnel -> %lu (driver memory, cleared on reboot)", v);
    return true;
}

// Windows' REAL link-local IPv6 address on the T2 adapter, read straight from
// the IP stack's own configuration (works while a VPN/WFP filter drops all
// IPv6 traffic - it never touches the wire). Prefers a Preferred address,
// otherwise takes any link-local one (Tentative right after boot).
inline bool LookupLocalLinkLocal(unsigned long ifIndex, in6_addr* out) {
    PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
    if (GetUnicastIpAddressTable(AF_INET6, &table) != NO_ERROR || !table) {
        return false;
    }
    bool found = false;
    bool foundPreferred = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        if (row.InterfaceIndex != ifIndex) continue;
        if (row.Address.si_family != AF_INET6) continue;
        const in6_addr& a = row.Address.Ipv6.sin6_addr;
        if (a.s6_addr[0] != 0xFE || (a.s6_addr[1] & 0xC0) != 0x80) continue;
        const bool preferred = (row.DadState == IpDadStatePreferred);
        if (foundPreferred || (found && !preferred)) continue;
        *out = a;
        found = true;
        foundPreferred = preferred;
    }
    FreeMibTable(table);
    return found;
}

// Hand Windows' real link-local address to T2Ncm.sys
// (IOCTL_T2NCM_SET_TUNNEL_LOCAL, code 0x904). Without it the driver only
// learns that address from a native outbound IPv6 frame; when tunnel mode is
// switched on while a VPN is already blocking IPv6 no such frame ever leaves,
// the tunnel TX source falls back to a MAC-derived address Windows does not
// own, the T2's Neighbor Solicitation for it is never answered and every
// AF_INET connect() times out. Best-effort: on any failure the old passive
// learning still applies.
inline bool PushTunnelLocalToDriver(unsigned long ifIndex) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PushTunnelLocalToDriver: skipped (system suspending / Dx)");
        return false;
    }
    in6_addr local{};
    if (!LookupLocalLinkLocal(ifIndex, &local)) {
        T2_LOG("tunnel", L"PushTunnelLocalToDriver: no link-local IPv6 on ifIndex=%lu "
               L"- driver will have to learn it from native traffic", ifIndex);
        return false;
    }
    if (IsSameAsLastPushedLocal(local)) {
        return true; // already armed
    }
    const DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"PushTunnelLocalToDriver", code,
                                                 (LPVOID)&local, (DWORD)sizeof(local));
    if (r.openFailed) {
        return false;
    }
    if (!r.ok) {
        // An older T2Ncm.sys without this IOCTL fails here (ERROR_INVALID_FUNCTION):
        // harmless, the driver keeps learning passively as before.
        T2_LOG("tunnel", L"PushTunnelLocalToDriver: IOCTL failed, GetLastError=%lu", r.err);
        return false;
    }
    RememberLastPushedLocal(local);
    T2_LOG("tunnel", L"PushTunnelLocalToDriver: local fe80 ...%02x%02x:%02x%02x armed in driver",
           local.s6_addr[12], local.s6_addr[13], local.s6_addr[14], local.s6_addr[15]);
    return true;
}

// Push the TransportMode registry value into the driver LIVE, via
// IOCTL_T2NCM_SET_TRANSPORT_MODE (T2NCM/driver/Public.h, code 0x903).
//
// T2NcmTunnelRefreshMode (Tunnel.c) only re-reads
// HKLM\SOFTWARE\T2TouchId\Network\TransportMode at MiniportInitializeEx /
// MiniportRestart. A bare registry write from this process — or even a
// Disable-NetAdapter/Enable-NetAdapter cycle, which does not reliably
// reach a full miniport reinitialize for this NDIS device — leaves the
// running driver's DeviceContext->TunnelModeEnabled stale. When that
// happens T2NcmTunnelRewriteTxIpv4ToIpv6 keeps bailing out at its first
// check (`if (!DeviceContext->TunnelModeEnabled) return TRUE;`), so every
// outbound tunnel frame is sent as bare IPv4 — which the T2 side, an
// IPv6-only NCM link, silently drops — and every AF_INET connect() times
// out at 1500ms with WSA=0, no matter how correct the peer/ARP setup is.
//
// SepVaultGui already does this same push from a GUI checkbox
// (MainWindow.xaml.cs, IOCTL_T2NCM_SET_TRANSPORT_MODE = 0x0022A40C) so a
// live toggle takes effect without a restart. The CLI previously had no
// equivalent and depended entirely on an adapter restart lining up with a
// registry write that predated it - unreliable, and the cause of tunnel
// mode failing even after PushTunnelPeerToDriver/EnsureTunnelIpv4Neighbor
// both succeed. Calling this once per Connect(), for BOTH modes (not just
// Ipv4Tunnel), keeps the running driver a live mirror of the registry
// instead of a snapshot from whenever it last (re)initialized.
//
// The driver mode is the source of truth; LastPushedModeFlag is this process's exact
// record of what it last wrote (and is the only writer, see ModeScope), reset to -1
// whenever that can no longer be trusted. Without `force` the IOCTL is skipped when the
// record already equals the wanted mode. `force` still sends regardless, for a caller that
// has a reason to distrust the record; nothing in-tree needs it any more.
inline bool PushTransportModeToDriver(TransportMode mode, bool force = false) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PushTransportModeToDriver: skipped (system suspending / Dx)");
        return false;
    }
    const int want = (mode == TransportMode::Ipv4Tunnel) ? 1 : 0;
    if (!force && LastPushedModeFlag().load(std::memory_order_relaxed) == want) {
        // Already live in driver from our point of view — skip IOCTL storm.
        return true;
    }
    DWORD modeValue = static_cast<DWORD>(mode);
    // Same CTL_CODE as T2NCM/driver/Public.h's IOCTL_T2NCM_SET_TRANSPORT_MODE
    // (0x903) - hand-rolled rather than including Public.h, matching how
    // PushTunnelPeerToDriver above already hand-rolls IOCTL_T2NCM_SET_TUNNEL_PEER
    // (0x902) in this file to avoid the winioctl.h double-inclusion hazard
    // documented at the top of this file.
    const DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"PushTransportModeToDriver", code,
                                                 &modeValue, (DWORD)sizeof(modeValue));
    if (!r.ok) {
        if (!r.openFailed) {
            T2_LOG("tunnel", L"PushTransportModeToDriver: IOCTL failed, GetLastError=%lu", r.err);
        }
        // We no longer know what the driver holds. The re-arm decision below keys
        // off this hint, so a stale value would wrongly dedupe a later push.
        LastPushedModeFlag().store(-1, std::memory_order_relaxed);
        return false;
    }
    // Re-arm the local address only when the mode the driver holds has actually changed
    // (or was unknown, -1). A repeated write of the same mode (only a caller passing
    // force=true can still cause one) must not discard a local address that is still valid.
    const int prev = LastPushedModeFlag().exchange(want, std::memory_order_relaxed);
    if (prev != want) {
        ClearLastPushedLocal();
    }
    T2_LOG("tunnel", L"PushTransportModeToDriver: live TunnelModeEnabled -> %d", want);
    return true;
}

// Result of PrepareTunnelPeer. NoMac / NoPeer are LocalError evidence
// (section 4): the tunnel cannot be tried yet, which says nothing about whether
// the T2 is ready - the caller re-resolves the peer instead of counting a failure.
enum class TunnelPrep { Ok, NoMac, NoPeer, Suspended };

// Call before AF_INET connect in tunnel mode.
inline TunnelPrep PrepareTunnelPeer(unsigned long ifIndex, const in6_addr& peer6) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PrepareTunnelPeer: skipped (system suspending / Dx)");
        return TunnelPrep::Suspended;
    }
    // One control handle for the mode + peer + local pushes below (see T2NcmControlLease).
    T2NcmControlLease controlLease;
    if (IN6_IS_ADDR_UNSPECIFIED(&peer6)) {
        T2_LOG("tunnel", L"PrepareTunnelPeer: no peer address (LocalError, not a tunnel failure)");
        return TunnelPrep::NoPeer;
    }
    // Invariant: an AF_INET tunnel socket only works while T2Ncm.sys itself is
    // in tunnel mode (otherwise TX is sent as bare IPv4 and the T2 drops it).
    // Every tunnel user (Connection, PortScan, RemoteXPC) goes through here, so
    // arming the mode at this single choke point means "userspace says tunnel,
    // driver still native" cannot happen - e.g. cold-discovery's provisional
    // tunnel (CommitAutoTunnel only flips a flag in this process) scanning into
    // a void. Deduped by LastPushedModeFlag, so it is a no-op when already armed.
    PushTransportModeToDriver(TransportMode::Ipv4Tunnel);
    // Fast path: same peer as last time we successfully prepared it, and
    // nothing has invalidated that since (see InvalidateTunnelPrepCache).
    // Skips the neighbor-table walk and the ARP create/set syscalls -
    // still publishes the peer to the registry and (via the existing
    // IsSameAsLastPushedPeer dedupe inside it) pushes it to the driver,
    // both of which are already cheap early-outs.
    if (IsArpAlreadyPrepared(peer6)) {
        PublishTunnelPeer(peer6, nullptr);
        PushTunnelPeerToDriver(peer6);
        PushTunnelLocalToDriver(ifIndex);
        return TunnelPrep::Ok;
    }
    UCHAR mac[6]{};
    bool haveMac = LookupPeerMac(ifIndex, peer6, mac);
    if (!haveMac) {
        // Neighbor table empty (VPN/WFP dropped ND) - fall back to the MAC
        // persisted from the last time IPv6 worked, but only if it belongs
        // to this same peer.
        in6_addr savedPeer{};
        UCHAR savedMac[6]{};
        bool savedHaveMac = false;
        if (ReadPersistedPeer(&savedPeer, savedMac, &savedHaveMac) && savedHaveMac &&
            std::memcmp(&savedPeer, &peer6, sizeof(in6_addr)) == 0) {
            std::memcpy(mac, savedMac, 6);
            haveMac = true;
            T2_LOG("tunnel", L"PrepareTunnelPeer: neighbor table empty - using persisted peer MAC");
        }
    }
    T2_LOG("tunnel", L"PrepareTunnelPeer: ifIndex=%lu peer=%02x%02x:%02x%02x mac=%s",
           ifIndex, peer6.s6_addr[12], peer6.s6_addr[13],
           peer6.s6_addr[14], peer6.s6_addr[15],
           haveMac ? L"found" : L"NOT FOUND (ARP neighbor will not be set - tunnel will not work)");
    PublishTunnelPeer(peer6, haveMac ? mac : nullptr);
    PushTunnelPeerToDriver(peer6);
    PushTunnelLocalToDriver(ifIndex);
    if (haveMac) {
        EnsureTunnelIpv4Neighbor(ifIndex, MapPeerToIpv4(peer6), mac);
        RememberArpPrepared(peer6);
        return TunnelPrep::Ok;
    }
    return TunnelPrep::NoMac;
}

// ---- Path-silence streak -> distrust of the persisted peer (section 9) -----
// Two consecutive attempts that produced only Silent evidence (on either
// transport) make the persisted last-known peer suspect: the next peer
// resolution skips it and does the full neighbor/ping lookup. This applies in
// tunnel mode too (the old code trusted the persisted peer forever there).
inline std::atomic<int>& PathSilentStreak() {
    static std::atomic<int> s{0};
    return s;
}
inline bool NotePathSilent() { // true when the peer was just distrusted
    if (PathSilentStreak().fetch_add(1, std::memory_order_relaxed) + 1 >= 2) {
        PathSilentStreak().store(0, std::memory_order_relaxed);
        DistrustPersistedPeer();
        InvalidateTunnelPrepCache();
        T2_LOG("tunnel", L"2 silent attempts in a row - persisted peer distrusted, next resolve does a full lookup");
        return true;
    }
    return false;
}
inline void NotePathAlive() { PathSilentStreak().store(0, std::memory_order_relaxed); }

// ---- Cross-process transport lock + mode scope (sections 11, 12) ------------
// Named mutex shared by the UMDF host, the CLI and the GUI. Held for one
// "flip the driver mode + probe/scan + connect" phase, so no other process can
// flip TunnelModeEnabled in the middle of a scan (the unexplained
// "TunnelModeEnabled -> 0" mid-scan in the cold-boot log).
// DACL: SYSTEM, Administrators, LocalService full; interactive/authenticated
// users only SYNCHRONIZE|MUTEX_MODIFY_STATE (+READ_CONTROL) so the CLI/GUI can
// take it. [HW] verify LocalService can create/open it from WUDFHost.
inline constexpr wchar_t kTransportMutexName[] = L"Global\\T2TouchId_Transport";
inline constexpr DWORD kTransportLockWaitMs = 2000;

inline HANDLE TransportMutexHandle() {
    static HANDLE h = [] {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;0x120001;;;IU)(A;;0x120001;;;AU)",
                SDDL_REVISION_1, &sd, nullptr)) {
            sa.lpSecurityDescriptor = sd;
        }
        HANDLE m = CreateMutexExW(sd ? &sa : nullptr, kTransportMutexName, 0,
                                  SYNCHRONIZE | MUTEX_MODIFY_STATE);
        if (!m) m = OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, kTransportMutexName);
        if (!m) {
            T2_LOG("transport", L"transport mutex unavailable (GetLastError=%lu) - running without "
                   L"cross-process exclusivity", GetLastError());
        }
        if (sd) LocalFree(sd);
        return m;
    }();
    return h;
}

class TransportLock {
public:
    // Waits for the mutex OR the cancel event (whichever first). On timeout it
    // logs once and lets the caller proceed WITHOUT exclusivity: a process that
    // holds the mutex forever must not be able to block the fingerprint reader.
    explicit TransportLock(HANDLE cancelEvent = nullptr, DWORD waitMs = kTransportLockWaitMs) {
        h_ = TransportMutexHandle();
        if (!h_) return;
        HANDLE hs[2] = {h_, cancelEvent};
        const DWORD n = cancelEvent ? 2 : 1;
        const DWORD r = WaitForMultipleObjects(n, hs, FALSE, waitMs);
        // 0 = signaled (WAIT_OBJECT_0 spelled numerically, see Connection::IsEventSignaled),
        // 0x80 = WAIT_ABANDONED_0 (previous owner died: ownership is ours now).
        if (r == 0 || r == 0x80) {
            owned_ = true;
        } else if (r == 0x102) { // WAIT_TIMEOUT
            static std::atomic<bool> logged{false};
            if (!logged.exchange(true)) {
                T2_LOG("transport", L"TransportLock: %lu ms timeout - another process holds the transport "
                       L"mutex; continuing without exclusivity", waitMs);
            }
        }
    }
    ~TransportLock() { if (owned_) ReleaseMutex(h_); }
    TransportLock(const TransportLock&) = delete;
    TransportLock& operator=(const TransportLock&) = delete;
    bool owned() const { return owned_; }
private:
    HANDLE h_ = nullptr;
    bool owned_ = false;
};

// RAII driver-mode scope. Enter() puts the attempt's mode into the driver and makes it
// the attempt-scoped override (so PortScan/RemoteXPC/Connection, which read
// IsTunnelModeActive(), follow it). Restore() - also run by the destructor on
// EVERY exit path (success, failure, cancel, exception) - drops the override and
// puts the COMMITTED mode back:
//     driver mode == committed mode when a phase ends          (invariant 8)
//
// Both ends push only when the driver does NOT already hold that mode, judged by
// LastPushedModeFlag. That is exact, not a guess: this process is the only writer of
// the driver's mode (nothing else sends IOCTL_T2NCM_SET_TRANSPORT_MODE; the CLI only
// reads status), and the hint is reset to "unknown" on every event that can change what
// the driver holds - IOCTL failure, resume from Dx (Queue.cpp), InvalidateTunnelPrepCache
// after a failed connect. An unknown hint always writes.
// These calls used to be force=true, a leftover from when a GUI checkbox also wrote the
// mode. Blind forcing re-sent the value the driver already had: once on Enter and again
// on Restore of every phase, and between the native and the tunnel step of one connect
// a Restore(native) immediately followed by Enter(tunnel) - a mode flip the driver saw
// for microseconds and never needed.
class ModeScope {
public:
    ModeScope() = default;
    ~ModeScope() { Restore(); }
    ModeScope(const ModeScope&) = delete;
    ModeScope& operator=(const ModeScope&) = delete;
    void Enter(TransportMode m) {
        entered_ = true;
        TransportOverride().store(m == TransportMode::Ipv4Tunnel ? 1 : 0, std::memory_order_relaxed);
        PushTransportModeToDriver(m);
    }
    void Restore() {
        if (!entered_) return;
        entered_ = false;
        TransportOverride().store(-1, std::memory_order_relaxed);
        PushTransportModeToDriver(IsTunnelModeActive() ? TransportMode::Ipv4Tunnel
                                                       : TransportMode::NativeIpv6);
    }
private:
    bool entered_ = false;
};

// Lock + mode scope in one object. Members are destroyed in reverse order, so
// the mode is restored while the mutex is still held.
struct TransportPhase {
    explicit TransportPhase(HANDLE cancelEvent = nullptr) : lock(cancelEvent) {}
    // Declared FIRST so it is destroyed LAST: the Enter()/Restore() pushes (and every
    // push made by the phase body) share one control handle, and Restore() still has it
    // while the mutex is held. Opened lazily by the first IOCTL, closed when the phase ends.
    T2NcmControlLease controlLease;
    TransportLock lock;
    ModeScope mode;
};

} // namespace t2::transport
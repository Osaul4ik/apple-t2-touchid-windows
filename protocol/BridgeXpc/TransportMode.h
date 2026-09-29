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
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <vector>
#include "Log.h"
#include "Winsock.h"

#pragma comment(lib, "Iphlpapi.lib")

namespace t2::transport {

inline constexpr wchar_t kNetworkRegPath[] = L"SOFTWARE\\T2TouchId\\Network";
inline constexpr wchar_t kPeerIpv6Value[] = L"PeerIpv6";
inline constexpr wchar_t kPeerMacValue[] = L"PeerMac";

// ---- Transport selection: Native IPv6 vs IPv4 tunnel -------------------
//
// Three independent inputs decide which transport a Connect() starts on:
//
//  1. MANUAL FORCE (session, volatile): HKLM\...\Network\Session\
//     SkipNativeIpv6Probe = 1. Written by the GUI checkbox / SepVaultGui
//     --tunnel. Means "always tunnel, never probe IPv6". Disappears on reboot
//     (REG_OPTION_VOLATILE) so a forgotten box cannot pin future boots.
//
//  2. AUTO-SWITCH (persistent setting, default ON): HKLM\...\Network\
//     AutoSwitch (DWORD, missing == 1). Toggled from the GUI. When on, a
//     Native IPv6 connect that fails at the TCP level (VPN/WFP dropping IPv6)
//     is immediately retried over the IPv4 tunnel inside the same Connect()
//     call, and the tunnel is remembered (see 3). When off, behaviour is the
//     old manual-only one: whatever is forced, or Native IPv6.
//
//  3. AUTO-TUNNEL STATE (in-process only): set when a fallback to the tunnel
//     SUCCEEDED, never on a mere native failure (a T2 that is still booting
//     must not leave us pinned to a tunnel that does not work either). It is
//     deliberately not mirrored into the registry: the UMDF host runs as
//     LocalService and cannot write HKLM, and a stale cross-process copy that
//     one side can set but the other cannot clear was the source of the old
//     "stuck on tunnel" behaviour. Every process re-learns it with one
//     bounded native attempt.
//
// Native and tunnel are mutually exclusive at the driver level: while
// T2Ncm.sys has TunnelModeEnabled set it rewrites EVERY inbound IPv6 TCP/UDP
// frame to IPv4 (Tunnel.c, T2NcmTunnelRewriteRxIpv6ToIpv4), so a native SYN-ACK
// would never reach the IPv6 stack. That is why the two paths are tried one
// after the other, never raced in parallel.
//
// Getting back from tunnel to native is event-driven, not polled:
//  * a real add/delete of an IP interface (a VPN coming up or going down),
//  * WTS_SESSION_UNLOCK / real resume (Queue.cpp calls RequestNativeReprobe),
//  * the GUI bumping Session\ReprobeNonce,
//  * a slow safety net (kReprobeSafetyNetMs) for silent WFP policy changes.
// A re-probe costs one bounded native SYN (NativeConnectBudget) and only while
// auto-tunnel is active; on failure the known-good tunnel is used at once.
inline constexpr wchar_t kSessionRegPath[] = L"SOFTWARE\\T2TouchId\\Network\\Session";
inline constexpr wchar_t kSkipNativeIpv6ProbeValue[] = L"SkipNativeIpv6Probe"; // manual force (name kept for GUI compat)
inline constexpr wchar_t kReprobeNonceValue[] = L"ReprobeNonce";                // GUI bumps it on any transport change
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

inline bool IsTunnelForced() {
    static CachedDword c;
    return ReadDwordCached(c, kSessionRegPath, kSkipNativeIpv6ProbeValue, 0, 200) != 0;
}
inline bool IsAutoSwitchEnabled() {
    static CachedDword c;
    return ReadDwordCached(c, kNetworkRegPath, kAutoSwitchValue, 1, 1000) != 0;
}

inline std::atomic<bool> g_autoTunnel{false};

// THE query for "which transport is active right now" (discovery budgets,
// port scan, RemoteXPC and Connection all read this).
inline bool IsTunnelModeActive() {
    return g_autoTunnel.load(std::memory_order_relaxed) || IsTunnelForced();
}

// ---- native re-probe triggers -----------------------------------------
inline constexpr ULONGLONG kReprobeMinGapMs = 3000;       // flap guard
inline constexpr ULONGLONG kReprobeSafetyNetMs = 120000;  // silent WFP changes
inline std::atomic<bool> g_reprobeDue{false};
inline std::atomic<ULONGLONG> g_lastNativeTryTick{0};
inline std::atomic<DWORD> g_seenReprobeNonce{0};

inline void RequestNativeReprobe() { g_reprobeDue.store(true, std::memory_order_relaxed); }

// True at most once per trigger, and only while auto-tunnel is active.
inline bool ConsumeNativeReprobeDue() {
    if (!g_autoTunnel.load(std::memory_order_relaxed)) return false;
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG last = g_lastNativeTryTick.load(std::memory_order_relaxed);
    if (last != 0 && now - last < kReprobeMinGapMs) return false; // trigger stays pending
    bool due = g_reprobeDue.exchange(false, std::memory_order_relaxed);
    if (!due) {
        static CachedDword nonce;
        const DWORD n = ReadDwordCached(nonce, kSessionRegPath, kReprobeNonceValue, 0, 200);
        if (n != g_seenReprobeNonce.exchange(n, std::memory_order_relaxed)) due = true;
    }
    if (!due && last != 0 && now - last >= kReprobeSafetyNetMs) due = true;
    if (due) g_lastNativeTryTick.store(now, std::memory_order_relaxed);
    return due;
}

inline VOID NETIOAPI_API_ OnIpInterfaceChange(PVOID, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE type) {
    // Only real arrival/removal of an interface (VPN up/down). Parameter
    // changes (DAD, metrics, lifetimes) fire constantly and mean nothing here.
    if (type == MibAddInstance || type == MibDeleteInstance) RequestNativeReprobe();
}
inline void EnsureNetworkChangeWatch() {
    static std::once_flag once;
    std::call_once(once, [] {
        HANDLE h = nullptr;
        NotifyIpInterfaceChange(AF_UNSPEC, OnIpInterfaceChange, nullptr, FALSE, &h);
        // Handle intentionally kept for the process lifetime.
    });
}

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
    // 29.09.2026: until one native connect has succeeded in THIS process (ema == 0,
    // i.e. right after a cold boot) the neighbor table is empty and NDP + the T2's
    // bridgeOS listener still have to warm up; 150 ms was measured on a warm link
    // and made the very first native attempt after boot fail (WSA=10060 at 156 ms),
    // which committed the IPv4 tunnel for the rest of the process. Give that one
    // unmeasured attempt 400 ms; once ema is known the 60..250 ms rule applies.
    long long ms = (ema == 0) ? 400 : static_cast<long long>(ema) * 4 + 30;
    if (ms < 60) ms = 60;
    if (ms > ((ema == 0) ? 400 : 250)) ms = (ema == 0) ? 400 : 250;
    if (cap.count() < ms) ms = cap.count();
    return std::chrono::milliseconds(ms);
}
// Native TCP handshake completed: the IPv6 path works. Clears auto-tunnel.
inline void RecordNativeSuccess(ULONGLONG tcpMs) {
    const DWORD old = g_nativeEmaMs.load(std::memory_order_relaxed);
    DWORD next = (old == 0) ? static_cast<DWORD>(tcpMs) : static_cast<DWORD>((old * 3 + tcpMs) / 4);
    if (next == 0) next = 1;
    g_nativeEmaMs.store(next, std::memory_order_relaxed);
    g_autoTunnel.store(false, std::memory_order_relaxed);
}
// Tunnel handshake completed after native failed: remember it.
inline void CommitAutoTunnel(bool on) {
    g_autoTunnel.store(on, std::memory_order_relaxed);
    if (on) g_lastNativeTryTick.store(GetTickCount64(), std::memory_order_relaxed);
}

// ---- persisted-peer trust -----------------------------------------------
// Adapter.cpp uses the last-known T2 peer straight away when the neighbor
// table is empty (skipping the ~550 ms ping + poll). If a connect to that
// guessed peer then fails, this flag makes the NEXT discovery do the full
// ping-based lookup once instead of trusting it again.
inline std::atomic<bool> g_persistedPeerDistrusted{false};
inline void DistrustPersistedPeer() { g_persistedPeerDistrusted.store(true, std::memory_order_relaxed); }
inline bool ConsumePersistedPeerDistrust() { return g_persistedPeerDistrusted.exchange(false, std::memory_order_relaxed); }

// Standalone reachability probe: a throwaway TCP SYN at the T2 peer's IPv6
// link-local address, bounded by `timeout`. A completed handshake or an RST
// (WSAECONNREFUSED) both prove the SYN reached the peer over IPv6. Only
// meaningful while T2Ncm is in native mode (tunnel mode rewrites the reply).
inline bool ProbeNativeIpv6Reachable(const in6_addr& peer6, unsigned long ifIndex,
                                     std::chrono::milliseconds timeout) {
    if (!t2::EnsureWinsock()) return false;
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(1); // port need not be open - see comment above
    addr.sin6_addr = peer6;
    addr.sin6_scope_id = ifIndex;

    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);
    bool reachable = false;
    const int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        reachable = true;
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
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
            reachable = (err == 0 || err == WSAECONNREFUSED);
        }
        // sel <= 0: nothing came back within `timeout` - not reachable.
    }
    closesocket(s);
    return reachable;
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
    unsigned long ifIndex = 0;   // the static ARP row lives on ONE interface
    bool valid = false;
};
inline ArpPrepCacheState& ArpPrepCache() {
    static ArpPrepCacheState s;
    return s;
}
// 29.09.2026: keyed by (ifIndex, peer), not the peer alone. The T2 peer's
// link-local address is derived from its MAC and stays the same when the NCM
// adapter is re-enumerated (driver update/reinstall, cold boot) - but its
// ifIndex changes (log: 2 -> 17). With a peer-only key the cache said "already
// prepared" and skipped creating the static IPv4 ARP row on the NEW interface,
// so the first tunnel connect waited out its whole 2000 ms with nowhere to go.
inline bool IsArpAlreadyPrepared(unsigned long ifIndex, const in6_addr& peer6) {
    std::lock_guard<std::mutex> lock(ArpPrepCache().mu);
    return ArpPrepCache().valid && ArpPrepCache().ifIndex == ifIndex &&
           std::memcmp(&ArpPrepCache().peer, &peer6, sizeof(in6_addr)) == 0;
}
inline void RememberArpPrepared(unsigned long ifIndex, const in6_addr& peer6) {
    std::lock_guard<std::mutex> lock(ArpPrepCache().mu);
    ArpPrepCache().peer = peer6;
    ArpPrepCache().ifIndex = ifIndex;
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
}
inline ULONGLONG GetRealSuspendGeneration() {
    return RealSuspendGeneration().load(std::memory_order_acquire);
}

inline bool PushTunnelPeerToDriver(const in6_addr& peer6) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PushTunnelPeerToDriver: skipped (system suspending / Dx)");
        return false;
    }
    if (IsSameAsLastPushedPeer(peer6)) {
        return true; // already armed — kill port-scan IOCTL storm
    }
    // FILE_WRITE_DATA only (not GENERIC_WRITE): the control device grants
    // LocalService exactly that (see NdisMiniport.c SDDL); GENERIC_WRITE also
    // asks for WRITE_ATTRIBUTES/EA/APPEND and would be denied for the service.
    HANDLE h = CreateFileW(L"\\\\.\\T2Ncm", FILE_WRITE_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        T2_LOG("tunnel", L"PushTunnelPeerToDriver: could not open \\\\.\\T2Ncm "
               L"(GetLastError=%lu) - driver not loaded, or (5) access denied", GetLastError());
        return false;
    }
    DWORD returned = 0;
    const DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    BOOL ok = DeviceIoControl(h, code, (LPVOID)&peer6, (DWORD)sizeof(peer6),
                              nullptr, 0, &returned, nullptr);
    if (!ok) {
        T2_LOG("tunnel", L"PushTunnelPeerToDriver: IOCTL failed, GetLastError=%lu", GetLastError());
    } else {
        RememberLastPushedPeer(peer6);
    }
    CloseHandle(h);
    return ok != FALSE;
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
    HANDLE h = CreateFileW(L"\\\\.\\T2Ncm", FILE_WRITE_DATA, // see PushTunnelPeerToDriver
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        T2_LOG("tunnel", L"PushTunnelLocalToDriver: could not open \\\\.\\T2Ncm "
               L"(GetLastError=%lu) - driver not loaded, or (5) access denied", GetLastError());
        return false;
    }
    DWORD returned = 0;
    const DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    BOOL ok = DeviceIoControl(h, code, (LPVOID)&local, (DWORD)sizeof(local),
                              nullptr, 0, &returned, nullptr);
    if (!ok) {
        // An older T2Ncm.sys without this IOCTL fails here (ERROR_INVALID_FUNCTION):
        // harmless, the driver keeps learning passively as before.
        T2_LOG("tunnel", L"PushTunnelLocalToDriver: IOCTL failed, GetLastError=%lu", GetLastError());
    } else {
        RememberLastPushedLocal(local);
        T2_LOG("tunnel", L"PushTunnelLocalToDriver: local fe80 ...%02x%02x:%02x%02x armed in driver",
               local.s6_addr[12], local.s6_addr[13], local.s6_addr[14], local.s6_addr[15]);
    }
    CloseHandle(h);
    return ok != FALSE;
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
inline bool PushTransportModeToDriver(TransportMode mode) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PushTransportModeToDriver: skipped (system suspending / Dx)");
        return false;
    }
    const int want = (mode == TransportMode::Ipv4Tunnel) ? 1 : 0;
    if (LastPushedModeFlag().load(std::memory_order_relaxed) == want) {
        // Already live in driver from our point of view — skip IOCTL storm.
        return true;
    }
    HANDLE h = CreateFileW(L"\\\\.\\T2Ncm", FILE_WRITE_DATA, // see PushTunnelPeerToDriver
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        T2_LOG("tunnel", L"PushTransportModeToDriver: could not open \\\\.\\T2Ncm "
               L"(GetLastError=%lu) - driver not loaded, or (5) access denied", GetLastError());
        return false;
    }
    DWORD returned = 0;
    DWORD modeValue = static_cast<DWORD>(mode);
    // Same CTL_CODE as T2NCM/driver/Public.h's IOCTL_T2NCM_SET_TRANSPORT_MODE
    // (0x903) - hand-rolled rather than including Public.h, matching how
    // PushTunnelPeerToDriver above already hand-rolls IOCTL_T2NCM_SET_TUNNEL_PEER
    // (0x902) in this file to avoid the winioctl.h double-inclusion hazard
    // documented at the top of this file.
    const DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    BOOL ok = DeviceIoControl(h, code, &modeValue, (DWORD)sizeof(modeValue),
                              nullptr, 0, &returned, nullptr);
    if (!ok) {
        T2_LOG("tunnel", L"PushTransportModeToDriver: IOCTL failed, GetLastError=%lu", GetLastError());
    } else {
        LastPushedModeFlag().store(want, std::memory_order_relaxed);
        ClearLastPushedLocal(); // mode flipped: re-arm the local address on the next PrepareTunnelPeer
        T2_LOG("tunnel", L"PushTransportModeToDriver: live TunnelModeEnabled -> %d", want);
    }
    CloseHandle(h);
    return ok != FALSE;
}

// Call before AF_INET connect in tunnel mode.
inline void PrepareTunnelPeer(unsigned long ifIndex, const in6_addr& peer6) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PrepareTunnelPeer: skipped (system suspending / Dx)");
        return;
    }
    // Fast path: same peer as last time we successfully prepared it, and
    // nothing has invalidated that since (see InvalidateTunnelPrepCache).
    // Skips the neighbor-table walk and the ARP create/set syscalls -
    // still publishes the peer to the registry and (via the existing
    // IsSameAsLastPushedPeer dedupe inside it) pushes it to the driver,
    // both of which are already cheap early-outs.
    if (IsArpAlreadyPrepared(ifIndex, peer6)) {
        PublishTunnelPeer(peer6, nullptr);
        PushTunnelPeerToDriver(peer6);
        PushTunnelLocalToDriver(ifIndex);
        return;
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
        RememberArpPrepared(ifIndex, peer6);
    }
}

// Cold-discovery pre-flight (BridgeDiscovery.cpp): with no cached BridgeXPC
// port the next step is a full port scan, which over a blocked IPv6 path
// burns seconds probing nothing. One bounded native SYN at the peer decides
// first. Returns true when native IPv6 works (or the answer is unknowable),
// false when it does not - the caller then arms the tunnel provisionally.
inline bool PreflightNativeIpv6(const in6_addr& peer6, unsigned long ifIndex) {
    PushTransportModeToDriver(TransportMode::NativeIpv6); // probe needs a native RX path
    const ULONGLONG t0 = GetTickCount64();
    const bool ok = ProbeNativeIpv6Reachable(peer6, ifIndex,
                        NativeConnectBudget(std::chrono::milliseconds(250)));
    if (ok) RecordNativeSuccess(GetTickCount64() - t0);
    T2_LOG("tunnel", L"PreflightNativeIpv6: %s (%llu ms)", ok ? L"reachable" : L"UNREACHABLE",
           static_cast<unsigned long long>(GetTickCount64() - t0));
    return ok;
}

} // namespace t2::transport
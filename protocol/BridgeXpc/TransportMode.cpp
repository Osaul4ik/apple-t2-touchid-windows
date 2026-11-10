// SPDX-License-Identifier: GPL-2.0-only
// TransportMode.cpp - definitions for TransportMode.h. All in-process transport
// state is ONE object (TransportState) instead of ~40 function-local statics and
// inline globals spread over the header: what a process knows about the transport
// is visible in one place, a test can reset it (testing::ResetState), and the
// diagnostic snapshot reads it from there.
#include "TransportMode.h"
// After TransportMode.h (winsock2.h before windows.h). See the old header comment:
// winioctl.h only when an earlier include has not already pulled it in.
#ifndef _WINIOCTL_
#include <winioctl.h>
#endif
#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
#include <cstring>
#include <mutex>

namespace t2::transport {

// ============================================================================
// State
// ============================================================================
namespace {

struct PushedAddr {
    std::mutex mu;
    in6_addr addr{};
    bool valid = false;
    bool Is(const in6_addr& a) {
        std::lock_guard<std::mutex> lock(mu);
        return valid && std::memcmp(&addr, &a, sizeof(in6_addr)) == 0;
    }
    void Set(const in6_addr& a) {
        std::lock_guard<std::mutex> lock(mu);
        addr = a;
        valid = true;
    }
    void Clear() {
        std::lock_guard<std::mutex> lock(mu);
        valid = false;
    }
};

struct T2NcmControlState {
    std::mutex mu;
    // Serializes IOCTL use and stale-handle replacement. A lease only protects
    // the final close; without this lock another caller may close a handle
    // while DeviceIoControl is using it. Acquire before mu, never vice versa.
    std::timed_mutex ioctlMu;
    HANDLE h = INVALID_HANDLE_VALUE;
    unsigned refs = 0;
};

struct TransportState {
    // Generation (section 3) and the real-suspend counter.
    std::atomic<ULONGLONG> generation{1};
    std::atomic<ULONGLONG> realSuspendGeneration{0};

    // Committed ("sticky") tunnel: in-process copy of the driver flag.
    std::atomic<bool> autoTunnel{false};
    std::atomic<ULONGLONG> autoTunnelGen{0};
    // 0 = not seeded yet, 1 = seeded from the driver, 2 = the driver has no such
    // IOCTL or is not reachable (in-process flag only).
    std::atomic<int> stickySeed{0};
    std::mutex stickySeedMu;

    // Attempt-scoped override: -1 none, 0 native, 1 tunnel (ModeScope).
    std::atomic<int> override_{-1};
    // Generation in which IPv6 was found unusable on the adapter (0 = never).
    std::atomic<ULONGLONG> v6UnavailableGen{0};
    // One native re-check of a committed tunnel is pending.
    std::atomic<bool> nativeRevalidate{false};

    // Adaptive budgets (smoothed successful TCP handshake, ms; 0 = not measured).
    std::atomic<DWORD> nativeEmaMs{0};
    std::atomic<DWORD> tunnelEmaMs{0};

    // Persisted-peer trust and the silence streak (section 9).
    std::atomic<bool> persistedPeerDistrusted{false};
    std::atomic<int> pathSilentStreak{0};

    // Sleep / Dx gate.
    std::atomic<bool> ioSuspended{false};

    // What this process last pushed to T2Ncm.sys (dedupe records).
    std::atomic<int> lastPushedMode{-1}; // -1 unknown, 0 native, 1 tunnel
    PushedAddr lastPushedPeer;
    PushedAddr lastPushedLocal;
    PushedAddr arpPrepared; // static ARP row known to hold the peer's MAC

    // In-process serialization for the PeerIpv6/PeerMac registry pair.
    std::mutex peerRegistryMu;

    T2NcmControlState control;

    void Reset() {
        generation = 1;
        realSuspendGeneration = 0;
        autoTunnel = false;
        autoTunnelGen = 0;
        stickySeed = 0;
        override_ = -1;
        v6UnavailableGen = 0;
        nativeRevalidate = false;
        nativeEmaMs = 0;
        tunnelEmaMs = 0;
        persistedPeerDistrusted = false;
        pathSilentStreak = 0;
        ioSuspended = false;
        lastPushedMode = -1;
        lastPushedPeer.Clear();
        lastPushedLocal.Clear();
        arpPrepared.Clear();
        std::lock_guard<std::mutex> lock(control.mu);
        if (control.h != INVALID_HANDLE_VALUE) CloseHandle(control.h);
        control.h = INVALID_HANDLE_VALUE;
        control.refs = 0;
    }
};

TransportState& S() {
    static TransportState s;
    return s;
}

// Cached registry DWORDs of the Network key. Reset with the state.
struct RegCache {
    CachedDword autoSwitch;
    CachedDword rstIsProof;
    void Reset() {
        autoSwitch.at = 0;
        rstIsProof.at = 0;
    }
};
RegCache& R() {
    static RegCache r;
    return r;
}

std::atomic<const hooks::Hooks*> g_hooks{nullptr};

} // namespace

namespace hooks {
const Hooks* Active() { return g_hooks.load(std::memory_order_acquire); }
void Install(const Hooks* h) {
    g_hooks.store(h, std::memory_order_release);
    R().Reset(); // the registry root may have moved
}
void Clear() {
    g_hooks.store(nullptr, std::memory_order_release);
    R().Reset();
}
} // namespace hooks

namespace testing {
void ResetState() {
    S().Reset();
    R().Reset();
}
} // namespace testing

// ============================================================================
// Registry
// ============================================================================
static DWORD ReadDwordCachedAt(CachedDword& c, HKEY root, const wchar_t* subKey,
                               const wchar_t* name, DWORD def, ULONGLONG ttlMs) {
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG last = c.at.load(std::memory_order_relaxed);
    if (last != 0 && now - last < ttlMs) return c.val.load(std::memory_order_relaxed);
    DWORD v = def;
    DWORD cb = sizeof(v);
    if (RegGetValueW(root, subKey, name, RRF_RT_REG_DWORD, nullptr, &v, &cb) != ERROR_SUCCESS) {
        v = def; // missing key/value or no read access: fail to the default
    }
    c.val.store(v, std::memory_order_relaxed);
    c.at.store(now, std::memory_order_relaxed);
    return v;
}

DWORD ReadDwordCached(CachedDword& c, const wchar_t* subKey, const wchar_t* name, DWORD def,
                      ULONGLONG ttlMs) {
    return ReadDwordCachedAt(c, HKEY_LOCAL_MACHINE, subKey, name, def, ttlMs);
}

HKEY NetworkRegRoot() {
    const hooks::Hooks* h = hooks::Active();
    return (h && h->regRoot) ? h->regRoot : HKEY_LOCAL_MACHINE;
}
const wchar_t* NetworkRegPath() {
    const hooks::Hooks* h = hooks::Active();
    return (h && !h->regPath.empty()) ? h->regPath.c_str() : kNetworkRegPath;
}
DWORD ReadNetworkDwordCached(CachedDword& c, const wchar_t* name, DWORD def, ULONGLONG ttlMs) {
    return ReadDwordCachedAt(c, NetworkRegRoot(), NetworkRegPath(), name, def, ttlMs);
}

bool IsAutoSwitchEnabled() {
    return ReadNetworkDwordCached(R().autoSwitch, kAutoSwitchValue, 1, 1000) != 0;
}

// ============================================================================
// Generation
// ============================================================================
ULONGLONG CurrentGeneration() { return S().generation.load(std::memory_order_acquire); }

ULONGLONG BumpGeneration(const wchar_t* why) {
    const ULONGLONG n = S().generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    T2_LOG("transport", L"Generation -> %llu (%s)", static_cast<unsigned long long>(n),
           why ? why : L"?");
    T2_DIAG("state", L"Generation -> %llu (%s) - committed tunnel keeps, V6Unavailable/scan progress reset",
            static_cast<unsigned long long>(n), why ? why : L"?");
    return n;
}

void BumpRealSuspendGeneration() {
    S().realSuspendGeneration.fetch_add(1, std::memory_order_acq_rel);
    BumpGeneration(L"real Sx suspend/resume"); // V6Unavailable, scan progress start over
}
ULONGLONG GetRealSuspendGeneration() {
    return S().realSuspendGeneration.load(std::memory_order_acquire);
}

// ============================================================================
// Committed tunnel, override, V6Unavailable, re-check
// ============================================================================
bool IsAutoTunnelCommitted() {
    EnsureStickySeededFromDriver(); // one IOCTL per process, then a relaxed load
    return S().autoTunnel.load(std::memory_order_relaxed);
}

bool HasTransportOverride() { return S().override_.load(std::memory_order_relaxed) >= 0; }

bool IsTunnelModeActive() {
    const int ov = S().override_.load(std::memory_order_relaxed);
    if (ov >= 0) return ov == 1;
    return IsAutoTunnelCommitted();
}

void MarkV6Unavailable(const wchar_t* why) {
    S().v6UnavailableGen.store(CurrentGeneration(), std::memory_order_relaxed);
    T2_DIAG("state", L"V6Unavailable SET gen=%llu reason=%s",
            static_cast<unsigned long long>(CurrentGeneration()), why ? why : L"?");
}
void ClearV6Unavailable(const wchar_t* why) {
    if (S().v6UnavailableGen.exchange(0, std::memory_order_relaxed) != 0) {
        T2_DIAG("state", L"V6Unavailable CLEARED reason=%s", why ? why : L"?");
    }
}
bool IsV6Unavailable() {
    return S().v6UnavailableGen.load(std::memory_order_relaxed) == CurrentGeneration();
}

void RequestNativeRevalidate() {
    S().nativeRevalidate.store(true, std::memory_order_relaxed);
    T2_DIAG("state", L"native re-check requested (sticky tunnel=%d)",
            S().autoTunnel.load(std::memory_order_relaxed) ? 1 : 0);
}
bool ConsumeNativeRevalidate() {
    const bool had = S().nativeRevalidate.exchange(false, std::memory_order_relaxed);
    if (had) T2_DIAG("state", L"native re-check consumed by this connect");
    return had;
}
void RequestNativeReprobe() {
    ClearV6Unavailable(L"unlock / network change (RequestNativeReprobe)");
    RequestNativeRevalidate();
}

// ============================================================================
// Path evidence
// ============================================================================
bool IsRstProof() {
    return ReadNetworkDwordCached(R().rstIsProof, L"RstIsProof", 0, 1000) != 0;
}
bool IsPositiveEvidence(PathEvidence e) {
    return e == PathEvidence::Positive || (e == PathEvidence::Refused && IsRstProof());
}
PathEvidence ClassifyWsaError(int wsa) {
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

// ============================================================================
// Adaptive budgets
// ============================================================================
std::chrono::milliseconds NativeConnectBudget(std::chrono::milliseconds cap) {
    const DWORD ema = S().nativeEmaMs.load(std::memory_order_relaxed);
    long long ms = (ema == 0) ? 150 : static_cast<long long>(ema) * 4 + 30;
    if (ms < 60) ms = 60;
    if (ms > 250) ms = 250;
    if (cap.count() < ms) ms = cap.count();
    return std::chrono::milliseconds(ms);
}

void RecordNativeSuccess(ULONGLONG tcpMs) {
    auto& s = S();
    const DWORD old = s.nativeEmaMs.load(std::memory_order_relaxed);
    DWORD next = (old == 0) ? static_cast<DWORD>(tcpMs) : static_cast<DWORD>((old * 3 + tcpMs) / 4);
    if (next == 0) next = 1;
    s.nativeEmaMs.store(next, std::memory_order_relaxed);
    EnsureStickySeededFromDriver();
    if (s.autoTunnel.exchange(false, std::memory_order_relaxed)) {
        T2_DIAG("state", L"sticky tunnel CLEARED: native handshake worked (tcp %llu ms)",
                static_cast<unsigned long long>(tcpMs));
        PushTunnelStickyToDriver(false);
    }
    ClearV6Unavailable(L"native handshake worked");
    s.nativeRevalidate.store(false, std::memory_order_relaxed); // nothing left to re-check
}

std::chrono::milliseconds TunnelConnectBudget(std::chrono::milliseconds cap) {
    const DWORD ema = S().tunnelEmaMs.load(std::memory_order_relaxed);
    long long ms = (ema == 0) ? 500 : static_cast<long long>(ema) * 8 + 150;
    if (ms < 200) ms = 200;
    if (ms > 500) ms = 500;
    if (cap.count() < ms) ms = cap.count();
    return std::chrono::milliseconds(ms);
}

void RecordTunnelSuccess(ULONGLONG tcpMs) {
    const DWORD old = S().tunnelEmaMs.load(std::memory_order_relaxed);
    DWORD next = (old == 0) ? static_cast<DWORD>(tcpMs) : static_cast<DWORD>((old * 3 + tcpMs) / 4);
    if (next == 0) next = 1;
    S().tunnelEmaMs.store(next, std::memory_order_relaxed);
}

void CommitAutoTunnel(bool on) {
    auto& s = S();
    EnsureStickySeededFromDriver();
    const bool was = s.autoTunnel.exchange(on, std::memory_order_relaxed);
    if (was != on) {
        T2_DIAG("state", L"sticky tunnel %s (gen=%llu, v6Unavailable=%d)",
                on ? L"COMMITTED" : L"DROPPED (auto-switch off)",
                static_cast<unsigned long long>(CurrentGeneration()), IsV6Unavailable() ? 1 : 0);
    }
    if (on) {
        s.autoTunnelGen.store(CurrentGeneration(), std::memory_order_relaxed);
        // Native was just found dead: an older unlock's re-check request is stale.
        s.nativeRevalidate.store(false, std::memory_order_relaxed);
    }
    if (was != on) PushTunnelStickyToDriver(on);
}

// ============================================================================
// Persisted-peer trust, silence streak
// ============================================================================
void DistrustPersistedPeer() { S().persistedPeerDistrusted.store(true, std::memory_order_relaxed); }
bool ConsumePersistedPeerDistrust() {
    return S().persistedPeerDistrusted.exchange(false, std::memory_order_relaxed);
}
bool NotePathSilent() {
    auto& s = S();
    if (s.pathSilentStreak.fetch_add(1, std::memory_order_relaxed) + 1 >= 2) {
        s.pathSilentStreak.store(0, std::memory_order_relaxed);
        DistrustPersistedPeer();
        InvalidateTunnelPrepCache();
        T2_LOG("tunnel", L"2 silent attempts in a row - persisted peer distrusted, next resolve does a full lookup");
        T2_DIAG("state", L"2 silent attempts in a row - persisted peer distrusted");
        return true;
    }
    return false;
}
void NotePathAlive() { S().pathSilentStreak.store(0, std::memory_order_relaxed); }

// ============================================================================
// Peer addressing
// ============================================================================
in_addr MapPeerToIpv4(const in6_addr& peer6) {
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

bool IsTunnelMappedIpv4(const in_addr& a) {
    return a.S_un.S_un_b.s_b1 == 169 && a.S_un.S_un_b.s_b2 == 254;
}

PeerAddress MakePeerAddress(bool tunnel, const in6_addr& peer6, unsigned long ifIndex,
                            uint16_t port) {
    PeerAddress pa;
    const hooks::Hooks* h = hooks::Active();
    if (h && h->peerAddress && h->peerAddress(tunnel, port, &pa)) return pa;
    if (tunnel) {
        auto* a4 = reinterpret_cast<sockaddr_in*>(&pa.addr);
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        a4->sin_addr = MapPeerToIpv4(peer6);
        pa.len = sizeof(sockaddr_in);
        pa.family = AF_INET;
    } else {
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&pa.addr);
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        a6->sin6_addr = peer6;
        a6->sin6_scope_id = ifIndex;
        pa.len = sizeof(sockaddr_in6);
        pa.family = AF_INET6;
    }
    return pa;
}

int ConnectToPeer(SOCKET s, const PeerAddress& a, bool tunnel, uint16_t port) {
    const hooks::Hooks* h = hooks::Active();
    if (h && h->connectVerdict) {
        const int verdict = h->connectVerdict(tunnel, port);
        if (verdict != 0) {
            WSASetLastError(verdict);
            return SOCKET_ERROR;
        }
    }
    return connect(s, a.sa(), a.len);
}

PathEvidence ProbeNativePath(const in6_addr& peer6, unsigned long ifIndex, uint16_t port,
                             std::chrono::milliseconds timeout, ULONGLONG* outMs) {
    const ULONGLONG t0 = GetTickCount64();
    auto done = [&](PathEvidence e) {
        if (outMs) *outMs = GetTickCount64() - t0;
        return e;
    };
    if (!t2::EnsureWinsock() || port == 0) return done(PathEvidence::LocalError);
    const PeerAddress pa = MakePeerAddress(false, peer6, ifIndex, port);
    SOCKET s = socket(pa.family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return done(PathEvidence::LocalError);

    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);
    PathEvidence ev = PathEvidence::Silent;
    const int rc = ConnectToPeer(s, pa, false, port);
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
    // RST instead of a FIN dance: this was only a reachability probe.
    linger lg{1, 0};
    setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg));
    closesocket(s);
    return done(ev);
}

// ============================================================================
// MAC / peer persistence
// ============================================================================
bool IsUsableMac(const UCHAR mac[6]) {
    if (!mac) return false;
    if (mac[0] & 0x01) return false; // multicast / broadcast
    for (int i = 0; i < 6; ++i) {
        if (mac[i] != 0) return true;
    }
    return false;
}

bool MacFromEui64(const in6_addr& peer6, UCHAR outMac[6]) {
    if (peer6.s6_addr[0] != 0xFE || (peer6.s6_addr[1] & 0xC0) != 0x80) return false;
    if (peer6.s6_addr[11] != 0xFF || peer6.s6_addr[12] != 0xFE) return false;
    outMac[0] = static_cast<UCHAR>(peer6.s6_addr[8] ^ 0x02); // flip U/L bit
    outMac[1] = peer6.s6_addr[9];
    outMac[2] = peer6.s6_addr[10];
    outMac[3] = peer6.s6_addr[13];
    outMac[4] = peer6.s6_addr[14];
    outMac[5] = peer6.s6_addr[15];
    return IsUsableMac(outMac);
}

bool PublishTunnelPeer(const in6_addr& peer6, const UCHAR mac[6]) {
    std::lock_guard<std::mutex> guard(S().peerRegistryMu);
    HKEY key = nullptr;
    const LSTATUS opened = RegCreateKeyExW(NetworkRegRoot(), NetworkRegPath(), 0, nullptr, 0,
                                           KEY_READ | KEY_WRITE, nullptr, &key, nullptr);
    if (opened != ERROR_SUCCESS) {
        T2_LOG("tunnel", L"PublishTunnelPeer: cannot open registry key (error=%ld)", opened);
        return false;
    }
    in6_addr previousPeer{};
    DWORD previousType = 0;
    DWORD previousSize = sizeof(previousPeer);
    const bool samePeer =
        RegQueryValueExW(key, kPeerIpv6Value, nullptr, &previousType,
                         reinterpret_cast<LPBYTE>(&previousPeer), &previousSize) == ERROR_SUCCESS &&
        previousType == REG_BINARY && previousSize == sizeof(previousPeer) &&
        std::memcmp(&previousPeer, &peer6, sizeof(peer6)) == 0;
    const bool writeMac = IsUsableMac(mac);
    // Invalidate stale MAC before switching to a new peer. Preserve it when
    // the exact peer is unchanged and discovery has no new MAC.
    if (!samePeer) {
        const LSTATUS deleted = RegDeleteValueW(key, kPeerMacValue);
        if (deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND) {
            T2_LOG("tunnel", L"PublishTunnelPeer: cannot invalidate old MAC (error=%ld)", deleted);
            RegCloseKey(key);
            return false;
        }
    }
    LSTATUS result = RegSetValueExW(key, kPeerIpv6Value, 0, REG_BINARY,
                                   reinterpret_cast<const BYTE*>(&peer6), sizeof(peer6));
    if (result == ERROR_SUCCESS && writeMac) {
        result = RegSetValueExW(key, kPeerMacValue, 0, REG_BINARY, mac, 6);
    }
    if (result != ERROR_SUCCESS) {
        // Fail closed: don't leave a new peer paired with a previous MAC.
        // Best effort only: registry writes are not an atomic transaction.
        RegDeleteValueW(key, kPeerMacValue);
        RegDeleteValueW(key, kPeerIpv6Value);
        T2_LOG("tunnel", L"PublishTunnelPeer: write failed (error=%ld)", result);
    }
    RegCloseKey(key);
    return result == ERROR_SUCCESS;
}

bool ReadPersistedPeer(in6_addr* peer6, UCHAR mac[6], bool* haveMac) {
    std::lock_guard<std::mutex> guard(S().peerRegistryMu);
    HKEY key = nullptr;
    if (RegOpenKeyExW(NetworkRegRoot(), NetworkRegPath(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
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
                   type == REG_BINARY && cb == 6 && IsUsableMac(mac);
    }
    RegCloseKey(key);
    return ok;
}

bool LookupPeerMac(unsigned long ifIndex, const in6_addr& peer6, UCHAR outMac[6]) {
    PMIB_IPNET_TABLE2 table = nullptr;
    if (GetIpNetTable2(AF_INET6, &table) != NO_ERROR || !table) {
        return false;
    }
    bool found = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& e = table->Table[i];
        if (e.InterfaceIndex != ifIndex) continue;
        if (e.Address.si_family != AF_INET6) continue;
        if (e.PhysicalAddressLength != 6) continue;
        if (e.State == NlnsUnreachable || e.State == NlnsIncomplete) continue;
        if (!IsUsableMac(e.PhysicalAddress)) continue;
        if (std::memcmp(&e.Address.Ipv6.sin6_addr, &peer6, sizeof(in6_addr)) == 0) {
            std::memcpy(outMac, e.PhysicalAddress, 6);
            found = true;
            break;
        }
    }
    FreeMibTable(table);
    return found;
}

// Static neighbor so TCP SYN is not stuck on ARP for 169.254.x.y.
// Returns true only if the row now holds `mac`. A non-usable MAC is refused
// outright - a static row pointing at 00-00-00-00-00-00 black-holes the tunnel.
static bool EnsureTunnelIpv4Neighbor(unsigned long ifIndex, const in_addr& peer4,
                                     const UCHAR mac[6]) {
    if (!IsUsableMac(mac)) {
        T2_LOG("tunnel", L"ARP neighbor not set: refusing unusable MAC (zero/multicast) for ifIndex=%lu", ifIndex);
        return false;
    }
    MIB_IPNET_ROW2 row{};
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr = peer4;
    row.InterfaceIndex = ifIndex;
    std::memcpy(row.PhysicalAddress, mac, 6);
    row.PhysicalAddressLength = 6;
    row.State = NlnsPermanent;
    // CreateIpNetEntry2 only succeeds for a row that doesn't exist yet. In
    // tunnel mode the row for 169.254.a.b almost always already exists - a
    // leftover Permanent entry with a now-stale MAC (T2 rebooted), or an
    // Incomplete/Unreachable row Windows' own ARP left behind. Any failure to
    // create (ALREADY_EXISTS included) must fall through to Set, which
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
    return createdFresh || setResult == NO_ERROR;
}

// ============================================================================
// Sleep / Dx gate, dedupe records
// ============================================================================
void SetTransportIoSuspended(bool suspended) {
    S().ioSuspended.store(suspended, std::memory_order_release);
}
bool IsTransportIoSuspended() { return S().ioSuspended.load(std::memory_order_acquire); }

void ResetLastPushedMode() { S().lastPushedMode.store(-1, std::memory_order_relaxed); }
void ClearLastPushedPeer() { S().lastPushedPeer.Clear(); }

void InvalidateTunnelPrepCache() {
    auto& s = S();
    s.arpPrepared.Clear();
    s.lastPushedPeer.Clear();
    s.lastPushedLocal.Clear();
    s.lastPushedMode.store(-1, std::memory_order_relaxed);
}

// ============================================================================
// \\.\T2Ncm control handle
// ============================================================================
T2NcmControlLease::T2NcmControlLease() {
    auto& c = S().control;
    std::lock_guard<std::mutex> lock(c.mu);
    ++c.refs;
}

T2NcmControlLease::~T2NcmControlLease() {
    auto& c = S().control;
    std::lock_guard<std::mutex> lock(c.mu);
    if (c.refs > 0) --c.refs;
    if (c.refs == 0 && c.h != INVALID_HANDLE_VALUE) {
        CloseHandle(c.h);
        c.h = INVALID_HANDLE_VALUE;
    }
}

namespace {

struct T2NcmIoctlResult {
    bool  ok = false;
    bool  openFailed = false; // open failure is already logged by T2NcmControlIoctl
    DWORD err = 0;            // GetLastError of the failing call (0 when ok)
};

// Errors that mean "this handle no longer refers to a live control device"
// (driver unloaded / re-created while the handle was cached). Anything else -
// notably ERROR_INVALID_FUNCTION from an older T2Ncm.sys - is a real answer and
// must reach the caller unchanged.
bool IsStaleControlHandleError(DWORD e) {
    return e == ERROR_INVALID_HANDLE || e == ERROR_DEVICE_REMOVED ||
           e == ERROR_NO_SUCH_DEVICE || e == ERROR_DEV_NOT_EXIST ||
           e == ERROR_DEVICE_NOT_CONNECTED;
}

// One IOCTL on the shared handle. FILE_WRITE_DATA only (not GENERIC_WRITE): the
// control device grants LocalService exactly that (see NdisMiniport.c SDDL);
// GENERIC_WRITE also asks for WRITE_ATTRIBUTES/EA/APPEND and would be denied for
// the service. A stale cached handle is dropped and the IOCTL retried once on a
// fresh open.
T2NcmIoctlResult T2NcmControlIoctl(const wchar_t* who, DWORD code, LPVOID in, DWORD inSize,
                                   LPVOID out = nullptr, DWORD outSize = 0,
                                   DWORD* outReturned = nullptr) {
    T2NcmIoctlResult r;
    if (const hooks::Hooks* h = hooks::Active(); h && h->ncmIoctl) {
        if (IsTransportIoSuspended()) {
            r.err = ERROR_OPERATION_ABORTED;
            return r;
        }
        DWORD returned = 0;
        bool ok = false;
        DWORD err = 0;
        if (h->ncmIoctl(code, in, inSize, out, outSize, &returned, &ok, &err)) {
            r.ok = ok;
            r.err = ok ? 0 : err;
            if (ok && outReturned) *outReturned = returned;
            return r;
        }
    }
    T2NcmControlLease lease; // keeps the handle open for the duration of this call at least
    auto& s = S().control;
    // Do not let a competing IOCTL invalidate and close our handle mid-call.
    // Lease construction holds mu only briefly; no path takes mu and then ioctlMu.
    // Suspend can arrive while another IOCTL holds this mutex. Bound each
    // wait slice so we can abort without opening a new handle or issuing IOCTL.
    std::unique_lock<std::timed_mutex> ioctlLock(s.ioctlMu, std::defer_lock);
    while (!ioctlLock.try_lock_for(std::chrono::milliseconds(100))) {
        if (IsTransportIoSuspended()) {
            r.err = ERROR_OPERATION_ABORTED;
            return r;
        }
    }
    for (int attempt = 0; attempt < 2; ++attempt) {
        // A stale-handle retry must not reopen T2Ncm after Dx/suspend.
        // This does not interrupt an already running synchronous IOCTL.
        if (IsTransportIoSuspended()) {
            r.err = ERROR_OPERATION_ABORTED;
            return r;
        }
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
        // Suspending while waiting to open the handle must not start an IOCTL.
        if (IsTransportIoSuspended()) {
            r.err = ERROR_OPERATION_ABORTED;
            return r;
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

// Same CTL_CODEs as T2NCM/driver/Public.h (hand-rolled rather than including it,
// to avoid the winioctl.h double-inclusion hazard). All FILE_WRITE_ACCESS: the
// control device hands LocalService a write-only handle, and the I/O manager checks
// only the access the code requires, so the GET still returns its output.
constexpr DWORD kIoctlSetTunnelPeer =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_WRITE_ACCESS);
constexpr DWORD kIoctlSetTransportMode =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_WRITE_ACCESS);
constexpr DWORD kIoctlSetTunnelLocal =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_WRITE_ACCESS);
constexpr DWORD kIoctlSetTunnelSticky =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_WRITE_ACCESS);
constexpr DWORD kIoctlGetTunnelState =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_WRITE_ACCESS);

struct T2NcmTunnelStateWire { // == T2NCM_TUNNEL_STATE (Public.h)
    ULONG Version;
    ULONG Sticky;
    ULONG Mode;
};

bool ReadTunnelStateFromDriver(T2NcmTunnelStateWire* out, DWORD* err) {
    T2NcmTunnelStateWire st{};
    DWORD returned = 0;
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"GetTunnelState", kIoctlGetTunnelState,
                                                 nullptr, 0, &st, sizeof(st), &returned);
    if (err) *err = r.err;
    if (!r.ok || returned < sizeof(st)) return false;
    *out = st;
    return true;
}

// Windows' REAL link-local IPv6 address on the T2 adapter, read straight from
// the IP stack's own configuration (works while a VPN/WFP filter drops all
// IPv6 traffic - it never touches the wire). Prefers a Preferred address,
// otherwise takes any link-local one (Tentative right after boot).
bool LookupLocalLinkLocal(unsigned long ifIndex, in6_addr* out) {
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

} // namespace

// ============================================================================
// Sticky flag in T2Ncm.sys memory
// ============================================================================
void EnsureStickySeededFromDriver() {
    auto& s = S();
    if (s.stickySeed.load(std::memory_order_acquire) != 0) return;
    if (IsTransportIoSuspended()) return;
    std::lock_guard<std::mutex> lock(s.stickySeedMu);
    if (s.stickySeed.load(std::memory_order_relaxed) != 0) return;
    T2NcmTunnelStateWire st{};
    DWORD err = 0;
    if (ReadTunnelStateFromDriver(&st, &err)) {
        if (st.Sticky != 0) {
            s.autoTunnel.store(true, std::memory_order_relaxed);
            s.autoTunnelGen.store(CurrentGeneration(), std::memory_order_relaxed);
        }
        T2_LOG("transport", L"sticky tunnel seeded from T2Ncm memory: sticky=%lu mode=%lu",
               st.Sticky, st.Mode);
        T2_DIAG("state", L"sticky tunnel seeded from T2Ncm memory: sticky=%lu mode=%lu",
                st.Sticky, st.Mode);
        s.stickySeed.store(1, std::memory_order_release);
        return;
    }
    T2_LOG("transport", L"T2Ncm GET_TUNNEL_STATE unavailable (GetLastError=%lu%s) - sticky "
           L"tunnel kept in this process only", err,
           err == ERROR_INVALID_FUNCTION ? L", older T2Ncm.sys" : L"");
    s.stickySeed.store(2, std::memory_order_release);
}

void RefreshStickyFromDriver() {
    auto& s = S();
    EnsureStickySeededFromDriver();
    if (s.stickySeed.load(std::memory_order_acquire) != 1) return;
    if (IsTransportIoSuspended()) return;
    T2NcmTunnelStateWire st{};
    DWORD err = 0;
    if (!ReadTunnelStateFromDriver(&st, &err)) return; // keep the in-process copy
    const bool driverSticky = st.Sticky != 0;
    if (s.autoTunnel.exchange(driverSticky, std::memory_order_relaxed) != driverSticky) {
        if (driverSticky) s.autoTunnelGen.store(CurrentGeneration(), std::memory_order_relaxed);
        T2_LOG("transport", L"sticky tunnel re-synced from T2Ncm memory: sticky=%lu (another "
               L"process changed it)", st.Sticky);
        T2_DIAG("state", L"sticky tunnel re-synced from T2Ncm memory: sticky=%lu mode=%lu",
                st.Sticky, st.Mode);
    }
}

bool PushTunnelStickyToDriver(bool on) {
    if (S().stickySeed.load(std::memory_order_acquire) == 2) return false; // no IOCTL
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

// ============================================================================
// Driver pushes
// ============================================================================
bool PushTunnelPeerToDriver(const in6_addr& peer6) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PushTunnelPeerToDriver: skipped (system suspending / Dx)");
        return false;
    }
    if (S().lastPushedPeer.Is(peer6)) {
        return true; // already armed - kill port-scan IOCTL storm
    }
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"PushTunnelPeerToDriver", kIoctlSetTunnelPeer,
                                                 (LPVOID)&peer6, (DWORD)sizeof(peer6));
    if (r.openFailed) {
        return false;
    }
    if (!r.ok) {
        T2_LOG("tunnel", L"PushTunnelPeerToDriver: IOCTL failed, GetLastError=%lu", r.err);
        return false;
    }
    S().lastPushedPeer.Set(peer6);
    return true;
}

// Hand Windows' real link-local address to T2Ncm.sys (0x904). Without it the driver
// only learns that address from a native outbound IPv6 frame; when tunnel mode is
// switched on while a VPN is already blocking IPv6 no such frame ever leaves, the
// tunnel TX source falls back to a MAC-derived address Windows does not own, and
// every AF_INET connect() times out. Best-effort.
bool PushTunnelLocalToDriver(unsigned long ifIndex) {
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
    if (S().lastPushedLocal.Is(local)) {
        return true; // already armed
    }
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"PushTunnelLocalToDriver", kIoctlSetTunnelLocal,
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
    S().lastPushedLocal.Set(local);
    T2_LOG("tunnel", L"PushTunnelLocalToDriver: local fe80 ...%02x%02x:%02x%02x armed in driver",
           local.s6_addr[12], local.s6_addr[13], local.s6_addr[14], local.s6_addr[15]);
    return true;
}

// Push the transport mode into the driver LIVE (0x903). T2NcmTunnelRefreshMode only
// re-reads the registry at MiniportInitializeEx / MiniportRestart, so a registry
// write alone leaves the running driver's TunnelModeEnabled stale and every tunnel
// frame goes out as bare IPv4, which the IPv6-only T2 drops. The driver mode is the
// source of truth; lastPushedMode is this process's exact record of what it last
// wrote, reset to -1 whenever that can no longer be trusted.
bool PushTransportModeToDriver(TransportMode mode, bool force) {
    if (IsTransportIoSuspended()) {
        T2_LOG("tunnel", L"PushTransportModeToDriver: skipped (system suspending / Dx)");
        return false;
    }
    auto& s = S();
    const int want = (mode == TransportMode::Ipv4Tunnel) ? 1 : 0;
    if (!force && s.lastPushedMode.load(std::memory_order_relaxed) == want) {
        return true; // already live in the driver from our point of view
    }
    DWORD modeValue = static_cast<DWORD>(mode);
    const T2NcmIoctlResult r = T2NcmControlIoctl(L"PushTransportModeToDriver", kIoctlSetTransportMode,
                                                 &modeValue, (DWORD)sizeof(modeValue));
    if (!r.ok) {
        if (!r.openFailed) {
            T2_LOG("tunnel", L"PushTransportModeToDriver: IOCTL failed, GetLastError=%lu", r.err);
        }
        // We no longer know what the driver holds.
        s.lastPushedMode.store(-1, std::memory_order_relaxed);
        return false;
    }
    // Re-arm the local address only when the mode the driver holds has actually
    // changed (or was unknown).
    const int prev = s.lastPushedMode.exchange(want, std::memory_order_relaxed);
    if (prev != want) {
        s.lastPushedLocal.Clear();
    }
    T2_LOG("tunnel", L"PushTransportModeToDriver: live TunnelModeEnabled -> %d", want);
    return true;
}

TunnelPrep PrepareTunnelPeer(unsigned long ifIndex, const in6_addr& peer6,
                             const std::atomic<bool>* cancel) {
    // Cooperative cancellation between blocking operations; a synchronous
    // DeviceIoControl itself cannot be interrupted through this flag.
    const auto stopped = [&]() {
        return (cancel && cancel->load(std::memory_order_acquire)) || IsTransportIoSuspended();
    };
    if (stopped()) {
        T2_LOG("tunnel", L"PrepareTunnelPeer: skipped (system suspending / Dx)");
        return TunnelPrep::Suspended;
    }
    // One control handle for the mode + peer + local pushes below.
    T2NcmControlLease controlLease;
    if (stopped()) return TunnelPrep::Suspended;
    if (IN6_IS_ADDR_UNSPECIFIED(&peer6)) {
        T2_LOG("tunnel", L"PrepareTunnelPeer: no peer address (LocalError, not a tunnel failure)");
        return TunnelPrep::NoPeer;
    }
    // Invariant: an AF_INET tunnel socket only works while T2Ncm.sys itself is
    // in tunnel mode (otherwise TX is sent as bare IPv4 and the T2 drops it).
    // Every tunnel user goes through here, so arming the mode at this single
    // choke point means "userspace says tunnel, driver still native" cannot happen.
    if (!PushTransportModeToDriver(TransportMode::Ipv4Tunnel)) {
        T2_LOG("tunnel", L"PrepareTunnelPeer: failed to arm IPv4 tunnel mode");
        return stopped() ? TunnelPrep::Suspended : TunnelPrep::NoPeer;
    }
    if (stopped()) return TunnelPrep::Suspended;
    if (const hooks::Hooks* h = hooks::Active(); h && h->tunnelNeighborReady) {
        // Simulated T2: the peer is reachable as is - only the driver sees the peer.
        PushTunnelPeerToDriver(peer6);
        return stopped() ? TunnelPrep::Suspended : TunnelPrep::Ok;
    }
    auto& s = S();
    // Fast path: same peer as last time we successfully prepared it, and nothing
    // has invalidated that since (InvalidateTunnelPrepCache). Skips the
    // neighbor-table walk and the ARP create/set syscalls.
    if (s.arpPrepared.Is(peer6)) {
        if (stopped()) return TunnelPrep::Suspended;
        if (!PublishTunnelPeer(peer6, nullptr)) {
            InvalidateTunnelPrepCache();
            return stopped() ? TunnelPrep::Suspended : TunnelPrep::NoPeer;
        }
        if (stopped()) return TunnelPrep::Suspended;
        if (!PushTunnelPeerToDriver(peer6)) {
            InvalidateTunnelPrepCache();
            T2_LOG("tunnel", L"PrepareTunnelPeer: failed to publish cached tunnel peer");
            return stopped() ? TunnelPrep::Suspended : TunnelPrep::NoPeer;
        }
        if (stopped()) return TunnelPrep::Suspended;
        PushTunnelLocalToDriver(ifIndex);
        return stopped() ? TunnelPrep::Suspended : TunnelPrep::Ok;
    }
    // MAC resolution order (first usable wins):
    //   1. IPv6 neighbor table (live, same peer)
    //   2. MAC persisted from the last successful session (same peer only)
    //   3. EUI-64 derivation from the peer's own link-local address
    // 2 and 3 matter when a VPN/WFP blocks ND and the table is empty or holds
    // only Incomplete rows. Zero MACs are never accepted at any step.
    UCHAR mac[6]{};
    const wchar_t* macSource = nullptr;
    if (LookupPeerMac(ifIndex, peer6, mac)) {
        macSource = L"neighbor table";
    } else {
        in6_addr savedPeer{};
        UCHAR savedMac[6]{};
        bool savedHaveMac = false;
        if (ReadPersistedPeer(&savedPeer, savedMac, &savedHaveMac) && savedHaveMac &&
            std::memcmp(&savedPeer, &peer6, sizeof(in6_addr)) == 0) {
            std::memcpy(mac, savedMac, 6);
            macSource = L"persisted";
        } else if (MacFromEui64(peer6, mac)) {
            macSource = L"EUI-64 of peer address";
        }
    }
    if (stopped()) return TunnelPrep::Suspended;
    const bool haveMac = macSource != nullptr;
    T2_LOG("tunnel", L"PrepareTunnelPeer: ifIndex=%lu peer=%02x%02x:%02x%02x mac=%s%s%s",
           ifIndex, peer6.s6_addr[12], peer6.s6_addr[13],
           peer6.s6_addr[14], peer6.s6_addr[15],
           haveMac ? L"found (" : L"NOT FOUND (ARP neighbor will not be set - tunnel will not work)",
           haveMac ? macSource : L"", haveMac ? L")" : L"");
    if (!PublishTunnelPeer(peer6, haveMac ? mac : nullptr)) {
        InvalidateTunnelPrepCache();
        return TunnelPrep::NoPeer;
    }
    if (stopped()) return TunnelPrep::Suspended;
    if (!PushTunnelPeerToDriver(peer6)) {
        T2_LOG("tunnel", L"PrepareTunnelPeer: failed to publish tunnel peer");
        return stopped() ? TunnelPrep::Suspended : TunnelPrep::NoPeer;
    }
    if (stopped()) return TunnelPrep::Suspended;
    PushTunnelLocalToDriver(ifIndex);
    if (stopped()) return TunnelPrep::Suspended;
    if (haveMac) {
        // Only cache "prepared" if the ARP row really took the MAC; otherwise
        // the fast path above would skip the repair on every later attempt.
        if (EnsureTunnelIpv4Neighbor(ifIndex, MapPeerToIpv4(peer6), mac)) {
            if (stopped()) return TunnelPrep::Suspended;
            s.arpPrepared.Set(peer6);
            return TunnelPrep::Ok;
        }
        return stopped() ? TunnelPrep::Suspended : TunnelPrep::NoMac;
    }
    return stopped() ? TunnelPrep::Suspended : TunnelPrep::NoMac;
}

// ============================================================================
// Diagnostics
// ============================================================================
void DiagTransportSnapshot(const wchar_t* why) {
    if (!::t2::log::DiagEnabled()) return;
    auto& s = S();
    const ULONGLONG gen = CurrentGeneration();
    const ULONGLONG v6gen = s.v6UnavailableGen.load(std::memory_order_relaxed);
    T2_DIAG("snapshot",
            L"%s: gen=%llu v6Unavailable=%d(setGen=%llu) stickyTunnel=%d(commitGen=%llu seed=%d) "
            L"override=%d nativeRevalidatePending=%d autoSwitch=%d silentStreak=%d "
            L"peerDistrusted=%d ioSuspended=%d nativeEmaMs=%lu tunnelEmaMs=%lu lastPushedMode=%d",
            why ? why : L"?",
            static_cast<unsigned long long>(gen),
            v6gen == gen ? 1 : 0, static_cast<unsigned long long>(v6gen),
            s.autoTunnel.load(std::memory_order_relaxed) ? 1 : 0,
            static_cast<unsigned long long>(s.autoTunnelGen.load(std::memory_order_relaxed)),
            s.stickySeed.load(std::memory_order_relaxed),
            s.override_.load(std::memory_order_relaxed),
            s.nativeRevalidate.load(std::memory_order_relaxed) ? 1 : 0,
            IsAutoSwitchEnabled() ? 1 : 0,
            s.pathSilentStreak.load(std::memory_order_relaxed),
            s.persistedPeerDistrusted.load(std::memory_order_relaxed) ? 1 : 0,
            IsTransportIoSuspended() ? 1 : 0,
            static_cast<unsigned long>(s.nativeEmaMs.load(std::memory_order_relaxed)),
            static_cast<unsigned long>(s.tunnelEmaMs.load(std::memory_order_relaxed)),
            s.lastPushedMode.load(std::memory_order_relaxed));
}

// ============================================================================
// Cross-process lock, mode scope, phase
// ============================================================================
static HANDLE TransportMutexHandle() {
    // DACL: SYSTEM, Administrators, LocalService full; interactive/authenticated
    // users only SYNCHRONIZE|MUTEX_MODIFY_STATE (+READ_CONTROL) so the CLI/GUI can
    // take it.
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

TransportLock::TransportLock(HANDLE cancelEvent, DWORD waitMs) {
    h_ = TransportMutexHandle();
    if (!h_) return;
    HANDLE hs[2] = {h_, cancelEvent};
    const DWORD n = cancelEvent ? 2 : 1;
    const DWORD r = WaitForMultipleObjects(n, hs, FALSE, waitMs);
    // 0 = signaled (WAIT_OBJECT_0 spelled numerically: STATUS_WAIT_0 is undeclared
    // under UMDF_USING_NTSTATUS), 0x80 = WAIT_ABANDONED_0 (previous owner died:
    // ownership is ours now), 0x102 = WAIT_TIMEOUT.
    if (r == 0 || r == 0x80) {
        owned_ = true;
    } else if (r == 0x102) {
        static std::atomic<bool> logged{false};
        if (!logged.exchange(true)) {
            T2_LOG("transport", L"TransportLock: %lu ms timeout - another process holds the transport "
                   L"mutex; continuing without exclusivity", waitMs);
        }
    }
}

TransportLock::~TransportLock() {
    if (owned_) ReleaseMutex(h_);
}

void ModeScope::Enter(TransportMode m) {
    entered_ = true;
    S().override_.store(m == TransportMode::Ipv4Tunnel ? 1 : 0, std::memory_order_relaxed);
    PushTransportModeToDriver(m);
}

void ModeScope::Restore() {
    if (!entered_) return;
    entered_ = false;
    S().override_.store(-1, std::memory_order_relaxed);
    PushTransportModeToDriver(IsTunnelModeActive() ? TransportMode::Ipv4Tunnel
                                                   : TransportMode::NativeIpv6);
}

TransportPhase::TransportPhase(HANDLE cancelEvent) : lock(cancelEvent) {
    // This process is NOT the only writer of the driver mode: the CLI (GUI Rescan /
    // Test) runs the same phases from its own process, and T2Ncm.sys itself restores
    // the committed mode when a phase owner dies (IRP_MJ_CLEANUP). So the "what did I
    // last push" record cannot be trusted across phases: forget it once the mutex is
    // held, and the phase's first push always writes.
    ResetLastPushedMode();
}

} // namespace t2::transport

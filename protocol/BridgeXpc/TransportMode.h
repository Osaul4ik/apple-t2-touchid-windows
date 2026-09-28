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
#include <chrono>
#include <cstdint>
#include <cstring>
#include "Log.h"
#include "Winsock.h"

#pragma comment(lib, "Iphlpapi.lib")

namespace t2::transport {

inline constexpr wchar_t kNetworkRegPath[] = L"SOFTWARE\\T2TouchId\\Network";
inline constexpr wchar_t kPeerIpv6Value[] = L"PeerIpv6";
inline constexpr wchar_t kPeerMacValue[] = L"PeerMac";

// There used to be a second, PERSISTENT flag here (kTransportModeValue /
// ReadTransportMode(), a manual A/B override the GUI checkbox wrote
// straight to HKLM\...\Network\TransportMode). It was removed: it lived
// right next to the auto-detected session cache below, did the same job
// ("which transport to use right now"), and — because it survived a
// reboot while the session cache deliberately does not — a forgotten
// checked box silently pinned every future boot to Ipv4Tunnel and fought
// the auto probe/fallback cycle below. There is now exactly one flag that
// decides the live transport (kSkipNativeIpv6ProbeValue, in the volatile
// subkey right below); the GUI checkbox now toggles that same flag
// directly instead of a separate one — see MainWindow.xaml.cs.
//
// kPeerIpv6Value/kPeerMacValue above are meant to persist (last-known peer
// for the driver's own PASSIVE-level refresh). This subkey is the opposite
// — an auto-detected "NativeIpv6 is currently unreachable" cache that MUST
// NOT survive a reboot (a VPN that was up last session may be gone, a
// Cisco profile may have changed, and a stale "assume tunnel" left over
// from weeks ago would silently defeat the native-first default forever).
// Created with REG_OPTION_VOLATILE: the key and everything under it is
// destroyed by the OS itself on shutdown/reboot, so there is no cross-boot
// staleness to invalidate by hand — a fresh boot simply finds nothing here
// and Connect() falls through to its normal NativeIpv6-first behavior.
// This also means every t2touchid.exe invocation (a new process each time,
// per the CLI's usage pattern) sees the same cache without needing a
// long-running service — the registry is the shared, per-boot-lifetime
// store across those separate processes.
inline constexpr wchar_t kSessionRegPath[] = L"SOFTWARE\\T2TouchId\\Network\\Session";
// Event-driven, not time-driven: one bit, "skip the NativeIpv6 probe until
// the next unlock". Replaces an earlier exponential-backoff timer
// (NextProbeTick64/BackoffMs) that kept re-probing IPv6 on a clock while
// the screen was still locked with the VPN still up — wasted 400ms/wasted
// wall-clock on every re-probe that could only ever fail again, since
// nothing about the VPN/WFP state was going to change mid-lock. The
// desired cycle (per the user's own spec): IPv6 is always tried first at
// boot; once it fails while locked, EVERY subsequent unlock attempt goes
// straight to Ipv4Tunnel (no re-probing while still locked); on a real
// WTS_SESSION_UNLOCK, this flag is cleared so the very next Connect() gets
// exactly one fresh NativeIpv6 probe — if the VPN is still up it fails and
// the flag is set again for the next lock cycle, if the VPN is now down it
// succeeds and stays on NativeIpv6. T2TouchIdBio's SessionLockWndProc
// (Queue.cpp) is the one place that clears this on WTS_SESSION_UNLOCK.
inline constexpr wchar_t kSkipNativeIpv6ProbeValue[] = L"SkipNativeIpv6Probe"; // DWORD 0/1
// Cold-boot IPv4 tunnel pre-warm (once per boot, after the first real unlock).
// Volatile session key — disappears on reboot so the next cold boot warms again.
inline constexpr wchar_t kColdBootWarmupDoneValue[] = L"ColdBootWarmupDone"; // DWORD 1 when done
inline constexpr wchar_t kWarmupStatusValue[] = L"WarmupStatus";           // REG_SZ human status
inline constexpr wchar_t kWarmupDetailValue[] = L"WarmupDetail";           // REG_SZ optional detail

inline void WriteWarmupStatus(const wchar_t* status, const wchar_t* detail = L"") {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kSessionRegPath, 0, nullptr,
                        REG_OPTION_VOLATILE, KEY_SET_VALUE, nullptr,
                        &key, nullptr) != ERROR_SUCCESS) {
        return;
    }
    if (status) {
        RegSetValueExW(key, kWarmupStatusValue, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(status),
                       static_cast<DWORD>((wcslen(status) + 1) * sizeof(wchar_t)));
    }
    if (detail) {
        RegSetValueExW(key, kWarmupDetailValue, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(detail),
                       static_cast<DWORD>((wcslen(detail) + 1) * sizeof(wchar_t)));
    }
    RegCloseKey(key);
}

inline bool IsColdBootWarmupDone() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSessionRegPath, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }
    DWORD type = 0, val = 0, cb = sizeof(val);
    const LONG err = RegQueryValueExW(key, kColdBootWarmupDoneValue, nullptr, &type,
                                      reinterpret_cast<BYTE*>(&val), &cb);
    RegCloseKey(key);
    return err == ERROR_SUCCESS && type == REG_DWORD && val != 0;
}

inline void MarkColdBootWarmupDone() {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kSessionRegPath, 0, nullptr,
                        REG_OPTION_VOLATILE, KEY_SET_VALUE, nullptr,
                        &key, nullptr) != ERROR_SUCCESS) {
        return;
    }
    DWORD one = 1;
    RegSetValueExW(key, kColdBootWarmupDoneValue, 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&one), sizeof(one));
    RegCloseKey(key);
}



enum class TransportMode : DWORD {
    NativeIpv6 = 0,
    Ipv4Tunnel = 1,
};
// IsTunnelModeActive() is defined further down, right after
// ShouldSkipNativeIpv6Probe() (the one flag it now reads).

// Session-lifetime "NativeIpv6 is currently unreachable" cache. This is
// what lets Connection::Connect() stop paying the 400ms NativeIpv6 probe on every
// single call once that probe has already failed once since the last
// unlock (e.g. VPN up while locked), while still recovering automatically
// on the very next unlock — see AllowNextNativeIpv6ProbeOnUnlock() below
// for the other half of that cycle.
//
// kSessionRegPath's REG_OPTION_VOLATILE key means "reset after reboot"
// requires no logic here at all: a fresh boot has no key, ReadValue
// below fails closed to "don't skip, probe normally" exactly as if this
// function didn't exist yet — matching "on start, IPv6 is always tried
// first".
// In-process copy of the flag. The UMDF host (LocalService) usually cannot
// WRITE HKLM\\SOFTWARE\\T2TouchId (the key is created by an admin installer), so
// RecordNativeIpv6Failure()'s registry write silently failed there and every
// retry started on NativeIpv6 again ("mode=NativeIpv6" on all 7 attempts in
// the field log). WUDFHost.exe outlives every capture, so a process-lifetime
// atomic is a reliable store for the service; the registry value remains the
// cross-process channel (CLI/GUI). Effective flag = process flag OR registry.
inline std::atomic<bool> g_procSkipNativeIpv6Probe{false};

inline bool ShouldSkipNativeIpv6Probe() {
    if (g_procSkipNativeIpv6Probe.load(std::memory_order_relaxed)) return true;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSessionRegPath, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return false; // no cache yet (or a fresh boot) - probe as normal
    }
    DWORD skip = 0;
    DWORD type = 0;
    DWORD cb = sizeof(skip);
    const LONG err = RegQueryValueExW(key, kSkipNativeIpv6ProbeValue, nullptr, &type,
                                      reinterpret_cast<LPBYTE>(&skip), &cb);
    RegCloseKey(key);
    if (err != ERROR_SUCCESS || type != REG_DWORD || cb != sizeof(skip)) {
        return false;
    }
    return skip != 0;
}

// The one and only "which transport is active right now" query. Callers
// that just need a yes/no (RemoteXpc.cpp, PortScan.cpp, BridgeDiscovery.cpp,
// main.cpp) read this instead of duplicating the flag lookup; Connection.cpp
// itself still calls ShouldSkipNativeIpv6Probe() directly because it also
// needs to react to a same-call fallback that happens after this point is
// evaluated. No persisted override sits behind this anymore (see the removed
// kTransportModeValue note above) — MainWindow.xaml.cs's checkbox sets/clears
// exactly this same session flag now, so there is nothing else to check.
inline bool IsTunnelModeActive() {
    return ShouldSkipNativeIpv6Probe();
}

// Call when a NativeIpv6 probe (the 400ms first-connect attempt) times
// out. Sets the skip flag so every further Connect() this lock cycle goes
// straight to Ipv4Tunnel without re-paying the 400ms probe - there is
// nothing to gain from re-probing on a clock while the screen is still
// locked and the VPN/WFP state hasn't changed. The flag is cleared only
// by an actual NativeIpv6 success (RecordNativeIpv6Success) or by a real
// WTS_SESSION_UNLOCK (AllowNextNativeIpv6ProbeOnUnlock), never by time.
inline void RecordNativeIpv6Failure() {
    g_procSkipNativeIpv6Probe.store(true, std::memory_order_relaxed);
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kSessionRegPath, 0, nullptr,
                        REG_OPTION_VOLATILE, KEY_SET_VALUE, nullptr,
                        &key, nullptr) != ERROR_SUCCESS) {
        return; // best-effort cache; a failure here just means every call
                 // keeps paying the 400ms probe, not a functional break
    }
    DWORD one = 1;
    RegSetValueExW(key, kSkipNativeIpv6ProbeValue, 0, REG_DWORD,
                  reinterpret_cast<const BYTE*>(&one), sizeof(one));
    RegCloseKey(key);
}

// Call the moment a NativeIpv6 probe actually succeeds. Clears the skip
// flag outright so the very next Connect() call - and every one after it
// this lock cycle - goes back to trying NativeIpv6 first, instead of
// carrying forward a stale "skip" state from an outage that just ended.
inline void RecordNativeIpv6Success() {
    g_procSkipNativeIpv6Probe.store(false, std::memory_order_relaxed);
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSessionRegPath, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return; // nothing cached - already the desired state
    }
    RegDeleteValueW(key, kSkipNativeIpv6ProbeValue);
    RegCloseKey(key);
}

// How long a post-unlock reachability probe is allowed to take. Tighter
// than kIpv6FirstConnectTimeout (400ms, Connection.cpp) on purpose: this
// probe runs off to the side of any real verify attempt (see
// ProbeNativeIpv6Reachable's own comment below) - there is no live user
// action waiting on it, so there is no reason to give it the same budget
// as an actual in-flight connect. 100ms is still generous for a real
// link-local peer (single-digit ms in practice) while failing fast when
// the VPN/WFP is still dropping IPv6.
constexpr std::chrono::milliseconds kUnlockProbeTimeout{100};

// Standalone reachability probe: a throwaway TCP SYN at the T2 peer's
// real IPv6 link-local address, bounded by `timeout`. This is NEVER part
// of the live Connect() path used by an actual verify attempt - it exists
// solely so a real WTS_SESSION_UNLOCK (T2TouchIdBio's SessionLockWndProc,
// Queue.cpp) can find out whether NativeIpv6 has become viable again
// WITHOUT risking the switch happening mid-attempt on a real unlock.
// Per the user's own spec: after unlock, while cached on Ipv4Tunnel, we
// only TEST NativeIpv6 - we do not switch a live connect over to it - and
// a failure within the 100ms budget means staying on Ipv4Tunnel, full
// stop, until the next real unlock tries again.
//
// A completed handshake (err==0) or an immediate WSAECONNREFUSED both
// prove the SYN actually reached the peer over IPv6 (a real RST requires
// that) - either counts as "reachable" even though no real BridgeXPC
// service is expected to be listening on this throwaway port. Anything
// else (timeout, unreachable, VPN/WFP silently dropping the SYN) is not.
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
inline bool PushTunnelPeerToDriver(const in6_addr& peer6) {
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
        T2_LOG("tunnel", L"PushTransportModeToDriver: live TunnelModeEnabled -> %d",
               mode == TransportMode::Ipv4Tunnel ? 1 : 0);
    }
    CloseHandle(h);
    return ok != FALSE;
}

// Call before AF_INET connect in tunnel mode.
inline void PrepareTunnelPeer(unsigned long ifIndex, const in6_addr& peer6) {
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
    if (haveMac) {
        EnsureTunnelIpv4Neighbor(ifIndex, MapPeerToIpv4(peer6), mac);
    }
}


// Once-per-boot: arm IPv4 tunnel infra (driver mode + ARP + peer push), then
// restore NativeIpv6. Does NOT leave the session on tunnel. Safe to call only
// after a real unlock when a peer is (or will become) known.
inline bool RunColdBootTunnelWarmup(unsigned long ifIndex, const in6_addr& peer6) {
    WriteWarmupStatus(L"arming-tunnel", L"PushTransportModeToDriver(Ipv4Tunnel)");
    if (!PushTransportModeToDriver(TransportMode::Ipv4Tunnel)) {
        WriteWarmupStatus(L"failed", L"PushTransportModeToDriver(Ipv4Tunnel) failed");
        T2_LOG("warmup", L"ColdBootWarmup: Push Ipv4Tunnel FAILED");
        return false;
    }
    WriteWarmupStatus(L"preparing-peer", L"PrepareTunnelPeer (ARP + driver peer)");
    PrepareTunnelPeer(ifIndex, peer6);
    // Brief pause so ARP/neighbor settles before we flip mode back.
    Sleep(50);
    WriteWarmupStatus(L"restoring-v6", L"PushTransportModeToDriver(NativeIpv6)");
    RecordNativeIpv6Success(); // clear any skip flag; stay native after warm
    if (!PushTransportModeToDriver(TransportMode::NativeIpv6)) {
        WriteWarmupStatus(L"failed", L"Push NativeIpv6 after warm failed (peer prepared)");
        T2_LOG("warmup", L"ColdBootWarmup: Push NativeIpv6 FAILED (peer still prepared)");
        // Peer is prepared either way; mode push failure is non-fatal for later fallback.
    }
    MarkColdBootWarmupDone();
    WriteWarmupStatus(L"ok", L"IPv4 tunnel pre-warmed; session stays on Native IPv6");
    T2_LOG("warmup", L"ColdBootWarmup: OK ifIndex=%lu", ifIndex);
    return true;
}

} // namespace t2::transport
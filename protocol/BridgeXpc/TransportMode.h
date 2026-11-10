// SPDX-License-Identifier: GPL-2.0-only
// TransportMode — Native IPv6 (default) vs IPv4 tunnel for Cisco/WFP that
// drops all IPv6 before the packet reaches T2Ncm. When tunnel is on,
// userspace uses AF_INET to a link-local IPv4 mapped from the T2 fe80
// address; T2Ncm.sys rewrites IPv4<->IPv6 on the wire (T2 still speaks IPv6).
//
// This header is the API. The state (one TransportState object per process) and
// every definition live in TransportMode.cpp; the test seams in TransportHooks.h.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include "Log.h"
#include "Winsock.h"
#include "TransportHooks.h"

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
//       - on native TCP-level failure -> one recovery multicast ping (ff02::1) to
//         re-reveal the T2 peer (same prompt used at cold start);
//       - if that single recovery attempt fails -> fall to the IPv4 tunnel;
//       - when off, only Native IPv6 is used.
//
//  2. STICKY TUNNEL (until reboot or a successful native re-check): set only when a
//     switch to the tunnel SUCCEEDED
//     (a tunnel handshake worked), never on a mere native failure. The source of
//     truth is T2Ncm.sys MEMORY (IOCTL_T2NCM_SET_TUNNEL_STICKY / GET_TUNNEL_STATE,
//     a driver global): it survives a WUDFHost restart, an adapter re-init and
//     sleep, and a reboot (or driver unload) clears it. Each process seeds its
//     in-process copy from the driver once (EnsureStickySeededFromDriver), re-reads it
//     at the start of every connect (RefreshStickyFromDriver) and pushes every change
//     back. No registry. The way back to native IPv6 is ONE re-check per real unlock
//     (RequestNativeRevalidate) or host network change: the next connect - which has
//     no live session - tries the cached port on native IPv6 once; a native HELO
//     clears the sticky flag, anything else keeps the tunnel. A reboot also clears
//     it: the next cold boot starts from Native IPv6 again and switches to the tunnel
//     only if IPv6 is blocked.
//     An older T2Ncm.sys without those IOCTLs: the in-process flag alone (the
//     pre-IOCTL behaviour), logged once.
//
//  The BridgeXPC port itself is NOT transport state: it is the same port on both
//  transports and lives only in the registry (Discovery/PortCache.h).
//
// CONNECT ARCHITECTURE v2 (CONNECT_ARCHITECTURE_v2.md) adds:
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
inline constexpr wchar_t kAutoSwitchValue[] = L"AutoSwitch"; // under kNetworkRegPath, persistent

enum class TransportMode : DWORD {
    NativeIpv6 = 0,
    Ipv4Tunnel = 1,
};

// ---- Registry ----------------------------------------------------------------
// Registry reads are cached for a short TTL: IsTunnelModeActive() sits on hot
// paths (PortScan::ProbePort calls it once per probed port - up to 16384 times
// per scan - and used to open/query/close the key every time).
struct CachedDword {
    std::atomic<ULONGLONG> at{0};
    std::atomic<DWORD> val{0};
};
// HKLM\<subKey>\<name>; `def` when missing / unreadable.
DWORD ReadDwordCached(CachedDword& c, const wchar_t* subKey, const wchar_t* name,
                      DWORD def, ULONGLONG ttlMs);
// The Network key (HKLM\SOFTWARE\T2TouchId\Network, or the test override).
HKEY NetworkRegRoot();
const wchar_t* NetworkRegPath();
// ReadDwordCached on the Network key.
DWORD ReadNetworkDwordCached(CachedDword& c, const wchar_t* name, DWORD def, ULONGLONG ttlMs);

bool IsAutoSwitchEnabled();

// ---- Generation (architecture v2, section 3) -----------------------------
// Starts at 1 in every process (process start IS a new generation). Bumped on
// real Sx suspend/resume (BumpRealSuspendGeneration), when the NCM adapter
// re-registers with another ifIndex/MAC and when the T2 peer address changes.
// Value 0 is reserved for "never set".
ULONGLONG CurrentGeneration();
ULONGLONG BumpGeneration(const wchar_t* why);

// Real Sx suspend generation (NOT screen-lock). Bio bumps this only on
// PBT_APMSUSPEND so Connect settle does not fire on every WTS_SESSION_LOCK.
void BumpRealSuspendGeneration();
ULONGLONG GetRealSuspendGeneration();

// ---- Committed auto-tunnel ("sticky", see 2.) ------------------------------
// In-process copy of the driver's sticky flag. Stays through resume / NCM
// re-enumeration / peer change (NOT tied to the Generation); a reboot clears it.
bool IsAutoTunnelCommitted();
// Tunnel handshake completed after native failed: sticky until reboot or until a
// native re-check succeeds. on=false only when auto-switch was turned off.
void CommitAutoTunnel(bool on);
// Seeds the in-process flag from T2Ncm memory once per process.
void EnsureStickySeededFromDriver();
// Re-reads the sticky flag from T2Ncm memory and brings this process's copy in
// line with it, in BOTH directions (the CLI and WUDFHost both write it). Called at
// the start of every connect. No-op without the IOCTL or while suspending.
void RefreshStickyFromDriver();

// Attempt-scoped transport override (set by ModeScope while an attempt probes a
// transport that is NOT committed). Nothing is committed until a handshake
// succeeded, and the override disappears on every exit path (RAII).
bool HasTransportOverride();

// THE query for "which transport is active right now" (discovery budgets,
// port scan, RemoteXPC and Connection all read this).
bool IsTunnelModeActive();

// ---- IPv6 unavailable on the adapter (this Generation) ----------------------
// `why` is for the diagnostic log only.
void MarkV6Unavailable(const wchar_t* why = L"?");
void ClearV6Unavailable(const wchar_t* why = L"?");
bool IsV6Unavailable();

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
bool IsRstProof();
bool IsPositiveEvidence(PathEvidence e);
PathEvidence ClassifyWsaError(int wsa);

// ---- Native re-check of a committed tunnel ---------------------------------
// One-shot "re-check native IPv6 once" request. Set on a real unlock / host network
// change (RequestNativeReprobe); consumed by the NEXT connect, which by definition
// runs with no live BridgeXPC session. In-process only.
void RequestNativeRevalidate();
bool ConsumeNativeRevalidate();
// Unlock / network change: drops a stale "IPv6 unavailable" verdict and asks for
// one native re-check of a committed tunnel. NOT called on resume: a VPN that
// persists across sleep would turn every wake into a failed native probe.
void RequestNativeReprobe();

// ---- Adaptive connect budgets ------------------------------------------------
// Native: 4x the smoothed successful connect time + 30, clamped to [60, 250] ms;
// 150 ms before anything has been measured. Tunnel: 8x + 150, clamped to
// [200, 500] ms; 500 ms at first. Both only bound the TCP handshake.
std::chrono::milliseconds NativeConnectBudget(std::chrono::milliseconds cap);
std::chrono::milliseconds TunnelConnectBudget(std::chrono::milliseconds cap);
// Native TCP handshake completed: the IPv6 path works. Clears the sticky tunnel.
void RecordNativeSuccess(ULONGLONG tcpMs);
// Tunnel TCP handshake completed (cached or scan-confirmed port).
void RecordTunnelSuccess(ULONGLONG tcpMs);

// ---- Persisted-peer trust / silence streak (section 9) ----------------------
// Two consecutive attempts that produced only Silent evidence flag the persisted
// last-known peer; ResolveT2Peer's lookup order (table -> ping -> persisted) is
// fixed, so this only marks the fallback peer as distrusted in the log.
void DistrustPersistedPeer();
bool ConsumePersistedPeerDistrust();
bool NotePathSilent(); // true when the peer was just distrusted
void NotePathAlive();

// ---- Peer addressing ------------------------------------------------------------
// The IPv4 address the tunnel maps the T2's fe80 address to (169.254.a.b).
in_addr MapPeerToIpv4(const in6_addr& peer6);
bool IsTunnelMappedIpv4(const in_addr& a);
// THE socket address of the T2's `port` on one transport: [fe80%ifIndex]:port for
// native IPv6, 169.254.a.b:port for the tunnel. Every caller that opens a socket to
// the T2 (Connection, PortScan, RemoteXPC, ProbeNativePath) uses this, and creates
// the socket with out.family.
PeerAddress MakePeerAddress(bool tunnel, const in6_addr& peer6, unsigned long ifIndex,
                            uint16_t port);
// connect() to that address (non-blocking or not, as the socket is). Same return
// value and WSAGetLastError() contract as connect().
int ConnectToPeer(SOCKET s, const PeerAddress& a, bool tunnel, uint16_t port);

// Standalone native path probe: a throwaway TCP SYN to the T2's fe80 address,
// bounded by `timeout`, classified as PathEvidence (handshake -> Positive, RST ->
// Refused, WSAEACCES -> Blocked, nothing -> Silent, no route etc. -> LocalError).
// Only meaningful while T2Ncm is in native mode. Closed with RST (no FIN dance).
PathEvidence ProbeNativePath(const in6_addr& peer6, unsigned long ifIndex, uint16_t port,
                             std::chrono::milliseconds timeout, ULONGLONG* outMs = nullptr);

// ---- MAC / peer persistence -----------------------------------------------------
// Not all-zero, not broadcast, not multicast.
bool IsUsableMac(const UCHAR mac[6]);
// The T2 link-local address is EUI-64 derived from its MAC. False if not EUI-64 shaped.
bool MacFromEui64(const in6_addr& peer6, UCHAR outMac[6]);
// Publish peer fe80 (+ optional MAC) for T2Ncm.sys / the next cold boot. A
// non-usable MAC is never persisted.
bool PublishTunnelPeer(const in6_addr& peer6, const UCHAR mac[6] /*nullable*/);
// Last-known peer (fe80 + MAC) persisted by PublishTunnelPeer.
bool ReadPersistedPeer(in6_addr* peer6, UCHAR mac[6], bool* haveMac);
// Exact peer MAC from the IPv6 neighbor table (resolved rows only).
bool LookupPeerMac(unsigned long ifIndex, const in6_addr& peer6, UCHAR outMac[6]);

// ---- Sleep / Dx gate -----------------------------------------------------------
// Set by Bio OnSuspendResume(PBT_APMSUSPEND). While true, all T2Ncm control
// IOCTLs (mode + peer) are skipped: the miniport is paused / in D3.
void SetTransportIoSuspended(bool suspended);
bool IsTransportIoSuspended();

// ---- Driver push dedupe ---------------------------------------------------------
// Forget what this process last pushed (mode), so the next push really writes.
// Called at the start of every phase, after resume and on every failed connect.
void ResetLastPushedMode();
void ClearLastPushedPeer();
// A tunnel connect actually FAILED: redo the full MAC lookup + ARP set next time
// and distrust every IOCTL dedupe record.
void InvalidateTunnelPrepCache();

// ---- T2Ncm.sys pushes -------------------------------------------------------------
// Live driver mode (IOCTL_T2NCM_SET_TRANSPORT_MODE, 0x903). Skipped when this
// process's record already equals `mode` (unless `force`).
bool PushTransportModeToDriver(TransportMode mode, bool force = false);
bool PushTunnelPeerToDriver(const in6_addr& peer6);   // 0x902
bool PushTunnelLocalToDriver(unsigned long ifIndex);  // 0x904
bool PushTunnelStickyToDriver(bool on);               // 0x905

// Result of PrepareTunnelPeer. NoMac / NoPeer are LocalError evidence
// (section 4): the tunnel cannot be tried yet, which says nothing about whether
// the T2 is ready - the caller re-resolves the peer instead of counting a failure.
enum class TunnelPrep { Ok, NoMac, NoPeer, Suspended };
// Call before an AF_INET connect in tunnel mode: arms the driver's tunnel mode,
// publishes the peer, pushes peer + local address, sets the static ARP row.
TunnelPrep PrepareTunnelPeer(unsigned long ifIndex, const in6_addr& peer6,
                             const std::atomic<bool>* cancel = nullptr);

// One line with every piece of transport state (Log.h T2_DIAG). Never does an IOCTL.
void DiagTransportSnapshot(const wchar_t* why);

// ---- Counters (since process start) ---------------------------------------------
// What the transport owner did, for `t2touchid status` / the GUI - no logs needed.
struct TransportStats {
    uint64_t connectsOk = 0;
    uint64_t connectsFailed = 0;
    uint64_t tunnelCommits = 0;   // native -> IPv4 tunnel (sticky set)
    uint64_t nativeReturns = 0;   // IPv4 tunnel -> native (sticky cleared)
    uint64_t nativeRechecks = 0;  // one-shot re-checks consumed (unlock / network change)
    ULONGLONG lastConnectTick = 0; // GetTickCount64 of the last connect END, 0 = none
    bool lastConnectOk = false;
    bool lastConnectTunnel = false;
    uint16_t lastPort = 0;
};
TransportStats GetTransportStats();
// Called once per connect step by BridgeDiscovery.
void NoteConnectResult(bool ok, bool tunnel, uint16_t port);

// ---- Shared \\.\T2Ncm control handle (lease-counted) ---------------------
// A lease keeps ONE handle alive for as long as at least one lease exists in the
// process; the last lease closes it. Deliberately not a process-lifetime handle:
// an idle open handle would pin T2Ncm.sys and make a driver update need a reboot.
// The handle is opened lazily by the first IOCTL, not by the lease itself.
class T2NcmControlLease {
public:
    T2NcmControlLease();
    ~T2NcmControlLease();
    T2NcmControlLease(const T2NcmControlLease&) = delete;
    T2NcmControlLease& operator=(const T2NcmControlLease&) = delete;
};

// ---- Cross-process transport lock + mode scope (sections 11, 12) ------------
// Named mutex shared by the UMDF host, the CLI and the GUI. Held for one
// "flip the driver mode + probe/scan + connect" phase, so no other process can
// flip TunnelModeEnabled in the middle of a scan.
inline constexpr wchar_t kTransportMutexName[] = L"Global\\T2TouchId_Transport";
inline constexpr DWORD kTransportLockWaitMs = 2000;

class TransportLock {
public:
    // Waits for the mutex OR the cancel event (whichever first). On timeout it
    // logs once and lets the caller proceed WITHOUT exclusivity: a process that
    // holds the mutex forever must not be able to block the fingerprint reader.
    explicit TransportLock(HANDLE cancelEvent = nullptr, DWORD waitMs = kTransportLockWaitMs);
    ~TransportLock();
    TransportLock(const TransportLock&) = delete;
    TransportLock& operator=(const TransportLock&) = delete;
    bool owned() const { return owned_; }
private:
    HANDLE h_ = nullptr;
    bool owned_ = false;
};

// RAII driver-mode scope. Enter() puts the attempt's mode into the driver and makes
// it the attempt-scoped override. Restore() - also run by the destructor on EVERY
// exit path - drops the override and puts the COMMITTED mode back:
//     driver mode == committed mode when a phase ends          (invariant 8)
// Both ends push only when the driver does not already hold that mode (judged by
// the last-pushed record, reset at the start of every phase). If the process dies
// inside a phase, T2Ncm.sys restores the committed mode when the phase's control
// handle is cleaned up.
class ModeScope {
public:
    ModeScope() = default;
    ~ModeScope() { Restore(); }
    ModeScope(const ModeScope&) = delete;
    ModeScope& operator=(const ModeScope&) = delete;
    void Enter(TransportMode m);
    void Restore();
private:
    bool entered_ = false;
};

// Lock + mode scope in one object. Members are destroyed in reverse order, so
// the mode is restored while the mutex is still held.
struct TransportPhase {
    // Forgets the last-pushed record once the mutex is held: the CLI and T2Ncm.sys
    // itself (IRP_MJ_CLEANUP of a dead phase owner) also write the driver mode.
    explicit TransportPhase(HANDLE cancelEvent = nullptr);
    // Declared FIRST so it is destroyed LAST: every push of the phase shares one
    // control handle, and Restore() still has it while the mutex is held.
    T2NcmControlLease controlLease;
    TransportLock lock;
    ModeScope mode;
};

namespace testing {
// Puts every piece of in-process transport state back to a fresh process's
// (tests only; nothing may be running).
void ResetState();
} // namespace testing

} // namespace t2::transport

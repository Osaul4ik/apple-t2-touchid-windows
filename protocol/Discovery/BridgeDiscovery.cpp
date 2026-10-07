// SPDX-License-Identifier: GPL-2.0-only
// BridgeDiscovery.cpp — the TransportManager: one silent (no stdout, no argv)
// implementation of "find the BiometricKit BridgeXPC port and connect", see
// BridgeDiscovery.h and CONNECT_ARCHITECTURE_v2.md.
//
// One call of ConnectToBiometricKitBridge is ONE step of the caller's retry
// ladder (Queue.cpp ConnectForCaptureWithRetry). What survives between steps -
// and between cancelled CAPTURE_DATAs - is: the BridgeXPC port (registry ONLY,
// PortCache.h; the same port on both transports), the committed sticky tunnel
// (T2Ncm.sys memory, TransportMode.h) and the scan progress (ScanState below,
// a resume cursor for a pass cut short by cancel).
//
// Sequence per step:
//   A. readiness gate   - preconditions only, never a conclusion (Adapter.cpp)
//   B. native IPv6      - HELO on the registry port. No cache / no HELO =>
//                         FULL-CHAIN rescan right away (59000-60000, 49000-49999,
//                         rest of 49000-65535; 256 wide, 25 ms). Instant skip when
//                         connect() says WSAEACCES (WFP block).
//   C. IPv6 blocked     - (WSAEACCES, or the scan got no SYN-ACK and no RST at all)
//                         -> one ff02::1 recovery ping (unless WFP) -> IPv4 tunnel:
//                         HELO on the SAME registry port, else a full-chain tunnel
//                         scan. A tunnel handshake commits the sticky tunnel (driver
//                         memory) until reboot; the next cold boot starts on IPv6.
//   D. nothing          - return false; *outScansExhausted says whether that was
//                         a COMPLETED full pass with no BiometricKit on every
//                         transport that applies (the caller then gives up), or
//                         just "not yet" (cancel, silent path, cool-down, no peer).
#include "BridgeDiscovery.h"
#include "PortCache.h"
#include "PortScan.h"
#include "RemoteXpc.h"
#include "../BridgeXpc/Log.h"
#include "../BridgeXpc/TransportMode.h"
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace t2::discovery {

namespace {

namespace tp = t2::transport;
using tp::PathEvidence;
using t2::bridgexpc::Connection;
using t2::bridgexpc::ConnectResult;

constexpr const char* kBiometricKitService = "com.apple.eos.BiometricKit";
constexpr std::chrono::milliseconds kRemoteXpcCheckTimeout{2000};

// ---- scan parameters ----------------------------------------------------------
// Same on both transports and on every pass (owner spec): 256 sockets in flight,
// 25 ms per connect. The attempt budget only has to fit one full pass of the
// 16536-port chain (native: closed ports answer RST in ~1 ms; tunnel: one more
// USB round trip through the T2Ncm rewrite) - it is a safety net, not a slice.
constexpr uint16_t kScanBegin = 49000;
constexpr uint16_t kScanEnd = 65535;
constexpr unsigned kScanConcurrency = 256;
constexpr unsigned kScanConnectTimeoutMs = 25;
// No SYN-ACK and no RST after this many probes => the path is silent/filtered:
// stop the pass (~2 rounds) instead of grinding through 16k dead ports.
constexpr unsigned kSilentAbortAfter = 512;
ULONGLONG AttemptBudgetMs(bool tunnel) { return tunnel ? 15000 : 8000; }

// Plain helper instead of the std min template: windows.h defines min()/max() macros
// that break it in this build (same reason Connection.cpp avoids it in WaitForEvent).
inline ULONGLONG MinU64(ULONGLONG a, ULONGLONG b) { return a < b ? a : b; }

bool Cancelled(void* cancelEvent) {
    return Connection::IsEventSignaled(static_cast<HANDLE>(cancelEvent));
}

const wchar_t* TransportName(bool tunnel) { return tunnel ? L"IPv4 tunnel" : L"Native IPv6"; }

// ---- ScanState ----------------------------------------------------------------
// Progress of the port scan for one (adapter, transport), kept in-process so a
// pass cut short by a cancelled CAPTURE_DATA resumes where it stopped instead of
// starting over. This is resume state, NOT a port cache (the port lives only in
// the registry). Every claimed port runs to completion, so the cursor into the
// dispatch order is an exact resume point.
struct Candidate {
    uint16_t port = 0;
    unsigned fails = 0;
};
struct ScanState {
    ULONGLONG generation = 0;
    in6_addr peer{};
    unsigned cursor = 0;        // next index in the dispatch order
    unsigned emptyPasses = 0;   // full passes completed without finding the service
    ULONGLONG lastPassEnd = 0;
    std::vector<Candidate> candidates; // HTTP/2 hits whose RemoteXPC check failed
};
std::mutex g_scanMu;
std::map<std::string, ScanState>& ScanStates() {
    static std::map<std::string, ScanState> m;
    return m;
}
std::string ScanKey(const NcmEndpoint& ep, bool tunnel) {
    char buf[40];
    if (ep.hasMac) {
        std::snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X", ep.mac[0], ep.mac[1],
                      ep.mac[2], ep.mac[3], ep.mac[4], ep.mac[5]);
    } else {
        std::snprintf(buf, sizeof(buf), "if%lu", ep.ifIndex);
    }
    return std::string(buf) + (tunnel ? "/tunnel" : "/native");
}
ScanState LoadScanState(const NcmEndpoint& ep, bool tunnel) {
    std::lock_guard<std::mutex> lock(g_scanMu);
    auto it = ScanStates().find(ScanKey(ep, tunnel));
    if (it != ScanStates().end() && it->second.generation == tp::CurrentGeneration() &&
        std::memcmp(&it->second.peer, &ep.peerLinkLocal, sizeof(in6_addr)) == 0) {
        return it->second;
    }
    ScanState fresh; // Generation / peer changed (or first use): start over
    fresh.generation = tp::CurrentGeneration();
    fresh.peer = ep.peerLinkLocal;
    return fresh;
}
void StoreScanState(const NcmEndpoint& ep, bool tunnel, const ScanState& st) {
    std::lock_guard<std::mutex> lock(g_scanMu);
    ScanStates()[ScanKey(ep, tunnel)] = st;
}
// How many consecutive EMPTY full-chain passes it takes before discovery reports the
// scans as exhausted (=> the caller gives up). One empty pass is not a verdict on a
// cold boot: the NCM link and the T2 TCP stack answer (RST) several seconds before
// BiometricKit starts listening, so a single quick pass wrongly reads as "no
// BiometricKit". Passes skipped by the cool-down do not count. The cool-down spaces
// the passes (1 s, 2 s), so 3 passes span roughly 7-8 s.
constexpr unsigned kEmptyPassesToGiveUp = 3;
// Cool-down after an EMPTY full pass only (a cache miss always rescans at once):
// 1 s, doubling, capped at 5 s, so a T2 whose services are not up yet does not
// get 16k SYNs back to back from the retry ladder.
ULONGLONG CooldownMs(unsigned emptyPasses) {
    if (emptyPasses == 0) return 0;
    const unsigned shift = (emptyPasses - 1) < 3u ? (emptyPasses - 1) : 3u;
    return MinU64(1000ull << shift, 5000);
}

struct ScanOutcome {
    uint16_t servicePort = 0;
    uint16_t rsdPort = 0;
    bool ranScan = false;          // false: skipped by the cool-down
    bool passCompletedEmpty = false; // kEmptyPassesToGiveUp consecutive full passes ended without BiometricKit
    bool silent = false;           // aborted: no SYN-ACK and no RST (path dead/filtered)
    bool anyTcp = false;           // some SYN was answered (SYN-ACK) => the path works
    bool anyRefused = false;       // some RST came back => packets reach the T2
    bool anyBlocked = false;       // WSAEACCES seen => local WFP block
    unsigned tried = 0;
};

// Every HTTP/2 hit gets its own RemoteXPC checker thread racing the still-running
// scan; the first confirmed BiometricKit hit stops the scan. Checkers are joined
// before returning (no background threads outlive the call). HTTP/2 hits that were
// NOT confirmed are reported through `http2Ports` so they can be re-checked first
// on the next step.
struct ScanProbeResult {
    uint16_t servicePort = 0;
    uint16_t rsdPort = 0;
};
ScanProbeResult ScanAndProbe(const NcmEndpoint& ep, ScanOptions opt,
                             std::vector<uint16_t>* http2Ports) {
    std::atomic<bool> stop{false};
    std::atomic<bool> serviceFound{false};
    std::mutex checkersMu;
    std::vector<std::thread> checkers;
    ScanProbeResult res;

    opt.cancel = &stop;
    opt.onHit = [&](const PortCandidate& c) {
        if (!c.http2PrefaceOk) return;
        if (serviceFound.load(std::memory_order_relaxed)) return;
        uint16_t port = c.port;
        std::lock_guard<std::mutex> lock(checkersMu);
        if (http2Ports) http2Ports->push_back(port);
        checkers.emplace_back([&, port]() {
            if (serviceFound.load(std::memory_order_relaxed)) return;
            uint16_t servicePort = 0;
            if (!ProbeServiceOnPort(ep, port, kBiometricKitService, kRemoteXpcCheckTimeout,
                                    &servicePort)) {
                return;
            }
            bool expected = false;
            if (serviceFound.compare_exchange_strong(expected, true)) {
                res.servicePort = servicePort;
                res.rsdPort = port;
                stop.store(true, std::memory_order_relaxed);
            }
        });
    };

    ScanHttp2Preface(ep, opt);
    {
        std::lock_guard<std::mutex> lock(checkersMu);
        for (auto& th : checkers) th.join();
    }
    return res;
}

// Re-check HTTP/2 listeners that were seen but did not (yet) advertise BiometricKit:
// "NCM is up, BiometricKit is not yet" turns into "up" here without a rescan.
// Cheap by construction: newest 3, a small total budget, dropped after 2 failures
// (decoy listeners are dense on the T2, so most of these will never match).
bool RecheckCandidates(const NcmEndpoint& ep, ScanState* st, bool tunnel, ULONGLONG deadlineTick,
                       void* cancelEvent, ScanOutcome* out) {
    const ULONGLONG budgetEnd = MinU64(deadlineTick, GetTickCount64() + (tunnel ? 1500 : 600));
    unsigned checked = 0;
    for (size_t i = st->candidates.size(); i-- > 0 && checked < 3;) {
        const ULONGLONG now = GetTickCount64();
        if (Cancelled(cancelEvent) || now >= budgetEnd) break;
        ++checked;
        uint16_t svc = 0;
        if (ProbeServiceOnPort(ep, st->candidates[i].port, kBiometricKitService,
                               std::chrono::milliseconds(MinU64(budgetEnd - now, 1000)), &svc)) {
            out->servicePort = svc;
            out->rsdPort = st->candidates[i].port;
            st->candidates.erase(st->candidates.begin() + static_cast<std::ptrdiff_t>(i));
            return true;
        }
        if (++st->candidates[i].fails >= 2) {
            st->candidates.erase(st->candidates.begin() + static_cast<std::ptrdiff_t>(i));
        }
    }
    return false;
}

// One full-chain scan pass on `tunnel` (the caller is inside the matching
// TransportPhase), resumed from the stored cursor. Returns when the service is
// confirmed, the pass ended (empty or silent), the budget ran out, or cancel fired.
ScanOutcome RunScanAttempt(const NcmEndpoint& ep, bool tunnel, void* cancelEvent) {
    ScanOutcome out;
    ScanState st = LoadScanState(ep, tunnel);

    const ULONGLONG start = GetTickCount64();
    if (st.cursor == 0 && st.emptyPasses > 0 && st.lastPassEnd != 0 &&
        start < st.lastPassEnd + CooldownMs(st.emptyPasses)) {
        T2_LOG("discovery", L"scan (%s): cool-down after empty pass %u, %llu ms left - skipped",
               TransportName(tunnel), st.emptyPasses,
               static_cast<unsigned long long>(st.lastPassEnd + CooldownMs(st.emptyPasses) - start));
        StoreScanState(ep, tunnel, st);
        return out;
    }
    out.ranScan = true;
    const ULONGLONG deadline = start + AttemptBudgetMs(tunnel);

    if (RecheckCandidates(ep, &st, tunnel, deadline, cancelEvent, &out)) {
        T2_LOG("discovery", L"scan (%s): candidate re-check confirmed BiometricKit on port %u",
               TransportName(tunnel), static_cast<unsigned>(out.servicePort));
        StoreScanState(ep, tunnel, st);
        return out;
    }
    if (Cancelled(cancelEvent)) {
        StoreScanState(ep, tunnel, st);
        return out;
    }

    ScanOptions opt;
    opt.portBegin = kScanBegin;
    opt.portEnd = kScanEnd;
    opt.concurrency = kScanConcurrency;
    opt.connectTimeoutMs = kScanConnectTimeoutMs;
    opt.includeTcpOnly = true;
    opt.priorityBands = true;
    opt.orderSkip = st.cursor;
    opt.orderLimit = 0; // always the whole chain
    opt.deadlineTick = deadline;
    opt.cancelEvent = cancelEvent;
    // Silence is only judged on a pass that starts at the beginning: a resumed
    // pass already proved the path alive in its first part.
    opt.silentAbortAfter = (st.cursor == 0) ? kSilentAbortAfter : 0;
    ScanStats stats;
    opt.stats = &stats;

    std::vector<uint16_t> http2Ports;
    const unsigned fromCursor = st.cursor;
    ScanProbeResult r = ScanAndProbe(ep, opt, &http2Ports);
    st.cursor = stats.claimedEnd;
    out.tried = stats.tried;
    out.anyTcp = stats.tcpHits > 0;
    out.anyRefused = stats.refused > 0;
    out.anyBlocked = stats.blocked > 0;
    T2_LOG("discovery", L"scan (%s, %u-wide, %u ms): order %u->%u/%u, tried %u, tcp %u, http2 %u, "
           L"rst %u, wfp-blocked %u, %llu ms%s%s", TransportName(tunnel), kScanConcurrency,
           kScanConnectTimeoutMs, fromCursor, st.cursor, stats.orderTotal, stats.tried, stats.tcpHits,
           stats.http2Hits, stats.refused, stats.blocked,
           static_cast<unsigned long long>(GetTickCount64() - start),
           r.servicePort ? L", FOUND" : L"", stats.silentAborted ? L", SILENT (aborted)" : L"");

    if (r.servicePort != 0) {
        out.servicePort = r.servicePort;
        out.rsdPort = r.rsdPort;
        st.cursor = 0;
        st.emptyPasses = 0;
        StoreScanState(ep, tunnel, st);
        return out;
    }
    for (uint16_t p : http2Ports) {
        const bool known = std::any_of(st.candidates.begin(), st.candidates.end(),
                                       [p](const Candidate& c) { return c.port == p; });
        if (!known && st.candidates.size() < 16) st.candidates.push_back({p, 0});
    }
    if (stats.silentAborted) {
        out.silent = true;
        st.cursor = 0; // nothing learned; the next pass starts over
    } else if (stats.exhausted && fromCursor != 0 && !Cancelled(cancelEvent)) {
        // Only the TAIL of a pass that an earlier step (cancel / lock / budget) cut
        // short was scanned now. The head was scanned earlier, possibly before the
        // service opened its port, so this proves nothing: not an empty pass. Start
        // over from port 0 on the next step (no cool-down: lastPassEnd is unchanged).
        st.cursor = 0;
        T2_LOG("discovery", L"scan (%s): resumed tail finished (from %u) - not counted as an empty "
               L"pass, next step rescans from the start", TransportName(tunnel), fromCursor);
    } else if (stats.exhausted && !Cancelled(cancelEvent)) {
        ++st.emptyPasses;
        st.cursor = 0;
        st.lastPassEnd = GetTickCount64();
        // Only the Nth consecutive empty pass is a verdict; earlier ones are "not yet".
        out.passCompletedEmpty = st.emptyPasses >= kEmptyPassesToGiveUp;
        T2_LOG("discovery", L"scan (%s): FULL pass complete without BiometricKit (empty passes=%u/%u)%s",
               TransportName(tunnel), st.emptyPasses, kEmptyPassesToGiveUp,
               out.passCompletedEmpty ? L" - exhausted" : L" - retrying");
    }
    StoreScanState(ep, tunnel, st);
    return out;
}

// ---- cached port ------------------------------------------------------------
struct CacheTry {
    bool hadCache = false;
    bool ok = false;
    uint16_t port = 0;
    uint16_t rsd = 0;
    PathEvidence ev = PathEvidence::LocalError;
    ULONGLONG tcpMs = 0;
};

// Path A: HELO on the registry port. Path B: RSD replay through the cached
// RemoteXPC port. On ONE explicit transport (the port is the same on both). The
// budget is short on native (a healthy T2 answers in single-digit ms) and longer
// on the tunnel. A failure never deletes the entry; only a scan-confirmed port
// overwrites it.
CacheTry TryCachedBridgePort(const NcmEndpoint& ep, Connection* conn, bool tunnel) {
    CacheTry r;
    uint16_t svcPort = 0, rsdPort = 0;
    if (!LoadCachedPort(ep, &svcPort, &rsdPort)) {
        T2_LOG("discovery", L"no valid cached BridgeXPC port in the registry - full rescan");
        return r;
    }
    r.hadCache = true;
    r.port = svcPort;
    r.rsd = rsdPort;

    const std::chrono::milliseconds tcp = tunnel ? std::chrono::milliseconds(2000)
                                                 : tp::NativeConnectBudget(std::chrono::milliseconds(250));
    const std::chrono::milliseconds helo = tunnel ? std::chrono::milliseconds(2000)
                                                  : std::chrono::milliseconds(500);
    ConnectResult crA = conn->ConnectVia(tunnel, ep.peerLinkLocal, ep.ifIndex, svcPort, tcp, helo,
                                         &r.ev, &r.tcpMs);
    if (crA == ConnectResult::Ok) {
        T2_LOG("discovery", L"cached port %u answered with HELO (%s) - no scan needed",
               static_cast<unsigned>(svcPort), TransportName(tunnel));
        r.ok = true;
        return r;
    }
    T2_LOG("discovery", L"cached port %u (rsd %u) did not answer on %s: ConnectResult=%d evidence=%d",
           static_cast<unsigned>(svcPort), static_cast<unsigned>(rsdPort), TransportName(tunnel),
           static_cast<int>(crA), static_cast<int>(r.ev));

    // Path B only makes sense when the path itself answered.
    if (rsdPort != 0 && (r.ev == PathEvidence::Positive || r.ev == PathEvidence::Refused)) {
        const std::chrono::milliseconds half(tunnel ? 1000 : 250);
        uint16_t advertised = 0;
        if (ProbeServiceOnPort(ep, rsdPort, kBiometricKitService, half, &advertised)) {
            PathEvidence evB = PathEvidence::Silent;
            ConnectResult crB = conn->ConnectVia(tunnel, ep.peerLinkLocal, ep.ifIndex, advertised,
                                                 half, half, &evB, &r.tcpMs);
            if (crB == ConnectResult::Ok) {
                if (advertised != svcPort) SaveCachedPort(ep, advertised, rsdPort);
                r.port = advertised;
                r.ev = PathEvidence::Positive;
                r.ok = true;
            }
        }
    }
    return r;
}

// Live HELO on a port the scan just confirmed, on the transport that found it.
bool ConnectFoundPort(const NcmEndpoint& ep, Connection* conn, bool tunnel, uint16_t port,
                      ULONGLONG* outTcpMs) {
    PathEvidence ev = PathEvidence::Silent;
    ConnectResult cr = conn->ConnectVia(tunnel, ep.peerLinkLocal, ep.ifIndex, port,
                                        std::chrono::milliseconds(2000), std::chrono::milliseconds(2000),
                                        &ev, outTcpMs);
    if (cr != ConnectResult::Ok) {
        T2_LOG("discovery", L"scan found port %u but HELO failed (ConnectResult=%d evidence=%d)",
               static_cast<unsigned>(port), static_cast<int>(cr), static_cast<int>(ev));
        return false;
    }
    return true;
}

struct StepResult {
    bool ok = false;
    uint16_t servicePort = 0;
    uint16_t rsdPort = 0;
    bool pathAlive = false;      // SYN-ACK or RST seen on this transport
    bool blocked = false;        // the transport is dead: WFP block, or silent scan
    bool wfpBlocked = false;     // ...and specifically WSAEACCES (a ping will not help)
    bool sawSilent = false;      // evidence pointed at a silent path
    bool fullPassEmpty = false;  // a full-chain pass completed without BiometricKit
    bool localError = false;     // the transport could not even be attempted
};

// Scan on the current transport and connect what it confirms. Shared by both steps.
void ScanAndConnect(const NcmEndpoint& ep, Connection* conn, bool tunnel, void* cancelEvent,
                    StepResult* sr, ScanOutcome* outScan) {
    ScanOutcome so = RunScanAttempt(ep, tunnel, cancelEvent);
    *outScan = so;
    if (so.servicePort != 0) {
        // Save at the moment of confirmation, before the final connect and
        // regardless of cancel: the finding must survive. Same registry entry
        // for both transports.
        SaveCachedPort(ep, so.servicePort, so.rsdPort);
        ULONGLONG tcpMs = 0;
        if (ConnectFoundPort(ep, conn, tunnel, so.servicePort, &tcpMs)) {
            if (!tunnel) tp::RecordNativeSuccess(tcpMs);
            sr->ok = true;
            sr->servicePort = so.servicePort;
            sr->rsdPort = so.rsdPort;
            sr->pathAlive = true;
            return;
        }
        sr->pathAlive = true; // a SYN-ACK came back even though HELO did not
    }
    if (so.anyTcp || so.anyRefused) sr->pathAlive = true;
    sr->fullPassEmpty = so.passCompletedEmpty;
}

// ---- Step B: native IPv6 -----------------------------------------------------
StepResult NativeStep(const NcmEndpoint& ep, Connection* conn, void* cancelEvent, bool autoSwitch) {
    StepResult sr;
    tp::TransportPhase phase(static_cast<HANDLE>(cancelEvent));
    phase.mode.Enter(tp::TransportMode::NativeIpv6);

    // B.1: registry port, live HELO on native.
    CacheTry ct = TryCachedBridgePort(ep, conn, false);
    if (ct.ok) {
        tp::RecordNativeSuccess(ct.tcpMs); // native works
        sr.ok = true;
        sr.servicePort = ct.port;
        sr.rsdPort = ct.rsd;
        sr.pathAlive = true;
        return sr;
    }
    if (Cancelled(cancelEvent)) return sr;

    // B.2: a WFP block filter answers connect() with WSAEACCES at once - IPv6 is
    // blocked, a native scan would only collect 16k identical errors.
    if (ct.ev == PathEvidence::Blocked && autoSwitch) {
        T2_LOG("discovery", L"native IPv6 blocked by a local WFP filter (WSAEACCES) - skipping the "
               L"native scan, going to the IPv4 tunnel");
        sr.blocked = true;
        sr.wfpBlocked = true;
        return sr;
    }

    // B.3: no cache or no HELO => full-chain native rescan right away.
    ScanOutcome so;
    ScanAndConnect(ep, conn, false, cancelEvent, &sr, &so);
    if (sr.ok) return sr;
    if (ct.ev == PathEvidence::Positive || ct.ev == PathEvidence::Refused) sr.pathAlive = true;
    if (!sr.pathAlive && so.ranScan && (so.silent || so.anyBlocked)) {
        sr.blocked = true;
        sr.wfpBlocked = so.anyBlocked;
        sr.sawSilent = !so.anyBlocked;
        T2_LOG("discovery", L"native IPv6 path %s: no SYN-ACK and no RST from the T2",
               so.anyBlocked ? L"blocked by a local WFP filter" : L"silent");
    }
    return sr;
}

// ---- Step C: IPv4 tunnel -----------------------------------------------------
StepResult TunnelStep(NcmEndpoint* ep, Connection* conn, void* cancelEvent) {
    StepResult sr;
    tp::TransportPhase phase(static_cast<HANDLE>(cancelEvent));
    phase.mode.Enter(tp::TransportMode::Ipv4Tunnel);

    tp::TunnelPrep prep = tp::PrepareTunnelPeer(ep->ifIndex, ep->peerLinkLocal);
    if (prep == tp::TunnelPrep::NoMac || prep == tp::TunnelPrep::NoPeer) {
        // LocalError, not "T2 not ready": resolve the peer/MAC properly and retry
        // once. Distrusting the persisted peer forces the neighbor/ping lookup.
        tp::DistrustPersistedPeer();
        NcmEndpoint fresh = *ep;
        ResolveT2Peer(&fresh, !tp::IsV6Unavailable());
        if (fresh.peerSource != PeerSource::None) {
            *ep = fresh;
            prep = tp::PrepareTunnelPeer(ep->ifIndex, ep->peerLinkLocal);
        }
        if (prep != tp::TunnelPrep::Ok) {
            T2_LOG("discovery", L"tunnel: peer/MAC not resolvable yet (%s) - LocalError, not counted "
                   L"as a tunnel failure", prep == tp::TunnelPrep::NoMac ? L"no MAC" : L"no peer");
            sr.localError = true;
            return sr;
        }
    }
    if (prep == tp::TunnelPrep::Suspended) {
        sr.localError = true;
        return sr;
    }

    // Same registry port as native (one port for both transports).
    CacheTry ct = TryCachedBridgePort(*ep, conn, true);
    if (ct.ok) {
        tp::CommitAutoTunnel(true);
        T2_LOG("discovery", L"CommitTunnel (cached port %u) - sticky until reboot",
               static_cast<unsigned>(ct.port));
        sr.ok = true;
        sr.servicePort = ct.port;
        sr.rsdPort = ct.rsd;
        sr.pathAlive = true;
        return sr;
    }
    if (Cancelled(cancelEvent)) return sr;

    ScanOutcome so;
    ScanAndConnect(*ep, conn, true, cancelEvent, &sr, &so);
    if (sr.ok) {
        tp::CommitAutoTunnel(true);
        T2_LOG("discovery", L"CommitTunnel (scanned port %u) - sticky until reboot",
               static_cast<unsigned>(sr.servicePort));
        return sr;
    }
    if (ct.ev == PathEvidence::Positive || ct.ev == PathEvidence::Refused) sr.pathAlive = true;
    sr.sawSilent = !sr.pathAlive && (so.silent || ct.ev == PathEvidence::Silent);
    return sr;
}

// ---- Step A shared by Pick and Connect ---------------------------------------
std::atomic<ULONGLONG> g_gateGeneration{0};
std::atomic<unsigned long> g_gateIfIndex{0};

// Runs the readiness gate unless it already passed for this Generation and adapter
// (steady state: a sticky endpoint costs nothing here).
GateResult EnsureGate(NcmEndpoint* ep, void* cancelEvent) {
    if (g_gateGeneration.load(std::memory_order_acquire) == tp::CurrentGeneration() &&
        g_gateIfIndex.load(std::memory_order_relaxed) == ep->ifIndex &&
        ep->peerSource != PeerSource::None && !tp::IsV6Unavailable()) {
        return GateResult::Ready;
    }
    const GateResult g = RunReadinessGate(ep, cancelEvent);
    if (g != GateResult::Cancelled) {
        g_gateIfIndex.store(ep->ifIndex, std::memory_order_relaxed);
        g_gateGeneration.store(tp::CurrentGeneration(), std::memory_order_release);
    }
    return g;
}

} // namespace

bool PickDefaultT2Endpoint(NcmEndpoint* outEndpoint, void* cancelEvent) {
    if (outEndpoint == nullptr) return false;
    // Peer resolution happens inside the gate, AFTER the link-local address is
    // usable - not inside the adapter enumeration.
    auto endpoints = FindT2NcmEndpoints(/*resolvePeer=*/false);
    if (endpoints.empty()) return false;
    NcmEndpoint ep = endpoints.front();
    if (EnsureGate(&ep, cancelEvent) == GateResult::Cancelled) return false;
    *outEndpoint = ep;
    return true;
}

bool ConnectToBiometricKitBridge(const NcmEndpoint& endpoint, t2::bridgexpc::Connection* outConn,
                                  uint16_t* outServicePort, uint16_t* outRsdPort,
                                  void* cancelEvent, bool* outScansExhausted) {
    if (outScansExhausted) *outScansExhausted = false;
    if (outConn == nullptr) return false;
    if (Cancelled(cancelEvent)) return false;
    NcmEndpoint ep = endpoint; // the step may refine the peer; the caller's copy is untouched

    // Step A - readiness gate. Preconditions only; no conclusion about transports.
    if (EnsureGate(&ep, cancelEvent) == GateResult::Cancelled) return false;
    if (ep.peerSource == PeerSource::None) {
        T2_LOG("discovery", L"no T2 peer known (neighbor table empty, nothing persisted, ping got no "
               L"answer) - nothing to connect to yet");
        return false;
    }

    const bool autoSwitch = tp::IsAutoSwitchEnabled();
    if (!autoSwitch && tp::IsAutoTunnelCommitted()) {
        tp::CommitAutoTunnel(false); // auto-switch was turned off: drop the learned tunnel
    }

    // Native IPv6 is the default; skipped only when the sticky tunnel is committed
    // (T2Ncm memory, until reboot) or IPv6 is unusable on the adapter.
    const bool sticky = autoSwitch && tp::IsAutoTunnelCommitted();
    const bool v6Unavailable = autoSwitch && tp::IsV6Unavailable();
    const bool tryNative = !sticky && !v6Unavailable;

    StepResult native;
    bool sawSilent = false;
    if (tryNative) {
        native = NativeStep(ep, outConn, cancelEvent, autoSwitch);
        sawSilent = native.sawSilent;
        if (native.ok) {
            tp::NotePathAlive();
            if (outServicePort) *outServicePort = native.servicePort;
            if (outRsdPort) *outRsdPort = native.rsdPort;
            return true;
        }

        // A SILENT native path may just be a stale peer address: one ff02::1
        // multicast ping (the cold-start peer reveal). If the peer shows up, give
        // native one more step with the refreshed address before declaring IPv6
        // blocked. Pointless for a WFP block (WSAEACCES), so skipped there.
        if (autoSwitch && native.blocked && !native.wfpBlocked && !Cancelled(cancelEvent)) {
            T2_LOG("discovery", L"native IPv6 silent - recovery ff02::1 ping before switching to IPv4");
            if (RecoverPeerViaMulticastPing(&ep)) {
                native = NativeStep(ep, outConn, cancelEvent, autoSwitch);
                sawSilent = sawSilent || native.sawSilent;
                if (native.ok) {
                    tp::NotePathAlive();
                    if (outServicePort) *outServicePort = native.servicePort;
                    if (outRsdPort) *outRsdPort = native.rsdPort;
                    return true;
                }
            }
        }
    }

    // Step C - IPv4 tunnel: sticky, IPv6 unusable, or native judged blocked.
    const bool goTunnel = autoSwitch && (sticky || v6Unavailable || (tryNative && native.blocked));
    StepResult tunnel;
    bool tunnelTried = false;
    if (goTunnel && !Cancelled(cancelEvent)) {
        tunnelTried = true;
        T2_LOG("discovery", L"tunnel step: sticky=%d v6unavail=%d nativeBlocked=%d%s",
               sticky ? 1 : 0, v6Unavailable ? 1 : 0, native.blocked ? 1 : 0,
               native.wfpBlocked ? L" (WFP)" : L"");
        tunnel = TunnelStep(&ep, outConn, cancelEvent);
        sawSilent = sawSilent || tunnel.sawSilent;
        if (tunnel.ok) {
            tp::NotePathAlive();
            if (outServicePort) *outServicePort = tunnel.servicePort;
            if (outRsdPort) *outRsdPort = tunnel.rsdPort;
            return true;
        }
    }

    // Step D - nothing worked. Exhausted only when a full-chain pass COMPLETED empty
    // on the transport that decides: the tunnel when we fell over to it (or are
    // sticky on it), otherwise native. A cancelled / silent / cooled-down pass, or a
    // LocalError (no MAC/peer yet), is "not yet", never "failed".
    const bool exhausted = tunnelTried ? tunnel.fullPassEmpty
                                       : (tryNative && native.fullPassEmpty && !native.blocked);
    if (exhausted && !Cancelled(cancelEvent)) {
        T2_LOG("discovery", L"full-chain scan exhausted on %s - BiometricKit not found",
               tunnelTried ? L"the IPv4 tunnel (native IPv6 blocked or sticky tunnel)" : L"native IPv6");
        if (outScansExhausted) *outScansExhausted = true;
    }

    if (!Cancelled(cancelEvent)) {
        // Only silence counts towards distrusting the persisted peer; a LocalError
        // (no MAC yet) or an alive-but-not-ready path does not.
        const StepResult& last = tunnelTried ? tunnel : native;
        if (ep.peerSource == PeerSource::LastKnown && sawSilent && !last.pathAlive &&
            !last.localError) {
            tp::NotePathSilent();
        }
    }
    return false;
}

} // namespace t2::discovery
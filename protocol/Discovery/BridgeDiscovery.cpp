// SPDX-License-Identifier: GPL-2.0-only
// BridgeDiscovery.cpp — the TransportManager: one silent (no stdout, no argv)
// implementation of "find the BiometricKit BridgeXPC port and connect", see
// BridgeDiscovery.h and CONNECT_ARCHITECTURE_v2.md (section numbers below).
//
// One call of ConnectToBiometricKitBridge is ONE bounded step of the caller's
// retry ladder (Queue.cpp ConnectForCaptureWithRetry: 30 s window, 50 -> 1000 ms
// backoff). What survives between steps - and between cancelled CAPTURE_DATAs - is
// in-process state keyed by Generation: the committed transport (TransportMode.h),
// the confirmed port (PortCache), and the scan progress (ScanState below).
//
// Sequence per step (section 6):
//   A. readiness gate       - preconditions only, never a conclusion (Adapter.cpp)
//   B. "try v6"             - cached-port HELO + <= 3 bounded probes, NOT a full scan
//   C. scan on the proven transport - resumable, deadline-bounded, port saved on
//                             confirmation
//   D. tunnel attempt       - when v6 produced no Positive evidence
//   E. both empty           - return false; the ladder alternates and retries
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

// ---- budgets (section 13) ---------------------------------------------------
// Native tuning comes from real T2 sessions (RTT ~1 ms). The tunnel adds a
// userspace -> T2Ncm TX rewrite -> USB -> T2 -> USB -> RX rewrite round trip on a
// single serialized bulk pipe pair, so it gets fewer sockets in flight and longer
// per-port waits (the 27.09.2026 DebugView capture of 256 SYNs flooding the pipe).
struct Budgets {
    ULONGLONG chunkMs;       // one scan slice
    ULONGLONG attemptMs;     // one scan attempt (several slices)
    unsigned concurrency;
    unsigned connectTimeoutMs[2]; // first pass / later passes ("20 ms then 60 ms")
};
const Budgets& BudgetsFor(bool tunnel) {
    static const Budgets native{1500, 3000, 256, {20, 60}};
    static const Budgets tunnelB{3000, 5000, 256, {20, 20}}; // same as native, per owner request
    return tunnel ? tunnelB : native;
}
constexpr ULONGLONG kEvidenceScanMs = 1000;  // native scan used AS evidence (no cache to probe)
constexpr unsigned kMinProbesForSilent = 64; // a scan that tried fewer ports proves nothing
constexpr unsigned kProbeCount = 3;          // "try v6" probes
constexpr DWORD kProbeGapMs = 300;

// Plain helper instead of the std min template: windows.h defines min()/max() macros
// that break it in this build (same reason Connection.cpp avoids it in WaitForEvent).
inline ULONGLONG MinU64(ULONGLONG a, ULONGLONG b) { return a < b ? a : b; }

bool Cancelled(void* cancelEvent) {
    return Connection::IsEventSignaled(static_cast<HANDLE>(cancelEvent));
}
// Sleeps up to `ms`; true when the cancel event fired.
bool SleepOrCancel(void* cancelEvent, DWORD ms) {
    if (cancelEvent) return WaitForSingleObject(static_cast<HANDLE>(cancelEvent), ms) == 0;
    Sleep(ms);
    return false;
}

// ---- ScanState (section 7) --------------------------------------------------
// Progress of the port scan for one (adapter, transport), kept in-process so a
// cancelled CAPTURE_DATA does not throw the work away. DEVIATION from the
// architecture doc, which sketched a bitmap of completed chunks: with the tunnel's
// 16-wide/150 ms probes a 1000-port chunk cannot finish inside a 3 s budget, so a
// "chunk done" bitmap would never advance. A cursor into the dispatch order does:
// every claimed port runs to completion, so the cursor is an exact resume point.
struct Candidate {
    uint16_t port = 0;
    unsigned fails = 0;
};
struct ScanState {
    ULONGLONG generation = 0;
    in6_addr peer{};
    unsigned cursor = 0;        // next index in the dispatch order
    unsigned passLimit = 0;     // order length of the pass in progress
    unsigned emptyPasses = 0;   // passes completed without finding the service
    ULONGLONG lastPassEnd = 0;
    bool http2Seen = false;     // some HTTP/2 listener has been seen (T2 services are up)
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
// Cool-down after an empty pass (section 13): 1 s, doubling, capped at 5 s, so a
// dead link does not get 256 SYNs per second for 30 s from the retry ladder.
ULONGLONG CooldownMs(unsigned emptyPasses) {
    if (emptyPasses == 0) return 0;
    const unsigned shift = (emptyPasses - 1) < 3u ? (emptyPasses - 1) : 3u;
    return MinU64(1000ull << shift, 5000);
}

struct ScanOutcome {
    uint16_t servicePort = 0;
    uint16_t rsdPort = 0;
    bool ranScan = false;   // false: skipped by the cool-down
    unsigned tried = 0;
    bool anyTcp = false;    // some SYN was answered (SYN-ACK) => the path works
};

// Same concurrency shape as before: every HTTP/2 hit gets its own RemoteXPC
// checker thread racing the still-running scan; the first confirmed BiometricKit
// hit stops the scan. Checkers are joined before returning (no background threads
// outlive the call). HTTP/2 hits that were NOT confirmed are reported through
// `http2Ports` so they can be re-checked first on the next step.
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

// One resumable, deadline-bounded scan attempt on `tunnel` (the caller is inside
// the matching TransportPhase). Returns when the service is confirmed, the budget
// is used up, the pass completed empty, or cancel fired - and stores its progress.
ScanOutcome RunScanAttempt(const NcmEndpoint& ep, bool tunnel, ULONGLONG attemptBudgetMs,
                           void* cancelEvent) {
    ScanOutcome out;
    const Budgets& b = BudgetsFor(tunnel);
    ScanState st = LoadScanState(ep, tunnel);

    const ULONGLONG start = GetTickCount64();
    if (st.emptyPasses > 0 && st.lastPassEnd != 0 && start < st.lastPassEnd + CooldownMs(st.emptyPasses)) {
        T2_LOG("discovery", L"scan chunk: %s cool-down (%llu ms left after empty pass %u) - skipped",
               tunnel ? L"tunnel" : L"native",
               static_cast<unsigned long long>(st.lastPassEnd + CooldownMs(st.emptyPasses) - start),
               st.emptyPasses);
        StoreScanState(ep, tunnel, st);
        return out;
    }
    out.ranScan = true;
    const ULONGLONG deadline = start + MinU64(attemptBudgetMs, b.attemptMs);

    if (RecheckCandidates(ep, &st, tunnel, deadline, cancelEvent, &out)) {
        T2_LOG("discovery", L"scan chunk: candidate re-check confirmed BiometricKit on port %u",
               static_cast<unsigned>(out.servicePort));
        StoreScanState(ep, tunnel, st);
        return out;
    }

    constexpr uint16_t kBegin = 49152, kEnd = 65535;
    const unsigned total = static_cast<unsigned>(kEnd - kBegin) + 1;
    const unsigned priority = PriorityBandCount(kBegin, kEnd);

    while (!Cancelled(cancelEvent)) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) break;
        if (st.cursor == 0) {
            // Nothing HTTP/2 seen yet means the T2 services are not up: stay in the
            // priority bands (59xxx, 49xxx), and only every 4th empty pass pay for
            // the whole ephemeral range.
            const bool fullPass = (st.emptyPasses % 4) == 3;
            st.passLimit = (st.http2Seen || fullPass) ? total : priority;
        }
        ScanOptions opt;
        opt.portBegin = kBegin;
        opt.portEnd = kEnd;
        opt.concurrency = b.concurrency;
        opt.includeTcpOnly = true;
        opt.connectTimeoutMs = b.connectTimeoutMs[st.emptyPasses == 0 ? 0 : 1];
        opt.priorityBands = true;
        opt.orderSkip = st.cursor;
        opt.orderLimit = st.passLimit;
        opt.deadlineTick = now + MinU64(b.chunkMs, deadline - now);
        opt.cancelEvent = cancelEvent;
        ScanStats stats;
        opt.stats = &stats;

        std::vector<uint16_t> http2Ports;
        const ULONGLONG chunkStart = GetTickCount64();
        ScanProbeResult r = ScanAndProbe(ep, opt, &http2Ports);
        st.cursor = stats.claimedEnd;
        out.tried += stats.tried;
        if (stats.tcpHits > 0) out.anyTcp = true;
        if (stats.http2Hits > 0) st.http2Seen = true;
        T2_LOG("discovery", L"scan chunk (%s, %u-wide, %u ms): order %u/%u, tried %u, tcp %u, http2 %u, "
               L"%llu ms%s", tunnel ? L"IPv4 tunnel" : L"Native IPv6", b.concurrency,
               opt.connectTimeoutMs, st.cursor, st.passLimit, stats.tried, stats.tcpHits,
               stats.http2Hits, static_cast<unsigned long long>(GetTickCount64() - chunkStart),
               r.servicePort ? L", FOUND" : L"");

        if (r.servicePort != 0) {
            out.servicePort = r.servicePort;
            out.rsdPort = r.rsdPort;
            break;
        }
        for (uint16_t p : http2Ports) {
            const bool known = std::any_of(st.candidates.begin(), st.candidates.end(),
                                           [p](const Candidate& c) { return c.port == p; });
            if (!known && st.candidates.size() < 16) st.candidates.push_back({p, 0});
        }
        if (stats.exhausted) {
            ++st.emptyPasses;
            st.cursor = 0;
            st.lastPassEnd = GetTickCount64();
            T2_LOG("discovery", L"scan chunk: pass complete without BiometricKit (empty passes=%u)",
                   st.emptyPasses);
            break;
        }
        if (stats.tried == 0) break; // no progress possible right now (deadline raced)
    }
    StoreScanState(ep, tunnel, st);
    return out;
}

// ---- cached port (section 8) ------------------------------------------------
struct CacheTry {
    bool hadCache = false;
    bool ok = false;
    uint16_t port = 0;
    uint16_t rsd = 0;
    PathEvidence ev = PathEvidence::LocalError;
    ULONGLONG tcpMs = 0;
};

// Mirrors the old TryCachedBridgePort (path A: HELO on the cached BridgeXPC port;
// path B: RSD replay through the cached RemoteXPC port) on ONE explicit transport.
// The budget is short on native (a healthy T2 answers in single-digit ms) and long
// on the tunnel. An RST marks the entry Suspect but never deletes it: the T2 may
// simply not be listening yet after a reboot.
CacheTry TryCachedBridgePort(const NcmEndpoint& ep, Connection* conn, bool tunnel) {
    CacheTry r;
    uint16_t svcPort = 0, rsdPort = 0;
    bool suspect = false;
    if (!LoadCachedPort(ep, &svcPort, &rsdPort, &suspect)) {
        T2_LOG("discovery", L"no cached BridgeXPC port for this adapter");
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
               static_cast<unsigned>(svcPort), tunnel ? L"IPv4 tunnel" : L"Native IPv6");
        if (suspect) MarkCachedPortSuspect(ep, false);
        r.ok = true;
        return r;
    }
    T2_LOG("discovery", L"cached port %u (rsd %u%s) did not answer on %s: ConnectResult=%d evidence=%d",
           static_cast<unsigned>(svcPort), static_cast<unsigned>(rsdPort), suspect ? L", Suspect" : L"",
           tunnel ? L"IPv4 tunnel" : L"Native IPv6", static_cast<int>(crA), static_cast<int>(r.ev));
    if (r.ev == PathEvidence::Refused) MarkCachedPortSuspect(ep, true);

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
                else MarkCachedPortSuspect(ep, false);
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
    bool pathAlive = false;   // Positive evidence for this transport was seen
    bool sawSilent = false;   // evidence pointed at a silent path
    bool localError = false;  // the transport could not even be attempted
};

// ---- Step B/C: native IPv6 ----------------------------------------------------
StepResult NativeStep(const NcmEndpoint& ep, Connection* conn, void* cancelEvent, bool autoSwitch) {
    StepResult sr;
    tp::TransportPhase phase(static_cast<HANDLE>(cancelEvent));
    phase.mode.Enter(tp::TransportMode::NativeIpv6);

    // B.1: cached port, live HELO on native.
    CacheTry ct = TryCachedBridgePort(ep, conn, false);
    if (ct.ok) {
        tp::RecordNativeSuccess(ct.tcpMs); // native works: clears a committed tunnel
        sr.ok = true;
        sr.servicePort = ct.port;
        sr.rsdPort = ct.rsd;
        sr.pathAlive = true;
        return sr;
    }
    if (Cancelled(cancelEvent)) return sr;

    // Evidence so far. An RST sends us to a native scan in any case, but only counts
    // as PROOF of the path once assumption A0 is confirmed on hardware.
    bool proven = tp::IsPositiveEvidence(ct.ev);
    bool answered = proven || ct.ev == PathEvidence::Refused;
    bool anySilent = ct.ev == PathEvidence::Silent;

    // B.2: up to 3 bounded probes ~300 ms apart. Port: the cached one; without a
    // cache only port 1, and only once A0 says an RST is proof.
    if (!answered) {
        const uint16_t probePort = ct.hadCache ? ct.port : (tp::IsRstProof() ? uint16_t{1} : uint16_t{0});
        if (probePort != 0) {
            for (unsigned i = 0; i < kProbeCount && !answered; ++i) {
                if (i != 0 && SleepOrCancel(cancelEvent, kProbeGapMs)) return sr;
                ULONGLONG ms = 0;
                const PathEvidence ev = tp::ProbeNativePath(ep.peerLinkLocal, ep.ifIndex, probePort,
                                                            tp::NativeConnectBudget(std::chrono::milliseconds(250)), &ms);
                T2_LOG("discovery", L"v6 probe %u/%u port %u: evidence=%d (%llu ms)", i + 1, kProbeCount,
                       static_cast<unsigned>(probePort), static_cast<int>(ev),
                       static_cast<unsigned long long>(ms));
                if (ev == PathEvidence::Silent) anySilent = true;
                if (ev == PathEvidence::Positive || ev == PathEvidence::Refused) {
                    answered = true;
                    proven = tp::IsPositiveEvidence(ev);
                }
                // LocalError: proves nothing, neither counted nor a reason to stop.
            }
        }
    }

    // C: scan on native when the path answered, when there was nothing cheap to
    // probe (the scan itself is then the evidence), or when tunnel fallback is off.
    const bool noCheapProbe = !ct.hadCache && !tp::IsRstProof();
    if (answered || noCheapProbe || !autoSwitch) {
        // Without a cached port there is no tunnel fallback (see ConnectToBiometricKitBridge),
        // so the native scan is not just evidence: give it the full budget.
        const ULONGLONG budget = (proven || !autoSwitch || !ct.hadCache) ? BudgetsFor(false).attemptMs
                                                                        : kEvidenceScanMs;
        ScanOutcome so = RunScanAttempt(ep, false, budget, cancelEvent);
        if (so.servicePort != 0) {
            // Save at the moment of confirmation, before the final connect and
            // regardless of cancel (section 7): the finding must survive.
            SaveCachedPort(ep, so.servicePort, so.rsdPort);
            ULONGLONG tcpMs = 0;
            if (ConnectFoundPort(ep, conn, false, so.servicePort, &tcpMs)) {
                tp::RecordNativeSuccess(tcpMs);
                sr.ok = true;
                sr.servicePort = so.servicePort;
                sr.rsdPort = so.rsdPort;
                sr.pathAlive = true;
                return sr;
            }
            proven = true; // a SYN-ACK came back even though HELO did not
        }
        if (so.anyTcp) proven = true;
        else if (so.ranScan && so.tried >= kMinProbesForSilent) anySilent = true;
    }
    sr.pathAlive = proven;
    sr.sawSilent = !proven && anySilent;
    return sr;
}

// ---- Step D: IPv4 tunnel ------------------------------------------------------
StepResult TunnelStep(NcmEndpoint* ep, Connection* conn, void* cancelEvent, bool allowScan) {
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

    CacheTry ct = TryCachedBridgePort(*ep, conn, true);
    if (ct.ok) {
        tp::CommitAutoTunnel(true);
        T2_LOG("discovery", L"CommitTunnel (cached port %u, gen %llu)", static_cast<unsigned>(ct.port),
               static_cast<unsigned long long>(tp::CurrentGeneration()));
        sr.ok = true;
        sr.servicePort = ct.port;
        sr.rsdPort = ct.rsd;
        sr.pathAlive = true;
        return sr;
    }
    if (Cancelled(cancelEvent)) return sr;
    bool alive = ct.ev == PathEvidence::Positive || ct.ev == PathEvidence::Refused;
    bool silent = ct.ev == PathEvidence::Silent;
    if (!allowScan) {
        // Cold boot is v6-only: the tunnel is only for re-using a port that v6 already
        // found (cached HELO). It never scans by itself.
        sr.pathAlive = alive;
        sr.sawSilent = silent;
        return sr;
    }

    ScanOutcome so = RunScanAttempt(*ep, true, BudgetsFor(true).attemptMs, cancelEvent);
    if (so.servicePort != 0) {
        SaveCachedPort(*ep, so.servicePort, so.rsdPort);
        ULONGLONG tcpMs = 0;
        if (ConnectFoundPort(*ep, conn, true, so.servicePort, &tcpMs)) {
            tp::CommitAutoTunnel(true);
            T2_LOG("discovery", L"CommitTunnel (scanned port %u, gen %llu)",
                   static_cast<unsigned>(so.servicePort),
                   static_cast<unsigned long long>(tp::CurrentGeneration()));
            sr.ok = true;
            sr.servicePort = so.servicePort;
            sr.rsdPort = so.rsdPort;
            sr.pathAlive = true;
            return sr;
        }
        alive = true;
    }
    if (so.anyTcp) alive = true;
    else if (so.ranScan && so.tried >= kMinProbesForSilent) silent = true;
    sr.pathAlive = alive;
    sr.sawSilent = !alive && silent;
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
        return tp::IsV6Unavailable() ? GateResult::V6Unavailable : GateResult::Ready;
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
                                  void* cancelEvent) {
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

    const bool forced = tp::IsTunnelForced();
    const bool autoSwitch = !forced && tp::IsAutoSwitchEnabled();
    if (!forced && !autoSwitch && tp::IsAutoTunnelCommitted()) {
        tp::CommitAutoTunnel(false); // auto-switch was turned off: drop the learned tunnel
    }

    // Alternation flag (section 6.E): after a committed tunnel failed, the NEXT
    // step tries native first, so a VPN that went away without any interface event
    // is found again within one ladder step.
    static std::atomic<bool> s_altPending{false};

    // Decide whether this step starts on native.
    bool tryNative = !forced;
    if (tryNative && autoSwitch && tp::IsV6Unavailable()) {
        tryNative = false; // IPv6 unusable on the adapter for this Generation
    }
    if (tryNative && autoSwitch && tp::IsAutoTunnelCommitted()) {
        // Tunnel is the committed transport. Leave it only for a confirmed reason:
        // the previous tunnel step failed, or a debounced re-probe trigger fired
        // and TWO native probes agree (hysteresis, section 10).
        bool leave = s_altPending.exchange(false);
        if (!leave && tp::ConsumeNativeReprobeDue()) {
            uint16_t cachedPort = 0;
            LoadCachedPort(ep, &cachedPort);
            tp::TransportPhase phase(static_cast<HANDLE>(cancelEvent));
            phase.mode.Enter(tp::TransportMode::NativeIpv6);
            leave = tp::ConfirmNativeReturn(ep.peerLinkLocal, ep.ifIndex, cachedPort,
                                            static_cast<HANDLE>(cancelEvent));
            T2_LOG("discovery", L"return-to-native: %s", leave ? L"confirmed by 2 probes" : L"not confirmed");
        }
        tryNative = leave;
    }

    StepResult result;
    bool nativeAlive = false;
    bool sawSilent = false;
    bool nativeTried = false;
    if (tryNative) {
        nativeTried = true;
        result = NativeStep(ep, outConn, cancelEvent, autoSwitch);
        nativeAlive = result.pathAlive;
        sawSilent = result.sawSilent;
    }
    bool tunnelTried = false;
    // Tunnel policy: cold boot has no VPN, so the start is native IPv6 ONLY. The tunnel
    // is used when (a) the user forced it, or (b) native is silent AND a port is already
    // cached (found earlier over v6): then one HELO over the tunnel is enough, no scan.
    // A tunnel SCAN happens only when forced or when IPv6 is unusable on the adapter.
    bool haveCachedPort = false;
    {
        uint16_t cp = 0;
        haveCachedPort = LoadCachedPort(ep, &cp);
    }
    const bool tunnelScanAllowed = forced || tp::IsV6Unavailable();
    if (!result.ok && !Cancelled(cancelEvent) &&
        (forced || (autoSwitch && !nativeAlive && (haveCachedPort || tunnelScanAllowed)))) {
        tunnelTried = true;
        result = TunnelStep(&ep, outConn, cancelEvent, tunnelScanAllowed);
        sawSilent = sawSilent || result.sawSilent;
    }

    if (result.ok) {
        tp::NotePathAlive();
        s_altPending.store(false, std::memory_order_relaxed);
        if (outServicePort) *outServicePort = result.servicePort;
        if (outRsdPort) *outRsdPort = result.rsdPort;
        return true;
    }

    // Step E - nothing worked this step. State is untouched (nothing was committed),
    // the port cache and the scan progress stay, and the ladder retries from step A.
    if (!Cancelled(cancelEvent)) {
        if (tunnelTried && !nativeTried && tp::IsAutoTunnelCommitted() && autoSwitch) {
            s_altPending.store(true, std::memory_order_relaxed); // alternate next step
        }
        // Only silence counts towards distrusting the persisted peer; a LocalError
        // (no MAC yet) or an alive-but-not-ready path does not.
        if (ep.peerSource == PeerSource::LastKnown && sawSilent && !result.pathAlive &&
            !result.localError) {
            tp::NotePathSilent();
        }
    }
    return false;
}

} // namespace t2::discovery
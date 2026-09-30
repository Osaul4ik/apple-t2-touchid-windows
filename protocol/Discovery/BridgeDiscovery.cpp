// SPDX-License-Identifier: GPL-2.0-only
// BridgeDiscovery.cpp — see BridgeDiscovery.h for why this exists as a
// separate, silent copy of tools/t2touchid/main.cpp's discovery shape
// instead of a shared refactor of that (still argv/cout-shaped) code.
#include "BridgeDiscovery.h"
#include "PortCache.h"
#include "PortScan.h"
#include "RemoteXpc.h"
#include "../BridgeXpc/Log.h"
#include "../BridgeXpc/TransportMode.h"
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

namespace t2::discovery {

namespace {

// Same constant and rationale as tools/t2touchid/main.cpp's
// kBiometricKitService / kRemoteXpcCheckTimeout.
constexpr const char* kBiometricKitService = "com.apple.eos.BiometricKit";
constexpr std::chrono::milliseconds kRemoteXpcCheckTimeout{2000};

// Mirrors main.cpp's TryCachedBridgePort exactly (path A: direct HELO on
// the cached BridgeXPC port; path B: RSD replay on the cached RemoteXPC
// port), minus every std::wcout diagnostic line — silent by design, see
// header comment.
// 26.09.2026: the cache is trusted (it is right the overwhelming majority
// of the time - see the "no scan needed" log line all over a normal
// session), so this always tries it first. But "trusted" must not mean
// "worth an unbounded wait": path A alone used to allow up to 1500ms, and
// path B (RSD probe + reconnect) up to another 4000ms (2000+2000) - so a
// truly stale cached port (adapter gone after a real suspend, T2 side
// rebooted, NCM re-enumerated with a new port) could delay the fallback
// full scan by up to 5.5s. kCacheTrustBudgetMs bounds the WHOLE cached-port
// attempt (path A + path B combined): once it is used up, give up on the
// cache and let the caller's full scan run instead of continuing to wait
// on a port that has already shown it is not answering.
constexpr ULONGLONG kCacheTrustBudgetMs = 500;

// 27.09.2026: the 500ms figure above (and the port-scan concurrency/timeout
// constants in ScanAndProbe below) was tuned against Native IPv6, where
// t2::transport RTT to the T2 peer is ~1ms (see PortScan.h). IPv4 tunnel
// mode adds a real cost on every packet in both directions — userspace
// AF_INET connect -> T2Ncm.sys TX rewrite (IPv4->IPv6) -> USB bulk-OUT ->
// T2 -> USB bulk-IN -> T2Ncm.sys RX rewrite (IPv6->IPv4) -> userspace —
// on top of which every one of these packets shares the single serialized
// USB bulk pipe pair with every OTHER in-flight connection attempt.
// Native's tuning (500ms cache budget; a 256-wide, 20ms-then-60ms full
// scan) was never validated against that, and a DebugView capture from a
// tunnel-mode session showed exactly the failure mode that combination
// produces: none of the cached port's ~500ms budget is enough to get an
// answer back, so every capture falls through to the full scan, and the
// full scan's 256 near-simultaneous connect()s (still each individually
// timing out in 20ms) flood the one bulk-OUT pipe with SYNs that were
// never going to get a same-tick reply - "tunnel TX IPv4->IPv6" logged
// hundreds of times inside the first ~20ms of the scan, no BiometricKit
// port ever found, no fingerprint capture. Scale both knobs when tunnel
// mode is active: fewer sockets in flight so the tunnel isn't asked to
// rewrite/serialize more SYNs than the USB link can actually carry at
// once, and enough per-attempt time for a rewritten round trip to
// complete instead of only for a native one.
ULONGLONG CacheTrustBudgetMs() {
    return t2::transport::IsTunnelModeActive() ? 2000 : kCacheTrustBudgetMs;
}

bool TryCachedBridgePort(const NcmEndpoint& ep, t2::bridgexpc::Connection* conn,
                          uint16_t* outPort) {
    using namespace t2::bridgexpc;
    const ULONGLONG cacheTrustBudgetMs = CacheTrustBudgetMs();

    uint16_t svcPort = 0, rsdPort = 0;
    if (!LoadCachedPort(ep, &svcPort, &rsdPort)) {
        // 20.09.2026 diagnostics: a miss here means the caller falls through
        // to the full port scan (seconds). Logging it makes "every capture
        // pays the scan" visible in the DebugView capture instead of having
        // to be inferred from timestamps.
        T2_LOG("discovery", L"no cached BridgeXPC port for this adapter - full port scan follows");
        return false;
    }

    const ULONGLONG budgetStart = GetTickCount64();
    ConnectResult crA = conn->Connect(ep.peerLinkLocal, ep.ifIndex, svcPort,
                                       std::chrono::milliseconds(cacheTrustBudgetMs));
    if (crA == ConnectResult::Ok) {
        T2_LOG("discovery", L"cached port %u answered with HELO - no scan needed",
               static_cast<unsigned>(svcPort));
        *outPort = svcPort;
        return true;
    }
    T2_LOG("discovery", L"cached port %u (rsd %u) did not answer, ConnectResult=%d",
           static_cast<unsigned>(svcPort), static_cast<unsigned>(rsdPort), static_cast<int>(crA));

    const ULONGLONG elapsedMs = GetTickCount64() - budgetStart;
    if (elapsedMs >= cacheTrustBudgetMs) {
        T2_LOG("discovery", L"cache trust budget (%llu ms) used up on path A alone - full port scan follows",
               static_cast<unsigned long long>(cacheTrustBudgetMs));
        return false;
    }

    if (rsdPort != 0) {
        // Split whatever is left of the budget between the RSD probe and the
        // reconnect it may lead to, instead of giving each its own full
        // kRemoteXpcCheckTimeout (that pair used to be able to cost 4000ms
        // on top of path A). Not worth attempting on scraps of budget.
        const auto halfRemaining = std::chrono::milliseconds((cacheTrustBudgetMs - elapsedMs) / 2);
        if (halfRemaining.count() >= 20) {
            uint16_t advertised = 0;
            if (ProbeServiceOnPort(ep, rsdPort, kBiometricKitService, halfRemaining,
                                    &advertised)) {
                ConnectResult crB = conn->Connect(ep.peerLinkLocal, ep.ifIndex, advertised,
                                                   halfRemaining);
                if (crB == ConnectResult::Ok) {
                    if (advertised != svcPort) {
                        SaveCachedPort(ep, advertised, rsdPort);
                    }
                    *outPort = advertised;
                    return true;
                }
            }
        }
    }
    return false;
}

// Mirrors main.cpp's ScanAndProbe exactly (same concurrency shape: every
// HTTP/2 hit gets its own RemoteXPC checker thread racing the still-running
// scan; the first confirmed BiometricKit hit sets the scan's cancel flag).
struct ScanProbeResult {
    uint16_t servicePort = 0;
    uint16_t rsdPort = 0;
};

ScanProbeResult ScanAndProbe(const NcmEndpoint& ep, ScanOptions opt) {
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

} // namespace

bool PickDefaultT2Endpoint(NcmEndpoint* outEndpoint) {
    if (outEndpoint == nullptr) return false;
    auto endpoints = FindT2NcmEndpoints();
    if (endpoints.empty()) return false;
    *outEndpoint = endpoints.front();
    return true;
}

bool ConnectToBiometricKitBridge(const NcmEndpoint& endpoint, t2::bridgexpc::Connection* outConn,
                                  uint16_t* outServicePort, uint16_t* outRsdPort,
                                  void* cancelEvent) {
    using t2::bridgexpc::ConnectResult;

    if (outConn == nullptr || endpoint.peerSource == PeerSource::None) {
        return false;
    }

    auto cancelled = [&]() {
        return cancelEvent != nullptr &&
               WaitForSingleObject(static_cast<HANDLE>(cancelEvent), 0) == WAIT_OBJECT_0;
    };
    if (cancelled()) return false;

    // Cache fast path — same policy as the CLI: try it first, fall through
    // to a full scan on any miss, never trust it without a live HELO.
    {
        uint16_t cachedPort = 0;
        if (TryCachedBridgePort(endpoint, outConn, &cachedPort)) {
            if (outServicePort) *outServicePort = cachedPort;
            if (outRsdPort) *outRsdPort = 0; // path A/B both leave rsdPort ambiguous here; not needed by callers today
            return true;
        }
    }

    // Cold path (no cached port, or the cached one did not answer): a full
    // port scan is next. Over a blocked IPv6 path that scan probes 16k ports
    // into a void for seconds, so decide the transport first with one bounded
    // native SYN. The tunnel is armed only provisionally here and is rolled
    // back below if the scan finds nothing (T2 simply not ready yet).
    bool provisionalTunnel = false;
    if (!t2::transport::IsTunnelModeActive() && t2::transport::IsAutoSwitchEnabled()) {
        if (!t2::transport::PreflightNativeIpv6(endpoint.peerLinkLocal, endpoint.ifIndex)) {
            t2::transport::CommitAutoTunnel(true);
            provisionalTunnel = true;
            T2_LOG("discovery", L"native IPv6 unreachable - scanning over the IPv4 tunnel");
        }
    }
    auto rollbackProvisionalTunnel = [&]() {
        if (!provisionalTunnel) return;
        t2::transport::CommitAutoTunnel(false);
        t2::transport::PushTransportModeToDriver(t2::transport::TransportMode::NativeIpv6);
    };

    uint16_t foundPort = 0;
    uint16_t foundRsdPort = 0;
    const ULONGLONG scanStartMs = GetTickCount64();
    const bool tunnelActive = t2::transport::IsTunnelModeActive();
    // Native timings/concurrency (see the CacheTrustBudgetMs comment
    // above for why tunnel mode needs its own numbers): 256 concurrent
    // sockets is fine when each one is a native connect(), but under the
    // tunnel every one of those SYNs is serialized onto the same USB
    // bulk-OUT pipe and rewritten by T2Ncm.sys, so firing 256 at once
    // just floods that single pipe faster than replies (rewritten back
    // on RX) can come in — 20ms was never a real round-trip budget for
    // that path. 16-wide keeps the scan from stacking more in-flight
    // SYNs than one physical link can carry; 150ms/400ms give a
    // rewritten round trip realistic room to land.
    const unsigned timeoutsMsNative[] = {20, 60};
    const unsigned timeoutsMsTunnel[] = {150, 400};
    const unsigned* timeoutsMs = tunnelActive ? timeoutsMsTunnel : timeoutsMsNative;
    const unsigned kAttempts = tunnelActive
        ? static_cast<unsigned>(sizeof(timeoutsMsTunnel) / sizeof(timeoutsMsTunnel[0]))
        : static_cast<unsigned>(sizeof(timeoutsMsNative) / sizeof(timeoutsMsNative[0]));
    for (unsigned attempt = 0; attempt < kAttempts; ++attempt) {
        if (cancelled()) break;
        ScanOptions opt;
        opt.cancelEvent = cancelEvent;
        opt.concurrency = tunnelActive ? 16 : 256;
        opt.includeTcpOnly = true;
        opt.connectTimeoutMs = timeoutsMs[attempt];
        // priorityBands default: 59xxx → 49xxx → rest (see PortScan.h).

        ScanProbeResult scan = ScanAndProbe(endpoint, opt);
        if (scan.servicePort != 0) {
            foundPort = scan.servicePort;
            foundRsdPort = scan.rsdPort;
            break;
        }
    }
    T2_LOG("discovery", L"full port scan (%s, %u-wide, %u/%u ms) finished in %llu ms, found port %u",
           tunnelActive ? L"IPv4 tunnel" : L"Native IPv6",
           tunnelActive ? 16u : 256u, timeoutsMs[0], timeoutsMs[kAttempts - 1],
           static_cast<unsigned long long>(GetTickCount64() - scanStartMs),
           static_cast<unsigned>(foundPort));
    if (foundPort == 0) {
        rollbackProvisionalTunnel();
        if (!cancelled() && endpoint.peerSource == PeerSource::LastKnown) {
            t2::transport::DistrustPersistedPeer(); // next discovery does the full lookup
        }
        return false;
    }

    ConnectResult cr = outConn->Connect(endpoint.peerLinkLocal, endpoint.ifIndex, foundPort,
                                         std::chrono::milliseconds(2000));
    if (cr != ConnectResult::Ok) {
        rollbackProvisionalTunnel();
        return false;
    }
    SaveCachedPort(endpoint, foundPort, foundRsdPort);
    if (outServicePort) *outServicePort = foundPort;
    if (outRsdPort) *outRsdPort = foundRsdPort;
    return true;
}

} // namespace t2::discovery
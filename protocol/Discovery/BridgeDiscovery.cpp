// SPDX-License-Identifier: GPL-2.0-only
// BridgeDiscovery.cpp — see BridgeDiscovery.h for why this exists as a
// separate, silent copy of tools/t2touchid/main.cpp's discovery shape
// instead of a shared refactor of that (still argv/cout-shaped) code.
#include "BridgeDiscovery.h"
#include "PortCache.h"
#include "PortScan.h"
#include "RemoteXpc.h"
#include "../BridgeXpc/Log.h"
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

bool TryCachedBridgePort(const NcmEndpoint& ep, t2::bridgexpc::Connection* conn,
                          uint16_t* outPort) {
    using namespace t2::bridgexpc;

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
                                       std::chrono::milliseconds(kCacheTrustBudgetMs));
    if (crA == ConnectResult::Ok) {
        T2_LOG("discovery", L"cached port %u answered with HELO - no scan needed",
               static_cast<unsigned>(svcPort));
        *outPort = svcPort;
        return true;
    }
    T2_LOG("discovery", L"cached port %u (rsd %u) did not answer, ConnectResult=%d",
           static_cast<unsigned>(svcPort), static_cast<unsigned>(rsdPort), static_cast<int>(crA));

    const ULONGLONG elapsedMs = GetTickCount64() - budgetStart;
    if (elapsedMs >= kCacheTrustBudgetMs) {
        T2_LOG("discovery", L"cache trust budget (%llu ms) used up on path A alone - full port scan follows",
               static_cast<unsigned long long>(kCacheTrustBudgetMs));
        return false;
    }

    if (rsdPort != 0) {
        // Split whatever is left of the budget between the RSD probe and the
        // reconnect it may lead to, instead of giving each its own full
        // kRemoteXpcCheckTimeout (that pair used to be able to cost 4000ms
        // on top of path A). Not worth attempting on scraps of budget.
        const auto halfRemaining = std::chrono::milliseconds((kCacheTrustBudgetMs - elapsedMs) / 2);
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
                                  uint16_t* outServicePort, uint16_t* outRsdPort) {
    using t2::bridgexpc::ConnectResult;

    if (outConn == nullptr || endpoint.peerSource == PeerSource::None) {
        return false;
    }

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

    uint16_t foundPort = 0;
    uint16_t foundRsdPort = 0;
    const ULONGLONG scanStartMs = GetTickCount64();
    const unsigned timeoutsMs[] = {20, 60};
    constexpr unsigned kAttempts = sizeof(timeoutsMs) / sizeof(timeoutsMs[0]);
    for (unsigned attempt = 0; attempt < kAttempts; ++attempt) {
        ScanOptions opt;
        opt.concurrency = 256;
        opt.includeTcpOnly = true;
        opt.connectTimeoutMs = timeoutsMs[attempt];
        // Ascending (ScanOptions::scanFromEnd default) — the real
        // candidate sits near portBegin (~49000), not the high end.

        ScanProbeResult scan = ScanAndProbe(endpoint, opt);
        if (scan.servicePort != 0) {
            foundPort = scan.servicePort;
            foundRsdPort = scan.rsdPort;
            break;
        }
    }
    T2_LOG("discovery", L"full port scan finished in %llu ms, found port %u",
           static_cast<unsigned long long>(GetTickCount64() - scanStartMs),
           static_cast<unsigned>(foundPort));
    if (foundPort == 0) {
        return false;
    }

    ConnectResult cr = outConn->Connect(endpoint.peerLinkLocal, endpoint.ifIndex, foundPort,
                                         std::chrono::milliseconds(2000));
    if (cr != ConnectResult::Ok) {
        return false;
    }
    SaveCachedPort(endpoint, foundPort, foundRsdPort);
    if (outServicePort) *outServicePort = foundPort;
    if (outRsdPort) *outRsdPort = foundRsdPort;
    return true;
}

} // namespace t2::discovery
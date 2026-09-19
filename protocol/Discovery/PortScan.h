// SPDX-License-Identifier: GPL-2.0-only
// PortScan.h — dynamic-port probe (Linux discover-biometric-port.py phase 1).
#pragma once
#include "Adapter.h"
#include <cstdint>
#include <vector>
#include <functional>
#include <atomic>

namespace t2::discovery {

struct PortCandidate {
    uint16_t port = 0;
    bool tcpOpen = false;
    bool http2PrefaceOk = false;
    // Diagnostic: raw first bytes after connect (max 21, Linux recv size).
    unsigned char recvHead[21]{};
    int recvLen = 0;
    // True if the peer was silent on the passive (Linux-reference) attempt
    // and we sent our own HTTP/2 client preface + empty SETTINGS to probe
    // whether it's a standard RFC 7540 server waiting for the client to go
    // first. If http2PrefaceOk is true AND this is true, the port only
    // answered *after* we spoke — that contradicts the "peer speaks first"
    // assumption the passive scan is built on and must not be reported as
    // an ordinary Phase-1 hit.
    bool activePrefaceTried = false;
};

struct ScanOptions {
    uint16_t portBegin = 49152;
    uint16_t portEnd = 65535;
    unsigned concurrency = 64;
    // Linux default --probe-timeout 0.15 (150ms). Lowered here: observed
    // RTT to the T2 peer over this NCM link is ~1ms, so 150ms was far
    // more headroom than the link needs for a single probe. 20ms leaves
    // margin for VPN-induced jitter (see Adapter.cpp's neighbor-poll
    // comment) without reintroducing the old 150ms cost across 16384
    // ports.
    unsigned connectTimeoutMs = 20;
    bool includeTcpOnly = true;
    // If a TCP-open peer stays fully silent (0 bytes) on the passive
    // recv-only attempt, retry once by sending our own HTTP/2 client
    // preface + empty SETTINGS frame before giving up on that port.
    // Diagnostic only — see PortCandidate::activePrefaceTried.
    bool activePrefaceFallback = true;
    // tried, total, tcpHits, http2Hits
    std::function<void(unsigned, unsigned, unsigned, unsigned)> onProgress;

    // Fires synchronously, on whichever worker thread found it, the moment
    // a candidate is accepted (same filter as what ends up in the returned
    // vector: tcpOpen && (http2PrefaceOk || includeTcpOnly)) — i.e. before
    // the rest of the port range has been scanned. Lets a caller start
    // verifying a hit (e.g. a RemoteXPC probe) *while the scan is still
    // running* instead of waiting for the full vector to come back. Keep
    // this callback cheap/non-blocking: do real verification work on a
    // separate thread it spawns, not inline here, or it will stall the
    // worker that called it.
    std::function<void(const PortCandidate&)> onHit;

    // External stop signal, checked by every worker before it claims the
    // next port. Set this (e.g. from onHit, once verification confirms a
    // hit) to make the scan abandon the rest of the range immediately
    // instead of exhaustively probing every port up to portEnd. Probes
    // already in flight when this is set still run to completion (bounded
    // by connectTimeoutMs / the recv window) — this only stops new ones
    // from starting.
    std::atomic<bool>* cancel = nullptr;
};

std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options = {});

} // namespace t2::discovery
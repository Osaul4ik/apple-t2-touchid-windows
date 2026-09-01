// SPDX-License-Identifier: GPL-2.0-only
// PortScan.h — dynamic-port probe (Linux discover-biometric-port.py phase 1).
#pragma once
#include "Adapter.h"
#include <cstdint>
#include <vector>
#include <functional>

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
    // Linux default --probe-timeout 0.15; used for connect. Recv uses max(300, this).
    unsigned connectTimeoutMs = 150;
    bool includeTcpOnly = true;
    // If a TCP-open peer stays fully silent (0 bytes) on the passive
    // recv-only attempt, retry once by sending our own HTTP/2 client
    // preface + empty SETTINGS frame before giving up on that port.
    // Diagnostic only — see PortCandidate::activePrefaceTried.
    bool activePrefaceFallback = true;
    // tried, total, tcpHits, http2Hits
    std::function<void(unsigned, unsigned, unsigned, unsigned)> onProgress;
};

std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options = {});

} // namespace t2::discovery
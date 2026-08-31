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
};

struct ScanOptions {
    uint16_t portBegin = 49152;
    uint16_t portEnd = 65535;
    unsigned concurrency = 64;
    // Linux default --probe-timeout 0.15; used for connect. Recv uses max(300, this).
    unsigned connectTimeoutMs = 150;
    bool includeTcpOnly = true;
    // tried, total, tcpHits, http2Hits
    std::function<void(unsigned, unsigned, unsigned, unsigned)> onProgress;
};

std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options = {});

} // namespace t2::discovery

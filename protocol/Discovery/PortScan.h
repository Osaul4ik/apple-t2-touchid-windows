// SPDX-License-Identifier: GPL-2.0-only
// PortScan.h — dynamic-port probe (Linux discover-biometric-port.py phase 1).
#pragma once
#include "Adapter.h"
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace t2::discovery {

struct PortCandidate {
    uint16_t port = 0;
    bool tcpOpen = false;       // connect() succeeded
    bool http2PrefaceOk = false; // peer frame type == SETTINGS (0x04)
};

struct ScanOptions {
    uint16_t portBegin = 49152;
    uint16_t portEnd   = 65535; // inclusive
    unsigned concurrency = 64;
    unsigned connectTimeoutMs = 400;
    // If true, keep ports that only accepted TCP (no HTTP/2 SETTINGS).
    // Useful for diagnostics when HTTP/2 filtering yields zero hits.
    bool includeTcpOnly = true;
    std::function<void(unsigned, unsigned, unsigned, unsigned)> onProgress;
    // args: tried, total, tcpHits, http2Hits
};

std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options = {});

constexpr char kHttp2ClientPreface[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

} // namespace t2::discovery

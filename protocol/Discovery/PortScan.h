// SPDX-License-Identifier: GPL-2.0-only
// PortScan.h — HTTP/2-preface probe of the dynamic port range (Linux
// discover-biometric-port.py equivalent, Phase 1 of Gate 6).
#pragma once
#include "Adapter.h"
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace t2::discovery {

struct PortCandidate {
    uint16_t port = 0;
    // True if TCP connected and the peer's first bytes looked like an
    // HTTP/2 SETTINGS frame (type byte == 4), matching the Linux probe.
    bool http2PrefaceOk = false;
};

struct ScanOptions {
    uint16_t portBegin = 49152;
    uint16_t portEnd   = 65535; // inclusive
    // Concurrent outstanding connects (Linux default 512).
    unsigned concurrency = 256;
    // Per-connect timeout in milliseconds.
    unsigned connectTimeoutMs = 200;
    // Optional progress callback: (portsTried, portsTotal, hitsSoFar).
    std::function<void(unsigned, unsigned, unsigned)> onProgress;
};

// Scans [portBegin, portEnd] on endpoint.linkLocal%ifIndex.
// Returns only ports that accepted TCP and passed the HTTP/2 preface check.
// Does NOT perform RemoteXPC/RSD handshake — that is Gate 6 phase 2.
std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options = {});

// HTTP/2 connection preface client sends; we also accept a peer that
// speaks first with a SETTINGS frame (type 0x04).
constexpr char kHttp2ClientPreface[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

} // namespace t2::discovery
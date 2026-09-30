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
};

struct ScanOptions {
    uint16_t portBegin = 49152;
    uint16_t portEnd = 65535;
    unsigned concurrency = 256;
    // Linux default --probe-timeout 0.15 (150ms). Lowered here: observed
    // RTT to the T2 peer over this NCM link is ~1ms, so 150ms was far
    // more headroom than the link needs for a single probe. 20ms leaves
    // margin for VPN-induced jitter (see Adapter.cpp's neighbor-poll
    // comment) without reintroducing the old 150ms cost across 16384
    // ports.
    unsigned connectTimeoutMs = 20;
    bool includeTcpOnly = true;
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

    // Optional Win32 event (HANDLE, typed void* to keep this header free of
    // <windows.h>) that also stops the scan when signaled - lets a caller tie
    // the scan to an outside cancel (WBF CancelIoEx) that `cancel` above, which
    // ScanAndProbe owns for its own early exit, cannot carry.
    void* cancelEvent = nullptr;

    // Port dispatch order within [portBegin, portEnd]:
    //
    //   priorityBands=true (default): hardware-tuned order observed on
    //   real T2 sessions —
    //     1) 59xxx  (RemoteXPC often lands here, e.g. 59602)
    //     2) 49xxx  (BridgeXPC / dense HTTP/2 decoys, e.g. 49341)
    //     3) everything else in the range, ascending
    //   So a BiometricKit hit at 59xxx cancels long before the scan
    //   grinds through the middle of the ephemeral range.
    //
    //   priorityBands=false: legacy linear order. scanFromEnd=false →
    //   ascending from portBegin; scanFromEnd=true → descending from
    //   portEnd.
    bool priorityBands = true;

    // Only used when priorityBands=false. See above.
    bool scanFromEnd = false;
};

std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options = {});

} // namespace t2::discovery
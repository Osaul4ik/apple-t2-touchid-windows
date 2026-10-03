// SPDX-License-Identifier: GPL-2.0-only
// PortScan.h — dynamic-port probe (Linux discover-biometric-port.py phase 1).
#pragma once
#include "Adapter.h"
#include <cstdint>
#include <vector>
#include <functional>
#include <atomic>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace t2::discovery {

struct PortCandidate {
    uint16_t port = 0;
    bool tcpOpen = false;
    bool http2PrefaceOk = false;
    // Diagnostic: raw first bytes after connect (max 21, Linux recv size).
    unsigned char recvHead[21]{};
    int recvLen = 0;
};

// Filled by ScanHttp2Preface (ScanOptions::stats). Progress is expressed as an
// index into the port dispatch order, so a caller can RESUME a scan that was cut
// short by a deadline or a cancel instead of starting over (architecture v2
// section 7: the old scan lived and died with one CAPTURE_DATA).
struct ScanStats {
    unsigned orderTotal = 0;     // length of the full dispatch order
    unsigned claimedEnd = 0;     // every order index below this was probed to completion
    unsigned tried = 0;          // probes finished during this call
    unsigned tcpHits = 0;
    unsigned http2Hits = 0;
    unsigned refused = 0;        // RST (WSAECONNREFUSED): a packet came back, the path works
    unsigned blocked = 0;        // WSAEACCES on connect: a local WFP block filter (VPN kill-switch)
    bool exhausted = false;      // reached the end of the (limited) order
    bool silentAborted = false;  // stopped by ScanOptions::silentAbortAfter (path silent)
};

struct ScanOptions {
    // 49000, not 49152: the 49xxx priority band starts at 49000 and the
    // Windows/T2 ephemeral range alone would silently skip 49000-49151.
    uint16_t portBegin = 49000;
    uint16_t portEnd = 65535;
    unsigned concurrency = 256;
    // Linux default --probe-timeout 0.15 (150ms). Lowered here: observed
    // RTT to the T2 peer over this NCM link is ~1ms, so 150ms was far
    // more headroom than the link needs for a single probe. 20ms leaves
    // margin for VPN-induced jitter (see Adapter.cpp's neighbor-poll
    // comment) without reintroducing the old 150ms cost across 16384
    // ports.
    unsigned connectTimeoutMs = 25;
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
    //     1) 59000-60000 (RemoteXPC often lands here, e.g. 59602)
    //     2) 49000-49999 (BridgeXPC / dense HTTP/2 decoys, e.g. 49341)
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

    // ---- resumable / bounded scanning (architecture v2, section 7) ----
    // Absolute GetTickCount64() value after which no NEW port is claimed (probes
    // already in flight still finish). 0 = no deadline.
    ULONGLONG deadlineTick = 0;
    // Skip the first `orderSkip` entries of the dispatch order (resume point) and
    // stop at `orderLimit` (0 = the whole order). Indexes are into the same order
    // BuildPortOrder returns for these options.
    unsigned orderSkip = 0;
    unsigned orderLimit = 0;
    ScanStats* stats = nullptr;

    // Path-silence early abort: once this many probes of THIS call have finished
    // and not one of them got anything back (no SYN-ACK, no RST), stop claiming
    // new ports and report stats->silentAborted. A dead/filtered path is then
    // known after ~2 rounds of probes instead of a whole 16k-port pass.
    // A WFP block (WSAEACCES) counts as "nothing back". 0 = disabled.
    unsigned silentAbortAfter = 0;
};

// Dispatch order used by ScanHttp2Preface (see ScanOptions::priorityBands).
std::vector<uint16_t> BuildPortOrder(uint16_t begin, uint16_t end,
                                     bool priorityBands, bool scanFromEnd);
// Number of leading entries of the priority order that belong to the two priority
// bands (59000-60000, 49000-49999) - i.e. "priority ranges only" is orderLimit = this.
unsigned PriorityBandCount(uint16_t begin, uint16_t end);

std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options = {});

} // namespace t2::discovery
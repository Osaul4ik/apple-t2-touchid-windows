// SPDX-License-Identifier: GPL-2.0-only
// PortScan.cpp — VERIFIED FROM SOURCE: jmurth1234/t2-touchid-linux
// src/discover-biometric-port.py probe_port()
//
// Connect, then recv only (peer SETTINGS first). No client preface.
#include "PortScan.h"
#include "../BridgeXpc/Winsock.h"
#include "../BridgeXpc/TransportMode.h"
#include "../BridgeXpc/Connection.h"
#include <ws2tcpip.h>
#include <windows.h>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "Ws2_32.lib")

namespace t2::discovery {
namespace {

struct ProbeResult {
    bool connected = false;
    bool http2 = false;
    // First bytes received after connect (for diagnostics when SETTINGS missing).
    unsigned char head[21]{};
    int headLen = 0;
};

// Deadline-based wait until readable or timeout_ms elapsed.
bool WaitReadable(SOCKET s, unsigned timeoutMs) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    timeval tv{};
    tv.tv_sec = static_cast<long>(timeoutMs / 1000);
    tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
    return select(0, &rset, nullptr, nullptr, &tv) > 0;
}

ProbeResult ProbePort(const NcmEndpoint& ep, uint16_t port,
                      unsigned connectTimeoutMs, unsigned recvTimeoutMs) {
    ProbeResult r;
    const bool tunnel = t2::transport::IsTunnelModeActive();
    SOCKET s = socket(tunnel ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return r;

    if (tunnel) {
        DWORD ifIndexNet = htonl(static_cast<DWORD>(ep.ifIndex));
        setsockopt(s, IPPROTO_IP, IP_UNICAST_IF,
                   reinterpret_cast<const char*>(&ifIndexNet), sizeof(ifIndexNet));
    } else {
        DWORD ifIndex = ep.ifIndex;
        setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF,
                   reinterpret_cast<const char*>(&ifIndex), sizeof(ifIndex));
    }

    // Disable Nagle — small control frames.
    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    int cr;
    if (tunnel) {
        sockaddr_in addr4{};
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        addr4.sin_addr = t2::transport::MapPeerToIpv4(ep.peerLinkLocal);
        cr = connect(s, reinterpret_cast<sockaddr*>(&addr4), sizeof(addr4));
    } else {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        addr.sin6_addr = ep.peerLinkLocal;
        addr.sin6_scope_id = ep.ifIndex;
        cr = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    }
    if (cr != 0) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            closesocket(s);
            return r;
        }
        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        FD_SET(s, &wset);
        FD_SET(s, &eset);
        timeval tv{};
        tv.tv_sec = static_cast<long>(connectTimeoutMs / 1000);
        tv.tv_usec = static_cast<long>((connectTimeoutMs % 1000) * 1000);
        int sel = select(0, nullptr, &wset, &eset, &tv);
        if (sel <= 0 || FD_ISSET(s, &eset)) {
            closesocket(s);
            return r;
        }
        int soerr = 0;
        int solen = sizeof(soerr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &solen);
        if (soerr != 0) {
            closesocket(s);
            return r;
        }
    }
    r.connected = true;

    // VERIFIED FROM SOURCE: peer speaks first. Accumulate up to 21 bytes
    // within recvTimeoutMs (Linux sock_recv(21) with the same timeout).
    // Partial reads are common on Windows NCM; loop until 9+ or deadline.
    ULONGLONG deadline =
        GetTickCount64() + static_cast<ULONGLONG>(recvTimeoutMs);
    int got = 0;
    while (got < 21) {
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) break;
        unsigned left = static_cast<unsigned>(deadline - now);
        if (!WaitReadable(s, left)) break;
        int n = recv(s, reinterpret_cast<char*>(r.head + got), 21 - got, 0);
        if (n == 0) break; // peer closed
        if (n < 0) {
            int e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK) continue;
            break;
        }
        got += n;
        // Fast-path: enough for the Linux check
        if (got >= 9) {
            // Can stop early if SETTINGS already clear; still keep what we have.
            break;
        }
    }
    r.headLen = got;

    // Linux: len >= 9 && type==4 && stream id == 0
    if (got >= 9 && r.head[3] == 0x04 &&
        r.head[5] == 0 && r.head[6] == 0 && r.head[7] == 0 && r.head[8] == 0) {
        r.http2 = true;
    }

    closesocket(s);
    return r;
}

} // namespace

// Build the probe order for [begin, end].
//
// priorityBands (default): hardware order from real T2 sessions —
//   1) 59xxx  — RemoteXPC often lands here (e.g. 59602)
//   2) 49xxx  — BridgeXPC + dense HTTP/2 cluster (e.g. 49341)
//   3) rest of the range, ascending
// Each band is clipped to [begin, end]; ports already covered by an
// earlier band are not repeated.
//
// Linear fallback: ascending from begin, or descending from end when
// scanFromEnd is set.
std::vector<uint16_t> BuildPortOrder(uint16_t begin, uint16_t end,
                                      bool priorityBands, bool scanFromEnd) {
    std::vector<uint16_t> order;
    if (end < begin) return order;
    const unsigned total = static_cast<unsigned>(end - begin) + 1;
    order.reserve(total);

    if (!priorityBands) {
        if (scanFromEnd) {
            for (unsigned i = 0; i < total; ++i)
                order.push_back(static_cast<uint16_t>(end - i));
        } else {
            for (unsigned i = 0; i < total; ++i)
                order.push_back(static_cast<uint16_t>(begin + i));
        }
        return order;
    }

    // bitset-like mark for ports already scheduled (index = port - begin).
    std::vector<uint8_t> used(total, 0);
    auto appendBand = [&](uint16_t bandLo, uint16_t bandHi) {
        const uint16_t lo = (bandLo > begin) ? bandLo : begin;
        const uint16_t hi = (bandHi < end) ? bandHi : end;
        if (hi < lo) return;
        for (uint32_t p = lo; p <= hi; ++p) {
            const unsigned idx = static_cast<unsigned>(p - begin);
            if (used[idx]) continue;
            used[idx] = 1;
            order.push_back(static_cast<uint16_t>(p));
        }
    };

    appendBand(59000, 59999); // 59xxx first — typical RemoteXPC
    appendBand(49000, 49999); // 49xxx next  — BridgeXPC / decoy cluster
    // Remainder ascending.
    for (unsigned i = 0; i < total; ++i) {
        if (!used[i]) order.push_back(static_cast<uint16_t>(begin + i));
    }
    return order;
}

std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options) {
    std::vector<PortCandidate> hits;
    if (!EnsureWinsock()) return hits;
    if (endpoint.ifIndex == 0) return hits;
    if (options.portEnd < options.portBegin) return hits;

    // Seed T2Ncm peer IPv6 + static IPv4 neighbor (ARP) BEFORE any AF_INET
    // probe connect() below. Without this, every ProbePort() tunnel-mode
    // connect() targets a 169.254.x.y address Windows has never resolved:
    // it falls back to broadcasting an ARP request over the NCM link, which
    // T2Ncm.sys never answers (Tunnel.c only rewrites TCP/UDP-over-IP, not
    // ARP frames) and the T2 itself doesn't understand, so the ARP entry
    // stays incomplete and every connect() dies silently — the whole
    // 16384-port range comes back tcp=0 even though the peer is reachable
    // over native IPv6. Connection.cpp's real BridgeXPC connect already did
    // this before its own AF_INET connect; the scanner needs the same seed
    // before it starts probing, not after.
    if (t2::transport::IsTunnelModeActive()) {
        t2::transport::PrepareTunnelPeer(endpoint.ifIndex, endpoint.peerLinkLocal);
    } else {
        // Mirror of the above: a native scan needs T2Ncm.sys in native mode.
        // A failed tunnel fallback elsewhere leaves the driver in tunnel mode
        // (which rewrites EVERY inbound IPv6 frame to IPv4, so no native
        // SYN-ACK would ever reach this scan). No-op when already native.
        t2::transport::PushTransportModeToDriver(t2::transport::TransportMode::NativeIpv6);
    }

    const std::vector<uint16_t> portOrder = BuildPortOrder(
        options.portBegin, options.portEnd,
        options.priorityBands, options.scanFromEnd);
    const unsigned total = static_cast<unsigned>(portOrder.size());
    if (total == 0) return hits;

    std::atomic<unsigned> next{0};
    std::atomic<unsigned> tried{0};
    std::atomic<unsigned> tcpHits{0};
    std::atomic<unsigned> http2Hits{0};
    std::mutex hitsMu;

    unsigned workers = options.concurrency;
    if (workers == 0) workers = 1;
    if (workers > total) workers = total;
    // OPTIMIZATION: this used to cap at 64, which for the full 16384-port
    // dynamic range means 256 sequential probes per worker. The 64 number
    // was never actually load-bearing — every WaitReadable/connect select()
    // call here uses a fresh, thread-local fd_set holding exactly one
    // socket, so FD_SETSIZE (also 64) never comes into play; that made 64
    // look like a real ceiling when it wasn't. 256 workers means 64
    // ports/worker instead of 256 — a 4x cut in the worst-case wall-clock
    // cost of a full scan, which matters most for
    // DiscoverBiometricKitBridge's retry ladder in main.cpp, where a
    // full scan can run more than once.
    if (workers > 256) workers = 256;

    // Recv window: at least connect timeout; prefer a bit longer on Windows
    // NCM (partial deliveries). Still matches Linux spirit of ~150ms default
    // when connectTimeoutMs is 150; options can raise it.
    unsigned recvMs = options.connectTimeoutMs;
    if (recvMs < 300) recvMs = 300;

    auto worker = [&]() {
        for (;;) {
            // Checked before claiming each new port so a caller that already
            // got what it needed via onHit (e.g. BiometricKit confirmed) can
            // abort the rest of the range immediately.
            if (options.cancel &&
                options.cancel->load(std::memory_order_relaxed)) {
                break;
            }
            if (options.cancelEvent &&
                t2::bridgexpc::Connection::IsEventSignaled(static_cast<HANDLE>(options.cancelEvent))) {
                break;
            }
            unsigned i = next.fetch_add(1);
            if (i >= total) break;
            const uint16_t port = portOrder[i];
            ProbeResult pr =
                ProbePort(endpoint, port, options.connectTimeoutMs, recvMs);
            if (pr.connected) {
                tcpHits.fetch_add(1);
                if (pr.http2) http2Hits.fetch_add(1);
                if (pr.http2 || options.includeTcpOnly) {
                    PortCandidate c;
                    c.port = port;
                    c.tcpOpen = true;
                    c.http2PrefaceOk = pr.http2;
                    c.recvLen = pr.headLen;
                    std::memcpy(c.recvHead, pr.head, sizeof(c.recvHead));
                    {
                        std::lock_guard<std::mutex> lock(hitsMu);
                        hits.push_back(c);
                    }
                    // Fired outside hitsMu: caller can start verifying this
                    // hit in parallel while this worker moves on.
                    if (options.onHit) options.onHit(c);
                }
            }
            unsigned t = tried.fetch_add(1) + 1;
            if (options.onProgress && (t % 512 == 0 || t == total)) {
                options.onProgress(t, total, tcpHits.load(), http2Hits.load());
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (unsigned w = 0; w < workers; ++w) threads.emplace_back(worker);
    for (auto& th : threads) th.join();

    std::sort(hits.begin(), hits.end(),
              [](const PortCandidate& a, const PortCandidate& b) {
                  return a.port < b.port;
              });
    return hits;
}

} // namespace t2::discovery
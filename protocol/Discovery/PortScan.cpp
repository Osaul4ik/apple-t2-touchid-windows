// SPDX-License-Identifier: GPL-2.0-only
// PortScan.cpp — VERIFIED FROM SOURCE: jmurth1234/t2-touchid-linux
// src/discover-biometric-port.py probe_port()
//
// Connect, then recv only (peer SETTINGS first). No client preface.
#include "PortScan.h"
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

bool EnsureWinsock() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        WSADATA wsa{};
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    });
    return ok;
}

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
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return r;

    DWORD ifIndex = ep.ifIndex;
    setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF,
               reinterpret_cast<const char*>(&ifIndex), sizeof(ifIndex));

    // Disable Nagle — small control frames.
    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = ep.linkLocal;
    addr.sin6_scope_id = ep.ifIndex;

    int cr = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
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

std::vector<PortCandidate> ScanHttp2Preface(const NcmEndpoint& endpoint,
                                            const ScanOptions& options) {
    std::vector<PortCandidate> hits;
    if (!EnsureWinsock()) return hits;
    if (endpoint.ifIndex == 0) return hits;
    if (options.portEnd < options.portBegin) return hits;

    const unsigned total =
        static_cast<unsigned>(options.portEnd - options.portBegin) + 1;
    std::atomic<unsigned> next{0};
    std::atomic<unsigned> tried{0};
    std::atomic<unsigned> tcpHits{0};
    std::atomic<unsigned> http2Hits{0};
    std::mutex hitsMu;

    unsigned workers = options.concurrency;
    if (workers == 0) workers = 1;
    if (workers > total) workers = total;
    if (workers > 64) workers = 64;

    // Recv window: at least connect timeout; prefer a bit longer on Windows
    // NCM (partial deliveries). Still matches Linux spirit of ~150ms default
    // when connectTimeoutMs is 150; options can raise it.
    unsigned recvMs = options.connectTimeoutMs;
    if (recvMs < 300) recvMs = 300;

    auto worker = [&]() {
        for (;;) {
            unsigned i = next.fetch_add(1);
            if (i >= total) break;
            uint16_t port = static_cast<uint16_t>(options.portBegin + i);
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
                    std::lock_guard<std::mutex> lock(hitsMu);
                    hits.push_back(c);
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

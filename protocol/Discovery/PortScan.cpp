// SPDX-License-Identifier: GPL-2.0-only
// PortScan.cpp — VERIFIED FROM SOURCE: jmurth1234/t2-touchid-linux
// src/discover-biometric-port.py probe_port()
//
// Linux does NOT send an HTTP/2 client preface. It connects, then
// sock_recv(21) and checks:
//   len >= 9 && greeting[3] == 4 (SETTINGS) && greeting[5:9] == 00 00 00 00
// (stream id 0). Sending a preface first was wrong and yielded zero hits.
#include "PortScan.h"
#include <ws2tcpip.h>
#include <windows.h>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <algorithm>

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

struct ProbeResult { bool connected = false; bool http2 = false; };

ProbeResult ProbePort(const NcmEndpoint& ep, uint16_t port, unsigned timeoutMs) {
    ProbeResult r;
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return r;

    // Prefer the T2 NCM interface for link-local (Windows routing).
    DWORD ifIndex = ep.ifIndex;
    setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF,
               reinterpret_cast<const char*>(&ifIndex), sizeof(ifIndex));

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
        tv.tv_sec = static_cast<long>(timeoutMs / 1000);
        tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
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

    // VERIFIED FROM SOURCE: peer speaks first. Do NOT send client preface.
    // sock_recv up to 21 bytes; require SETTINGS type and stream id 0.
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    timeval rtv{};
    rtv.tv_sec = static_cast<long>(timeoutMs / 1000);
    rtv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
    if (select(0, &rset, nullptr, nullptr, &rtv) > 0) {
        unsigned char buf[21] = {};
        int n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        // greeting[3] == 4 (SETTINGS), greeting[5:9] == \0\0\0\0 (stream 0)
        if (n >= 9 && buf[3] == 0x04 &&
            buf[5] == 0 && buf[6] == 0 && buf[7] == 0 && buf[8] == 0) {
            r.http2 = true;
        }
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

    const unsigned total = static_cast<unsigned>(options.portEnd - options.portBegin) + 1;
    std::atomic<unsigned> next{0};
    std::atomic<unsigned> tried{0};
    std::atomic<unsigned> tcpHits{0};
    std::atomic<unsigned> http2Hits{0};
    std::mutex hitsMu;

    unsigned workers = options.concurrency;
    if (workers == 0) workers = 1;
    if (workers > total) workers = total;
    if (workers > 64) workers = 64;

    auto worker = [&]() {
        for (;;) {
            unsigned i = next.fetch_add(1);
            if (i >= total) break;
            uint16_t port = static_cast<uint16_t>(options.portBegin + i);
            ProbeResult pr = ProbePort(endpoint, port, options.connectTimeoutMs);
            if (pr.connected) {
                tcpHits.fetch_add(1);
                if (pr.http2) http2Hits.fetch_add(1);
                if (pr.http2 || options.includeTcpOnly) {
                    std::lock_guard<std::mutex> lock(hitsMu);
                    hits.push_back(PortCandidate{port, true, pr.http2});
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
              [](const PortCandidate& a, const PortCandidate& b) { return a.port < b.port; });
    return hits;
}

} // namespace t2::discovery

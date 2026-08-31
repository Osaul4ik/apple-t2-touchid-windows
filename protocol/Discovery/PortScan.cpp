// SPDX-License-Identifier: GPL-2.0-only
// PortScan.cpp
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

// Returns: connected (TCP), http2 (SETTINGS seen).
struct ProbeResult { bool connected = false; bool http2 = false; };

ProbeResult ProbePort(const NcmEndpoint& ep, uint16_t port, unsigned timeoutMs) {
    ProbeResult r;
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return r;

    // Bind to the T2 NCM interface so link-local traffic leaves the right NIC.
    sockaddr_in6 bindAddr{};
    bindAddr.sin6_family = AF_INET6;
    bindAddr.sin6_addr = in6addr_any;
    bindAddr.sin6_scope_id = ep.ifIndex;
    // Binding with scope_id only is not always enough; IPV6_UNICAST_IF helps.
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

    // Optional: send HTTP/2 client preface and look for SETTINGS (type 0x04).
    send(s, kHttp2ClientPreface, static_cast<int>(sizeof(kHttp2ClientPreface) - 1), 0);

    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    timeval rtv{};
    rtv.tv_sec = 0;
    rtv.tv_usec = static_cast<long>((std::min)(timeoutMs, 500u) * 1000);
    if (select(0, &rset, nullptr, nullptr, &rtv) > 0) {
        unsigned char buf[32] = {};
        int n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n >= 9) {
            // Standard HTTP/2 frame header: length[3] type[1] ...
            if (buf[3] == 0x04) {
                r.http2 = true;
            }
            // Some peers prepend the 24-byte client-preface echo path or
            // server connection preface; search first 24 bytes for type 0x04
            // at offset 3 of any aligned frame.
            for (int i = 0; i + 9 <= n; ++i) {
                if (buf[i + 3] == 0x04) {
                    r.http2 = true;
                    break;
                }
            }
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

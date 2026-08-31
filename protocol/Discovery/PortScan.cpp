// SPDX-License-Identifier: GPL-2.0-only
// PortScan.cpp — concurrent TCP + HTTP/2 preface probe (Gate 6 phase 1).
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

// Non-blocking connect with timeout; on success optionally reads peer bytes
// and checks for HTTP/2 SETTINGS (type == 4) or accepts our preface echo path.
bool ProbePort(const NcmEndpoint& ep, uint16_t port, unsigned timeoutMs, bool* http2Ok) {
    *http2Ok = false;
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    // Non-blocking
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
            return false;
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
            return false;
        }
        int soerr = 0;
        int solen = sizeof(soerr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &solen);
        if (soerr != 0) {
            closesocket(s);
            return false;
        }
    }

    // Connected. Send HTTP/2 client preface (Linux probe does this style of
    // filtering). Then try to read a small response.
    send(s, kHttp2ClientPreface, static_cast<int>(sizeof(kHttp2ClientPreface) - 1), 0);

    // Brief wait for peer data
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    timeval rtv{};
    rtv.tv_sec = 0;
    rtv.tv_usec = static_cast<long>(timeoutMs * 1000);
    if (rtv.tv_usec > 500000) rtv.tv_usec = 500000; // cap read wait 500ms
    if (select(0, &rset, nullptr, nullptr, &rtv) > 0) {
        unsigned char buf[24] = {};
        int n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        // HTTP/2 frame: length(3) type(1) flags(1) stream(4) ...
        // SETTINGS type == 0x04. Peer may also send server preface first.
        if (n >= 9) {
            unsigned char type = buf[3];
            if (type == 0x04) {
                *http2Ok = true;
            }
        }
        // Some stacks reply with fewer bytes; treat any readable peer that
        // accepted the TCP connect after preface as a soft candidate only if
        // type matched. Strict mode: require type==4 (Linux reference).
    }

    closesocket(s);
    return *http2Ok;
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
    std::mutex hitsMu;

    unsigned workers = options.concurrency;
    if (workers == 0) workers = 1;
    if (workers > total) workers = total;
    // Cap threads to something reasonable for a user-mode CLI.
    if (workers > 64) workers = 64;

    auto worker = [&]() {
        for (;;) {
            unsigned i = next.fetch_add(1);
            if (i >= total) break;
            uint16_t port = static_cast<uint16_t>(options.portBegin + i);
            bool http2 = false;
            if (ProbePort(endpoint, port, options.connectTimeoutMs, &http2) && http2) {
                std::lock_guard<std::mutex> lock(hitsMu);
                hits.push_back(PortCandidate{port, true});
            }
            unsigned t = tried.fetch_add(1) + 1;
            if (options.onProgress && (t % 512 == 0 || t == total)) {
                std::lock_guard<std::mutex> lock(hitsMu);
                options.onProgress(t, total, static_cast<unsigned>(hits.size()));
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (unsigned w = 0; w < workers; ++w) {
        threads.emplace_back(worker);
    }
    for (auto& th : threads) th.join();

    std::sort(hits.begin(), hits.end(),
              [](const PortCandidate& a, const PortCandidate& b) { return a.port < b.port; });
    return hits;
}

} // namespace t2::discovery

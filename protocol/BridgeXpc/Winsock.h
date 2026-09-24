// SPDX-License-Identifier: GPL-2.0-only
// Winsock.h - process-wide, idempotent WSAStartup for the protocol library.
//
// Every code path that creates a socket (BridgeXpc::Connection::Connect,
// Discovery::RemoteXpcConnection::Connect, Discovery PortScan) must call
// EnsureWinsock() first instead of relying on some other path having done it.
// Until 24.09.2026 only PortScan did, so in a fresh WUDFHost process the very
// first Connection::Connect (the cached-port fast path) failed with
// WSAGetLastError=10093 (WSANOTINITIALISED), was reported as "cached port did
// not answer", and the capture fell into a full port scan - ~4.9 s before the
// sensor was even armed, once per host process (hardware log 24.09.2026).
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mutex>

#pragma comment(lib, "Ws2_32.lib")

namespace t2 {

// Ref-counted by Winsock itself, so tools/t2touchid's own WSAStartup is harmless.
inline bool EnsureWinsock() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        WSADATA wsa{};
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    });
    return ok;
}

} // namespace t2
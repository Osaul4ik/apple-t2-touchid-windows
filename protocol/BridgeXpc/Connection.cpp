// SPDX-License-Identifier: GPL-2.0-only
// Connection.cpp
#include "Connection.h"
#include <atomic>
#include "Log.h"
#include "TransportMode.h"
#include "Winsock.h"
#include <ws2tcpip.h>
#include <rpc.h>
#include <cctype>
#include <climits>
#include <algorithm>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Rpcrt4.lib")

namespace t2::bridgexpc {
using t2::log::HexDump;
using t2::log::Widen;

// VERIFIED FROM SOURCE: bridge-xpc-probe.py generates a fresh
// str(uuid.uuid4()).upper() per request — every request/reply/event id in
// this file must be a real, unique UUIDv4, never a fixed placeholder.
static std::string NewRequestUuid() {
    UUID uuid;
    if (UuidCreate(&uuid) != RPC_S_OK) {
        T2_LOG("uuid", L"UuidCreate failed");
        return {}; // caller must treat an empty id as a hard failure
    }
    RPC_CSTR str = nullptr;
    if (UuidToStringA(&uuid, &str) != RPC_S_OK || !str) {
        T2_LOG("uuid", L"UuidToStringA failed");
        return {};
    }
    std::string result(reinterpret_cast<char*>(str));
    RpcStringFreeA(&str);
    for (auto& c : result) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return result;
}

Connection::~Connection() { Close(); }

void Connection::Close() {
    if (socket_ != INVALID_SOCKET) {
        T2_LOG("connect", L"disconnect: closesocket (socket was open, pendingEvents=%zu)",
               pendingEvents_.size());
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    } else {
        T2_LOG("connect", L"disconnect: already closed (pendingEvents=%zu)",
               pendingEvents_.size());
    }
    ResetRx();   // buffered bytes belong to the socket just closed
    // Defensive only: this class is one-connection-per-verification-attempt
    // (see the class comment) and is expected to be discarded after Close(),
    // never reused, so there should be no queued events left to leak into a
    // next session. Clearing anyway costs nothing and removes any doubt.
    pendingEvents_.clear();
}

static bool SetSocketTimeout(SOCKET s, int optname, std::chrono::milliseconds timeout) {
    // A zero value disables SO_RCVTIMEO/SO_SNDTIMEO on Windows.
    // Never permit a non-positive or overflowing deadline to turn I/O unbounded.
    if (timeout.count() <= 0 || timeout.count() > 0xFFFFFFFFLL) return false;
    DWORD ms = static_cast<DWORD>(timeout.count());
    return setsockopt(s, SOL_SOCKET, optname, reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0;
}

// BUG FIX (v6/v4 fallback work): SO_RCVTIMEO/SO_SNDTIMEO, set right after
// socket() below, do NOT bound connect() itself on Windows - they only
// govern send()/recv() on an already-established socket. A plain blocking
// connect() is instead bounded by the OS's own TCP connect timeout (several
// seconds), so a link that accepts the SYN but never completes the
// handshake (or a WFP/firewall rule that silently drops it) used to hang
// past `connectTimeout` entirely before HELO's own timeout even started.
// This puts the socket in non-blocking mode for the handshake only, then
// restores blocking mode before returning - callers get an ordinary
// blocking socket either way, just with a real, enforced connect deadline.
static bool ConnectWithTimeout(SOCKET s, const sockaddr* addr, int addrlen,
                                std::chrono::milliseconds timeout,
                                int* outWsaError = nullptr) {
    // outWsaError (optional): 0 on success, WSAETIMEDOUT when nothing came
    // back within `timeout`, otherwise the real socket error (SO_ERROR or
    // the immediate connect() failure). Callers that must tell "the SYN got
    // an RST back" (WSAECONNREFUSED - the path WORKS, only the port is dead)
    // apart from "the SYN vanished" (timeout - path broken) need this; a
    // bare bool collapses both into false.
    if (outWsaError) *outWsaError = 0;
    if (timeout.count() <= 0) {
        if (outWsaError) *outWsaError = WSAETIMEDOUT;
        return false;
    }
    u_long nonBlocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        if (outWsaError) *outWsaError = WSAGetLastError();
        return false;
    }
    bool ok = false;
    const int rc = connect(s, addr, addrlen);
    if (rc == 0) {
        ok = true;
    } else if (WSAGetLastError() != WSAEWOULDBLOCK) {
        if (outWsaError) *outWsaError = WSAGetLastError(); // immediate failure
    } else {
        fd_set writeSet, errSet;
        FD_ZERO(&writeSet);
        FD_ZERO(&errSet);
        FD_SET(s, &writeSet);
        FD_SET(s, &errSet);
        timeval tv{};
        tv.tv_sec = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
        const int sel = select(0, nullptr, &writeSet, &errSet, &tv);
        if (sel > 0) {
            int err = 0;
            int errLen = sizeof(err);
            const bool haveErr =
                getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errLen) == 0;
            ok = haveErr && err == 0 && FD_ISSET(s, &writeSet) && !FD_ISSET(s, &errSet);
            if (!ok && outWsaError) *outWsaError = haveErr && err != 0 ? err : WSAECONNABORTED;
        } else if (outWsaError) {
            *outWsaError = sel == 0 ? WSAETIMEDOUT : WSAGetLastError();
        }
    }
    u_long blocking = 0;
    if (ioctlsocket(s, FIONBIO, &blocking) != 0) {
        // A connected nonblocking socket cannot safely be passed to
        // synchronous WriteFrame/ReadFrame, which rely on socket timeouts.
        const int restoreError = WSAGetLastError();
        if (outWsaError) *outWsaError = restoreError;
        return false;
    }
    return ok;
}

// Latency tuning for the established BridgeXPC socket (both NativeIpv6 and
// the Ipv4 tunnel). BridgeXPC is a request/response protocol made of many
// small frames, which is the worst case for two Windows TCP defaults:
//  * Nagle: WriteFrame used to send the 16-byte header and the body as two
//    separate send() calls. The second (small) send is held back until the
//    first is ACKed, and the T2 delays that ACK (~40 ms) -> +40 ms/command.
//  * Delayed ACK: Windows waits up to 200 ms before ACKing a lone segment,
//    which stalls a peer that itself writes header+body separately.
// TCP_NODELAY + an ACK frequency of 1 remove both. Every step is
// best-effort: a failure only means the old (slower) behaviour.
#ifndef SIO_TCP_SET_ACK_FREQUENCY
#define SIO_TCP_SET_ACK_FREQUENCY _WSAIOW(IOC_VENDOR, 23)
#endif
static void TuneEstablishedSocket(SOCKET s) {
    BOOL nodelay = TRUE;
    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)) != 0) {
        T2_LOG("connect", L"TCP_NODELAY failed WSA=%d (continuing)", WSAGetLastError());
    }
    DWORD ackFreq = 1;
    DWORD bytes = 0;
    if (WSAIoctl(s, SIO_TCP_SET_ACK_FREQUENCY, &ackFreq, sizeof(ackFreq),
                 nullptr, 0, &bytes, nullptr, nullptr) != 0) {
        // Needs Windows 10 1809+; older builds just keep delayed ACK.
        T2_LOG("connect", L"SIO_TCP_SET_ACK_FREQUENCY failed WSA=%d (continuing)",
               WSAGetLastError());
    }
}

// Narrow, bounded extraction of one integer field from the peer's HELO
// JSON - e.g. {"MaxSupportedProtocolVersion":1,"OSBuild":"...",
// "BridgeXPCVersion":39,"ProcessName":"..."}. This is deliberately not a
// general JSON parser (same "only the narrow shapes we need" philosophy as
// PlistPayload.h): it looks for "<key>" followed by : and reads the
// unsigned decimal digits that follow, whitespace-tolerant, and fails
// closed (returns false) on anything else - missing key, non-numeric
// value, or a value so large it can't be an actual BridgeXPCVersion.
static bool ExtractJsonIntField(const std::string& json, const std::string& key, int64_t* out) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();
    pos = json.find(':', pos);
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    size_t start = pos;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') ++pos;
    if (pos == start) return false; // no digits found
    int64_t value = 0;
    for (size_t i = start; i < pos; ++i) {
        value = value * 10 + (json[i] - '0');
        if (value > 0xFFFFFF) return false; // implausible for a protocol version, fail closed
    }
    *out = value;
    return true;
}

// Builds this client's own HELO body. VERIFIED FROM SOURCE
// (t2_bridge_wire.py send_helo(), matching docs/linux-reference-analysis.md
// line 187): the client sends its OWN HELO - MaxSupportedProtocolVersion,
// its own OSBuild/ProcessName - reusing only the peer's BridgeXPCVersion.
// Field order and separator style (no spaces, matching Python's
// separators=(",", ":")) mirror the reference exactly even though this is
// JSON and a real parser wouldn't care about either - no reason to differ
// from a verified-working format.
//
// 17.09.2026: OSBuild/ProcessName literals changed from "Windows"/
// "t2touchid" to the EXACT literals the real, proven-working Linux client
// sends (t2_bridge_wire.py send_helo() body + T2Backend._run_probe()'s
// hardcoded ProcessName="t2-touchid-probe" - VERIFIED FROM SOURCE, not
// guessed). Rationale: every other pre-StartMatch field/command/reply this
// project sends has now been independently cross-checked against the
// reference's real runtime path and matches byte-for-byte (see
// docs/linux-reference-analysis.md, EP7-TRANSPORT-ANALYSIS.md); this HELO
// body was the one remaining place the client told bridgeOS/SEP something
// the working reference never says. Not confirmed to be the root cause -
// pure string change, zero wire-shape/parsing impact, cheap to test and
// easy to revert if the next hardware capture shows no difference.
static std::vector<uint8_t> BuildClientHeloBody(int64_t bridgeXpcVersion) {
    std::string json = "{\"MaxSupportedProtocolVersion\":1,\"OSBuild\":\"Linux\","
                        "\"BridgeXPCVersion\":" + std::to_string(bridgeXpcVersion) +
                        ",\"ProcessName\":\"t2-touchid-probe\"}";
    return std::vector<uint8_t>(json.begin(), json.end());
}

static std::chrono::milliseconds RemainingBudget(std::chrono::steady_clock::time_point end);

// One transport attempt (no fallback logic). `tcpTimeout` bounds only the TCP
// handshake; `heloTimeout` bounds the HELO exchange and the established
// socket's later send/recv defaults. *outTcpFailed is set when the handshake
// itself did not complete (the only failure that says "this path is dead" -
// a HELO problem means the path works), *outTcpMs is the handshake time.
ConnectResult Connection::ConnectOnce(bool tunnel, const in6_addr& linkLocalAddress,
                                      unsigned long interfaceIndex, uint16_t port,
                                      std::chrono::milliseconds tcpTimeout,
                                      std::chrono::milliseconds heloTimeout,
                                      bool* outTcpFailed, ULONGLONG* outTcpMs,
                                      t2::transport::PathEvidence* outEvidence,
                                      const std::chrono::steady_clock::time_point* overallDeadline) {
    *outTcpFailed = false;
    *outTcpMs = 0;
    t2::transport::PathEvidence evidenceLocal = t2::transport::PathEvidence::Silent;
    t2::transport::PathEvidence& evidence = outEvidence ? *outEvidence : evidenceLocal;
    evidence = t2::transport::PathEvidence::Silent;
    t2::transport::PushTransportModeToDriver(
        tunnel ? t2::transport::TransportMode::Ipv4Tunnel
               : t2::transport::TransportMode::NativeIpv6);

    // Bound TCP plus tunnel preparation by the caller's overall deadline.
    const auto tcpStartTime = std::chrono::steady_clock::now();
    auto tcpDeadline = tcpStartTime + tcpTimeout;
    if (overallDeadline && *overallDeadline < tcpDeadline) tcpDeadline = *overallDeadline;
    if (tcpDeadline <= tcpStartTime) return ConnectResult::ConnectFailed;
    const ULONGLONG tcpStart = GetTickCount64();
    int wsa = 0;
    if (tunnel) {
        const t2::transport::TunnelPrep prep =
            t2::transport::PrepareTunnelPeer(interfaceIndex, linkLocalAddress);
        if (prep == t2::transport::TunnelPrep::NoMac || prep == t2::transport::TunnelPrep::NoPeer) {
            // LocalError (section 4): without a peer MAC the static ARP row cannot be
            // set, so the SYN would just die after the full TCP timeout. That says
            // nothing about the T2 - do not burn the budget and do not count a
            // tunnel failure; the caller re-resolves the peer.
            T2_LOG("connect", L"Ipv4Tunnel not attemptable (%s) - LocalError",
                   prep == t2::transport::TunnelPrep::NoMac ? L"no peer MAC" : L"no peer");
            evidence = t2::transport::PathEvidence::LocalError;
            return ConnectResult::ConnectFailed;
        }
        // Tunnel preparation may perform synchronous neighbor/driver operations.
        // Do not start TCP when that work has already exhausted this attempt's budget.
        // Treat it as local preparation exhaustion, not evidence of a dead T2 path.
        if (RemainingBudget(tcpDeadline).count() <= 0) {
            T2_LOG("connect", L"Ipv4Tunnel preparation exhausted TCP budget before socket creation");
            evidence = t2::transport::PathEvidence::LocalError;
            return ConnectResult::ConnectFailed;
        }
        const in_addr peer4 = t2::transport::MapPeerToIpv4(linkLocalAddress);
        socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_ == INVALID_SOCKET) {
            T2_LOG("connect", L"socket(AF_INET) failed, WSAGetLastError=%d", WSAGetLastError());
            evidence = t2::transport::PathEvidence::LocalError;
            return ConnectResult::ConnectFailed;
        }
        DWORD ifIndexNet = htonl(static_cast<DWORD>(interfaceIndex));
        if (setsockopt(socket_, IPPROTO_IP, IP_UNICAST_IF,
                       reinterpret_cast<const char*>(&ifIndexNet), sizeof(ifIndexNet)) != 0) {
            T2_LOG("connect", L"IP_UNICAST_IF ifIndex=%lu failed WSA=%d (continuing)",
                   interfaceIndex, WSAGetLastError());
        }
        sockaddr_in addr4{};
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        addr4.sin_addr = peer4;
        T2_LOG("connect", L"Ipv4Tunnel peer %u.%u.%u.%u:%u ifIndex=%lu",
               peer4.S_un.S_un_b.s_b1, peer4.S_un.S_un_b.s_b2,
               peer4.S_un.S_un_b.s_b3, peer4.S_un.S_un_b.s_b4,
               static_cast<unsigned>(port), interfaceIndex);
        if (!ConnectWithTimeout(socket_, reinterpret_cast<sockaddr*>(&addr4), sizeof(addr4),
                                RemainingBudget(tcpDeadline), &wsa)) {
            T2_LOG("connect", L"connect(AF_INET) failed WSA=%d (%llu ms)", wsa,
                   static_cast<unsigned long long>(GetTickCount64() - tcpStart));
            Close();
            evidence = t2::transport::ClassifyWsaError(wsa);
            if (wsa == WSAECONNREFUSED) {
                // RST from the T2 (rewritten back by T2Ncm.sys): the tunnel path
                // WORKS, only this port is dead (e.g. a port cached from an
                // earlier boot). Not a transport failure - see the native branch.
                *outTcpMs = GetTickCount64() - tcpStart;
                return ConnectResult::ConnectFailed;
            }
            t2::transport::InvalidateTunnelPrepCache(); // re-prepare neighbor/peer next time
            *outTcpFailed = true; // the handshake did not complete on this transport (evidence says why)
            return ConnectResult::ConnectFailed;
        }
    } else {
        socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (socket_ == INVALID_SOCKET) {
            T2_LOG("connect", L"socket(AF_INET6) failed, WSAGetLastError=%d", WSAGetLastError());
            evidence = t2::transport::PathEvidence::LocalError;
            return ConnectResult::ConnectFailed;
        }
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        addr.sin6_addr = linkLocalAddress;
        addr.sin6_scope_id = interfaceIndex;
        T2_LOG("connect", L"NativeIpv6 ifIndex=%lu port=%u (tcp budget %lld ms)",
               interfaceIndex, static_cast<unsigned>(port),
               static_cast<long long>(tcpTimeout.count()));
        if (!ConnectWithTimeout(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                                RemainingBudget(tcpDeadline), &wsa)) {
            T2_LOG("connect", L"connect(AF_INET6) failed WSA=%d (%llu ms)", wsa,
                   static_cast<unsigned long long>(GetTickCount64() - tcpStart));
            Close();
            evidence = t2::transport::ClassifyWsaError(wsa);
            if (wsa == WSAECONNREFUSED) {
                // RST from the T2: the SYN got there and back, so native IPv6
                // WORKS and only this port is dead (a stale cached port after a
                // T2/boot change). Treating it as "transport dead" made Connect()
                // needlessly flip to the tunnel (IOCTLs, ARP prep, a driver left in
                // tunnel mode) on every stale-port try. ConnectWithTimeout exists
                // to make exactly this distinction; *outTcpFailed stays false.
                *outTcpMs = GetTickCount64() - tcpStart;
                return ConnectResult::ConnectFailed;
            }
            *outTcpFailed = true; // the handshake did not complete on this transport (evidence says why)
            return ConnectResult::ConnectFailed;
        }
    }
    evidence = t2::transport::PathEvidence::Positive; // handshake completed
    *outTcpMs = GetTickCount64() - tcpStart;
    TuneEstablishedSocket(socket_);
    if (overallDeadline) {
        heloTimeout = (std::min)(heloTimeout, RemainingBudget(*overallDeadline));
        if (heloTimeout.count() <= 0) {
            Close();
            return ConnectResult::HeloTimeout;
        }
    }
    if (!SetSocketTimeout(socket_, SO_RCVTIMEO, heloTimeout) ||
        !SetSocketTimeout(socket_, SO_SNDTIMEO, heloTimeout)) {
        T2_LOG("connect", L"unable to configure bounded HELO socket I/O (WSA=%d)",
               WSAGetLastError());
        Close();
        return ConnectResult::ConnectFailed;
    }
    ResetRx();   // new stream: no buffered bytes
    rcvTimeoutMs_ = static_cast<DWORD>(heloTimeout.count());   // what was just set
    T2_LOG("connect", L"TCP connected (%s): ifIndex=%lu port=%u, %llu ms (waiting for peer HELO)",
           tunnel ? L"IPv4 tunnel" : L"Native IPv6", interfaceIndex,
           static_cast<unsigned>(port), static_cast<unsigned long long>(*outTcpMs));

    auto heloDeadline = std::chrono::steady_clock::now() + heloTimeout;
    if (overallDeadline && *overallDeadline < heloDeadline) heloDeadline = *overallDeadline;
    RawFrame helo;
    if (!ReadFrame(&helo, RemainingBudget(heloDeadline)) || helo.type != FrameType::Helo) {
        T2_LOG("connect", L"HELO read failed or wrong frame type "
               "(connected=true, timeout=%lldms)", static_cast<long long>(heloTimeout.count()));
        if (tunnel) t2::transport::InvalidateTunnelPrepCache();
        Close();
        return ConnectResult::HeloTimeout;
    }
    T2_LOG("connect", L"peer HELO received, %zu bytes: %s",
           helo.body.size(), HexDump(helo.body, 96).c_str());

    // The client replies with its OWN HELO (only the peer's BridgeXPCVersion
    // is reused), not an echo of the peer's - see BuildClientHeloBody.
    std::string peerHeloJson(helo.body.begin(), helo.body.end());
    int64_t bridgeXpcVersion = 0;
    if (!ExtractJsonIntField(peerHeloJson, "BridgeXPCVersion", &bridgeXpcVersion)) {
        T2_LOG("connect", L"BridgeXPCVersion missing/unparseable in peer HELO: %s",
               Widen(peerHeloJson).c_str());
        Close();
        return ConnectResult::HeloMalformed;
    }
    std::vector<uint8_t> ownHelo = BuildClientHeloBody(bridgeXpcVersion);
    if (std::chrono::steady_clock::now() >= heloDeadline ||
        !WriteFrame(FrameType::Helo, ownHelo, RemainingBudget(heloDeadline))) {
        T2_LOG("connect", L"writing own HELO failed, WSAGetLastError=%d", WSAGetLastError());
        Close();
        return ConnectResult::HeloMalformed;
    }
    T2_LOG("connect", L"handshake OK, BridgeXPCVersion=%lld", static_cast<long long>(bridgeXpcVersion));
    return ConnectResult::Ok;
}

// Explicit-transport entry point for the TransportManager (see Connection.h).
// No fallback, no re-probe: the caller decides which transport to try and holds
// the TransportPhase. A completed native handshake still feeds the adaptive
// budget (RecordNativeSuccess), exactly like Connect().
ConnectResult Connection::ConnectVia(bool tunnel, const in6_addr& linkLocalAddress,
                                     unsigned long interfaceIndex, uint16_t port,
                                     std::chrono::milliseconds tcpTimeout,
                                     std::chrono::milliseconds heloTimeout,
                                     t2::transport::PathEvidence* outEvidence,
                                     ULONGLONG* outTcpMs) {
    if (outEvidence) *outEvidence = t2::transport::PathEvidence::LocalError;
    if (outTcpMs) *outTcpMs = 0;
    if (!t2::EnsureWinsock()) {
        T2_LOG("connect", L"EnsureWinsock failed - cannot create sockets");
        return ConnectResult::ConnectFailed;
    }
    connectionLost_.store(false);
    bool tcpFailed = false;
    ULONGLONG tcpMs = 0;
    t2::transport::PathEvidence ev = t2::transport::PathEvidence::Silent;
    const ConnectResult r = ConnectOnce(tunnel, linkLocalAddress, interfaceIndex, port,
                                        tcpTimeout, heloTimeout, &tcpFailed, &tcpMs, &ev);
    if (outEvidence) *outEvidence = ev;
    if (outTcpMs) *outTcpMs = tcpMs;
    return r;
}

// Entry point. Transport policy lives in TransportMode.h (read its header
// comment first). In short:
//  * auto-switch OFF               -> native IPv6 only;
//  * auto-switch ON (default)      -> start on Native IPv6 (short adaptive TCP budget,
//    NativeConnectBudget); a TCP-level failure immediately retries over the IPv4
//    tunnel within this same call. A SUCCESSFUL switch is sticky until reboot:
//    there is no way back to native IPv6, and no manual force.
ConnectResult Connection::Connect(const in6_addr& linkLocalAddress, unsigned long interfaceIndex,
                                  uint16_t port, std::chrono::milliseconds connectTimeout) {
    // Fresh WUDFHost has no prior WSAStartup. Without this the first
    // cached-port Connect fails with 10093 (WSANOTINITIALISED), is logged
    // as "cached port did not answer", and cold-boot CAPTURE falls into a
    // full scan or a flaky retry — sensor never arms for the first touch.
    if (!t2::EnsureWinsock()) {
        T2_LOG("connect", L"EnsureWinsock failed - cannot create sockets");
        return ConnectResult::ConnectFailed;
    }
    if (connectTimeout.count() <= 0) return ConnectResult::ConnectFailed;
    const auto overallDeadline = std::chrono::steady_clock::now() + connectTimeout;
    auto remaining = [&]() -> std::chrono::milliseconds {
        const auto now = std::chrono::steady_clock::now();
        if (now >= overallDeadline) return std::chrono::milliseconds(0);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(overallDeadline - now);
        return ms.count() ? ms : std::chrono::milliseconds(1);
    };
    namespace tp = t2::transport;
    connectionLost_.store(false);

    const bool autoSwitch = tp::IsAutoSwitchEnabled();
    if (!autoSwitch && tp::IsAutoTunnelCommitted()) tp::CommitAutoTunnel(false); // auto-switch turned off
    bool tunnel = tp::IsTunnelModeActive();
    const std::chrono::milliseconds firstTcp =
        (autoSwitch && !tunnel) ? tp::NativeConnectBudget(connectTimeout) : connectTimeout;
    const auto firstBudget = (std::min)(firstTcp, remaining());
    if (firstBudget.count() <= 0) return ConnectResult::ConnectFailed;
    bool tcpFailed = false;
    ULONGLONG tcpMs = 0;
    tp::PathEvidence ev1 = tp::PathEvidence::Silent;
    const ULONGLONG t0 = GetTickCount64();
    ConnectResult r = ConnectOnce(tunnel, linkLocalAddress, interfaceIndex, port,
                                  firstBudget, connectTimeout, &tcpFailed, &tcpMs, &ev1,
                                  &overallDeadline);
    // LocalError (no peer MAC for the tunnel, socket() failure) is "cannot try this
    // transport", not "the transport answered": still worth the other one.
    if (!tcpFailed && ev1 != tp::PathEvidence::LocalError) {
        if (!tunnel) tp::RecordNativeSuccess(tcpMs); // path works -> clears auto-tunnel
        return r;                                     // Ok, or a HELO-level problem (no switch)
    }
    // Sticky tunnel: once committed there is no way back to native IPv6 before reboot.
    if (!autoSwitch || (tunnel && tp::IsAutoTunnelCommitted())) return r;

    // TCP handshake did not complete: this transport is dead right now. Try
    // the other one immediately. Tunnel handshakes get a floor because the
    // ARP/peer prep is part of them; native ones use the adaptive budget.
    if (remaining().count() <= 0) return r;
    const bool other = !tunnel;
    long long fbMs = connectTimeout.count();
    if (other) {
        if (fbMs > 800) fbMs = 800;
        if (fbMs < 300) fbMs = 300;
    }
    const std::chrono::milliseconds fallbackTcp =
        other ? std::chrono::milliseconds(fbMs) : tp::NativeConnectBudget(connectTimeout);
    const auto fallbackBudget = (std::min)(fallbackTcp, remaining());
    if (fallbackBudget.count() <= 0) return r;
    bool tcpFailed2 = false;
    ULONGLONG tcpMs2 = 0;
    tp::PathEvidence ev2 = tp::PathEvidence::Silent;
    ConnectResult r2 = ConnectOnce(other, linkLocalAddress, interfaceIndex, port,
                                   fallbackBudget, connectTimeout, &tcpFailed2, &tcpMs2, &ev2,
                                   &overallDeadline);
    if (!tcpFailed2 && ev2 != tp::PathEvidence::LocalError) {
        if (other) tp::CommitAutoTunnel(true);
        else       tp::RecordNativeSuccess(tcpMs2);
        T2_LOG("connect", L"auto-switch: %s -> %s after %llu ms (%s)",
               tunnel ? L"IPv4 tunnel" : L"Native IPv6", other ? L"IPv4 tunnel" : L"Native IPv6",
               static_cast<unsigned long long>(GetTickCount64() - t0),
               r2 == ConnectResult::Ok ? L"connected" : L"TCP ok, HELO failed");
        return r2;
    }
    // Both transports failed at TCP level: the T2 is probably not ready.
    // State is left untouched (nothing was committed) so the caller's retry
    // loop simply starts over with the same bounded attempts.
    T2_LOG("connect", L"auto-switch: both transports failed at TCP level (%llu ms)",
           static_cast<unsigned long long>(GetTickCount64() - t0));
    return r;
}


// One deadline shared by the write and the subsequent reply wait.
// Round a positive sub-millisecond remainder up rather than accidentally
// passing zero (which disables Winsock socket timeouts).
static std::chrono::milliseconds RemainingBudget(std::chrono::steady_clock::time_point end) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= end) return std::chrono::milliseconds(0);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - now);
    return ms.count() ? ms : std::chrono::milliseconds(1);
}

bool Connection::ReadUntilMatchingReply(const std::string& expectedReqId,
                                        MessageEnvelope* outEnv,
                                        std::chrono::steady_clock::time_point deadline,
                                        const wchar_t* logTag) {
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            ::t2::log::Logf(logTag, L"deadline reached waiting for reply (reqId=%s)",
                   Widen(expectedReqId).c_str());
            return false;
        }
        auto remaining = RemainingBudget(deadline);

        RawFrame frame;
        if (!ReadFrame(&frame, remaining)) {
            ::t2::log::Logf(logTag, L"ReadFrame failed/timed out (reqId=%s, %lldms remained)",
                   Widen(expectedReqId).c_str(), static_cast<long long>(remaining.count()));
            return false;
        }
        if (frame.type != FrameType::Message) {
            continue;
        }

        auto env = ParseMessageBody(frame.body);
        if (!env) {
            ::t2::log::Logf(logTag, L"ParseMessageBody failed, body=%zuB %s",
                   frame.body.size(), HexDump(frame.body).c_str());
            return false;
        }

        if (!env->isReply) {
            ::t2::log::Logf(logTag, L"async event while waiting for reply (reqId=%s), event reqId=%s "
                   L"payload=%zuB - acking and queuing",
                   Widen(expectedReqId).c_str(), Widen(env->requestId).c_str(),
                   env->payloadPlist.size());
            if (!AcknowledgeEvent(env->requestId, RemainingBudget(deadline))) {
                ::t2::log::Logf(logTag, L"AcknowledgeEvent failed for event reqId=%s",
                       Widen(env->requestId).c_str());
                return false;
            }
            pendingEvents_.push_back(std::move(env->payloadPlist));
            continue;
        }

        if (env->requestId != expectedReqId) {
            ::t2::log::Logf(logTag, L"ignoring stray reply (expected=%s got=%s)",
                   Widen(expectedReqId).c_str(), Widen(env->requestId).c_str());
            continue;
        }

        *outEnv = std::move(*env);
        return true;
    }
}

bool Connection::GetBridgeVersion(int64_t* outVersion, std::chrono::milliseconds timeout) {
    // Include mutex contention in the operation budget, not only wire I/O.
    const auto operationDeadline = std::chrono::steady_clock::now() + timeout;
    IoLock ioLock(*this, timeout);
    if (!ioLock.owns()) {
        T2_LOG("io", L"could not acquire connection I/O lock within %lldms",
               static_cast<long long>((timeout).count()));
        return false;
    }
    if (RemainingBudget(operationDeadline).count() <= 0) {
        T2_LOG("io", L"operation deadline expired while acquiring I/O lock");
        return false;
    }
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {0});
    if (!WriteFrame(FrameType::Message, req, RemainingBudget(operationDeadline))) {
        T2_LOG("getBridgeVersion", L"WriteFrame failed, WSAGetLastError=%d", WSAGetLastError());
        return false;
    }

    // Same event-before-reply loop as SendBiometricCommand (ACK+queue).
    MessageEnvelope env;
    if (!ReadUntilMatchingReply(reqId, &env, operationDeadline, L"getBridgeVersion")) {
        return false;
    }

    // VERIFIED FROM SOURCE: getBridgeVersion reply is [0, api_version];
    // Apple's own client rejects any other shape ("getBridgeVersion
    // failed") rather than guessing, and so do we.
    auto ints = DecodeIntArrayPayload(env.payloadPlist);
    if (!ints || ints->size() != 2 || (*ints)[0] != 0) {
        T2_LOG("getBridgeVersion", L"unexpected payload shape, %zuB %s",
               env.payloadPlist.size(), HexDump(env.payloadPlist).c_str());
        return false;
    }
    *outVersion = (*ints)[1];
    T2_LOG("getBridgeVersion", L"OK, bridge api_version=%lld", static_cast<long long>(*outVersion));
    return true;
}

bool Connection::SetClientVersion(int64_t version, std::chrono::milliseconds timeout) {
    // Include mutex contention in the operation budget, not only wire I/O.
    const auto operationDeadline = std::chrono::steady_clock::now() + timeout;
    IoLock ioLock(*this, timeout);
    if (!ioLock.owns()) {
        T2_LOG("io", L"could not acquire connection I/O lock within %lldms",
               static_cast<long long>((timeout).count()));
        return false;
    }
    if (RemainingBudget(operationDeadline).count() <= 0) {
        T2_LOG("io", L"operation deadline expired while acquiring I/O lock");
        return false;
    }
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {10, version});
    if (!WriteFrame(FrameType::Message, req, RemainingBudget(operationDeadline))) {
        T2_LOG("setClientVersion", L"WriteFrame failed, WSAGetLastError=%d", WSAGetLastError());
        return false;
    }

    MessageEnvelope env;
    if (!ReadUntilMatchingReply(reqId, &env, operationDeadline, L"setClientVersion")) {
        return false;
    }

    T2_LOG("setClientVersion", L"OK, negotiated=%lld", static_cast<long long>(version));
    return true;
}

bool Connection::SendBiometricCommand(const std::vector<uint8_t>& innerBmMessage,
                                       uint32_t outputCapacity,
                                       std::vector<uint8_t>* outReply,
                                       std::chrono::milliseconds timeout,
                                       int64_t* outCommandStatus) {
    // Include mutex contention in the operation budget, not only wire I/O.
    const auto operationDeadline = std::chrono::steady_clock::now() + timeout;
    IoLock ioLock(*this, timeout);
    if (!ioLock.owns()) {
        T2_LOG("sendBiometricCommand", L"could not acquire connection I/O lock within %lldms",
               static_cast<long long>(timeout.count()));
        return false;
    }
    if (outCommandStatus) *outCommandStatus = 0;
    if (RemainingBudget(operationDeadline).count() <= 0) {
        T2_LOG("io", L"operation deadline expired while acquiring I/O lock");
        return false;
    }
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    // VERIFIED FROM SOURCE: outer payload is exactly
    // [3, 0, innerBmBytes, outputCapacity] — outputCapacity is a real,
    // load-bearing field (it tells bkremoted how large a reply buffer to
    // fill), not a value the caller can silently drop.
    auto req = EncodeRequestEnvelope(reqId, {3, 0}, &innerBmMessage,
                                      {static_cast<int64_t>(outputCapacity)});
    T2_LOG("sendBiometricCommand",
           L"-> reqId=%s inner=%zuB (%s) outputCapacity=%u timeout=%lldms",
           Widen(reqId).c_str(), innerBmMessage.size(),
           HexDump(innerBmMessage, 8).c_str(), outputCapacity,
           static_cast<long long>(timeout.count()));

    if (!WriteFrame(FrameType::Message, req, RemainingBudget(operationDeadline))) {
        T2_LOG("sendBiometricCommand", L"WriteFrame failed, WSAGetLastError=%d, "
               "outer envelope was %zuB", WSAGetLastError(), req.size());
        return false;
    }

    // bkremoted can push an async, non-reply event (isReply=false, e.g. a
    // serviceStatus callback shaped [9, status, data, x, x] — see
    // PlistPayload.h's DecodeStatusEventData) ahead of a command's real
    // reply, exactly the way Connection::WaitForEvent already expects
    // during a match session. A single ReadFrame here used to assume the
    // very next frame WAS the reply and fail as soon as an event arrived
    // first — confirmed live: load-calibration's real reply was preceded
    // by one such event. Loop, acknowledging (and discarding, same as
    // WaitForEvent) anything that isn't our reply, until either the
    // matching reply arrives or the deadline passes.
    auto deadline = operationDeadline;
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            T2_LOG("sendBiometricCommand", L"deadline reached waiting for reply "
                   "(reqId=%s, timeout=%lldms)", Widen(reqId).c_str(),
                   static_cast<long long>(timeout.count()));
            return false;
        }
        auto remaining = RemainingBudget(deadline);

        RawFrame reply;
        if (!ReadFrame(&reply, remaining)) {
            T2_LOG("sendBiometricCommand", L"ReadFrame failed/timed out (reqId=%s, "
                   "%lldms remained) - WSAGetLastError=%d",
                   Widen(reqId).c_str(), static_cast<long long>(remaining.count()),
                   WSAGetLastError());
            return false;
        }
        if (reply.type != FrameType::Message) {
            T2_LOG("sendBiometricCommand", L"unexpected frame type %u (reqId=%s), "
                   "expected Message(%u) - ignoring, keep waiting",
                   static_cast<unsigned>(reply.type), Widen(reqId).c_str(),
                   static_cast<unsigned>(FrameType::Message));
            continue;
        }

        auto env = ParseMessageBody(reply.body);
        if (!env) {
            T2_LOG("sendBiometricCommand", L"ParseMessageBody failed (reqId=%s), "
                   "body=%zuB %s", Widen(reqId).c_str(), reply.body.size(),
                   HexDump(reply.body).c_str());
            return false; // malformed -> fail closed, do not keep guessing
        }

        if (!env->isReply) {
            // Async bridge-side callback: ack it (same contract as
            // WaitForEvent) and keep waiting for the actual reply. A
            // wider dump cap than the 32B default (see the matching note
            // on WaitForEvent below) so status/statistics events (the
            // ones seen here in practice, 131-167B) print in full instead
            // of "..."-truncated at a third of their length.
            T2_LOG("sendBiometricCommand", L"async event while waiting for reply "
                   "(reqId=%s), event reqId=%s payload=%zuB %s - acking and queuing",
                   Widen(reqId).c_str(), Widen(env->requestId).c_str(),
                   env->payloadPlist.size(), HexDump(env->payloadPlist, 512).c_str());
            if (!AcknowledgeEvent(env->requestId, RemainingBudget(deadline))) {
                T2_LOG("sendBiometricCommand", L"AcknowledgeEvent failed for "
                       "event reqId=%s", Widen(env->requestId).c_str());
                return false;
            }
            // LINUX PARITY FIX: the Linux reference (t2_bridge_wire.py's
            // request_with_events(), which biometric_command() wraps
            // directly) does not discard events seen while waiting for a
            // command reply - it appends them to a list and hands that
            // list back to the caller alongside the reply. Dropping them
            // here (as this used to do) silently loses any status,
            // statistics, or match_result event that happens to race a
            // command's reply - e.g. StartMatch's own reply - which is
            // exactly the failure mode WaitForEvent's caller
            // (VerificationEngine::Verify) cannot see or recover from.
            // Retain in pendingEvents_ (already acked, per protocol) so
            // WaitForEvent() can still deliver it to the match-session
            // loop in receipt order.
            pendingEvents_.push_back(std::move(env->payloadPlist));
            continue;
        }

        if (env->requestId != reqId) {
            // A stray reply to something we're not waiting on (e.g. a
            // best-effort command whose caller didn't read its reply):
            // ignore, keep looping — same as WaitForEvent.
            T2_LOG("sendBiometricCommand", L"ignoring stray reply, sent=%s got=%s",
                   Widen(reqId).c_str(), Widen(env->requestId).c_str());
            continue;
        }

        // env->payloadPlist is still one level wrapped: every BM command
        // reply's outer payload is [status, blob] (VERIFIED LIVE — see
        // PlistPayload.h's DecodeStatusBlobPayload comment). Callers
        // (ParseIdentityList and StartMatch's command-status inspection)
        // need the unwrapped status/blob values, not this bplist-encoded array —
        // that mismatch, not the async-event issue above, is why
        // identity-list kept failing "not a whole number of 20-byte
        // records" even after the reply itself arrived successfully.
        auto statusBlob = DecodeStatusBlobPayload(env->payloadPlist);
        if (!statusBlob) {
            T2_LOG("sendBiometricCommand", L"payload isn't the expected "
                   "[status, blob] shape (reqId=%s), %zuB %s",
                   Widen(reqId).c_str(), env->payloadPlist.size(),
                   HexDump(env->payloadPlist).c_str());
            return false;
        }
        if (outCommandStatus) *outCommandStatus = statusBlob->status;
        if (statusBlob->status != 0) {
            if (outCommandStatus) {
                *outReply = std::move(statusBlob->blob);
                T2_LOG("sendBiometricCommand", L"command returned status=%lld (reqId=%s); "
                       L"returning it to caller for command-specific handling",
                       static_cast<long long>(statusBlob->status), Widen(reqId).c_str());
                return true;
            }
            T2_LOG("sendBiometricCommand", L"non-zero status=%lld (reqId=%s), "
                   "blob=%zuB %s - treating as failure",
                   static_cast<long long>(statusBlob->status), Widen(reqId).c_str(),
                   statusBlob->blob.size(), HexDump(statusBlob->blob).c_str());
            return false;
        }

        *outReply = std::move(statusBlob->blob);
        // Left at the 32B default deliberately, unlike the two async-event
        // dumps above: this line's blob is a generic command reply and can
        // legitimately BE the identity-list reply (cmd 0x42) - real
        // enrolled-identity UUIDs, which the rest of this project treats as
        // "opaque and never logged" (see CmdIdentities). Raising this one's
        // cap the same way would print those UUIDs in the clear under
        // --verbose.
        T2_LOG("sendBiometricCommand", L"OK, reqId=%s blob=%zuB %s",
               Widen(reqId).c_str(), outReply->size(), HexDump(*outReply).c_str());
        return true;
    }
}

bool Connection::GetFdrCalibration(std::vector<uint8_t>* outBlob, std::chrono::milliseconds timeout) {
    // Include mutex contention in the operation budget, not only wire I/O.
    const auto operationDeadline = std::chrono::steady_clock::now() + timeout;
    IoLock ioLock(*this, timeout);
    if (!ioLock.owns()) {
        T2_LOG("io", L"could not acquire connection I/O lock within %lldms",
               static_cast<long long>((timeout).count()));
        return false;
    }
    if (RemainingBudget(operationDeadline).count() <= 0) {
        T2_LOG("io", L"operation deadline expired while acquiring I/O lock");
        return false;
    }
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {11});
    if (!WriteFrame(FrameType::Message, req, RemainingBudget(operationDeadline))) {
        T2_LOG("getFdrCalibration", L"WriteFrame failed, WSAGetLastError=%d", WSAGetLastError());
        return false;
    }

    // VERIFIED FROM SOURCE: bridge-xpc-probe.py --load-calibration uses
    // request_with_events(sock, [11]), which acks async callbacks until
    // the matching reply arrives. A single ReadFrame here used to treat
    // the first frame as the reply and fail if bkremoted pushed a
    // serviceStatus event first — the same bug SendBiometricCommand
    // already fixed for BM commands.
    auto deadline = operationDeadline;
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            T2_LOG("getFdrCalibration", L"deadline reached waiting for reply "
                   "(reqId=%s, timeout=%lldms)", Widen(reqId).c_str(),
                   static_cast<long long>(timeout.count()));
            return false;
        }
        auto remaining = RemainingBudget(deadline);

        RawFrame reply;
        if (!ReadFrame(&reply, remaining)) {
            T2_LOG("getFdrCalibration", L"ReadFrame failed/timed out (reqId=%s, "
                   "%lldms remained) - WSAGetLastError=%d",
                   Widen(reqId).c_str(), static_cast<long long>(remaining.count()),
                   WSAGetLastError());
            return false;
        }
        if (reply.type != FrameType::Message) {
            T2_LOG("getFdrCalibration", L"unexpected frame type %u (reqId=%s) - ignoring",
                   static_cast<unsigned>(reply.type), Widen(reqId).c_str());
            continue;
        }

        auto env = ParseMessageBody(reply.body);
        if (!env) {
            T2_LOG("getFdrCalibration", L"ParseMessageBody failed, body=%zuB %s",
                   reply.body.size(), HexDump(reply.body).c_str());
            return false;
        }

        if (!env->isReply) {
            T2_LOG("getFdrCalibration", L"async event while waiting for reply "
                   "(reqId=%s), event reqId=%s payload=%zuB - acking and queuing",
                   Widen(reqId).c_str(), Widen(env->requestId).c_str(),
                   env->payloadPlist.size());
            if (!AcknowledgeEvent(env->requestId, RemainingBudget(deadline))) {
                T2_LOG("getFdrCalibration", L"AcknowledgeEvent failed for event reqId=%s",
                       Widen(env->requestId).c_str());
                return false;
            }
            // LINUX PARITY FIX (same rationale as SendBiometricCommand
            // below): request_with_events(sock, [11]) - the exact call
            // --load-calibration uses - returns events seen while waiting
            // for method 11's reply to the caller instead of discarding
            // them. LoadCalibration runs before StartMatch in every verify
            // session (see VerificationEngine::Verify), so any event lost
            // here is lost before the match-session event loop even
            // starts. Retain (already acked) for WaitForEvent() to drain.
            pendingEvents_.push_back(std::move(env->payloadPlist));
            continue;
        }

        if (env->requestId != reqId) {
            T2_LOG("getFdrCalibration", L"ignoring stray reply, sent=%s got=%s",
                   Widen(reqId).c_str(), Widen(env->requestId).c_str());
            continue;
        }

        auto blob = DecodeSingleBlobPayload(env->payloadPlist);
        // VERIFIED FROM SOURCE: "--load-calibration requires bridgeOS returned
        // no usable FDR calibration data" is treated as a hard failure, not an
        // empty-but-ok result — do not skip calibration on a missing blob.
        if (!blob || blob->empty()) {
            T2_LOG("getFdrCalibration", L"bridgeOS returned no usable FDR blob "
                   "(decoded=%d, size=%zu) - payload was %zuB %s",
                   blob.has_value() ? 1 : 0, blob ? blob->size() : 0,
                   env->payloadPlist.size(), HexDump(env->payloadPlist).c_str());
            return false;
        }

        *outBlob = std::move(*blob);
        T2_LOG("getFdrCalibration", L"OK, blob=%zuB", outBlob->size());
        return true;
    }
}

size_t Connection::DiscardPendingEvents(std::vector<std::vector<uint8_t>>* outDiscardedPayloads) {
    IoLock ioLock(*this, std::chrono::milliseconds(500));
    const size_t n = pendingEvents_.size();
    if (n > 0) {
        T2_LOG("discardPending",
               L"dropping %zu pre-match event(s) retained during "
               L"LoadCalibration/identity warm-up (Linux keeps these "
               L"out of the match event stream)",
               n);
        if (outDiscardedPayloads) {
            outDiscardedPayloads->assign(pendingEvents_.begin(), pendingEvents_.end());
        }
        pendingEvents_.clear();
    }
    return n;
}

// design doc §9.4: how long a signaled cancelEvent can be left unnoticed
// while WaitForEvent is blocked inside ReadFrame. Small enough that a
// CancelIoEx-driven unlock (Win+L, or LogonUI completing a password
// fallback) frees g_captureBusy (Queue.cpp) fast enough for the very next
// CAPTURE_DATA — the actual bug this is fixing — well under the second;
// large enough not to turn an idle "waiting for a finger" session into a
// busy-poll. Not tied to kCaptureMatchWindow — that one bounds the whole
// session, this one bounds cancel latency within it.
// 200ms -> 100ms: with ioMu_ a cancel sender waits for the current slice
// to end, so the slice now bounds cancel-send latency too. 10 wakeups/s
// while idle is still negligible.
static constexpr std::chrono::milliseconds kCancelPollSlice{100};

Connection::WaitStep Connection::WaitForEventStep(std::vector<uint8_t>* outEventPayload,
                                                   std::chrono::steady_clock::time_point deadline,
                                                   HANDLE cancelEvent) {
    {
        // Let a pending cancel/command sender in between slices (see ioMu_).
        if (ioWaiters_.load(std::memory_order_acquire) > 0) Sleep(1);
        IoLock ioLock(*this, kCancelPollSlice);
        if (!ioLock.owns()) return WaitStep::Again;
        // Checked at the TOP of every iteration — including before the
        // very first ReadFrame — so a cancel that arrives while this
        // socket's previous recv() was already unblocked by a real SEP
        // event (i.e. we're back here deciding whether to read again) is
        // seen without waiting for one more slice.
        if (cancelEvent && Connection::IsEventSignaled(cancelEvent)) {
            T2_LOG("waitForEvent", L"cancelEvent signaled, giving up (design doc §9.4)");
            return WaitStep::Fail;
        }

        // LINUX PARITY FIX: drain events already observed (and acked) by
        // SendBiometricCommand/GetFdrCalibration before blocking on a new
        // ReadFrame. This is what actually closes the parity gap with the
        // Linux reference: request_with_events() hands its caller every
        // event seen while waiting for a command reply, in receipt order,
        // ahead of anything read afterward. Delivering a queued event
        // costs no wire I/O, so it is not subject to the deadline check
        // below - a StartMatch reply race should not let its own
        // already-acked events be silently timed out by the caller.
        if (!pendingEvents_.empty()) {
            *outEventPayload = std::move(pendingEvents_.front());
            pendingEvents_.pop_front();
            T2_LOG("waitForEvent", L"delivering queued event, payload=%zuB, "
                   "%zu still queued", outEventPayload->size(), pendingEvents_.size());
            return WaitStep::Deliver;
        }

        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            T2_LOG("waitForEvent", L"deadline reached, giving up");
            return WaitStep::Fail;
        }
        auto remaining = RemainingBudget(deadline);
        // Clamp to the poll slice only when there's actually a cancelEvent
        // to poll for; without one this is byte-identical to the previous
        // behavior (CLI `verify`, which never passes cancelEvent, still
        // waits the real `remaining` in one ReadFrame call).
        //
        // Deliberately NOT std::min(remaining, kCancelPollSlice): this file
        // is compiled without NOMINMAX (VERIFIED ON A REAL BUILD — MSVC
        // error C2589/C2059/C2737/C3536 right at that call, all symptoms of
        // <windows.h>'s own `min` function-like macro rewriting
        // `std::min(` into `std::(...)`-garbage before the compiler ever
        // sees the real std::min). A plain comparison sidesteps the macro
        // entirely instead of adding #define NOMINMAX here, which would
        // change every other TU that includes this header/TU pair across
        // both the CLI and driver builds — a bigger blast radius than this
        // fix needs.
        const auto readTimeout = (cancelEvent && kCancelPollSlice < remaining)
                                      ? kCancelPollSlice
                                      : remaining;

        RawFrame frame;
        ReadFailure why = ReadFailure::None;
        if (!ReadFrame(&frame, readTimeout, &why, /*quietIdleTimeout=*/cancelEvent != nullptr)) {
            if (why == ReadFailure::IdleTimeout) {
                // A slice timing out with zero bytes read is expected/silent
                // noise while polling for cancellation (WSAETIMEDOUT every
                // ~200ms is not a transport failure) — only log+fail here
                // when this was the real, un-clamped deadline, i.e. no
                // cancelEvent was in play.
                if (!cancelEvent) {
                    T2_LOG("waitForEvent", L"ReadFrame failed/timed out, %lldms remained",
                           static_cast<long long>(remaining.count()));
                    return WaitStep::Fail;
                }
                return WaitStep::Again; // slice elapsed with no data — loop back, re-check cancelEvent and deadline
            }
            // FIX (20.09.2026): this used to be a bare `continue` for EVERY
            // ReadFrame failure whenever a cancelEvent was in play. A peer
            // that closed/reset the TCP session (recv() -> 0 or
            // WSAECONNRESET) returns IMMEDIATELY, so the loop spun at 100%
            // CPU forever (no deadline is used with a cancelEvent) logging
            // one line per iteration, holding the single capture slot until
            // Windows happened to cancel. A dead or torn stream can never
            // deliver a match_result again: fail closed and let the caller
            // decide (reconnect, or complete the request with an error).
            connectionLost_.store(true);
            T2_LOG("waitForEvent",
                   L"connection lost while waiting for an event (peer closed/reset or "
                   L"torn frame) - giving up instead of retrying on a dead socket");
            return WaitStep::Fail;
        }
        if (frame.type != FrameType::Message) return WaitStep::Again; // ignore stray HELO-typed noise, keep waiting

        auto env = ParseMessageBody(frame.body);
        if (!env) {
            T2_LOG("waitForEvent", L"ParseMessageBody failed, body=%zuB %s",
                   frame.body.size(), HexDump(frame.body).c_str());
            return WaitStep::Fail; // malformed -> fail closed, do not keep guessing
        }

        if (!env->isReply) {
            // Async bridge-side callback: must be acknowledged (Milestone 1,
            // section 7) before we can keep reading.
            if (!AcknowledgeEvent(env->requestId, RemainingBudget(deadline))) {
                T2_LOG("waitForEvent", L"AcknowledgeEvent failed for reqId=%s",
                       Widen(env->requestId).c_str());
                return WaitStep::Fail;
            }
            T2_LOG("waitForEvent", L"event acked, reqId=%s payload=%zuB %s",
                   Widen(env->requestId).c_str(), env->payloadPlist.size(),
                   // 512B, not the 32B default: this line is currently the
                   // ONLY window into what these async status/statistics
                   // events actually contain during a match session (see
                   // VerificationEngine's own embedded_type logging, which
                   // names the event kind but not its body). 512B was
                   // chosen, not just "bigger than 32": the observed
                   // status/statistics events (131-167B) fit under it and
                   // now dump in full, while a genuine match_result event
                   // is >= kMinMatchResultEventBytes (0xC70 = 3184B,
                   // MatchResult.h) and so stays truncated here same as
                   // before - this line must never be the thing that
                   // prints an enrolled identity UUID in the clear.
                   HexDump(env->payloadPlist, 512).c_str());
            *outEventPayload = std::move(env->payloadPlist);   // env is local and not read again
            return WaitStep::Deliver;
        }
        // A stray reply to something we're not waiting on: ignore, keep looping.
        T2_LOG("waitForEvent", L"ignoring stray reply, reqId=%s", Widen(env->requestId).c_str());
    }
    return WaitStep::Again;
}

bool Connection::WaitForEvent(std::vector<uint8_t>* outEventPayload,
                               std::chrono::steady_clock::time_point deadline,
                               HANDLE cancelEvent) {
    // One poll slice per WaitForEventStep() call, each under ioMu_ (see
    // Connection.h). Deadline / cancel checks live in the step.
    for (;;) {
        switch (WaitForEventStep(outEventPayload, deadline, cancelEvent)) {
        case WaitStep::Deliver: return true;
        case WaitStep::Fail:    return false;
        case WaitStep::Again:   break;
        }
    }
}

bool Connection::AcknowledgeEvent(const std::string& requestId,
                                  std::chrono::milliseconds budget) {
    if (budget.count() <= 0) {
        WSASetLastError(WSAETIMEDOUT);
        return false;
    }
    auto ack = EncodeAckEnvelope(requestId);
    return WriteFrame(FrameType::Message, ack, budget);
}

// Once the FIRST byte of a frame has arrived the rest of it is already in
// flight, so the remaining recv()s get at least this long no matter how
// short the caller's `timeout` was. WaitForEvent() polls with a 200ms slice
// only to re-check its cancel event; without this a slice that happened to
// expire in the middle of a frame (e.g. the 3KB match_result) dropped the
// bytes already read and left the stream desynchronized (the next call then
// parsed body bytes as a frame header).
static constexpr std::chrono::milliseconds kFrameTailTimeout{3000};

bool Connection::SetRcvTimeoutCached(std::chrono::milliseconds timeout) {
    // Never issue recv() with a missing, disabled or stale timeout.
    if (timeout.count() <= 0 || timeout.count() > 0xFFFFFFFFLL) {
        T2_LOG("readFrame", L"invalid receive timeout: %lld ms",
               static_cast<long long>(timeout.count()));
        return false;
    }
    const DWORD ms = static_cast<DWORD>(timeout.count());
    if (ms == rcvTimeoutMs_) return true;
    if (!SetSocketTimeout(socket_, SO_RCVTIMEO, timeout)) {
        const int error = WSAGetLastError();
        rcvTimeoutMs_ = 0xFFFFFFFFu;
        T2_LOG("readFrame", L"SO_RCVTIMEO failed (timeout=%lu ms, WSA=%d)",
               static_cast<unsigned long>(ms), error);
        return false;
    }
    rcvTimeoutMs_ = ms;
    return true;
}

// Smallest read issued against the socket. A frame header + typical event body is
// 150-400 B, so one chunk usually holds several back-to-back frames.
static constexpr size_t kRxChunkBytes = 8192;
static constexpr size_t kRxFrameHeaderBytes = 16;
// Buffer capacity kept between frames; a rare multi-KB match_result frame grows it
// temporarily, anything above this is released once drained.
static constexpr size_t kRxKeepBytes = 65536;

bool Connection::ReadFrame(RawFrame* out, std::chrono::milliseconds timeout,
                            ReadFailure* why, bool quietIdleTimeout) {
    if (why) *why = ReadFailure::None;

    FrameHeader hdr{};
    bool haveHeader = false;

    // The tail allowance belongs to the whole frame, not each recv().
    // Without a fixed deadline a peer sending one byte every ~3 seconds
    // can keep a capture worker alive indefinitely.
    bool tailStarted = rxLen_ != rxPos_;
    auto tailDeadline = std::chrono::steady_clock::now() + kFrameTailTimeout;

    // Reads from the socket until at least `need` bytes of the current frame are
    // buffered. Failure semantics are those of the old two-recv() loop: a timeout with
    // ZERO bytes of a new frame buffered is IdleTimeout (stream still in sync); anything
    // else - reset, EOF, or a frame torn mid-way - fails closed.
    auto fill = [&](size_t need) -> bool {
        while (rxLen_ - rxPos_ < need) {
            if (rxPos_ != 0) {   // keep the unread tail at the front
                if (rxPos_ == rxLen_) {
                    rxPos_ = rxLen_ = 0;
                } else {
                    std::memmove(rxBuf_.data(), rxBuf_.data() + rxPos_, rxLen_ - rxPos_);
                    rxLen_ -= rxPos_;
                    rxPos_ = 0;
                }
            }
            const size_t want = need > kRxChunkBytes ? need : kRxChunkBytes;
            if (rxBuf_.size() < want) rxBuf_.resize(want);

            // Keep the first-byte idle poll short, but cap ALL subsequent
            // reads by one shared frame-tail deadline (not 3 seconds each).
            const bool midFrame = rxLen_ != rxPos_;
            std::chrono::milliseconds recvTimeout = timeout;
            if (midFrame) {
                const auto now = std::chrono::steady_clock::now();
                if (now >= tailDeadline) {
                    if (why) *why = ReadFailure::Error;
                    T2_LOG("readFrame", L"frame-tail deadline expired");
                    return false;
                }
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(tailDeadline - now);
                // Windows treats SO_RCVTIMEO=0 as infinite. Round up a
                // positive sub-millisecond remainder to 1 ms.
                recvTimeout = remaining.count() > 0 ? remaining : std::chrono::milliseconds(1);
            }
            if (!SetRcvTimeoutCached(recvTimeout)) {
                if (why) *why = ReadFailure::Error;
                return false;
            }

            const int n = recv(socket_, reinterpret_cast<char*>(rxBuf_.data()) + rxLen_,
                               static_cast<int>(rxBuf_.size() - rxLen_), 0);
            if (n <= 0) {
                const int wsaErr = (n < 0) ? WSAGetLastError() : 0;
                const bool timedOut = (n < 0) && (wsaErr == WSAETIMEDOUT || wsaErr == WSAEWOULDBLOCK);
                const size_t have = rxLen_ - rxPos_;
                if (timedOut && !midFrame) {
                    // Nothing of a new frame arrived: the stream is still in sync.
                    if (why) *why = ReadFailure::IdleTimeout;
                    if (!quietIdleTimeout) {
                        T2_LOG("readFrame", L"header recv failed after %zu/%zuB, n=%d, "
                               "WSAGetLastError=%d (0=timeout/closed cleanly)",
                               have, kRxFrameHeaderBytes, n, wsaErr);
                    }
                    return false;
                }
                if (!haveHeader) {
                    T2_LOG("readFrame", L"header recv failed after %zu/%zuB, n=%d, "
                           "WSAGetLastError=%d (0=timeout/closed cleanly)",
                           have, kRxFrameHeaderBytes, n, wsaErr);
                } else {
                    T2_LOG("readFrame", L"body recv failed after %zu/%lluB, n=%d, "
                           "WSAGetLastError=%d (frameType=%u)",
                           have - kRxFrameHeaderBytes, static_cast<unsigned long long>(hdr.bodyLength),
                           n, wsaErr, hdr.frameType);
                }
                if (why) *why = (n == 0) ? ReadFailure::Closed : ReadFailure::Error;
                return false;
            }
            rxLen_ += static_cast<size_t>(n);
            if (!tailStarted) {
                tailStarted = true;
                tailDeadline = std::chrono::steady_clock::now() + kFrameTailTimeout;
            }
        }
        return true;
    };

    if (!fill(kRxFrameHeaderBytes)) return false;

    ParseResult pr = ParseFrameHeader(rxBuf_.data() + rxPos_, kRxFrameHeaderBytes, &hdr);
    if (pr != ParseResult::Ok) {
        T2_LOG("readFrame", L"ParseFrameHeader failed, result=%d, header=%s",
               static_cast<int>(pr),
               HexDump(rxBuf_.data() + rxPos_, kRxFrameHeaderBytes, kRxFrameHeaderBytes).c_str());
        rxPos_ = rxLen_ = 0;   // stream is desynchronized; nothing buffered can be trusted
        if (why) *why = ReadFailure::Error;
        return false;
    }
    haveHeader = true;

    const size_t bodyLen = static_cast<size_t>(hdr.bodyLength);
    if (!fill(kRxFrameHeaderBytes + bodyLen)) return false;

    const uint8_t* body = rxBuf_.data() + rxPos_ + kRxFrameHeaderBytes;
    out->body.assign(body, body + bodyLen);
    out->type = static_cast<FrameType>(hdr.frameType);

    rxPos_ += kRxFrameHeaderBytes + bodyLen;
    if (rxPos_ == rxLen_) {
        rxPos_ = rxLen_ = 0;
        if (rxBuf_.size() > kRxKeepBytes) {   // a huge frame grew the buffer: release it
            rxBuf_.clear();
            rxBuf_.shrink_to_fit();
        }
    }
    return true;
}

// Sends every byte of [data, data+len), looping on short writes. A single
// send() call is NOT guaranteed to transmit the whole buffer even on a
// blocking TCP socket - it can return early once its own send buffer is
// full. This matters here because bodies can be several KB (e.g. the FDR
// calibration blob echoed back in the load-calibration command), unlike the
// few-byte HELO/getBridgeVersion/setClientVersion bodies that happened to
// always fit in one send() and masked this bug during earlier hardware
// runs. Mirrors RemoteXpcConnection::WriteRaw in
// protocol/Discovery/RemoteXpc.cpp, which already gets this right.
// Bound the ENTIRE frame write, not each short send(). A peer that only
// accepts a few bytes per timeout must not keep the capture worker alive forever.
static constexpr std::chrono::milliseconds kFrameWriteTimeout{10000};
static bool WriteAll(SOCKET s, const uint8_t* data, size_t len,
                     std::chrono::milliseconds budget) {
    if (budget.count() <= 0) {
        WSASetLastError(WSAETIMEDOUT);
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() +
                          (std::min)(budget, kFrameWriteTimeout);
    size_t sent = 0;
    while (sent < len) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            T2_LOG("writeAll", L"frame write deadline expired after %zu/%zuB", sent, len);
            WSASetLastError(WSAETIMEDOUT);
            return false;
        }
        const auto left = deadline - now;
        const auto leftMs = std::chrono::duration_cast<std::chrono::milliseconds>(left);
        const auto remaining = leftMs.count() > 0 ? leftMs : std::chrono::milliseconds(1);
        // SO_SNDTIMEO applies to blocking sends, but each successful short
        // write could otherwise reset it. Re-apply the shared remaining budget.
        if (!SetSocketTimeout(s, SO_SNDTIMEO, remaining)) {
            const int error = WSAGetLastError();
            T2_LOG("writeAll", L"SO_SNDTIMEO failed: WSA=%d", error);
            return false;
        }
        const size_t bytesLeft = len - sent;
        const int toSend = static_cast<int>(bytesLeft > static_cast<size_t>(INT_MAX)
                                            ? INT_MAX : bytesLeft);
        const int n = send(s, reinterpret_cast<const char*>(data + sent), toSend, 0);
        if (n <= 0) {
            int error = n < 0 ? WSAGetLastError() : WSAECONNRESET;
            if (n < 0 && error == WSAEWOULDBLOCK) {
                // Defensive fallback if the socket unexpectedly remains
                // non-blocking. select() also uses the remaining deadline.
                fd_set writeSet;
                FD_ZERO(&writeSet);
                FD_SET(s, &writeSet);
                const auto after = std::chrono::steady_clock::now();
                if (after < deadline) {
                    const auto waitUs = std::chrono::duration_cast<std::chrono::microseconds>(deadline - after).count();
                    timeval tv{};
                    tv.tv_sec = static_cast<long>(waitUs / 1000000);
                    tv.tv_usec = static_cast<long>(waitUs % 1000000);
                    const int ready = select(0, nullptr, &writeSet, nullptr, &tv);
                    if (ready > 0) continue;
                    error = ready == 0 ? WSAETIMEDOUT : WSAGetLastError();
                } else {
                    error = WSAETIMEDOUT;
                }
            }
            T2_LOG("writeAll", L"send failed after %zu/%zuB, n=%d, WSA=%d",
                   sent, len, n, error);
            WSASetLastError(error);
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool Connection::WriteFrame(FrameType type, const std::vector<uint8_t>& body,
                            std::chrono::milliseconds budget) {
    // Header and body go out in ONE send(): two back-to-back small sends
    // are the Nagle/delayed-ACK trap described at TuneEstablishedSocket.
    // Small frames (the common case) use a stack buffer, no allocation.
    uint16_t magic = kFrameMagic;
    uint16_t version = kProtocolVersion;
    uint32_t frameType = static_cast<uint32_t>(type);
    uint64_t bodyLength = body.size();

    uint8_t stackBuf[16 + 512];
    std::vector<uint8_t> heapBuf;
    uint8_t* out = stackBuf;
    const size_t total = 16 + body.size();
    if (total > sizeof(stackBuf)) {
        heapBuf.resize(total);
        out = heapBuf.data();
    }

    std::memcpy(out + 0, &magic, 2);
    std::memcpy(out + 2, &version, 2);
    std::memcpy(out + 4, &frameType, 4);
    std::memcpy(out + 8, &bodyLength, 8);
    if (!body.empty()) {
        std::memcpy(out + 16, body.data(), body.size());
    }
    return WriteAll(socket_, out, total, budget);
}

} // namespace t2::bridgexpc
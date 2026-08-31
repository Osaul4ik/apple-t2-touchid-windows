// SPDX-License-Identifier: GPL-2.0-only
// Connection.cpp
#include "Connection.h"
#include <ws2tcpip.h>
#include <rpc.h>
#include <cctype>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Rpcrt4.lib")

namespace t2::bridgexpc {

// VERIFIED FROM SOURCE: bridge-xpc-probe.py generates a fresh
// str(uuid.uuid4()).upper() per request — every request/reply/event id in
// this file must be a real, unique UUIDv4, never a fixed placeholder.
static std::string NewRequestUuid() {
    UUID uuid;
    if (UuidCreate(&uuid) != RPC_S_OK) {
        return {}; // caller must treat an empty id as a hard failure
    }
    RPC_CSTR str = nullptr;
    if (UuidToStringA(&uuid, &str) != RPC_S_OK || !str) {
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
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
}

static bool SetSocketTimeout(SOCKET s, int optname, std::chrono::milliseconds timeout) {
    DWORD ms = static_cast<DWORD>(timeout.count());
    return setsockopt(s, SOL_SOCKET, optname, reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0;
}

ConnectResult Connection::Connect(const in6_addr& linkLocalAddress, unsigned long interfaceIndex,
                                   uint16_t port, std::chrono::milliseconds connectTimeout) {
    socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
        return ConnectResult::ConnectFailed;
    }

    SetSocketTimeout(socket_, SO_RCVTIMEO, connectTimeout);
    SetSocketTimeout(socket_, SO_SNDTIMEO, connectTimeout);

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = linkLocalAddress;
    addr.sin6_scope_id = interfaceIndex; // required for link-local (fe80::/10)

    if (connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        Close();
        return ConnectResult::ConnectFailed;
    }

    // T2 sends HELO first (VERIFIED FROM SOURCE, Milestone 1 section 7).
    RawFrame helo;
    if (!ReadFrame(&helo, connectTimeout) || helo.type != FrameType::Helo) {
        Close();
        return ConnectResult::HeloTimeout;
    }

    // Echo a HELO body; per Linux reference the client's BridgeXPCVersion
    // must match whatever the peer just sent — we do not invent our own
    // arbitrary version.
    std::string helloJson = std::string(helo.body.begin(), helo.body.end());
    if (!WriteFrame(FrameType::Helo, helo.body)) { // echo verbatim, simplest correct behavior
        Close();
        return ConnectResult::HeloMalformed;
    }

    return ConnectResult::Ok;
}

bool Connection::GetBridgeVersion(int64_t* outVersion, std::chrono::milliseconds timeout) {
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {0});
    if (!WriteFrame(FrameType::Message, req)) return false;

    RawFrame reply;
    if (!ReadFrame(&reply, timeout) || reply.type != FrameType::Message) return false;

    auto env = ParseMessageBody(reply.body);
    if (!env || env->requestId != reqId) return false;

    // VERIFIED FROM SOURCE: getBridgeVersion reply is [0, api_version];
    // Apple's own client rejects any other shape ("getBridgeVersion
    // failed") rather than guessing, and so do we.
    auto ints = DecodeIntArrayPayload(env->payloadPlist);
    if (!ints || ints->size() != 2 || (*ints)[0] != 0) return false;
    *outVersion = (*ints)[1];
    return true;
}

bool Connection::SetClientVersion(int64_t version, std::chrono::milliseconds timeout) {
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {10, version});
    if (!WriteFrame(FrameType::Message, req)) return false;

    RawFrame reply;
    if (!ReadFrame(&reply, timeout) || reply.type != FrameType::Message) return false;

    auto env = ParseMessageBody(reply.body);
    if (!env || env->requestId != reqId) return false;

    negotiatedVersion_ = version;
    return true;
}

bool Connection::SendBiometricCommand(const std::vector<uint8_t>& innerBmMessage,
                                       uint32_t outputCapacity,
                                       std::vector<uint8_t>* outReply,
                                       std::chrono::milliseconds timeout) {
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    // VERIFIED FROM SOURCE: outer payload is exactly
    // [3, 0, innerBmBytes, outputCapacity] — outputCapacity is a real,
    // load-bearing field (it tells bkremoted how large a reply buffer to
    // fill), not a value the caller can silently drop.
    auto req = EncodeRequestEnvelope(reqId, {3, 0}, &innerBmMessage,
                                      {static_cast<int64_t>(outputCapacity)});
    if (!WriteFrame(FrameType::Message, req)) return false;

    RawFrame reply;
    if (!ReadFrame(&reply, timeout) || reply.type != FrameType::Message) return false;

    auto env = ParseMessageBody(reply.body);
    if (!env || env->requestId != reqId) return false;

    *outReply = env->payloadPlist;
    return true;
}

bool Connection::GetFdrCalibration(std::vector<uint8_t>* outBlob, std::chrono::milliseconds timeout) {
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {11});
    if (!WriteFrame(FrameType::Message, req)) return false;

    RawFrame reply;
    if (!ReadFrame(&reply, timeout) || reply.type != FrameType::Message) return false;

    auto env = ParseMessageBody(reply.body);
    if (!env || env->requestId != reqId) return false;

    auto blob = DecodeSingleBlobPayload(env->payloadPlist);
    // VERIFIED FROM SOURCE: "--load-calibration requires bridgeOS returned
    // no usable FDR calibration data" is treated as a hard failure, not an
    // empty-but-ok result — do not skip calibration on a missing blob.
    if (!blob || blob->empty()) return false;

    *outBlob = std::move(*blob);
    return true;
}

bool Connection::WaitForEvent(std::vector<uint8_t>* outEventPayload,
                               std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return false;
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);

        RawFrame frame;
        if (!ReadFrame(&frame, remaining)) return false;
        if (frame.type != FrameType::Message) continue; // ignore stray HELO-typed noise, keep waiting

        auto env = ParseMessageBody(frame.body);
        if (!env) return false; // malformed -> fail closed, do not keep guessing

        if (!env->isReply) {
            // Async bridge-side callback: must be acknowledged (Milestone 1,
            // section 7) before we can keep reading.
            if (!AcknowledgeEvent(env->requestId)) return false;
            *outEventPayload = env->payloadPlist;
            return true;
        }
        // A stray reply to something we're not waiting on: ignore, keep looping.
    }
}

bool Connection::AcknowledgeEvent(const std::string& requestId) {
    auto ack = EncodeAckEnvelope(requestId);
    return WriteFrame(FrameType::Message, ack);
}

bool Connection::ReadFrame(RawFrame* out, std::chrono::milliseconds timeout) {
    SetSocketTimeout(socket_, SO_RCVTIMEO, timeout);

    uint8_t headerBuf[16];
    size_t got = 0;
    while (got < sizeof(headerBuf)) {
        int n = recv(socket_, reinterpret_cast<char*>(headerBuf) + got,
                      static_cast<int>(sizeof(headerBuf) - got), 0);
        if (n <= 0) return false; // timeout, reset, or EOF: fail closed
        got += static_cast<size_t>(n);
    }

    FrameHeader hdr;
    if (ParseFrameHeader(headerBuf, sizeof(headerBuf), &hdr) != ParseResult::Ok) {
        return false;
    }

    out->body.resize(static_cast<size_t>(hdr.bodyLength));
    size_t bodyGot = 0;
    while (bodyGot < out->body.size()) {
        int n = recv(socket_, reinterpret_cast<char*>(out->body.data()) + bodyGot,
                      static_cast<int>(out->body.size() - bodyGot), 0);
        if (n <= 0) return false;
        bodyGot += static_cast<size_t>(n);
    }

    out->type = static_cast<FrameType>(hdr.frameType);
    return true;
}

bool Connection::WriteFrame(FrameType type, const std::vector<uint8_t>& body) {
    uint8_t header[16];
    uint16_t magic = kFrameMagic;
    uint16_t version = kProtocolVersion;
    uint32_t frameType = static_cast<uint32_t>(type);
    uint64_t bodyLength = body.size();

    std::memcpy(header + 0, &magic, 2);
    std::memcpy(header + 2, &version, 2);
    std::memcpy(header + 4, &frameType, 4);
    std::memcpy(header + 8, &bodyLength, 8);

    if (send(socket_, reinterpret_cast<const char*>(header), sizeof(header), 0) != sizeof(header)) {
        return false;
    }
    if (!body.empty() &&
        send(socket_, reinterpret_cast<const char*>(body.data()), static_cast<int>(body.size()), 0)
            != static_cast<int>(body.size())) {
        return false;
    }
    return true;
}

} // namespace t2::bridgexpc

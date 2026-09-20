// SPDX-License-Identifier: GPL-2.0-only
// Connection.cpp
#include "Connection.h"
#include "Log.h"
#include <ws2tcpip.h>
#include <rpc.h>
#include <cctype>
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
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
    // Defensive only: this class is one-connection-per-verification-attempt
    // (see the class comment) and is expected to be discarded after Close(),
    // never reused, so there should be no queued events left to leak into a
    // next session. Clearing anyway costs nothing and removes any doubt.
    pendingEvents_.clear();
}

static bool SetSocketTimeout(SOCKET s, int optname, std::chrono::milliseconds timeout) {
    DWORD ms = static_cast<DWORD>(timeout.count());
    return setsockopt(s, SOL_SOCKET, optname, reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0;
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

ConnectResult Connection::Connect(const in6_addr& linkLocalAddress, unsigned long interfaceIndex,
                                   uint16_t port, std::chrono::milliseconds connectTimeout) {
    socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
        T2_LOG("connect", L"socket() failed, WSAGetLastError=%d", WSAGetLastError());
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
        T2_LOG("connect", L"connect() to port %u failed, WSAGetLastError=%d",
               port, WSAGetLastError());
        Close();
        return ConnectResult::ConnectFailed;
    }

    // T2 sends HELO first (VERIFIED FROM SOURCE, Milestone 1 section 7).
    RawFrame helo;
    if (!ReadFrame(&helo, connectTimeout) || helo.type != FrameType::Helo) {
        T2_LOG("connect", L"HELO read failed or wrong frame type "
               "(connected=true, timeout=%lldms)",
               static_cast<long long>(connectTimeout.count()));
        Close();
        return ConnectResult::HeloTimeout;
    }
    T2_LOG("connect", L"peer HELO received, %zu bytes: %s",
           helo.body.size(), HexDump(helo.body, 96).c_str());

    // BUG FIX: this used to echo the peer's own HELO body straight back
    // (WriteFrame(FrameType::Helo, helo.body)). That is NOT what the
    // verified reference does. docs/linux-reference-analysis.md line 187
    // (itself sourced from bridge-xpc-probe.py's send_helo()) says the
    // client replies with its OWN HELO JSON - only reusing the peer's
    // BridgeXPCVersion number - not a copy of the T2's self-description
    // (its own OSBuild/ProcessName). Sending the device's own HELO back to
    // it, unchanged, doesn't identify us as a real client, which is a
    // plausible reason bridgeOS accepts the handshake (framing is valid,
    // so HELO/getBridgeVersion/setClientVersion/reset/cancel all still
    // "work") but then withholds the FDR calibration blob on a policy it
    // gates by client identity - GetFdrCalibration comes back with [None]
    // ("bridgeOS returned no usable FDR calibration data") instead of an
    // error, so nothing before it ever caught this.
    std::string peerHeloJson(helo.body.begin(), helo.body.end());
    int64_t bridgeXpcVersion = 0;
    if (!ExtractJsonIntField(peerHeloJson, "BridgeXPCVersion", &bridgeXpcVersion)) {
        T2_LOG("connect", L"BridgeXPCVersion missing/unparseable in peer HELO: %s",
               Widen(peerHeloJson).c_str());
        Close();
        return ConnectResult::HeloMalformed;
    }
    std::vector<uint8_t> ownHelo = BuildClientHeloBody(bridgeXpcVersion);
    if (!WriteFrame(FrameType::Helo, ownHelo)) {
        T2_LOG("connect", L"writing own HELO failed, WSAGetLastError=%d", WSAGetLastError());
        Close();
        return ConnectResult::HeloMalformed;
    }

    T2_LOG("connect", L"handshake OK, BridgeXPCVersion=%lld", static_cast<long long>(bridgeXpcVersion));
    return ConnectResult::Ok;
}


bool Connection::ReadUntilMatchingReply(const std::string& expectedReqId,
                                        MessageEnvelope* outEnv,
                                        std::chrono::milliseconds timeout,
                                        const wchar_t* logTag) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            ::t2::log::Logf(logTag, L"deadline reached waiting for reply (reqId=%s, timeout=%lldms)",
                   Widen(expectedReqId).c_str(), static_cast<long long>(timeout.count()));
            return false;
        }
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);

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
            if (!AcknowledgeEvent(env->requestId)) {
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
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {0});
    if (!WriteFrame(FrameType::Message, req)) {
        T2_LOG("getBridgeVersion", L"WriteFrame failed, WSAGetLastError=%d", WSAGetLastError());
        return false;
    }

    // Same event-before-reply loop as SendBiometricCommand (ACK+queue).
    MessageEnvelope env;
    if (!ReadUntilMatchingReply(reqId, &env, timeout, L"getBridgeVersion")) {
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
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {10, version});
    if (!WriteFrame(FrameType::Message, req)) {
        T2_LOG("setClientVersion", L"WriteFrame failed, WSAGetLastError=%d", WSAGetLastError());
        return false;
    }

    MessageEnvelope env;
    if (!ReadUntilMatchingReply(reqId, &env, timeout, L"setClientVersion")) {
        return false;
    }

    T2_LOG("setClientVersion", L"OK, negotiated=%lld", static_cast<long long>(version));
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
    T2_LOG("sendBiometricCommand",
           L"-> reqId=%s inner=%zuB (%s) outputCapacity=%u timeout=%lldms",
           Widen(reqId).c_str(), innerBmMessage.size(),
           HexDump(innerBmMessage, 8).c_str(), outputCapacity,
           static_cast<long long>(timeout.count()));

    if (!WriteFrame(FrameType::Message, req)) {
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
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            T2_LOG("sendBiometricCommand", L"deadline reached waiting for reply "
                   "(reqId=%s, timeout=%lldms)", Widen(reqId).c_str(),
                   static_cast<long long>(timeout.count()));
            return false;
        }
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);

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
            if (!AcknowledgeEvent(env->requestId)) {
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
        // (ParseIdentityList, VerificationEngine's raw int32 startResult
        // read) expect the unwrapped blob, not this bplist-encoded array —
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
        if (statusBlob->status != 0) {
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
    std::string reqId = NewRequestUuid();
    if (reqId.empty()) return false;
    auto req = EncodeRequestEnvelope(reqId, {11});
    if (!WriteFrame(FrameType::Message, req)) {
        T2_LOG("getFdrCalibration", L"WriteFrame failed, WSAGetLastError=%d", WSAGetLastError());
        return false;
    }

    // VERIFIED FROM SOURCE: bridge-xpc-probe.py --load-calibration uses
    // request_with_events(sock, [11]), which acks async callbacks until
    // the matching reply arrives. A single ReadFrame here used to treat
    // the first frame as the reply and fail if bkremoted pushed a
    // serviceStatus event first — the same bug SendBiometricCommand
    // already fixed for BM commands.
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            T2_LOG("getFdrCalibration", L"deadline reached waiting for reply "
                   "(reqId=%s, timeout=%lldms)", Widen(reqId).c_str(),
                   static_cast<long long>(timeout.count()));
            return false;
        }
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);

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
            if (!AcknowledgeEvent(env->requestId)) {
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

size_t Connection::DiscardPendingEvents() {
    const size_t n = pendingEvents_.size();
    if (n > 0) {
        T2_LOG("discardPending",
               L"dropping %zu pre-match event(s) retained during "
               L"LoadCalibration/identity warm-up (Linux keeps these "
               L"out of the match event stream)",
               n);
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
static constexpr std::chrono::milliseconds kCancelPollSlice{200};

bool Connection::WaitForEvent(std::vector<uint8_t>* outEventPayload,
                               std::chrono::steady_clock::time_point deadline,
                               HANDLE cancelEvent) {
    for (;;) {
        // Checked at the TOP of every iteration — including before the
        // very first ReadFrame — so a cancel that arrives while this
        // socket's previous recv() was already unblocked by a real SEP
        // event (i.e. we're back here deciding whether to read again) is
        // seen without waiting for one more slice.
        if (cancelEvent && Connection::IsEventSignaled(cancelEvent)) {
            T2_LOG("waitForEvent", L"cancelEvent signaled, giving up (design doc §9.4)");
            return false;
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
            return true;
        }

        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            T2_LOG("waitForEvent", L"deadline reached, giving up");
            return false;
        }
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
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
        if (!ReadFrame(&frame, readTimeout)) {
            // A slice timing out is expected/silent noise while polling for
            // cancellation (WSAETIMEDOUT every ~200ms is not a transport
            // failure) — only log+fail here when this was the real,
            // un-clamped deadline, i.e. no cancelEvent was in play.
            if (!cancelEvent) {
                T2_LOG("waitForEvent", L"ReadFrame failed/timed out, %lldms remained",
                       static_cast<long long>(remaining.count()));
                return false;
            }
            continue; // slice elapsed with no data — loop back, re-check cancelEvent and deadline
        }
        if (frame.type != FrameType::Message) continue; // ignore stray HELO-typed noise, keep waiting

        auto env = ParseMessageBody(frame.body);
        if (!env) {
            T2_LOG("waitForEvent", L"ParseMessageBody failed, body=%zuB %s",
                   frame.body.size(), HexDump(frame.body).c_str());
            return false; // malformed -> fail closed, do not keep guessing
        }

        if (!env->isReply) {
            // Async bridge-side callback: must be acknowledged (Milestone 1,
            // section 7) before we can keep reading.
            if (!AcknowledgeEvent(env->requestId)) {
                T2_LOG("waitForEvent", L"AcknowledgeEvent failed for reqId=%s",
                       Widen(env->requestId).c_str());
                return false;
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
            *outEventPayload = env->payloadPlist;
            return true;
        }
        // A stray reply to something we're not waiting on: ignore, keep looping.
        T2_LOG("waitForEvent", L"ignoring stray reply, reqId=%s", Widen(env->requestId).c_str());
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
        if (n <= 0) {
            T2_LOG("readFrame", L"header recv failed after %zu/%zuB, n=%d, "
                   "WSAGetLastError=%d (0=timeout/closed cleanly)",
                   got, sizeof(headerBuf), n, WSAGetLastError());
            return false; // timeout, reset, or EOF: fail closed
        }
        got += static_cast<size_t>(n);
    }

    FrameHeader hdr;
    ParseResult pr = ParseFrameHeader(headerBuf, sizeof(headerBuf), &hdr);
    if (pr != ParseResult::Ok) {
        T2_LOG("readFrame", L"ParseFrameHeader failed, result=%d, header=%s",
               static_cast<int>(pr), HexDump(std::vector<uint8_t>(headerBuf, headerBuf + 16)).c_str());
        return false;
    }

    out->body.resize(static_cast<size_t>(hdr.bodyLength));
    size_t bodyGot = 0;
    while (bodyGot < out->body.size()) {
        int n = recv(socket_, reinterpret_cast<char*>(out->body.data()) + bodyGot,
                      static_cast<int>(out->body.size() - bodyGot), 0);
        if (n <= 0) {
            T2_LOG("readFrame", L"body recv failed after %zu/%lluB, n=%d, "
                   "WSAGetLastError=%d (frameType=%u)",
                   bodyGot, static_cast<unsigned long long>(hdr.bodyLength), n,
                   WSAGetLastError(), hdr.frameType);
            return false;
        }
        bodyGot += static_cast<size_t>(n);
    }

    out->type = static_cast<FrameType>(hdr.frameType);
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
static bool WriteAll(SOCKET s, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, reinterpret_cast<const char*>(data + sent),
                     static_cast<int>(len - sent), 0);
        if (n <= 0) {
            int e = WSAGetLastError();
            if (n < 0 && e == WSAEWOULDBLOCK) continue;
            T2_LOG("writeAll", L"send failed after %zu/%zuB, n=%d, WSAGetLastError=%d",
                   sent, len, n, e);
            return false; // hard error or peer closed: fail closed
        }
        sent += static_cast<size_t>(n);
    }
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

    if (!WriteAll(socket_, header, sizeof(header))) {
        return false;
    }
    if (!body.empty() && !WriteAll(socket_, body.data(), body.size())) {
        return false;
    }
    return true;
}

} // namespace t2::bridgexpc
// SPDX-License-Identifier: GPL-2.0-only
// RemoteXpc.cpp — see RemoteXpc.h for the verification source and wire
// format summary. Socket connect/timeout plumbing mirrors PortScan.cpp
// (same select()-based non-blocking-connect pattern, same IPV6_UNICAST_IF
// scoping) rather than inventing a second style for the same problem.
#include "RemoteXpc.h"
#include <ws2tcpip.h>
#include <windows.h>
#include <cstring>
#include <bcrypt.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace t2::discovery {
namespace {

constexpr uint32_t kXpcMessageMagic = 0x29b00b92u;
constexpr uint32_t kXpcObjectMagic = 0x42133742u;
constexpr uint32_t kXpcObjectVersion = 0x00000005u;

// XPCFlag values (format.rs XPCFlag -> u32).
constexpr uint32_t kFlagAlwaysSet = 0x00000001u;
constexpr uint32_t kFlagDataFlag = 0x00000100u;
constexpr uint32_t kFlagWantingReply = 0x00010000u;
constexpr uint32_t kFlagInitHandshake = 0x00400000u;
constexpr uint32_t kFlagCustomHandshakeTail = 0x00000201u; // Custom(0x201) sent after do_handshake's reply frame

// XPCType tags (format.rs).
constexpr uint32_t kTypeNull = 0x00001000u;
constexpr uint32_t kTypeBool = 0x00002000u;
constexpr uint32_t kTypeInt64 = 0x00003000u;
constexpr uint32_t kTypeUInt64 = 0x00004000u;
constexpr uint32_t kTypeDouble = 0x00005000u;
constexpr uint32_t kTypeDate = 0x00007000u;
constexpr uint32_t kTypeData = 0x00008000u;
constexpr uint32_t kTypeString = 0x00009000u;
constexpr uint32_t kTypeUuid = 0x0000a000u;
constexpr uint32_t kTypeArray = 0x0000e000u;
constexpr uint32_t kTypeDictionary = 0x0000f000u;

size_t Padding(size_t len) {
    size_t rem = len % 4;
    return rem == 0 ? 0 : (4 - rem);
}

void PutU32LE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}
void PutU64LE(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}
bool GetU32LE(const uint8_t* p, size_t len, size_t off, uint32_t* out) {
    if (off + 4 > len) return false;
    *out = static_cast<uint32_t>(p[off]) | (static_cast<uint32_t>(p[off + 1]) << 8) |
           (static_cast<uint32_t>(p[off + 2]) << 16) | (static_cast<uint32_t>(p[off + 3]) << 24);
    return true;
}
bool GetU64LE(const uint8_t* p, size_t len, size_t off, uint64_t* out) {
    if (off + 8 > len) return false;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[off + i]) << (8 * i);
    *out = v;
    return true;
}

// Decodes one tagged XPC object starting at data[off]; advances *off past
// it. Returns false on any malformed/truncated/unknown-type input.
bool DecodeObjectAt(const uint8_t* data, size_t len, size_t* off, XpcObject* out) {
    uint32_t tag = 0;
    if (!GetU32LE(data, len, *off, &tag)) return false;
    *off += 4;

    switch (tag) {
        case kTypeNull:
            out->kind = XpcObject::Kind::Null;
            return true;
        case kTypeBool: {
            if (*off + 4 > len) return false;
            out->kind = XpcObject::Kind::Bool;
            out->boolValue = data[*off] != 0;
            *off += 4;
            return true;
        }
        case kTypeInt64: {
            uint64_t raw = 0;
            if (!GetU64LE(data, len, *off, &raw)) return false;
            out->kind = XpcObject::Kind::Int64;
            out->intValue = static_cast<int64_t>(raw);
            *off += 8;
            return true;
        }
        case kTypeUInt64: {
            uint64_t raw = 0;
            if (!GetU64LE(data, len, *off, &raw)) return false;
            out->kind = XpcObject::Kind::UInt64;
            out->uintValue = raw;
            *off += 8;
            return true;
        }
        case kTypeDouble: {
            uint64_t raw = 0;
            if (!GetU64LE(data, len, *off, &raw)) return false;
            out->kind = XpcObject::Kind::Double;
            std::memcpy(&out->doubleValue, &raw, 8);
            *off += 8;
            return true;
        }
        case kTypeDate: {
            // Not needed by the peer record; skip the 8-byte payload but
            // keep decoding in sync rather than guessing it's absent.
            uint64_t raw = 0;
            if (!GetU64LE(data, len, *off, &raw)) return false;
            out->kind = XpcObject::Kind::UInt64;
            out->uintValue = raw;
            *off += 8;
            return true;
        }
        case kTypeString: {
            uint32_t l = 0; // includes the trailing NUL
            if (!GetU32LE(data, len, *off, &l)) return false;
            *off += 4;
            if (l == 0 || *off + l > len) return false;
            out->kind = XpcObject::Kind::String;
            out->stringValue.assign(reinterpret_cast<const char*>(data + *off), l - 1);
            *off += l;
            *off += Padding(l);
            return true;
        }
        case kTypeData: {
            uint32_t l = 0;
            if (!GetU32LE(data, len, *off, &l)) return false;
            *off += 4;
            if (*off + l > len) return false;
            out->kind = XpcObject::Kind::Data;
            out->dataValue.assign(data + *off, data + *off + l);
            *off += l;
            *off += Padding(l);
            return true;
        }
        case kTypeUuid: {
            if (*off + 16 > len) return false;
            out->kind = XpcObject::Kind::Uuid;
            out->dataValue.assign(data + *off, data + *off + 16);
            *off += 16;
            return true;
        }
        case kTypeArray: {
            uint32_t contentLen = 0, count = 0;
            if (!GetU32LE(data, len, *off, &contentLen)) return false;
            *off += 4;
            if (!GetU32LE(data, len, *off, &count)) return false;
            *off += 4;
            out->kind = XpcObject::Kind::Array;
            out->arrayValue.clear();
            out->arrayValue.reserve(count);
            for (uint32_t i = 0; i < count; ++i) {
                XpcObject item;
                if (!DecodeObjectAt(data, len, off, &item)) return false;
                out->arrayValue.push_back(std::move(item));
            }
            (void)contentLen; // content_len is redundant with walking the entries; not re-validated
            return true;
        }
        case kTypeDictionary: {
            uint32_t contentLen = 0, count = 0;
            if (!GetU32LE(data, len, *off, &contentLen)) return false;
            *off += 4;
            if (!GetU32LE(data, len, *off, &count)) return false;
            *off += 4;
            out->kind = XpcObject::Kind::Dictionary;
            out->dictValue.clear();
            out->dictValue.reserve(count);
            for (uint32_t i = 0; i < count; ++i) {
                // NUL-terminated key, then padding to 4-byte alignment
                // (padding computed on key-length-including-NUL, per
                // format.rs's calculate_padding(key.len() + 1)).
                size_t start = *off;
                while (*off < len && data[*off] != 0) ++*off;
                if (*off >= len) return false; // no terminating NUL found
                std::string key(reinterpret_cast<const char*>(data + start), *off - start);
                *off += 1; // NUL
                *off += Padding(key.size() + 1);
                XpcObject value;
                if (!DecodeObjectAt(data, len, off, &value)) return false;
                out->dictValue.emplace_back(std::move(key), std::move(value));
            }
            (void)contentLen;
            return true;
        }
        default:
            return false; // unknown/unsupported type (e.g. FileTransfer) — not needed here
    }
}

} // namespace

// ---------------------------------------------------------------- XpcObject

XpcObject XpcObject::MakeUuidRandom() {
    XpcObject o;
    o.kind = Kind::Uuid;
    o.dataValue.resize(16);
    // BCryptGenRandom rather than rand(): this UUID is only ever an opaque
    // handshake nonce, but there is no reason to use a weaker source when
    // a CNG system RNG call is one line.
    NTSTATUS st = BCryptGenRandom(nullptr, o.dataValue.data(),
                                   static_cast<ULONG>(o.dataValue.size()),
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0 /*STATUS_SUCCESS*/) {
        // Fall back rather than send an all-zero UUID silently — still
        // clearly not cryptographic, but this value's only job is to be
        // distinguishable across handshake attempts for T2-side logging.
        for (auto& b : o.dataValue) b = static_cast<uint8_t>(GetTickCount64() ^ (rand() & 0xFF));
    }
    o.dataValue[6] = static_cast<uint8_t>((o.dataValue[6] & 0x0F) | 0x40); // version 4
    o.dataValue[8] = static_cast<uint8_t>((o.dataValue[8] & 0x3F) | 0x80); // RFC 4122 variant
    return o;
}

void XpcObject::SetField(const std::string& key, XpcObject value) {
    if (kind != Kind::Dictionary) return;
    dictValue.emplace_back(key, std::move(value));
}

const XpcObject* XpcObject::FindField(const std::string& key) const {
    if (kind != Kind::Dictionary) return nullptr;
    for (const auto& kv : dictValue) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

std::vector<uint8_t> XpcObject::Encode() const {
    std::vector<uint8_t> buf;
    PutU32LE(buf, kXpcObjectMagic);
    PutU32LE(buf, kXpcObjectVersion);

    // Local recursive encoder (mirrors format.rs's encode_object).
    struct Encoder {
        static void Run(const XpcObject& obj, std::vector<uint8_t>& out) {
            switch (obj.kind) {
                case Kind::Null:
                    PutU32LE(out, kTypeNull);
                    break;
                case Kind::Bool:
                    PutU32LE(out, kTypeBool);
                    out.push_back(static_cast<uint8_t>(obj.boolValue ? 1 : 0));
                    out.push_back(static_cast<uint8_t>(0)); out.push_back(static_cast<uint8_t>(0)); out.push_back(static_cast<uint8_t>(0));
                    break;
                case Kind::Int64:
                    PutU32LE(out, kTypeInt64);
                    PutU64LE(out, static_cast<uint64_t>(obj.intValue));
                    break;
                case Kind::UInt64:
                    PutU32LE(out, kTypeUInt64);
                    PutU64LE(out, obj.uintValue);
                    break;
                case Kind::Double: {
                    PutU32LE(out, kTypeDouble);
                    uint64_t raw = 0;
                    std::memcpy(&raw, &obj.doubleValue, 8);
                    PutU64LE(out, raw);
                    break;
                }
                case Kind::String: {
                    PutU32LE(out, kTypeString);
                    uint32_t l = static_cast<uint32_t>(obj.stringValue.size() + 1);
                    PutU32LE(out, l);
                    out.insert(out.end(), obj.stringValue.begin(), obj.stringValue.end());
                    out.push_back(static_cast<uint8_t>(0));
                    for (size_t i = 0; i < Padding(l); ++i) out.push_back(static_cast<uint8_t>(0));
                    break;
                }
                case Kind::Data: {
                    PutU32LE(out, kTypeData);
                    uint32_t l = static_cast<uint32_t>(obj.dataValue.size());
                    PutU32LE(out, l);
                    out.insert(out.end(), obj.dataValue.begin(), obj.dataValue.end());
                    for (size_t i = 0; i < Padding(l); ++i) out.push_back(static_cast<uint8_t>(0));
                    break;
                }
                case Kind::Uuid:
                    PutU32LE(out, kTypeUuid);
                    out.insert(out.end(), obj.dataValue.begin(), obj.dataValue.begin() + 16);
                    break;
                case Kind::Array: {
                    PutU32LE(out, kTypeArray);
                    std::vector<uint8_t> content;
                    PutU32LE(content, static_cast<uint32_t>(obj.arrayValue.size()));
                    for (const auto& item : obj.arrayValue) Run(item, content);
                    PutU32LE(out, static_cast<uint32_t>(content.size()));
                    out.insert(out.end(), content.begin(), content.end());
                    break;
                }
                case Kind::Dictionary: {
                    PutU32LE(out, kTypeDictionary);
                    std::vector<uint8_t> content;
                    PutU32LE(content, static_cast<uint32_t>(obj.dictValue.size()));
                    for (const auto& kv : obj.dictValue) {
                        uint32_t klen = static_cast<uint32_t>(kv.first.size() + 1);
                        content.insert(content.end(), kv.first.begin(), kv.first.end());
                        content.push_back(static_cast<uint8_t>(0));
                        for (size_t i = 0; i < Padding(klen); ++i) content.push_back(static_cast<uint8_t>(0));
                        Run(kv.second, content);
                    }
                    PutU32LE(out, static_cast<uint32_t>(content.size()));
                    out.insert(out.end(), content.begin(), content.end());
                    break;
                }
            }
        }
    };
    Encoder::Run(*this, buf);
    return buf;
}

bool XpcObject::Decode(const uint8_t* data, size_t len, XpcObject* out) {
    if (len < 8) return false;
    uint32_t magic = 0, version = 0;
    if (!GetU32LE(data, len, 0, &magic) || magic != kXpcObjectMagic) return false;
    if (!GetU32LE(data, len, 4, &version) || version != kXpcObjectVersion) return false;
    size_t off = 8;
    return DecodeObjectAt(data, len, &off, out);
}

// ------------------------------------------------------- RemoteXpcConnection

RemoteXpcConnection::~RemoteXpcConnection() { Close(); }

void RemoteXpcConnection::Close() {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
}

bool RemoteXpcConnection::WaitReadable(std::chrono::milliseconds timeout) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(socket_, &rset);
    timeval tv{};
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    return select(0, &rset, nullptr, nullptr, &tv) > 0;
}

bool RemoteXpcConnection::ReadExact(uint8_t* buf, size_t len,
                                     std::chrono::steady_clock::time_point deadline) {
    size_t got = 0;
    while (got < len) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return false;
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        if (!WaitReadable(left)) return false;
        int n = recv(socket_, reinterpret_cast<char*>(buf + got),
                     static_cast<int>(len - got), 0);
        if (n == 0) return false; // peer closed
        if (n < 0) {
            int e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK) continue;
            return false;
        }
        got += static_cast<size_t>(n);
    }
    return true;
}

bool RemoteXpcConnection::WriteRaw(const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(socket_, reinterpret_cast<const char*>(data + sent),
                     static_cast<int>(len - sent), 0);
        if (n <= 0) {
            int e = WSAGetLastError();
            if (n < 0 && e == WSAEWOULDBLOCK) continue;
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

namespace {
void PutHttp2FrameHeader(std::vector<uint8_t>& out, uint32_t payloadLen,
                          uint8_t type, uint8_t flags, uint32_t streamId) {
    out.push_back(static_cast<uint8_t>((payloadLen >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((payloadLen >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(payloadLen & 0xFF));
    out.push_back(type);
    out.push_back(flags);
    out.push_back(static_cast<uint8_t>((streamId >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((streamId >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((streamId >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(streamId & 0xFF));
}
} // namespace

bool RemoteXpcConnection::SendSettings(const std::vector<std::pair<uint16_t, uint32_t>>& settings,
                                        uint32_t streamId, uint8_t flags) {
    std::vector<uint8_t> payload;
    for (const auto& s : settings) {
        payload.push_back(static_cast<uint8_t>((s.first >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(s.first & 0xFF));
        payload.push_back(static_cast<uint8_t>((s.second >> 24) & 0xFF));
        payload.push_back(static_cast<uint8_t>((s.second >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((s.second >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(s.second & 0xFF));
    }
    std::vector<uint8_t> frame;
    PutHttp2FrameHeader(frame, static_cast<uint32_t>(payload.size()), /*SETTINGS*/ 0x04, flags, streamId);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return WriteRaw(frame.data(), frame.size());
}

bool RemoteXpcConnection::SendWindowUpdate(uint32_t increment, uint32_t streamId) {
    std::vector<uint8_t> frame;
    PutHttp2FrameHeader(frame, 4, /*WINDOW_UPDATE*/ 0x08, 0x00, streamId);
    frame.push_back(static_cast<uint8_t>((increment >> 24) & 0xFF));
    frame.push_back(static_cast<uint8_t>((increment >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((increment >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(increment & 0xFF));
    return WriteRaw(frame.data(), frame.size());
}

bool RemoteXpcConnection::SendHeadersOpen(uint32_t streamId) {
    // Deliberately not a real HPACK header block — RemoteXPC only uses the
    // HEADERS frame to allocate a stream number on this connection, per
    // idevice's HeadersFrame::serialize() ("we don't actually care about
    // this frame according to spec"). END_HEADERS (0x04) with an empty
    // payload is what that reference sends and what T2's peer accepts.
    std::vector<uint8_t> frame;
    PutHttp2FrameHeader(frame, 0, /*HEADERS*/ 0x01, /*END_HEADERS*/ 0x04, streamId);
    return WriteRaw(frame.data(), frame.size());
}

bool RemoteXpcConnection::SendDataFrame(uint32_t streamId, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    PutHttp2FrameHeader(frame, static_cast<uint32_t>(payload.size()), /*DATA*/ 0x00, 0x00, streamId);
    frame.insert(frame.end(), payload.begin(), payload.end());
    return WriteRaw(frame.data(), frame.size());
}

bool RemoteXpcConnection::SendXpcMessage(uint32_t streamId, uint32_t flags,
                                          const XpcObject* body, uint64_t messageId) {
    std::vector<uint8_t> wrapper;
    PutU32LE(wrapper, kXpcMessageMagic);
    PutU32LE(wrapper, flags);
    if (body) {
        std::vector<uint8_t> encoded = body->Encode();
        PutU64LE(wrapper, encoded.size());
        PutU64LE(wrapper, messageId);
        wrapper.insert(wrapper.end(), encoded.begin(), encoded.end());
    } else {
        PutU64LE(wrapper, 0);
        PutU64LE(wrapper, messageId);
    }
    return SendDataFrame(streamId, wrapper);
}

bool RemoteXpcConnection::ReadDataFrame(uint32_t wantStreamId, std::vector<uint8_t>* outPayload,
                                         std::chrono::steady_clock::time_point deadline,
                                         RemoteXpcResult* result) {
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) {
            *result = RemoteXpcResult::PeerRecordTimeout;
            return false;
        }
        uint8_t header[9];
        if (!ReadExact(header, sizeof(header), deadline)) {
            *result = RemoteXpcResult::PeerRecordTimeout;
            return false;
        }
        uint32_t payloadLen = (static_cast<uint32_t>(header[0]) << 16) |
                               (static_cast<uint32_t>(header[1]) << 8) |
                               static_cast<uint32_t>(header[2]);
        uint8_t type = header[3];
        uint8_t flags = header[4];
        uint32_t streamId = (static_cast<uint32_t>(header[5]) << 24) |
                             (static_cast<uint32_t>(header[6]) << 16) |
                             (static_cast<uint32_t>(header[7]) << 8) |
                             static_cast<uint32_t>(header[8]);
        std::vector<uint8_t> payload(payloadLen);
        if (payloadLen > 0 && !ReadExact(payload.data(), payloadLen, deadline)) {
            *result = RemoteXpcResult::PeerRecordTimeout;
            return false;
        }

        switch (type) {
            case 0x04: // SETTINGS
                if ((flags & 0x01) == 0) {
                    // Not an ACK from the peer's point of view — ACK it so
                    // the peer doesn't stall waiting for us (idevice does
                    // the same in Http2Client::read).
                    SendSettings({}, streamId, /*ACK*/ 0x01);
                }
                break;
            case 0x00: // DATA
                if (streamId == wantStreamId && payloadLen > 0) {
                    *outPayload = std::move(payload);
                    return true;
                }
                // Data for a channel we're not currently waiting on
                // (keepalives on another stream, etc.) — drop it; this
                // one-shot client never needs more than the root channel.
                break;
            case 0x03: // RST_STREAM
                *result = RemoteXpcResult::PeerReset;
                return false;
            case 0x07: // GOAWAY
                *result = RemoteXpcResult::PeerGoAway;
                return false;
            default:
                break; // HEADERS, WINDOW_UPDATE, PING, etc. — nothing to act on
        }
    }
}

RemoteXpcResult RemoteXpcConnection::Connect(const NcmEndpoint& endpoint, uint16_t port,
                                              std::chrono::milliseconds connectTimeout) {
    socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) return RemoteXpcResult::ConnectFailed;

    DWORD ifIndex = endpoint.ifIndex;
    setsockopt(socket_, IPPROTO_IPV6, IPV6_UNICAST_IF,
               reinterpret_cast<const char*>(&ifIndex), sizeof(ifIndex));
    BOOL nodelay = TRUE;
    setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    u_long nonblock = 1;
    ioctlsocket(socket_, FIONBIO, &nonblock);

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = endpoint.peerLinkLocal;
    addr.sin6_scope_id = endpoint.ifIndex;

    int cr = connect(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (cr != 0) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            Close();
            return RemoteXpcResult::ConnectFailed;
        }
        fd_set wset, eset;
        FD_ZERO(&wset); FD_ZERO(&eset);
        FD_SET(socket_, &wset); FD_SET(socket_, &eset);
        timeval tv{};
        tv.tv_sec = static_cast<long>(connectTimeout.count() / 1000);
        tv.tv_usec = static_cast<long>((connectTimeout.count() % 1000) * 1000);
        int sel = select(0, nullptr, &wset, &eset, &tv);
        if (sel <= 0 || FD_ISSET(socket_, &eset)) {
            Close();
            return RemoteXpcResult::ConnectFailed;
        }
        int soerr = 0;
        int solen = sizeof(soerr);
        getsockopt(socket_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &solen);
        if (soerr != 0) {
            Close();
            return RemoteXpcResult::ConnectFailed;
        }
    }

    static constexpr char kHttp2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (!WriteRaw(reinterpret_cast<const uint8_t*>(kHttp2Preface), sizeof(kHttp2Preface) - 1)) {
        Close();
        return RemoteXpcResult::PrefaceFailed;
    }
    return RemoteXpcResult::Ok;
}

RemoteXpcResult RemoteXpcConnection::FetchPeerRecord(std::chrono::milliseconds timeout,
                                                      XpcObject* outPeerRecord) {
    if (socket_ == INVALID_SOCKET) return RemoteXpcResult::HandshakeIoFailed;
    auto deadline = std::chrono::steady_clock::now() + timeout;

    // --- do_handshake() ---------------------------------------------------
    if (!SendSettings({{static_cast<uint16_t>(0x0003), static_cast<uint32_t>(100)},
                       {static_cast<uint16_t>(0x0004), static_cast<uint32_t>(1048576)}},
                      /*stream*/ 0, /*flags*/ 0x00)) {
        return RemoteXpcResult::HandshakeIoFailed;
    }
    if (!SendWindowUpdate(983041, /*stream*/ 0)) {
        return RemoteXpcResult::HandshakeIoFailed;
    }
    if (!SendHeadersOpen(/*root channel*/ 1)) {
        return RemoteXpcResult::HandshakeIoFailed;
    }
    {
        XpcObject emptyDict = XpcObject::MakeDict();
        if (!SendXpcMessage(1, kFlagAlwaysSet, &emptyDict, kRootMessageId)) {
            return RemoteXpcResult::HandshakeIoFailed;
        }
    }
    if (!SendHeadersOpen(/*reply channel*/ 3)) {
        return RemoteXpcResult::HandshakeIoFailed;
    }
    if (!SendXpcMessage(3, kFlagInitHandshake | kFlagAlwaysSet, nullptr, kRootMessageId)) {
        return RemoteXpcResult::HandshakeIoFailed;
    }
    if (!SendXpcMessage(1, kFlagCustomHandshakeTail, nullptr, kRootMessageId)) {
        return RemoteXpcResult::HandshakeIoFailed;
    }

    // --- send_device_handshake() ------------------------------------------
    {
        XpcObject props = XpcObject::MakeDict();
        // RemoteXPCVersionFlags = 0x0100_0000_0000_0006 (idevice
        // REMOTE_XPC_VERSION_FLAGS constant).
        props.SetField("RemoteXPCVersionFlags", XpcObject::MakeUInt64(0x0100000000000006ULL));
        props.SetField("SensitivePropertiesVisible", XpcObject::MakeBool(true));

        XpcObject handshake = XpcObject::MakeDict();
        handshake.SetField("MessageType", XpcObject::MakeString("Handshake"));
        handshake.SetField("MessagingProtocolVersion", XpcObject::MakeUInt64(7));
        handshake.SetField("UUID", XpcObject::MakeUuidRandom());
        handshake.SetField("Properties", props);
        handshake.SetField("Services", XpcObject::MakeDict());

        // send_object(msg, expect_reply=false) -> DataFlag|AlwaysSet, no
        // WantingReply, sent on the root channel with the root message id.
        if (!SendXpcMessage(1, kFlagDataFlag | kFlagAlwaysSet, &handshake, kRootMessageId)) {
            return RemoteXpcResult::HandshakeIoFailed;
        }
    }

    // --- receive_response(): one non-empty message off the root channel ---
    for (;;) {
        std::vector<uint8_t> frame;
        RemoteXpcResult err = RemoteXpcResult::Ok;
        if (!ReadDataFrame(/*root channel*/ 1, &frame, deadline, &err)) {
            return err;
        }
        if (frame.size() < 24) continue; // not a full wrapper; ignore and keep reading

        uint32_t magic = 0, flags = 0;
        uint64_t bodyLen = 0, msgId = 0;
        if (!GetU32LE(frame.data(), frame.size(), 0, &magic) || magic != kXpcMessageMagic) {
            return RemoteXpcResult::PeerRecordMalformed;
        }
        if (!GetU32LE(frame.data(), frame.size(), 4, &flags)) return RemoteXpcResult::PeerRecordMalformed;
        if (!GetU64LE(frame.data(), frame.size(), 8, &bodyLen)) return RemoteXpcResult::PeerRecordMalformed;
        if (!GetU64LE(frame.data(), frame.size(), 16, &msgId)) return RemoteXpcResult::PeerRecordMalformed;
        (void)msgId;
        if (bodyLen == 0) continue; // bodyless/keepalive frame, per RemoteXpcClient::recv_from_channel

        if (24 + bodyLen > frame.size()) return RemoteXpcResult::PeerRecordMalformed;

        XpcObject decoded;
        if (!XpcObject::Decode(frame.data() + 24, static_cast<size_t>(bodyLen), &decoded)) {
            return RemoteXpcResult::PeerRecordMalformed;
        }
        if (decoded.kind == XpcObject::Kind::Dictionary && decoded.dictValue.empty()) {
            continue; // empty-dictionary keepalive, per recv_from_channel
        }
        *outPeerRecord = std::move(decoded);
        return RemoteXpcResult::Ok;
    }
}

// --------------------------------------------------------- DiscoverServicePort

DiscoveredService DiscoverServicePort(const NcmEndpoint& endpoint,
                                       const std::vector<uint16_t>& candidatePorts,
                                       const std::string& serviceName,
                                       std::chrono::milliseconds perPortTimeout) {
    DiscoveredService result;
    if (candidatePorts.empty()) return result;

    // OPTIMIZATION: this used to be a plain sequential for-loop, up to
    // perPortTimeout (2000ms) TWICE per candidate (Connect + FetchPeerRecord)
    // before moving on — worst case ~candidatePorts.size() * 4s. Now a
    // worker pool, same pattern as PortScan.cpp's ScanHttp2Preface.
    //
    // Dispatch is still ascending from index 0 (REVERTED comment above
    // explains why — no heuristic here, matches the Linux reference), and
    // with candidatePorts.size() normally well under the 64-worker cap,
    // every candidate typically starts probing in the same instant rather
    // than one after another.
    //
    // Ascending order is preserved as the tie-break, not just the dispatch
    // order: bestIndex below only ever moves to a *lower* index, so if two
    // workers both find a match, the one that was earlier in
    // candidatePorts wins — identical semantics to the old sequential
    // "first match in scan order" behavior, just computed concurrently.
    //
    // No hard cancellation of in-flight probes: RemoteXpcConnection's
    // Connect/FetchPeerRecord are blocking calls captured by reference in
    // the worker lambda, so detaching a thread mid-call to "stop
    // immediately" would leave dangling references into this function's
    // locals the moment it returns — not safe. What "found -> stop
    // immediately" means here is workers stop pulling *new* candidates
    // the moment a match exists; already-dispatched probes still run to
    // completion (bounded by perPortTimeout) and can still improve the
    // answer if they turn out to have a lower index. In practice, with
    // candidate counts this small, effectively all of them are already
    // in flight before any answer comes back anyway.
    const size_t total = candidatePorts.size();
    std::atomic<size_t> next{0};
    std::atomic<bool> found{false};
    std::atomic<size_t> bestIndex{static_cast<size_t>(-1)};
    std::mutex resultMu;

    unsigned workers = static_cast<unsigned>(total);
    if (workers > 64) workers = 64;
    if (workers == 0) workers = 1;

    auto probeOne = [&](size_t idx) {
        uint16_t port = candidatePorts[idx];
        RemoteXpcConnection conn;
        if (conn.Connect(endpoint, port, perPortTimeout) != RemoteXpcResult::Ok) {
            return; // couldn't even open this candidate — try the next one
        }
        XpcObject peerRecord;
        if (conn.FetchPeerRecord(perPortTimeout, &peerRecord) != RemoteXpcResult::Ok) {
            // Several other T2 services share this HTTP/2 transport but
            // reject or never complete an RSD handshake — expected decoys,
            // not a discovery failure (matches discover-biometric-port.py's
            // blanket `except Exception: continue`).
            return;
        }
        const XpcObject* services = peerRecord.FindField("Services");
        if (!services || services->kind != XpcObject::Kind::Dictionary) return;
        const XpcObject* service = services->FindField(serviceName);
        if (!service || service->kind != XpcObject::Kind::Dictionary) return;
        const XpcObject* portField = service->FindField("Port");
        if (!portField) return;
        uint64_t portValue = 0;
        if (portField->kind == XpcObject::Kind::UInt64) portValue = portField->uintValue;
        else if (portField->kind == XpcObject::Kind::Int64) portValue = static_cast<uint64_t>(portField->intValue);
        else if (portField->kind == XpcObject::Kind::String) {
            try { portValue = std::stoull(portField->stringValue); } catch (...) { return; }
        } else {
            return;
        }
        if (portValue == 0 || portValue > 65535) return; // not a plausible dynamic port

        size_t expected = bestIndex.load(std::memory_order_relaxed);
        while (idx < expected) {
            if (bestIndex.compare_exchange_weak(expected, idx,
                    std::memory_order_relaxed, std::memory_order_relaxed)) {
                std::lock_guard<std::mutex> lock(resultMu);
                result.found = true;
                result.port = static_cast<uint16_t>(portValue);
                found.store(true, std::memory_order_relaxed);
                break;
            }
            // expected was refreshed by the failed CAS; loop re-checks
            // idx < expected in case another, even-earlier index just won.
        }
    };

    auto worker = [&]() {
        for (;;) {
            size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= total) break;
            if (found.load(std::memory_order_relaxed) &&
                i > bestIndex.load(std::memory_order_relaxed)) {
                // A strictly-earlier match already won; this candidate
                // could never change the answer even if it also matches.
                continue;
            }
            probeOne(i);
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (unsigned w = 0; w < workers; ++w) threads.emplace_back(worker);
    for (auto& th : threads) th.join();

    return result;
}


} // namespace t2::discovery
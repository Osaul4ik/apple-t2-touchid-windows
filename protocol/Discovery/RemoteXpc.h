// SPDX-License-Identifier: GPL-2.0-only
// RemoteXpc.h — Gate 6 Phase 2: RemoteXPC control-channel handshake and
// peer-record ("Services" dictionary) retrieval, run against the HTTP/2
// candidate ports PortScan.cpp already finds.
//
// VERIFIED FROM SOURCE: the Linux reference (discover-biometric-port.py)
// does not reimplement RemoteXPC itself — it calls
// pymobiledevice3.remote.remotexpc.RemoteXPCConnection and only wires the
// discovery loop around it. The actual wire format here (HTTP/2 framing +
// XPC binary object encoding) is taken from jkcoxson/idevice's clean-room
// Rust reimplementation of that same client (src/xpc/http2/{mod,frame}.rs,
// src/xpc/{mod,format}.rs — MIT, "ported from pymobiledevice3"), which is
// the closest available verification source for the byte-level protocol:
//
//   - HTTP/2: standard client preface ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
//     then a deliberately non-HPACK-compliant HEADERS frame (empty payload,
//     END_HEADERS only) used purely to "open" a stream number, then
//     ordinary SETTINGS / WINDOW_UPDATE / DATA frames.
//   - XPC message wrapper: magic 0x29b00b92 (LE) + flags (LE u32) +
//     body_len (LE u64) + message_id (LE u64) + body.
//   - XPC object stream (the body): magic 0x42133742 (LE) + version
//     0x00000005 (LE), then a tagged-union encoding (Dictionary/Array/
//     String/Data/UInt64/Int64/Double/Bool/Uuid/Null, each 4-byte LE type
//     tag followed by a type-specific payload, strings/data/dict/array
//     padded to 4-byte alignment).
//
// Every failure path here returns a specific RemoteXpcResult — no
// "assume it worked" branch (Milestone 2 §10/§27, same rule PortScan.cpp
// and t2touchid.exe follow).
#pragma once
#include "Adapter.h"
#include <cstdint>
#include <string>
#include <vector>
#include <utility>
#include <chrono>
#include <winsock2.h>

namespace t2::discovery {

// Minimal XPC object model — only the variants the RemoteXPC handshake and
// peer record actually use. IndexMap-equivalent: dictValue preserves
// insertion/decode order because encode() must round-trip deterministically,
// but Find() below is what callers use to read a decoded peer record.
struct XpcObject {
    enum class Kind {
        Null, Bool, Int64, UInt64, Double, String, Data, Uuid, Array, Dictionary
    } kind = Kind::Null;

    bool boolValue = false;
    int64_t intValue = 0;
    uint64_t uintValue = 0;
    double doubleValue = 0.0;
    std::string stringValue;
    std::vector<uint8_t> dataValue;                              // Data, and raw 16-byte Uuid
    std::vector<XpcObject> arrayValue;
    std::vector<std::pair<std::string, XpcObject>> dictValue;    // Dictionary entries, in order

    static XpcObject MakeDict() { XpcObject o; o.kind = Kind::Dictionary; return o; }
    static XpcObject MakeString(std::string s) {
        XpcObject o; o.kind = Kind::String; o.stringValue = std::move(s); return o;
    }
    static XpcObject MakeUInt64(uint64_t v) { XpcObject o; o.kind = Kind::UInt64; o.uintValue = v; return o; }
    static XpcObject MakeInt64(int64_t v) { XpcObject o; o.kind = Kind::Int64; o.intValue = v; return o; }
    static XpcObject MakeBool(bool v) { XpcObject o; o.kind = Kind::Bool; o.boolValue = v; return o; }
    // 16 random bytes with the RFC 4122 v4 version/variant bits set —
    // matches uuid::Uuid::new_v4() used by send_device_handshake().
    static XpcObject MakeUuidRandom();

    // Dictionary-only helpers. SetField is a no-op (does not append) if
    // called on a non-Dictionary.
    void SetField(const std::string& key, XpcObject value);
    const XpcObject* FindField(const std::string& key) const;

    // Encodes the full object stream: magic + version + tagged object.
    // This is what goes directly into an XPC message wrapper's body.
    std::vector<uint8_t> Encode() const;

    // Inverse of Encode(). Returns false (leaving *out unspecified) on any
    // malformed/truncated/unknown-type input — never a partial object.
    static bool Decode(const uint8_t* data, size_t len, XpcObject* out);
};

enum class RemoteXpcResult {
    Ok,
    ConnectFailed,
    PrefaceFailed,
    HandshakeIoFailed,
    HandshakeTimeout,
    PeerRecordTimeout,
    PeerRecordMalformed,
    PeerGoAway,
    PeerReset,
};

// One-shot connection, matching both BridgeXpc::Connection's documented
// policy (a fresh connection per attempt, not a reusable session — see
// BridgeXpc/Connection.h) and discover-biometric-port.py's outer loop,
// which opens a brand-new RemoteXPCConnection per candidate port.
class RemoteXpcConnection {
public:
    RemoteXpcConnection() = default;
    ~RemoteXpcConnection();
    RemoteXpcConnection(const RemoteXpcConnection&) = delete;
    RemoteXpcConnection& operator=(const RemoteXpcConnection&) = delete;

    // Opens the TCP connection to endpoint.peerLinkLocal%endpoint.ifIndex
    // on `port` and sends the raw HTTP/2 client preface. Does not yet do
    // the RemoteXPC-level handshake — see FetchPeerRecord.
    RemoteXpcResult Connect(const NcmEndpoint& endpoint, uint16_t port,
                             std::chrono::milliseconds connectTimeout);

    // Runs, in order: do_handshake() (SETTINGS + WINDOW_UPDATE + open root
    // channel 1 + open reply channel 3 + the three handshake frames), then
    // send_device_handshake() on the root channel, then reads exactly one
    // non-empty message back from the root channel — the peer record.
    // This is the C++ equivalent of pymobiledevice3's
    // RemoteXPCConnection.connect() + send_device_handshake() +
    // receive_response(), which is all discover-biometric-port.py calls.
    RemoteXpcResult FetchPeerRecord(std::chrono::milliseconds timeout, XpcObject* outPeerRecord);

    void Close();

private:
    SOCKET socket_ = INVALID_SOCKET;
    static constexpr uint64_t kRootMessageId = 1; // matches RemoteXpcClient::root_id

    bool WriteRaw(const uint8_t* data, size_t len);
    bool WaitReadable(std::chrono::milliseconds timeout);
    bool ReadExact(uint8_t* buf, size_t len, std::chrono::steady_clock::time_point deadline);

    bool SendSettings(const std::vector<std::pair<uint16_t, uint32_t>>& settings,
                       uint32_t streamId, uint8_t flags);
    bool SendWindowUpdate(uint32_t increment, uint32_t streamId);
    bool SendHeadersOpen(uint32_t streamId);
    bool SendDataFrame(uint32_t streamId, const std::vector<uint8_t>& payload);
    bool SendXpcMessage(uint32_t streamId, uint32_t flags, const XpcObject* body, uint64_t messageId);

    // Reads raw HTTP/2 frames until a non-empty DATA frame lands on
    // wantStreamId, auto-ACKing peer SETTINGS and skipping frame types we
    // don't act on. Returns false (with *result set) on timeout, GOAWAY,
    // RST_STREAM, or any I/O error.
    bool ReadDataFrame(uint32_t wantStreamId, std::vector<uint8_t>* outPayload,
                        std::chrono::steady_clock::time_point deadline,
                        RemoteXpcResult* result);
};

struct DiscoveredService {
    bool found = false;
    uint16_t port = 0;
};

// Tries each candidate port from the END of candidatePorts backward (see
// the 16.09.2026 real-hardware finding in RemoteXpc.cpp for why - this
// deliberately diverges from discover-biometric-port.py's ascending
// `for candidate_port in candidate_ports` walk): connect, handshake, read
// the peer record, look for Services[serviceName]["Port"]. A port that
// answers RemoteXPC but does not advertise serviceName is a decoy — the
// loop moves on to the next candidate rather than reporting it as a match.
DiscoveredService DiscoverServicePort(const NcmEndpoint& endpoint,
                                       const std::vector<uint16_t>& candidatePorts,
                                       const std::string& serviceName,
                                       std::chrono::milliseconds perPortTimeout);

} // namespace t2::discovery
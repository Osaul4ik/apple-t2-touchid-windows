// Frame.h — BridgeXpc/T2BridgeXpc
//
// Wire format VERIFIED FROM SOURCE (Milestone 1, section 7):
//   u16 magic (0xB892, LE) | u16 version (1) | u32 frame_type | u64 body_length | body
// frame_type: 1 = HELO (JSON body), 2 = MESSAGE (binary plist body: a
// 4-element array [version, is_reply, request_id(uuid-string), payload]).
//
// Every length is validated against a fixed maximum BEFORE any allocation
// (Milestone 2, section 14/15 requirement) — this header only deals with
// the frame envelope; binary-plist parsing is delegated to libplist
// (see PlistPayload.h) rather than hand-rolled, per section 15.

#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace t2::bridgexpc {

constexpr uint16_t kFrameMagic = 0xB892;
constexpr uint16_t kProtocolVersion = 1;

// Hard ceiling independent of whatever the remote peer claims in
// body_length. VERIFIED FROM SOURCE gives no upper bound from Apple's side,
// so this is a defensive, locally chosen limit (INFERRED-safe, not a
// protocol fact) sized generously above the largest observed body (FDR
// calibration blob) with headroom, and documented as such.
constexpr uint64_t kMaxFrameBodyBytes = 4u * 1024u * 1024u; // 4 MiB

enum class FrameType : uint32_t {
    Helo = 1,
    Message = 2,
};

struct FrameHeader {
    uint16_t magic;
    uint16_t version;
    uint32_t frameType;
    uint64_t bodyLength;
};

enum class ParseResult {
    Ok,
    Incomplete,        // need more bytes, not an error
    BadMagic,
    BadVersion,
    BodyTooLarge,
    UnknownFrameType,
};

// Parses only the fixed 16-byte header. Caller is responsible for reading
// exactly `bodyLength` further bytes (bounded by kMaxFrameBodyBytes) before
// interpreting the body. This split exists so a truncated body never causes
// an over-read: the header parse fails closed (BodyTooLarge) before any
// body buffer is sized off remote input.
ParseResult ParseFrameHeader(const uint8_t* data, size_t len, FrameHeader* out);

// Highest-level entry point used by Connection: reads a full frame off a
// blocking socket with a caller-supplied timeout. Returns std::nullopt on
// timeout/EOF/protocol error (all fail-closed — never partial garbage).
struct RawFrame {
    FrameType type;
    std::vector<uint8_t> body;
};

} // namespace t2::bridgexpc

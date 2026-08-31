// SPDX-License-Identifier: GPL-2.0-only
// Frame.cpp
#include "Frame.h"
#include <cstring>

namespace t2::bridgexpc {

ParseResult ParseFrameHeader(const uint8_t* data, size_t len, FrameHeader* out) {
    constexpr size_t kHeaderSize = 2 + 2 + 4 + 8;
    if (len < kHeaderSize) {
        return ParseResult::Incomplete;
    }

    uint16_t magic;
    uint16_t version;
    uint32_t frameType;
    uint64_t bodyLength;

    std::memcpy(&magic, data + 0, 2);
    std::memcpy(&version, data + 2, 2);
    std::memcpy(&frameType, data + 4, 4);
    std::memcpy(&bodyLength, data + 8, 8);
    // All fields little-endian on the wire (VERIFIED FROM SOURCE); this
    // code assumes a little-endian build target (x86/x64/ARM64 all LE),
    // which covers every realistic Windows 11 target for this project.

    if (magic != kFrameMagic) {
        return ParseResult::BadMagic;
    }
    if (version != kProtocolVersion) {
        return ParseResult::BadVersion;
    }
    if (bodyLength > kMaxFrameBodyBytes) {
        return ParseResult::BodyTooLarge;
    }
    if (frameType != static_cast<uint32_t>(FrameType::Helo) &&
        frameType != static_cast<uint32_t>(FrameType::Message)) {
        return ParseResult::UnknownFrameType;
    }

    out->magic = magic;
    out->version = version;
    out->frameType = frameType;
    out->bodyLength = bodyLength;
    return ParseResult::Ok;
}

} // namespace t2::bridgexpc

// SPDX-License-Identifier: GPL-2.0-only
// Commands.cpp
#include "Commands.h"
#include <cstring>

namespace t2::biometrickit {

constexpr size_t kMaxLocalIdentities = 256; // local defensive cap, not a protocol fact

std::vector<uint8_t> EncodeBmCommand(Command command, uint16_t version, uint16_t value,
                                      const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(sizeof(BmHeader) + data.size());
    BmHeader hdr{};
    hdr.magic = kBmMagic;
    hdr.command = static_cast<uint16_t>(command);
    hdr.version = version;
    hdr.value = value;
    std::memcpy(out.data(), &hdr, sizeof(hdr));
    if (!data.empty()) {
        std::memcpy(out.data() + sizeof(hdr), data.data(), data.size());
    }
    return out;
}

std::vector<uint8_t> EncodeMatchInitData(uint32_t flags, uint32_t macosUserId,
                                          const std::vector<IdentityRecordV1>& identities) {
    size_t count = identities.size();
    if (count > kMaxLocalIdentities) {
        count = kMaxLocalIdentities; // never send more than sane local cap
    }

    MatchInitDataV1 header{};
    header.flags = flags;
    header.macosUserId = macosUserId;
    header.identityCount = static_cast<uint32_t>(count);

    std::vector<uint8_t> out(sizeof(header) + count * sizeof(IdentityRecordV1));
    std::memcpy(out.data(), &header, sizeof(header));
    for (size_t i = 0; i < count; i++) {
        std::memcpy(out.data() + sizeof(header) + i * sizeof(IdentityRecordV1),
                    &identities[i], sizeof(IdentityRecordV1));
    }
    return out;
}

bool ParseIdentityList(const std::vector<uint8_t>& replyBody,
                        std::vector<IdentityRecordV1>* outIdentities) {
    outIdentities->clear();
    if (replyBody.size() % sizeof(IdentityRecordV1) != 0) {
        return false; // malformed: not a whole number of 20-byte records
    }
    size_t count = replyBody.size() / sizeof(IdentityRecordV1);
    if (count > kMaxLocalIdentities) {
        return false; // implausible device-reported count: fail closed, don't just truncate
    }
    outIdentities->resize(count);
    std::memcpy(outIdentities->data(), replyBody.data(), replyBody.size());
    return true;
}

} // namespace t2::biometrickit

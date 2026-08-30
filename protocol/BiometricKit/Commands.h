// Commands.h — T2BiometricKit
//
// All structures/IDs VERIFIED FROM SOURCE (Milestone 1, section 7).
// Only commands Milestone 2 section 16 lists are implemented; adding a new
// command ID requires updating docs/linux-reference-analysis.md provenance
// first, per the "no undocumented protocol" rule.

#pragma once
#include <cstdint>
#include <vector>
#include <array>

namespace t2::biometrickit {

#pragma pack(push, 1)
struct BmHeader {
    uint16_t magic;   // 0x4D42 ("BM")
    uint16_t command;
    uint16_t version;
    uint16_t value;
    // variable-length data follows
};

struct IdentityRecordV1 {
    uint32_t userId;
    std::array<uint8_t, 16> uuid; // opaque; never logged in full (Milestone 1 §7, §14)
};
static_assert(sizeof(uint32_t) + 16 == 20, "identity_record_v1_t must be 20 bytes");

struct MatchInitDataV1 {
    uint32_t flags;
    uint32_t macosUserId;
    std::array<uint8_t, 60> reserved{};
    uint32_t identityCount;
    // followed by identityCount * IdentityRecordV1
};
#pragma pack(pop)

constexpr uint16_t kBmMagic = 0x4D42;

enum class Command : uint16_t {
    ProtocolVersion   = 1,
    ResetSensor       = 2,
    StartMatch        = 4,
    Cancel            = 0x0c,
    LoadCalibration   = 0x20,
    SensorInfo        = 0x35,
    CatacombState     = 0x3c,
    IdentityList      = 0x42,
    SensorReadiness   = 0x53,
};

constexpr uint32_t kEmbeddedTypeStatus      = 0xE3FF8001;
constexpr uint32_t kEmbeddedTypeMatchResult = 0xE3FF8002;
constexpr uint32_t kEmbeddedTypeStatistics  = 0xE3FF8004;

// Serializes a BM-wrapped command: magic|command|version|value|data.
std::vector<uint8_t> EncodeBmCommand(Command command, uint16_t version, uint16_t value,
                                      const std::vector<uint8_t>& data = {});

// Serializes match_init_data_v1 + identity records. identities is capped
// at a sane local maximum (256) independent of any device-reported count,
// per "never trust remote length before allocation".
std::vector<uint8_t> EncodeMatchInitData(uint32_t flags, uint32_t macosUserId,
                                          const std::vector<IdentityRecordV1>& identities);

// Parses a raw identity-list reply body into 20-byte records. Returns false
// (and an empty vector) on any length mismatch — never truncates silently.
bool ParseIdentityList(const std::vector<uint8_t>& replyBody,
                        std::vector<IdentityRecordV1>* outIdentities);

} // namespace t2::biometrickit

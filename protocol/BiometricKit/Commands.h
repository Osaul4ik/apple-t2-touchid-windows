// SPDX-License-Identifier: GPL-2.0-only
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

// LEGACY LAYOUT ONLY - see MatchIdentityLayout below and
// docs/macos-verified-status-map.md section 3.
//
// This struct was derived from the Linux reference's "68-byte match
// options structure". A 16.09.2026 macOS unified-log capture on the very
// same machine (bridgeOS 23P5067, uid 501, 3 enrolled identities) shows
// biometrickitd issuing start-match as:
//
//   performCommand:version:inValue:inData:inSize: 4 1 0 <ptr> 68
//
// i.e. the WHOLE inner payload of command 4 is 68 bytes - not 68 bytes of
// options plus a counted identity blob (which is 68 + 4 + 3*20 = 132
// bytes, exactly what this project was sending). 68 == 8 + 3*20 == a small
// fixed header plus the three identity records verbatim, which also
// explains why the Linux-derived struct appeared to carry "60 reserved
// bytes": on a machine with three enrolled fingers those 60 bytes ARE the
// identity array.
struct MatchInitDataV1 {
    uint32_t flags;
    uint32_t macosUserId;
    std::array<uint8_t, 60> reserved{};
};
static_assert(sizeof(MatchInitDataV1) == 68, "match_init_data_v1_t must be 68 bytes");

// Fixed header that precedes the inline identity records in the layout the
// macOS capture shows on the wire.
struct MatchOptionsV1 {
    uint32_t flags;
    uint32_t macosUserId;
};
static_assert(sizeof(MatchOptionsV1) == 8, "match_options_v1_t must be 8 bytes");

// The selected-identities blob appended after MatchInitDataV1 starts with
// its own uint32 record count, followed by count * IdentityRecordV1 records.
// This is distinct from the 68-byte match options structure itself.
#pragma pack(pop)

// How the start-match (cmd 4) payload is serialized.
//
//  InlineIdentities    8-byte MatchOptionsV1 + N * IdentityRecordV1; no
//                      count field, no padding. For N == 3 this is exactly
//                      the 68-byte payload macOS sends. DEFAULT.
//  PaddedNoIdentities  the 68-byte MatchInitDataV1 alone, identities not
//                      sent at all. Also 68 bytes on the wire, so the
//                      macOS capture cannot tell it apart from
//                      InlineIdentities by size - kept as an explicitly
//                      selectable A/B variant instead of pretending the
//                      capture disambiguated the two.
//  LegacyCounted       MatchInitDataV1 + uint32 count + N records. What
//                      this project sent up to 16.09.2026 (132 bytes for
//                      N == 3). Kept only so the regression can be
//                      reproduced on demand.
enum class MatchIdentityLayout {
    InlineIdentities,
    PaddedNoIdentities,
    LegacyCounted,
};

constexpr uint16_t kBmMagic = 0x4D42;

enum class Command : uint16_t {
    ProtocolVersion   = 1,
    ResetSensor       = 2,
    StartMatch        = 4,
    Cancel            = 0x0c,
    LoadCalibration   = 0x20,
    SksLockState      = 0x27, // Linux probe number; macOS live uses 39
    SensorInfo        = 0x35,
    CatacombUuid      = 0x38,
    // macOS live unlock pre-match sequence (unified log 16.09.2026, bridgeOS 23P5067):
    //   48 getEnabledForUnlock (inSize=0)
    //   39 performGetSKSLockStateCommand (inSize=4, uid)
    //   46 performGetProtectedConfigCommand (inSize=4, uid)
    //   12 Cancel
    //   40 performGetBiometrickitdInfoCommand (inSize=0)
    //   … then 4 StartMatch (inSize=68)
    // Windows previously skipped all of these and went straight to StartMatch;
    // the sensor then never emitted 89 Idle or 55 ImageCaptured.
    GetSksLockStateMac   = 39,
    GetBiometrickitdInfo = 40,
    GetProtectedConfig   = 46,
    GetEnabledForUnlock  = 48,
    CatacombHash      = 0x3a,
    CatacombState     = 0x3c,
    IdentityList      = 0x42,
    GlobalIdentityList = 0x51,
    SensorReadiness   = 0x53,
};

// VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux,
// src/bridge-xpc-probe.py --identity-list):
//   biometric_command(sock, 0x42, data=pack("<I", uid), output_capacity=20 * 10)
// Ten identity_record_v1_t slots. t2-biometric-ready.sh uses this exact
// capacity; do not substitute 4096.
constexpr uint32_t kIdentityListOutputCapacity = 20 * 10;

// VERIFIED FROM SOURCE (bridge-xpc-probe.py resolve-any / --global-identity-list):
//   biometric_command(sock, 0x51, output_capacity=40 * 10)
constexpr uint32_t kGlobalIdentityListOutputCapacity = 40 * 10;

constexpr uint32_t kEmbeddedTypeStatus      = 0xE3FF8001;
constexpr uint32_t kEmbeddedTypeMatchResult = 0xE3FF8002;
constexpr uint32_t kEmbeddedTypeStatistics  = 0xE3FF8004;

// VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux,
// enrollment_research/FINDINGS.md, "Raw service-envelope map" — recovered
// from the matching daemon's 16-entry jump table, NOT scoped to
// enrollment specifically; this is the complete envelope-type space, only
// three of which (8001/8002/8004 above) this project previously named).
// Added so a hardware capture can show a real name instead of "unknown"
// if one of these ever arrives — no byte-level body of any of these is
// parsed or assumed here, only the type is named.
constexpr uint32_t kEmbeddedTypeEnrollmentResult      = 0xE3FF8003;
constexpr uint32_t kEmbeddedTypeSensorStatus          = 0xE3FF8005;
constexpr uint32_t kEmbeddedTypeButtonState1          = 0xE3FF8006;
constexpr uint32_t kEmbeddedTypeButtonState2          = 0xE3FF8007;
constexpr uint32_t kEmbeddedTypeKernelLog             = 0xE3FF8008;
constexpr uint32_t kEmbeddedTypeSensorRecoveryReason  = 0xE3FF8009;
constexpr uint32_t kEmbeddedTypeSksLockStateUpdate    = 0xE3FF800A;
constexpr uint32_t kEmbeddedTypeMatchEvent            = 0xE3FF800B;
constexpr uint32_t kEmbeddedTypeAccessoryListChange   = 0xE3FF800C;
constexpr uint32_t kEmbeddedTypeSensorInitTemplateSync = 0xE3FF800D;
constexpr uint32_t kEmbeddedTypeDeviceAuthRequired    = 0xE3FF800E;
constexpr uint32_t kEmbeddedTypeAccessoryImageInfo    = 0xE3FF800F;
constexpr uint32_t kEmbeddedTypeMesaHardwarePassReport = 0xE3FF8010;

// Serializes a BM-wrapped command: magic|command|version|value|data.
std::vector<uint8_t> EncodeBmCommand(Command command, uint16_t version, uint16_t value,
                                      const std::vector<uint8_t>& data = {});

// Serializes match_init_data_v1 + identity records. identities is capped
// at a sane local maximum (256) independent of any device-reported count,
// per "never trust remote length before allocation".
std::vector<uint8_t> EncodeMatchInitData(uint32_t flags, uint32_t macosUserId,
                                          const std::vector<IdentityRecordV1>& identities,
                                          MatchIdentityLayout layout =
                                              MatchIdentityLayout::LegacyCounted);

// Diagnostic-only name for a layout, for logging the wire format actually used.
const wchar_t* MatchIdentityLayoutName(MatchIdentityLayout layout);

// Parses a raw identity-list reply body into 20-byte records. Returns false
// (and an empty vector) on any length mismatch — never truncates silently.
bool ParseIdentityList(const std::vector<uint8_t>& replyBody,
                        std::vector<IdentityRecordV1>* outIdentities);

} // namespace t2::biometrickit
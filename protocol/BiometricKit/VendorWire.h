// SPDX-License-Identifier: GPL-2.0-only
// VendorWire.h - the fixed wire layout of the vendor sample payload that
// crosses the WBDI boundary (Windows-hello-design.MD section 5).
//
// Deliberately dependency-free (only <cstdint>/<cstring>): it is included by
//   * protocol/BiometricKit/VendorBir.h  (serializer, links VerificationEngine)
//   * driver/T2TouchIdBio/WbdiBir.h      (BIR wrapper, UMDF driver + the WBF
//                                         engine adapter loaded into wbiosrvc)
// The engine adapter DLL must not pull in BridgeXPC/libplist/winsock, which is
// why the layout lives here and not in VendorBir.h.
#pragma once
#include <cstdint>
#include <cstring>

namespace t2::biometrickit {

constexpr uint32_t kVendorPayloadVersion = 1;

// Wire value of VerifyOutcome::Match (VerificationEngine.h, first enumerator).
// VendorBir.h static_asserts that this stays in sync.
constexpr uint32_t kWireOutcomeMatch = 0;
// Anything that is not a valid outcome. The struct default is this value, so a
// payload that was never filled in can never read as a Match (fail-closed).
constexpr uint32_t kWireOutcomeInvalid = 0xFFFFFFFFu;

// What produced the sample.
//   Verify         - the SEP answered a real touch (VerificationEngine::Verify).
//   EnrollConfirm  - enrollment only confirmed that the SEP has an identity
//                    for macosUserId (design doc 4). NO touch happened, so the
//                    engine adapter must never let this kind authorize a
//                    verify/identify - only UpdateEnrollment accepts it.
constexpr uint8_t kSampleKindVerify        = 0;
constexpr uint8_t kSampleKindEnrollConfirm = 1;

#pragma pack(push, 1)
struct T2VendorSamplePayload {
    uint32_t Version = kVendorPayloadVersion;
    uint32_t Outcome = kWireOutcomeInvalid;  // VerifyOutcome widened to a fixed-size int
    uint32_t MacosUserId = 0;
    uint8_t  HasMatchedUuid = 0;   // 0/1 - MatchedUuid is only meaningful when this is 1
    uint8_t  Kind = kSampleKindVerify; // kSampleKind*
    uint8_t  Reserved[2]{};        // must be zero; keeps MatchedUuid's offset stable
    uint8_t  MatchedUuid[16]{};
};
#pragma pack(pop)
static_assert(sizeof(T2VendorSamplePayload) == 4 + 4 + 4 + 1 + 1 + 2 + 16,
              "T2VendorSamplePayload must stay a stable, tightly packed wire layout");

// Returns false (leaving *out untouched) on a truncated, version-mismatched or
// malformed buffer - never a partially-populated payload.
inline bool DeserializeVendorPayload(const uint8_t* data, size_t len, T2VendorSamplePayload* out) {
    if (data == nullptr || out == nullptr || len < sizeof(T2VendorSamplePayload)) {
        return false;
    }
    T2VendorSamplePayload p{};
    std::memcpy(&p, data, sizeof(p));
    if (p.Version != kVendorPayloadVersion) {
        return false;
    }
    if (p.HasMatchedUuid > 1 || p.Reserved[0] != 0 || p.Reserved[1] != 0) {
        return false;
    }
    if (p.Kind != kSampleKindVerify && p.Kind != kSampleKindEnrollConfirm) {
        return false;
    }
    *out = p;
    return true;
}

} // namespace t2::biometrickit
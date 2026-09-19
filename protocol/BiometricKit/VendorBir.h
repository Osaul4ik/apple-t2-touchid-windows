// SPDX-License-Identifier: GPL-2.0-only
// VendorBir.h — the vendor sample payload carried inside a WBDI
// IOCTL_BIOMETRIC_CAPTURE_DATA response (Windows-hello-design.MD section 5).
//
// This is intentionally NOT a full CBEFF WINBIO_BIR (WINBIO_BIR_HEADER +
// WINBIO_BDB_ANSI_381_HEADER standard data block, as winbio_types.h
// documents for a real minutiae-carrying fingerprint reader). There is no
// raw fingerprint image or template here to put in a standard data block —
// the SEP does the actual match and this project explicitly does not
// extract, transmit, or store raw biometric data (README: "does not store
// raw fingerprint images"). What crosses the WBDI boundary is only the
// already-fail-closed VerifyOutcome and, on a Match, the matchedUuid the
// SEP itself returned (VerificationEngine.h).
//
// This header has NO winbio_*.h dependency on purpose, so it stays usable
// from the plain-C++ protocol library (linked into tools/t2touchid, a
// normal console EXE with no WDK biometric headers) as well as from the
// UMDF driver. The umdf/Queue.cpp caller is responsible for placing the
// serialized bytes into WINBIO_CAPTURE_DATA::CaptureData and choosing
// WinBioHresult/SensorStatus/RejectDetail per the design doc 5 mapping
// table — that mapping is deliberately NOT duplicated here, so there is
// exactly one place (Queue.cpp) that decides what HRESULT the CAPTURE_DATA
// IOCTL completes with.
//
// OPEN QUESTION (design doc 8, not resolved by this file): whether WinBio's
// service expects the sensor-level CaptureData blob to already be a
// well-formed WINBIO_BIR (HeaderBlock + VendorDataBlock, with
// VendorDataBlock.Data pointing at the bytes this struct serializes to) or
// whether the raw vendor bytes alone are sufficient at this layer and the
// engine adapter is the first place a WINBIO_BIR wrapper is required. This
// project's own SupportedFormat entry (umdf/Queue.cpp FillAttributes) is
// still marked PLACEHOLDER for exactly this reason. Confirm the real shape
// against a live wbiosrvc trace (DebugView on both T2TouchIdBio.dll and
// T2TouchIdEngineAdapter.dll while Settings runs an enroll/verify attempt)
// before assuming SerializePayload's bytes alone are what WinBio forwards
// verbatim to EngineAcceptSampleData.
#pragma once
#include "VerificationEngine.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

namespace t2::biometrickit {

// Fixed-size, versioned so a future field can be added without breaking a
// caller that only knows an older Version.
#pragma pack(push, 1)
struct T2VendorSamplePayload {
    uint32_t Version = 1;
    uint32_t Outcome;              // VerifyOutcome, widened to a fixed-size int on the wire
    uint32_t MacosUserId;
    uint8_t  HasMatchedUuid;       // 0/1 — MatchedUuid is only meaningful when this is 1
    uint8_t  Reserved[3]{};        // must be zero; padding to keep MatchedUuid's offset stable
    uint8_t  MatchedUuid[16]{};
};
#pragma pack(pop)
static_assert(sizeof(T2VendorSamplePayload) == 4 + 4 + 4 + 1 + 3 + 16,
              "T2VendorSamplePayload must stay a stable, tightly packed wire layout");

inline std::vector<uint8_t> SerializeVendorPayload(
    VerifyOutcome outcome, uint32_t macosUserId,
    const std::optional<std::array<uint8_t, 16>>& matchedUuid) {
    T2VendorSamplePayload p{};
    p.Outcome = static_cast<uint32_t>(outcome);
    p.MacosUserId = macosUserId;
    p.HasMatchedUuid = matchedUuid.has_value() ? 1 : 0;
    if (matchedUuid.has_value()) {
        std::memcpy(p.MatchedUuid, matchedUuid->data(), sizeof(p.MatchedUuid));
    }
    std::vector<uint8_t> out(sizeof(p));
    std::memcpy(out.data(), &p, sizeof(p));
    return out;
}

// Returns false (leaving *out untouched) on a truncated or version-mismatched
// buffer — never a partially-populated payload.
inline bool DeserializeVendorPayload(const uint8_t* data, size_t len, T2VendorSamplePayload* out) {
    if (data == nullptr || out == nullptr || len < sizeof(T2VendorSamplePayload)) {
        return false;
    }
    T2VendorSamplePayload p{};
    std::memcpy(&p, data, sizeof(p));
    if (p.Version != 1) {
        return false;
    }
    *out = p;
    return true;
}

} // namespace t2::biometrickit

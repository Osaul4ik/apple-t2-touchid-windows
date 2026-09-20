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
// The wire layout itself lives in VendorWire.h (no VerificationEngine/BridgeXPC
// dependency, so the WBF engine adapter can parse it too). This header adds the
// serializer that needs VerifyOutcome.
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
// WBDI documents CaptureData as a WINBIO_BIR, so these bytes are NOT sent as
// CaptureData directly: driver/T2TouchIdBio/WbdiBir.h wraps them into the
// BIR's Vendor Data Block (winbio_types.h: data that is not ANSI-381 must go
// there) and the engine adapter unwraps them in AcceptSampleData. Whether WBF
// forwards that BIR verbatim is still to be confirmed on a live wbiosrvc
// trace (DebugView shows the BIR size/offsets on both sides).
#pragma once
#include "VerificationEngine.h"
#include "VendorWire.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

namespace t2::biometrickit {

static_assert(static_cast<uint32_t>(VerifyOutcome::Match) == kWireOutcomeMatch,
              "VendorWire.h kWireOutcomeMatch must equal VerifyOutcome::Match");

inline std::vector<uint8_t> SerializeVendorPayload(
    VerifyOutcome outcome, uint32_t macosUserId,
    const std::optional<std::array<uint8_t, 16>>& matchedUuid,
    uint8_t kind = kSampleKindVerify) {
    T2VendorSamplePayload p{};
    p.Outcome = static_cast<uint32_t>(outcome);
    p.MacosUserId = macosUserId;
    p.HasMatchedUuid = matchedUuid.has_value() ? 1 : 0;
    p.Kind = kind;
    if (matchedUuid.has_value()) {
        std::memcpy(p.MatchedUuid, matchedUuid->data(), sizeof(p.MatchedUuid));
    }
    std::vector<uint8_t> out(sizeof(p));
    std::memcpy(out.data(), &p, sizeof(p));
    return out;
}

} // namespace t2::biometrickit
// SPDX-License-Identifier: GPL-2.0-only
// MatchResult.cpp
//
// PROVENANCE NOTE (updated after direct read of bridge-xpc-probe.py's
// summarize_event, replacing the earlier "inferred fallback" note):
// the Linux reference itself does NOT use a fixed byte offset for the
// identity UUID inside a match_result event either. Its own comparison is
// `identity_uuid in event_data` — a raw Python `bytes in bytes` membership
// test, i.e. exactly the same whole-buffer substring scan this file
// performs. So the scan below is not a stand-in for an unverified offset;
// it is the VERIFIED technique. What the Linux source DOES also confirm:
// - the >=0xC70 minimum length check on event_data is applied before this
//   comparison (VERIFIED, kept below);
// - identity_record_v1_t is 4-byte user id + 16-byte UUID, and only the
//   16-byte UUID (not the user id) is compared (VERIFIED, matches
//   IdentityRecordV1 below);
// - the first signed word of the event is NOT a reliable success signal
//   (VERIFIED, this file never reads it).

#include "MatchResult.h"
#include <cstring>

namespace t2::biometrickit {

bool ParseStatusEventHeader(const std::vector<uint8_t>& data,
                             uint32_t* outEmbeddedType,
                             std::vector<uint8_t>* outEventData) {
    if (data.size() < kStatusEventHeaderBytes) {
        return false; // malformed: caller must keep waiting, never guess NoMatch
    }
    // VERIFIED FROM SOURCE: struct.unpack_from("<QIIQ", data) ==
    // (sequence, embedded_type, version, ordinal); only embedded_type
    // (bytes [8:12)) is needed by this project.
    uint32_t embeddedType = 0;
    std::memcpy(&embeddedType, data.data() + 8, sizeof(embeddedType));
    *outEmbeddedType = embeddedType;
    outEventData->assign(data.begin() + kStatusEventHeaderBytes, data.end());
    return true;
}

StatusEventBody ParseStatusEventBody(const std::vector<uint8_t>& eventData) {
    // VERIFIED FROM SOURCE: struct.unpack_from("<I", event_data) for the
    // first field (gated on len >= 4), struct.unpack_from("<Q", event_data, 8)
    // for the second (gated on len >= 16). Bytes [4:8) of event_data are not
    // read by the reference either - not an oversight here, it simply isn't
    // part of what the reference decodes.
    StatusEventBody body;
    if (eventData.size() >= 4) {
        uint32_t statusCode = 0;
        std::memcpy(&statusCode, eventData.data(), sizeof(statusCode));
        body.statusCode = statusCode;
    }
    if (eventData.size() >= 16) {
        uint64_t statusDataLength = 0;
        std::memcpy(&statusDataLength, eventData.data() + 8, sizeof(statusDataLength));
        body.statusDataLength = statusDataLength;
    }
    return body;
}

const wchar_t* EmbeddedTypeName(uint32_t embeddedType) {
    // VERIFIED FROM SOURCE (t2-touchid-linux, enrollment_research/
    // FINDINGS.md, "Raw service-envelope map"): this table is recovered
    // from the matching daemon's own dispatch jump table, i.e. it names
    // every envelope type the daemon can receive on this connection, not
    // just the ones observed on a specific operation - so it is valid to
    // name any of these regardless of whether the current session is a
    // verify or enrollment. Naming a type here does NOT mean this project
    // parses its body; kEmbeddedTypeMatchResult (0x8002) is the only one
    // with a body parser (MatchResult.cpp).
    switch (embeddedType) {
        case kEmbeddedTypeStatus:                return L"status";
        case kEmbeddedTypeMatchResult:            return L"match_result";
        case kEmbeddedTypeEnrollmentResult:       return L"enrollment_result";
        case kEmbeddedTypeStatistics:             return L"statistics";
        case kEmbeddedTypeSensorStatus:           return L"sensor_status";
        case kEmbeddedTypeButtonState1:           return L"button_state_1";
        case kEmbeddedTypeButtonState2:           return L"button_state_2";
        case kEmbeddedTypeKernelLog:              return L"kernel_log";
        case kEmbeddedTypeSensorRecoveryReason:   return L"sensor_recovery_reason";
        case kEmbeddedTypeSksLockStateUpdate:     return L"sks_lock_state_update";
        case kEmbeddedTypeMatchEvent:             return L"match_event";
        case kEmbeddedTypeAccessoryListChange:    return L"accessory_list_change";
        case kEmbeddedTypeSensorInitTemplateSync: return L"sensor_init_template_sync";
        case kEmbeddedTypeDeviceAuthRequired:     return L"device_auth_required";
        case kEmbeddedTypeAccessoryImageInfo:     return L"accessory_image_info";
        case kEmbeddedTypeMesaHardwarePassReport: return L"mesa_hardware_pass_report";
        default:                                  return L"unknown";
    }
}

const wchar_t* StatusOrdinalHypothesis(uint32_t ordinal) {
    // NOT VERIFIED FROM SOURCE FOR THIS PATH - HYPOTHESIS ONLY. This table
    // comes from t2-touchid-linux's "Enrollment event-flow conformance
    // matrix" (enrollment_research/FINDINGS.md), which is explicitly
    // decompiled from BKEnrollOperation - the ENROLLMENT class - not from
    // BKMatchOperation/verification. It is being applied here to a verify
    // session's 0xE3FF8001 ordinals only because the two operations
    // appear to share the same low-level envelope/ordinal wire format for
    // sensor-level feedback (finger presence, capture rejection) - that
    // sharing itself is NOT independently confirmed. Treat every string
    // this returns as a labeled guess for a human reading the log, never
    // as a value this project's own match/no-match decision depends on -
    // MatchResult.cpp's fail-closed UUID scan remains the only outcome
    // source. Returns nullptr for ordinals with no enrollment-side meaning
    // to hypothesize from at all.
    switch (ordinal) {
        case 63: return L"HYPOTHESIS(enrollment-sourced): finger-present feedback";
        case 64: return L"HYPOTHESIS(enrollment-sourced): finger-removed/waiting feedback";
        case 66: return L"HYPOTHESIS(enrollment-sourced): cancelled-terminal";
        case 67: return L"HYPOTHESIS(enrollment-sourced): generic-failure-terminal";
        case 68: return L"HYPOTHESIS(enrollment-sourced): timeout-terminal";
        case 70: return L"HYPOTHESIS(enrollment-sourced): continue-without-new-progress";
        case 74: return L"HYPOTHESIS(enrollment-sourced): waiting-for-finger-removal";
        case 78: case 85: case 87: case 88: case 98:
            return L"HYPOTHESIS(enrollment-sourced): rejected-capture feedback (retry)";
        case 86: return L"HYPOTHESIS(enrollment-sourced): rejected-small-coverage feedback";
        case 93: return L"HYPOTHESIS(enrollment-sourced): dirty-sensor advisory";
        default:
            if (ordinal >= 100 && ordinal <= 355) {
                return L"HYPOTHESIS(enrollment-sourced): progress ordinal (100..355 range)";
            }
            return nullptr; // no enrollment-side meaning to hypothesize (includes the
                             // documented no-op ranges 0..50/52..57/59/69/71..73/75..77/
                             // 79/81..84/89..92/94..97/356..500/503..UINT32_MAX)
    }
}

// Constant-time compare: always touches all 16 bytes regardless of where
// (or whether) a mismatch occurs, so timing does not leak which byte of a
// candidate UUID differed from the enrolled UUID.
static bool ConstantTimeEquals16(const uint8_t* a, const uint8_t* b) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

MatchResult ParseMatchResult(uint32_t embeddedType,
                              const std::vector<uint8_t>& eventPayload,
                              const std::vector<IdentityRecordV1>& enrolledIdentities) {
    MatchResult result{MatchOutcome::Malformed, std::nullopt};

    if (embeddedType != kEmbeddedTypeMatchResult) {
        // Not a match_result event at all (status/statistics/unknown) —
        // the verify engine's caller must keep waiting on Malformed only
        // when it actually expected this call to be a match_result; a
        // status/statistics event is a normal, separate case the caller
        // handles before reaching this function.
        return result;
    }

    if (eventPayload.size() < kMinMatchResultEventBytes) {
        return result; // Malformed — never treated as NoMatch (Milestone 2 §20)
    }

    if (enrolledIdentities.empty()) {
        // No enrolled identities means a MATCH is structurally impossible
        // this session — but that is a legitimate NoMatch, not a parse
        // failure, and every byte of the event is still scanned below so
        // the codepath's timing does not itself leak "were there zero
        // identities" via an early return.
    }

    bool anyMatch = false;
    std::array<uint8_t, 16> matchedUuid{};

    // Bounded scan: eventPayload.size() is capped by
    // Connection/BridgeXpc's kMaxFrameBodyBytes far upstream, so this loop
    // has a fixed, small upper bound (a handful of KB at most) — not an
    // unbounded remote-controlled cost.
    for (size_t offset = 0; offset + 16 <= eventPayload.size(); offset++) {
        for (const auto& identity : enrolledIdentities) {
            if (ConstantTimeEquals16(eventPayload.data() + offset, identity.uuid.data())) {
                anyMatch = true;
                matchedUuid = identity.uuid;
                // Deliberately do NOT early-return: keep scanning so total
                // work stays independent of *where* in the buffer (or
                // whether) a match was found, avoiding a coarse timing
                // side-channel across the whole event, not just per-UUID.
            }
        }
    }

    if (anyMatch) {
        result.outcome = MatchOutcome::Match;
        result.matchedIdentityUuid = matchedUuid;
    } else {
        result.outcome = MatchOutcome::NoMatch;
    }
    return result;
}

} // namespace t2::biometrickit
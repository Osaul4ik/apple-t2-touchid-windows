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
//
// DISTRUST NOTICE (per explicit instruction, superseding the "16.09.2026
// native macOS reference refinement" note this replaces): the claim below
// — a named status-code sequence (FingerOn/ImageCaptured/.../Pause) from an
// alleged live macOS/bridgeOS 23P5067 capture — has no corroboration
// anywhere in jmurth1234/t2-touchid-linux, checked directly against that
// repo's source and docs, not assumed from memory. It exists only as a
// comment in this file. StatusCodeName() and StatusCodeIsImagePipeline()
// below still encode it for best-effort diagnostic labeling only (they are
// never read by VerificationEngine.cpp's outcome logic — see that file),
// but it must not be treated as ground truth, and no future change should
// build new match/no-match logic on top of it. Orient on the Linux
// reference instead: its own verify path (t2-fprintd.py
// verdict_from_result) never inspects these ordinals at all, and its
// enrollment conformance matrix (a genuinely Linux-sourced, disassembly-
// confirmed document) actually classifies most of this ordinal range
// (81..84, 89..97) as a no-op with no semantic content — the opposite of
// what the distrusted capture claims.

#include "MatchResult.h"
#include <cstring>

namespace t2::biometrickit {

bool ParseStatusEventHeader(const std::vector<uint8_t>& data,
                             uint32_t* outEmbeddedType,
                             std::vector<uint8_t>* outEventData,
                             uint64_t* outSequence) {
    if (data.size() < kStatusEventHeaderBytes) {
        return false; // malformed: caller must keep waiting, never guess NoMatch
    }
    // VERIFIED FROM SOURCE: struct.unpack_from("<QIIQ", data) ==
    // (sequence, embedded_type, version, ordinal). Historically only
    // embedded_type (bytes [8:12)) was needed by this project; 26.09.2026
    // adds sequence (bytes [0:8)) for VerifyConfig::rejectSequenceAtOrBelow.
    // `version` [12:16) and `ordinal` [16:24) still have no established use
    // here (do not confuse this envelope-level `ordinal` with the
    // status-event status_code field StatusOrdinalHypothesis() takes — same
    // wire term, unrelated value, see that function's own comment).
    uint64_t sequence = 0;
    std::memcpy(&sequence, data.data() + 0, sizeof(sequence));
    uint32_t embeddedType = 0;
    std::memcpy(&embeddedType, data.data() + 8, sizeof(embeddedType));
    *outEmbeddedType = embeddedType;
    if (outSequence) {
        *outSequence = sequence;
    }
    outEventData->assign(data.begin() + kStatusEventHeaderBytes, data.end());
    return true;
}

StatusEventBody ParseStatusEventBody(const std::vector<uint8_t>& eventData) {
    // VERIFIED FROM SOURCE: struct.unpack_from("<I", event_data) for the
    // first field (gated on len >= 4), struct.unpack_from("<Q", event_data, 8)
    // for the second (gated on len >= 16). Bytes [4:8) of eventData are not
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

const wchar_t* StatusCodeName(uint32_t statusCode) {
    // UNVERIFIED / DISTRUSTED — see the file-level DISTRUST NOTICE above.
    // This table's claimed origin (a macOS unified-log capture allegedly
    // showing `-[BiometricKitDStatistics statusMessage:]` printing these
    // names) is not corroborated by t2-touchid-linux and cannot be
    // independently checked from this codebase. It is kept only so a human
    // reading a log has a readable guess instead of a bare integer.
    // Do not add new logic that depends on any of these names being
    // correct, and do not treat their absence/presence as evidence of
    // anything about the real protocol.
    switch (statusCode) {
        case 53: return L"ImageQueueIsEmpty";
        case 55: return L"ImageCaptured";
        case 63: return L"FingerOn";
        case 64: return L"FingerOff";
        case 72: return L"ImageForProcessing";
        case 73: return L"TemplateListUpdated";
        case 74: return L"RequestFingerOff";
        case 80: return L"MatchingCancelled";
        case 89: return L"SensorOperationModeIdle";
        case 90: return L"SensorOperationModeCapture";
        case 91: return L"SensorOperationModePause";
        case 95: return L"ImageWasAccepted";
        default: return nullptr; // not in the unverified table
    }
}

bool StatusCodeIsImagePipeline(uint32_t statusCode) {
    // UNVERIFIED / DISTRUSTED — see the file-level DISTRUST NOTICE above.
    // 55/72/95 are only "the image pipeline" according to the same
    // uncorroborated capture StatusCodeName relies on. Kept purely to
    // populate a diagnostic counter in the session-summary log
    // (imagePipelineEvents in VerificationEngine.cpp) — that counter is
    // informational only and is never used to choose a VerifyOutcome.
    switch (statusCode) {
        case 55: // ImageCaptured
        case 72: // ImageForProcessing
        case 95: // ImageWasAccepted
            return true;
        default:
            return false;
    }
}

StatisticsEventBody ParseStatisticsEventBody(const std::vector<uint8_t>& eventData) {
    // UNVERIFIED / DISTRUSTED for the "biometrickitd reports a 12-byte body
    // of type+value" framing — same uncorroborated capture as the
    // DISTRUST NOTICE above. What IS independently, directly observed on
    // real Windows-side hardware captures (not attributed to the macOS
    // claim): 28-byte statistics bodies decoding as ordinal=0, length=12,
    // then a 4-byte type and an 8-byte value at these offsets — e.g.
    // type 4 value 1, type 35 value 1, type 25 value 1215, type 30 value
    // 2169. The offsets below are kept because they match what this
    // project's own hardware actually produced, not because of the macOS
    // claim about it.
    StatisticsEventBody body;
    if (eventData.size() >= kStatusEventBodyFixedFieldsBytes + 4) {
        uint32_t type = 0;
        std::memcpy(&type, eventData.data() + kStatusEventBodyFixedFieldsBytes, sizeof(type));
        body.type = type;
    }
    if (eventData.size() >= kStatusEventBodyFixedFieldsBytes + 12) {
        uint64_t raw = 0;
        std::memcpy(&raw, eventData.data() + kStatusEventBodyFixedFieldsBytes + 4, sizeof(raw));
        body.rawValue = raw;
        double asDouble = 0.0;
        static_assert(sizeof(double) == sizeof(uint64_t), "double must be 8 bytes");
        std::memcpy(&asDouble, &raw, sizeof(asDouble));
        body.asDouble = asDouble;
    }
    return body;
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
    //
    // NOTE: an earlier revision of this comment resolved the tension below
    // by treating StatusCodeName's table as "the authority" and dismissing
    // Linux's own no-op range on that basis. That table's only claimed
    // origin is an unconfirmed macOS capture with no trace in
    // jmurth1234/t2-touchid-linux (checked directly against that repo) —
    // per explicit instruction, it is no longer trusted, so it cannot be
    // used to override what Linux itself documents. The honest state is:
    // Linux's enrollment conformance matrix (enrollment_research/
    // FINDINGS.md, VERIFIED FROM SOURCE, static-confirmed from disassembly)
    // marks ordinals 81..84 and 89..97 as a complete no-op domain for the
    // ENROLLMENT operation ("no feedback, state change, command, or
    // terminal result"). Whether that also holds for a MATCH/verify
    // operation is genuinely unconfirmed either way — this project has no
    // Linux-sourced evidence for or against it. 63/64 are the one place the
    // distrusted capture and Linux's own matrix independently agree
    // (finger-present / finger-removed feedback), so they are named below;
    // everything else in the 78..98 range stays an enrollment-sourced
    // hypothesis, explicitly not claimed to transfer to verify.
    switch (ordinal) {
        case 63: return L"finger-present feedback (Linux-verified, enrollment path)";
        case 64: return L"finger-removed/waiting feedback (Linux-verified, enrollment path)";
        case 66: return L"HYPOTHESIS(enrollment-sourced): cancelled-terminal";
        case 67: return L"HYPOTHESIS(enrollment-sourced): generic-failure-terminal";
        case 68: return L"HYPOTHESIS(enrollment-sourced): timeout-terminal";
        case 70: return L"HYPOTHESIS(enrollment-sourced): continue-without-new-progress";
        case 74: return L"HYPOTHESIS(enrollment-sourced): waiting-for-finger-removal";
        case 78:
        case 85: case 87: case 88: case 98:
            return L"HYPOTHESIS(enrollment-sourced): rejected-capture feedback (retry)";
        case 86: return L"HYPOTHESIS(enrollment-sourced): rejected-small-coverage feedback";
        case 93: return L"HYPOTHESIS(enrollment-sourced): dirty-sensor advisory";
        case 81: case 82: case 83: case 84:
        case 89: case 90: case 91: case 92: case 94: case 95: case 96: case 97:
            return L"Linux-verified no-op range for enrollment (81..84, 89..97); "
                    L"unconfirmed for verify";
        default:
            if (ordinal >= 100 && ordinal <= 355) {
                return L"HYPOTHESIS(enrollment-sourced): progress ordinal (100..355 range)";
            }
            return nullptr;
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
        // VERIFIED FROM SOURCE: bridge-xpc-probe.py's summarize_event sets
        // event_kind="match_result" as soon as embedded_type matches, before
        // the length check — the length check only gates the "matched"
        // field. verdict_from_result() then reads a match_result-kind event
        // with no truthy "matched" as an immediate "verify-no-match", and
        // --stop-on-match-result stops the loop on event_kind alone. A
        // too-short body is therefore a definite NoMatch here too, not a
        // reason to keep waiting for another event.
        result.outcome = MatchOutcome::NoMatch;
        return result;
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
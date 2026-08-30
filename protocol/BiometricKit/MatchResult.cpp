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

// MatchResult.h
//
// This file implements the single most security-critical decision in the
// whole project (Milestone 2, section 20). VERIFIED FROM SOURCE (Milestone
// 1, section 7): the first signed word of a match_result event is NOT a
// reliable success indicator — the only authoritative signal is whether a
// 16-byte identity UUID embedded in the event matches one of the
// enrolled-identity UUIDs obtained earlier via IdentityList.

#pragma once
#include "Commands.h"
#include <cstdint>
#include <vector>
#include <optional>

namespace t2::biometrickit {

enum class MatchOutcome {
    Match,
    NoMatch,
    Malformed, // event too short / wrong embedded_type / corrupt — NEVER silently NoMatch
};

// VERIFIED FROM SOURCE: valid match_result events are at least 0xC70 bytes.
constexpr size_t kMinMatchResultEventBytes = 0xC70;

// VERIFIED FROM SOURCE (bridge-xpc-probe.py summarize_event): the `data`
// bytes inside a status-callback event ([9, bridge_status, data, x, x])
// begin with a fixed 24-byte header — sequence:u64le, embedded_type:u32le,
// version:u32le, ordinal:u64le — followed by the event-type-specific body.
constexpr size_t kStatusEventHeaderBytes = 24;

// Splits raw status-event `data` bytes (as extracted by
// bridgexpc::DecodeStatusEventData) into embedded_type and the remaining
// event body. Returns false if data is shorter than the fixed 24-byte
// header — the caller must treat that as fail-closed, never as an
// implicit NoMatch.
bool ParseStatusEventHeader(const std::vector<uint8_t>& data,
                             uint32_t* outEmbeddedType,
                             std::vector<uint8_t>* outEventData);

struct MatchResult {
    MatchOutcome outcome;
    // Populated only when outcome == Match; the caller (verify engine) may
    // log that a match occurred but must never log the UUID itself in
    // normal (non-DEBUG-with-explicit-opt-in) logging paths.
    std::optional<std::array<uint8_t, 16>> matchedIdentityUuid;
};

// eventPayload: the raw async event payload as received from
// Connection::WaitForEvent (already event-type-agnostic at that layer).
// embeddedType: the type discriminator extracted by the caller from the
// bridge-level event envelope (kEmbeddedType* constants) — passed in
// rather than re-parsed here to keep this function pure and unit-testable
// without a live plist decoder.
//
// enrolledIdentities: the identity list obtained earlier in THIS SAME
// verification session (never a cached/stale list from a previous session —
// caller's responsibility per Milestone 2 §26).
MatchResult ParseMatchResult(uint32_t embeddedType,
                              const std::vector<uint8_t>& eventPayload,
                              const std::vector<IdentityRecordV1>& enrolledIdentities);

} // namespace t2::biometrickit

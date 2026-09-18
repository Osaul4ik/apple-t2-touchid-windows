// SPDX-License-Identifier: GPL-2.0-only
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
    // VERIFIED FROM SOURCE (bridge-xpc-probe.py summarize_event): event_kind
    // is set to "match_result" the moment embedded_type==0xE3FF8002 is seen,
    // BEFORE the >=0xC70 length check — the length check only gates whether
    // the "matched" field gets populated. verdict_from_result() then returns
    // "verify-no-match" for a match_result-kind event with no truthy
    // "matched" field, and --stop-on-match-result stops on event_kind alone.
    // So an event too short to contain a UUID is a NoMatch, not a distinct
    // "keep waiting" state — this project now matches that exactly.
    NoMatch,
    // Reserved for embeddedType != kEmbeddedTypeMatchResult reaching this
    // function despite the caller's own filter (VerificationEngine.cpp only
    // calls ParseMatchResult after checking embeddedType itself) — defensive
    // only, not expected to occur via the normal call path.
    Malformed,
};

// VERIFIED FROM SOURCE: only events at least this long can carry an
// enrolled-identity UUID (Apple's own >=0xC70-byte validation before
// parsing). Below this length there is nothing to scan, so the result is
// NoMatch, not a signal to keep waiting — matching bridge-xpc-probe.py's
// summarize_event/verdict_from_result exactly (see MatchOutcome::NoMatch).
constexpr size_t kMinMatchResultEventBytes = 0xC70;

// VERIFIED FROM SOURCE (bridge-xpc-probe.py summarize_event): the `data`
// bytes inside a status-callback event ([9, bridge_status, data, x, x])
// begin with a fixed 24-byte header — sequence:u64le, embedded_type:u32le,
// version:u32le, ordinal:u64le — followed by the event-type-specific body.
constexpr size_t kStatusEventHeaderBytes = 24;

// VERIFIED FROM SOURCE (ParseStatusEventBody below): the reference only
// ever reads eventData[0:4) (status_code) and eventData[8:16)
// (status_data_length). Nothing in [4:8) or beyond [16:...) is decoded by
// the reference, but status_data_length itself asserts that a body
// exists starting at this offset - this constant is that offset, used
// only for raw hex-dumping what's there, never for parsing it.
constexpr size_t kStatusEventBodyFixedFieldsBytes = 16;

// Splits raw status-event `data` bytes (as extracted by
// bridgexpc::DecodeStatusEventData) into embedded_type and the remaining
// event body. Returns false if data is shorter than the fixed 24-byte
// header — the caller must treat that as fail-closed, never as an
// implicit NoMatch.
bool ParseStatusEventHeader(const std::vector<uint8_t>& data,
                             uint32_t* outEmbeddedType,
                             std::vector<uint8_t>* outEventData);

// VERIFIED FROM SOURCE (bridge-xpc-probe.py summarize_event, embedded_type
// == 0xE3FF8001 branch): this is the COMPLETE set of fields the reference
// implementation itself decodes from a "status" event body — nothing more.
// In particular, the reference never derives a finger-presence, "verify
// progress", or any other semantic signal from this event kind; if a
// caller wants such a signal, it is not available at this layer of the
// protocol as currently understood, not a bug in this parser.
struct StatusEventBody {
    std::optional<uint32_t> statusCode;       // eventData[0:4), u32le
    std::optional<uint64_t> statusDataLength; // eventData[8:16), u64le
};

// eventData: the bytes AFTER the 24-byte header (i.e. ParseStatusEventHeader's
// outEventData), for an event whose embedded_type == kEmbeddedTypeStatus.
// Never returns false - every field is independently optional based on
// eventData's length, matching the reference's own "if len(event_data) >= N"
// gating exactly, so a short body degrades gracefully instead of failing
// the whole event.
StatusEventBody ParseStatusEventBody(const std::vector<uint8_t>& eventData);

// Human-readable name for any embedded_type this connection can receive
// (VERIFIED FROM SOURCE — see .cpp). Never affects parsing/outcome logic,
// diagnostic-only.
const wchar_t* EmbeddedTypeName(uint32_t embeddedType);

// NOT VERIFIED FROM SOURCE — DO NOT TRUST AS GROUND TRUTH. This table's
// only claimed origin is an alleged macOS unified-log capture ("16.09.2026",
// bridgeOS 23P5067) that exists solely as a comment in this repository.
// jmurth1234/t2-touchid-linux — the actual reference this project is
// otherwise built from — contains no trace of these names, this sequence,
// or this capture anywhere in its source or docs (checked directly against
// the repo, not from memory). Per explicit instruction: this source is not
// trusted going forward. Kept only as an opaque, best-effort diagnostic
// label for a human reading a log — never as a signal anything in this
// codebase decides on (VerificationEngine.cpp's outcome logic already does
// not read this function; it only logs its result). Returns nullptr for
// any ordinal not in the unverified table.
const wchar_t* StatusCodeName(uint32_t statusCode);

// NOT VERIFIED FROM SOURCE — DO NOT TRUST AS GROUND TRUTH, same unconfirmed
// origin as StatusCodeName above. Linux's own reference never gates
// anything on these three ordinals specifically, or on "did an image reach
// the matcher" as a distinct signal from a plain match_result-based
// verdict (VERIFIED FROM SOURCE: t2-fprintd.py verdict_from_result reads
// only match_result events). This function exists purely to populate a
// diagnostic counter (imagePipelineEvents) in the session-summary log line;
// it must never be used to pick a VerifyOutcome.
bool StatusCodeIsImagePipeline(uint32_t statusCode);

// VERIFIED (same capture): a 0xE3FF8004 statistics body is 12 bytes -
// uint32 type followed by a uint64 value, where the value is either an
// integer counter or the bit pattern of an IEEE-754 double, depending on
// the type. biometrickitd logs both interpretations side by side
// ("type 21 fixed: 4637863191261478912 floating: 116.000000"), so this
// struct does the same rather than choosing one.
struct StatisticsEventBody {
    std::optional<uint32_t> type;
    std::optional<uint64_t> rawValue;
    std::optional<double> asDouble;
};

// eventData: the bytes AFTER the 24-byte header, for an event whose
// embedded_type == kEmbeddedTypeStatistics. Degrades gracefully on a short
// body, same contract as ParseStatusEventBody.
StatisticsEventBody ParseStatisticsEventBody(const std::vector<uint8_t>& eventData);

// Best-effort human-readable label for a status event's ordinal
// (statusCode). NOT VERIFIED FROM SOURCE for the verify/match path — see
// the "HYPOTHESIS" note in the .cpp. Returns nullptr when there is no
// enrollment-sourced meaning to hypothesize. Diagnostic-only; never used
// for any match/no-match decision.
const wchar_t* StatusOrdinalHypothesis(uint32_t ordinal);

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
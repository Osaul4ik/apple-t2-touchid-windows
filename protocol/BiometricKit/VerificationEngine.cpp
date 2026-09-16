// SPDX-License-Identifier: GPL-2.0-only
// VerificationEngine.cpp
#include "VerificationEngine.h"
#include "../BridgeXpc/PlistPayload.h"
#include "../BridgeXpc/Log.h"
#include <cstring>
#include <string>

using t2::log::HexDump;

namespace t2::biometrickit {

using namespace std::chrono;

VerifyOutcome VerificationEngine::Verify(bridgexpc::Connection* conn,
                                          std::optional<std::array<uint8_t, 16>>* outMatchedUuid) {
    if (busy_) {
        return VerifyOutcome::Busy;
    }
    busy_ = true;
    struct BusyGuard { bool* b; ~BusyGuard() { *b = false; } } guard{&busy_};

    int64_t bridgeVersion = 0;
    if (!conn->GetBridgeVersion(&bridgeVersion, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }
    int64_t clientVersion = (bridgeVersion < 2) ? bridgeVersion : 2; // min(api_version, 2), VERIFIED FROM SOURCE
    if (!conn->SetClientVersion(clientVersion, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }

    std::vector<uint8_t> reply;

    // reset sensor (cmd 2, value=2). VERIFIED FROM SOURCE: bridge-xpc-probe.py's
    // biometric_command() defaults version=1 for every inner BM command -
    // LoadCalibration below was already given version=1 explicitly, but
    // reset/cancel/identity-list/start-match were left at version=0, which
    // does not match the reference for any of them.
    //
    // outputCapacity: VERIFIED FROM SOURCE - biometric_command() defaults
    // output_capacity=0, and reset/cancel/load-calibration/start-match
    // never pass an explicit value, so all four go out as capacity=0 on
    // the wire (outer envelope [3, 0, innerBmBytes, output_capacity]).
    // Only calls that actually return data (identity-list, catacomb
    // queries) get a nonzero capacity. This file previously used 64 for
    // every call on the theory that 0 was unsafe to send; that is not
    // what the reference does, so it no longer matches the verified byte
    // stream for these four fire-and-forget commands.
    //
    // 16.09.2026: gated behind VerifyConfig::resetSensor (default off).
    // The macOS reference capture never issues command 2 on a live
    // connection, and a sensor reset immediately before arming a match is
    // a plausible way to lose the sensor-side calibration state bridgeOS
    // set up at boot.
    if (config_.resetSensor) {
        auto resetCmd = EncodeBmCommand(Command::ResetSensor, 1, 2);
        if (!conn->SendBiometricCommand(resetCmd, 0, &reply, config_.ioTimeout)) {
            return VerifyOutcome::TransportError;
        }
    } else {
        T2_LOG("verify", L"skipping ResetSensor (cmd 2) - not issued by macOS reference capture");
    }

    // cancel any outstanding operation (cmd 12)
    auto cancelCmd = EncodeBmCommand(Command::Cancel, 1, 0);
    conn->SendBiometricCommand(cancelCmd, 0, &reply, config_.ioTimeout); // best-effort, ignore failure here

    // FDR calibration (Milestone 2 §6 / bridge-xpc-probe.py
    // --load-calibration): bridge-level method 11 fetches the calibration
    // blob, which is then loaded into the sensor via biometric command
    // 0x20 with value=3 ("source 3 is remote/bridgeOS FDR" — VERIFIED FROM
    // SOURCE; source 5 is local-macOS-filesystem-only and not applicable
    // here). This must run before every match attempt, matching the Linux
    // reference — it is not optional/skippable.
    //
    // 16.09.2026 CORRECTION: "must run before every match attempt" was an
    // inference from the Linux reference, not an observation. The macOS
    // capture on this exact machine shows zero calibration commands across
    // two successful unlocks - bridgeOS calibrates the sensor during its
    // own boot and macOS never re-pushes an FDR blob per match. Meanwhile
    // the failing Windows capture shows the SEP emitting an unnamed
    // status_code=94 while this 61407-byte blob is being loaded, and then
    // rejecting every image the sensor produces. Now opt-in.
    if (config_.loadCalibration) {
        std::vector<uint8_t> fdrBlob;
        if (!conn->GetFdrCalibration(&fdrBlob, config_.ioTimeout)) {
            return VerifyOutcome::TransportError;
        }
        auto loadCalibrationCmd = EncodeBmCommand(Command::LoadCalibration, /*version=*/1, /*value=*/3, fdrBlob);
        if (!conn->SendBiometricCommand(loadCalibrationCmd, 0, &reply, config_.ioTimeout)) {
            return VerifyOutcome::TransportError;
        }
    } else {
        T2_LOG("verify", L"skipping LoadCalibration (cmd 0x20) - not issued by macOS reference capture");
    }

    // identity list (cmd 0x42)
    std::vector<uint8_t> idReq(4);
    std::memcpy(idReq.data(), &config_.macosUserId, 4);
    auto idCmd = EncodeBmCommand(Command::IdentityList, 1, 0, idReq);
    if (!conn->SendBiometricCommand(idCmd, 4096, &reply, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }
    std::vector<IdentityRecordV1> identities;
    if (!ParseIdentityList(reply, &identities)) {
        return VerifyOutcome::Malformed;
    }
    // Never logged before: a hardware capture that timed out with no
    // match_result event left no way to tell "SEP had nothing enrolled to
    // compare against" apart from "SEP just never finalized a verdict" -
    // those are very different problems and this was the missing signal
    // to tell them apart. Count only, never any UUID (Milestone 1 §7/§14).
    T2_LOG("verify", L"identity list parsed: %zu identities (reply=%zuB)",
           identities.size(), reply.size());

    // start match (cmd 4)
    //
    // 16.09.2026 FIX: the payload used to be MatchInitDataV1 + uint32 count
    // + records = 132 bytes for the 3 identities on this machine. The macOS
    // capture shows biometrickitd sending inSize=68 for the same command on
    // the same machine with the same 3 identities. 68 == 8 + 3*20, so the
    // identity records go inline after an 8-byte header with no count word.
    // Sending 132 bytes means the SEP parsed garbage where it expected the
    // identity array, which is consistent with a match session that arms
    // the sensor (status 90) and detects the finger (status 63) but never
    // reaches the image/matching stage.
    auto matchInitData = EncodeMatchInitData(0, config_.macosUserId, identities,
                                              config_.matchLayout);
    T2_LOG("verify", L"start match: layout=%s payload=%zuB (macOS reference for %zu identities = %zuB)",
           MatchIdentityLayoutName(config_.matchLayout), matchInitData.size(),
           identities.size(), sizeof(MatchOptionsV1) + identities.size() * sizeof(IdentityRecordV1));
    auto startCmd = EncodeBmCommand(Command::StartMatch, 1, 0, matchInitData);
    if (!conn->SendBiometricCommand(startCmd, 0, &reply, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }

    // Milestone 2B §11: from here on the StartMatch IPC itself succeeded,
    // so a match session may now be live on the device regardless of what
    // happens next - a malformed/unparseable reply, an explicit device
    // rejection, a later transport error, a timeout, or normal completion.
    // CancelMatch must be attempted on every one of those exit paths, not
    // just the "we got all the way through the event loop" one. A
    // scope-exit guard (the same pattern as BusyGuard above) makes this
    // hold regardless of which `return` below actually fires, without
    // duplicating the cancel call at every one of them; it replaces the
    // single unconditional cancel that previously ran only after the event
    // loop and so was skipped by the two early returns below.
    struct CancelGuard {
        bridgexpc::Connection* conn;
        const std::vector<uint8_t>* cancelCmd;
        std::chrono::milliseconds ioTimeout;
        ~CancelGuard() {
            std::vector<uint8_t> discard;
            conn->SendBiometricCommand(*cancelCmd, 0, &discard, ioTimeout); // best-effort
        }
    } cancelGuard{conn, &cancelCmd, config_.ioTimeout};

    // "match_reply[0] != 0 -> match_rejected -> ERROR (never a silent
    // success)" (VERIFIED FROM SOURCE) refers to the OUTER bridgexpc
    // [status, blob] status word for this command - not to any content of
    // the blob itself. That outer status is already enforced above: this
    // point in the function is only reached when SendBiometricCommand
    // returned true, which itself requires statusBlob->status == 0 (see
    // Connection.cpp). The reference never inspects match_reply[1] (the
    // blob) for start-match at all, and now that this command is correctly
    // sent with outputCapacity=0 (matching the reference), the blob is
    // legitimately empty on every successful call - a size check here
    // would reject every accepted start-match as Malformed. Previously
    // this "worked" only by accident, because outputCapacity=64 made the
    // blob 64 zero bytes whose first 4 happened to read as 0.

    auto deadline = steady_clock::now() + config_.matchWindow;
    VerifyOutcome outcome = VerifyOutcome::Timeout; // default if loop exits via deadline

    // Session-level evidence, used only to turn an otherwise opaque
    // "verify-timeout" into a statement about WHERE the pipeline stopped.
    // Never feeds the match/no-match decision.
    bool sawFingerOn = false;
    size_t imagePipelineEvents = 0;
    size_t unnamedStatusEvents = 0;

    while (steady_clock::now() < deadline) {
        std::vector<uint8_t> eventPayload;
        if (!conn->WaitForEvent(&eventPayload, deadline)) {
            break; // timeout or malformed frame -> fall through to Cancel + Timeout/Malformed below
        }

        // VERIFIED FROM SOURCE (bridge-xpc-probe.py summarize_event): the
        // event payload is [9, bridge_status, data, x, x]; `data` begins
        // with a 24-byte header whose embedded_type field is the real
        // discriminator — this replaces the previous hardcoded
        // "assume every event is match_result" placeholder.
        auto statusData = bridgexpc::DecodeStatusEventData(eventPayload);
        if (!statusData) {
            continue; // not a recognizable status-callback shape; keep waiting
        }
        uint32_t embeddedType = 0;
        std::vector<uint8_t> eventData;
        if (!ParseStatusEventHeader(*statusData, &embeddedType, &eventData)) {
            continue; // header too short; keep waiting rather than guessing
        }
        if (embeddedType != kEmbeddedTypeMatchResult) {
            // status (0xE3FF8001) / statistics (0xE3FF8004) / other — not
            // yet a verdict, keep waiting up to the deadline. This is the
            // only place that decodes embedded_type, so without logging it
            // here a hardware session is an opaque wall of "event acked"
            // lines with no way to tell a genuine finger-presence/idle
            // status stream apart from something actually going wrong -
            // that ambiguity is exactly what made a real capture (3
            // back-to-back verify runs, all timing out on nothing but
            // <200B status/statistics events) unreadable after the fact.
            //
            // event_type=status also gets its body's two VERIFIED FROM
            // SOURCE fields (ParseStatusEventBody / MatchResult.h) logged
            // structured, matching what bridge-xpc-probe.py itself decodes
            // for this event kind - status_code and status_data_length.
            // As of 16.09.2026 status_code (== the "ordinal" field
            // FINDINGS.md's enrollment-flow table keys off) also gets a
            // HYPOTHESIS-only label from StatusOrdinalHypothesis when one
            // exists - explicitly NOT verified for this (verify, not
            // enrollment) operation, see that function's own comment.
            // There is deliberately no INVENTED finger/progress field
            // beyond what that hypothesis table itself provides: the
            // reference's own summarize_event() does not decode any
            // further signal from this event kind either, so adding one
            // here would be inventing a field this project has no source
            // for at all, which is exactly what Milestone 2's "no guessing
            // undocumented protocol details" rule forbids.
            const wchar_t* kind = EmbeddedTypeName(embeddedType);
            if (embeddedType == kEmbeddedTypeStatus) {
                StatusEventBody body = ParseStatusEventBody(eventData);
                if (body.statusCode) {
                    const uint32_t code = *body.statusCode;
                    if (code == 63) sawFingerOn = true;
                    if (StatusCodeIsImagePipeline(code)) imagePipelineEvents++;
                    if (!StatusCodeName(code)) unnamedStatusEvents++;
                }
                // ParseStatusEventBody only decodes eventData[0:4) and
                // [8:16) (VERIFIED FROM SOURCE - that is genuinely the
                // reference's entire decode). Whatever status_data_length
                // describes (eventData[16:...)) has never been logged by
                // this project in any form, on any capture to date - every
                // status_code=81/63/78/64 event (the ones bracketing the
                // status_code=91 no-payload event, i.e. the actual
                // per-touch capture cycle) has been a total blind spot.
                // Dumping it is the same "raw bytes, well under
                // kMinMatchResultEventBytes" reasoning already applied to
                // statistics events below - these bodies are 52B, nowhere
                // near the 0xC70B match_result floor, so this cannot be
                // printing anything UUID-shaped.
                T2_LOG("verify",
                       L"event_type=%s embedded_type=0x%08X body=%zuB status_code=%s status_name=%s status_data_length=%s ordinal_hypothesis=%s status_data=%s",
                       kind, embeddedType, eventData.size(),
                       body.statusCode ? std::to_wstring(*body.statusCode).c_str() : L"(n/a)",
                       body.statusCode
                           ? (StatusCodeName(*body.statusCode)
                                  ? StatusCodeName(*body.statusCode)
                                  : L"(not seen in macOS reference capture)")
                           : L"(n/a)",
                       body.statusDataLength ? std::to_wstring(*body.statusDataLength).c_str() : L"(n/a)",
                       body.statusCode
                           ? (StatusOrdinalHypothesis(*body.statusCode) ? StatusOrdinalHypothesis(*body.statusCode) : L"(no hypothesis)")
                           : L"(n/a)",
                       eventData.size() > kStatusEventBodyFixedFieldsBytes
                           ? HexDump(std::vector<uint8_t>(eventData.begin() + kStatusEventBodyFixedFieldsBytes, eventData.end()),
                                     eventData.size() - kStatusEventBodyFixedFieldsBytes).c_str()
                           : L"(none)");
            } else if (embeddedType == kEmbeddedTypeStatistics) {
                // Raw dump, not just size: statistics events are ~28B and
                // this project has never decoded their fields (see the
                // comment above — "statistics ... content not parsed in
                // detail"). Dumping the whole body (well under
                // kMinMatchResultEventBytes, so never risks printing
                // anything UUID-shaped) is meant to let a hardware capture
                // of several finger presentations in a row show whether any
                // byte in here tracks something like a per-attempt quality
                // score around a `status_code=78` (retry) moment — still no
                // meaning assigned here, just the bytes for comparison.
                // 16.09.2026: decoded rather than raw-dumped. The macOS
                // capture shows types 0/1/2 (IEEE-754 doubles, image
                // quality scores ~0.02-0.14) only ever appearing once an
                // image has actually been processed; the failing Windows
                // capture contains types 4/25/30/35 and none of 0/1/2,
                // which is independent confirmation that no image ever
                // reached the matcher. Raw bytes kept alongside.
                StatisticsEventBody stats = ParseStatisticsEventBody(eventData);
                T2_LOG("verify",
                       L"event_type=%s embedded_type=0x%08X body=%zuB stat_type=%s stat_value=%s stat_double=%s raw=%s",
                       kind, embeddedType, eventData.size(),
                       stats.type ? std::to_wstring(*stats.type).c_str() : L"(n/a)",
                       stats.rawValue ? std::to_wstring(*stats.rawValue).c_str() : L"(n/a)",
                       stats.asDouble ? std::to_wstring(*stats.asDouble).c_str() : L"(n/a)",
                       HexDump(eventData, eventData.size()).c_str());
            } else {
                // New as of 16.09.2026: previously any envelope other than
                // status/statistics logged size-only under the generic
                // name "unknown". Now that EmbeddedTypeName covers the
                // reference's full "Raw service-envelope map" (see
                // Commands.h), this also hex-dumps the body when it is
                // safely under kMinMatchResultEventBytes - the same bound
                // already relied on above to guarantee a statistics dump
                // can never be UUID-shaped. A body at or above that bound
                // is left undumped even if the type isn't kEmbeddedTypeMatchResult,
                // since nothing here has verified what such a body can
                // contain for these newly-named types.
                T2_LOG("verify", L"event_type=%s embedded_type=0x%08X body=%zuB%s",
                       kind, embeddedType, eventData.size(),
                       eventData.size() < kMinMatchResultEventBytes
                           ? (L" " + HexDump(eventData, eventData.size())).c_str()
                           : L" (body withheld: size >= kMinMatchResultEventBytes, unverified content)");
            }
            continue;
        }

        // Previously this branch called ParseMatchResult with no logging at
        // all, so a genuine 0xE3FF8002 event arriving on the wire was
        // invisible in the log — every earlier capture that ended in
        // "verify-timeout" left no way to tell whether SEP simply never
        // sent this event, or sent it and something afterward went wrong.
        // Log arrival unconditionally (size only — never the raw bytes,
        // since eventData at this point may embed the identity UUID this
        // project's own logging policy forbids printing), then log the
        // parsed outcome. Never logs the matched UUID itself, only that a
        // match occurred (MatchResult.h's contract for MatchResult::outcome).
        T2_LOG("verify", L"event_type=match_result embedded_type=0x%08X body=%zuB",
               embeddedType, eventData.size());

        MatchResult mr = ParseMatchResult(embeddedType, eventData, identities);
        if (mr.outcome == MatchOutcome::Match) {
            T2_LOG("verify", L"match_result outcome=MATCH (identity matched, UUID not logged)");
            outcome = VerifyOutcome::Match;
            *outMatchedUuid = mr.matchedIdentityUuid;
            break;
        } else if (mr.outcome == MatchOutcome::NoMatch) {
            T2_LOG("verify", L"match_result outcome=NO_MATCH (no enrolled UUID found in event)");
            outcome = VerifyOutcome::NoMatch;
            break;
        }
        // Malformed match_result (e.g. under 0xC70 bytes): keep waiting up
        // to the deadline rather than immediately failing — Milestone 2
        // §20 requires malformed MATCH-RESULT parsing to never become
        // NoMatch, but does not require aborting the whole session.
        T2_LOG("verify", L"match_result outcome=MALFORMED body=%zuB (min required=%zuB) — "
               L"still waiting, not treated as NO_MATCH",
               eventData.size(), kMinMatchResultEventBytes);
    }

    // 16.09.2026: a bare "Timeout" hid the single most informative fact a
    // failing session has. If the SEP told us a finger was on the sensor
    // but never once reported ImageCaptured / ImageForProcessing /
    // ImageWasAccepted, the failure is upstream of matching entirely and
    // no amount of waiting longer will help.
    if (outcome == VerifyOutcome::Timeout && sawFingerOn && imagePipelineEvents == 0) {
        outcome = VerifyOutcome::NoImageCaptured;
    }
    T2_LOG("verify",
           L"session summary: finger_on=%d image_pipeline_events=%zu unnamed_status_events=%zu outcome=%d",
           sawFingerOn ? 1 : 0, imagePipelineEvents, unnamedStatusEvents,
           static_cast<int>(outcome));

    // Cancel runs unconditionally via cancelGuard's destructor as this
    // function returns, matching Linux reference behavior (Milestone 1 §2)
    // - see the CancelGuard comment above for why it now covers every exit
    // path, not just this one.
    return outcome;
}

} // namespace t2::biometrickit
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
    auto resetCmd = EncodeBmCommand(Command::ResetSensor, 1, 2);
    if (!conn->SendBiometricCommand(resetCmd, 64, &reply, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }

    // cancel any outstanding operation (cmd 12)
    auto cancelCmd = EncodeBmCommand(Command::Cancel, 1, 0);
    conn->SendBiometricCommand(cancelCmd, 64, &reply, config_.ioTimeout); // best-effort, ignore failure here

    // FDR calibration (Milestone 2 §6 / bridge-xpc-probe.py
    // --load-calibration): bridge-level method 11 fetches the calibration
    // blob, which is then loaded into the sensor via biometric command
    // 0x20 with value=3 ("source 3 is remote/bridgeOS FDR" — VERIFIED FROM
    // SOURCE; source 5 is local-macOS-filesystem-only and not applicable
    // here). This must run before every match attempt, matching the Linux
    // reference — it is not optional/skippable.
    std::vector<uint8_t> fdrBlob;
    if (!conn->GetFdrCalibration(&fdrBlob, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }
    auto loadCalibrationCmd = EncodeBmCommand(Command::LoadCalibration, /*version=*/1, /*value=*/3, fdrBlob);
    if (!conn->SendBiometricCommand(loadCalibrationCmd, 64, &reply, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
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

    // start match (cmd 4)
    auto matchInitData = EncodeMatchInitData(0, config_.macosUserId, identities);
    auto startCmd = EncodeBmCommand(Command::StartMatch, 1, 0, matchInitData);
    if (!conn->SendBiometricCommand(startCmd, 64, &reply, config_.ioTimeout)) {
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
            conn->SendBiometricCommand(*cancelCmd, 64, &discard, ioTimeout); // best-effort
        }
    } cancelGuard{conn, &cancelCmd, config_.ioTimeout};

    if (reply.size() < 4) {
        return VerifyOutcome::Malformed;
    }
    int32_t startResult;
    std::memcpy(&startResult, reply.data(), 4);
    if (startResult != 0) {
        // VERIFIED FROM SOURCE: "match_reply[0] != 0 -> match_rejected ->
        // ERROR (never a silent success)".
        return VerifyOutcome::RejectedByDevice;
    }

    auto deadline = steady_clock::now() + config_.matchWindow;
    VerifyOutcome outcome = VerifyOutcome::Timeout; // default if loop exits via deadline

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
            // There is deliberately no finger=/progress= field here: the
            // reference implementation does not decode any such signal from
            // this event kind either, so adding one here would be inventing
            // a field this project has no source for, which is exactly what
            // Milestone 2's "no guessing undocumented protocol details"
            // rule forbids. If a finger-presence signal exists on the wire
            // at all, it is not part of what has been reverse-engineered so
            // far — see docs/linux-reference-analysis.md and the reference
            // project's own bridge-xpc-probe.py::summarize_event.
            const wchar_t* kind = (embeddedType == kEmbeddedTypeStatus) ? L"status"
                                 : (embeddedType == kEmbeddedTypeStatistics) ? L"statistics"
                                 : L"unknown";
            if (embeddedType == kEmbeddedTypeStatus) {
                StatusEventBody body = ParseStatusEventBody(eventData);
                T2_LOG("verify",
                       L"event_type=%s embedded_type=0x%08X body=%zuB status_code=%s status_data_length=%s",
                       kind, embeddedType, eventData.size(),
                       body.statusCode ? std::to_wstring(*body.statusCode).c_str() : L"(n/a)",
                       body.statusDataLength ? std::to_wstring(*body.statusDataLength).c_str() : L"(n/a)");
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
                T2_LOG("verify", L"event_type=%s embedded_type=0x%08X body=%zuB %s",
                       kind, embeddedType, eventData.size(), HexDump(eventData, eventData.size()).c_str());
            } else {
                T2_LOG("verify", L"event_type=%s embedded_type=0x%08X body=%zuB",
                       kind, embeddedType, eventData.size());
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

    // Cancel runs unconditionally via cancelGuard's destructor as this
    // function returns, matching Linux reference behavior (Milestone 1 §2)
    // - see the CancelGuard comment above for why it now covers every exit
    // path, not just this one.
    return outcome;
}

} // namespace t2::biometrickit
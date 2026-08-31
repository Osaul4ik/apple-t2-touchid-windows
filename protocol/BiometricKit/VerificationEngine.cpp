// SPDX-License-Identifier: GPL-2.0-only
// VerificationEngine.cpp
#include "VerificationEngine.h"
#include "../BridgeXpc/PlistPayload.h"
#include <cstring>

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

    // reset sensor (cmd 2, value=2)
    auto resetCmd = EncodeBmCommand(Command::ResetSensor, 0, 2);
    if (!conn->SendBiometricCommand(resetCmd, 64, &reply, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }

    // cancel any outstanding operation (cmd 12)
    auto cancelCmd = EncodeBmCommand(Command::Cancel, 0, 0);
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
    auto idCmd = EncodeBmCommand(Command::IdentityList, 0, 0, idReq);
    if (!conn->SendBiometricCommand(idCmd, 4096, &reply, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }
    std::vector<IdentityRecordV1> identities;
    if (!ParseIdentityList(reply, &identities)) {
        return VerifyOutcome::Malformed;
    }

    // start match (cmd 4)
    auto matchInitData = EncodeMatchInitData(0, config_.macosUserId, identities);
    auto startCmd = EncodeBmCommand(Command::StartMatch, 0, 0, matchInitData);
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
            // yet a verdict, keep waiting up to the deadline.
            continue;
        }

        MatchResult mr = ParseMatchResult(embeddedType, eventData, identities);
        if (mr.outcome == MatchOutcome::Match) {
            outcome = VerifyOutcome::Match;
            *outMatchedUuid = mr.matchedIdentityUuid;
            break;
        } else if (mr.outcome == MatchOutcome::NoMatch) {
            outcome = VerifyOutcome::NoMatch;
            break;
        }
        // Malformed match_result (e.g. under 0xC70 bytes): keep waiting up
        // to the deadline rather than immediately failing — Milestone 2
        // §20 requires malformed MATCH-RESULT parsing to never become
        // NoMatch, but does not require aborting the whole session.
    }

    // Cancel runs unconditionally via cancelGuard's destructor as this
    // function returns, matching Linux reference behavior (Milestone 1 §2)
    // - see the CancelGuard comment above for why it now covers every exit
    // path, not just this one.
    return outcome;
}

} // namespace t2::biometrickit

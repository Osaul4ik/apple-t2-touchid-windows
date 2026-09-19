// SPDX-License-Identifier: GPL-2.0-only
// VerificationEngine.cpp
#include "VerificationEngine.h"
#include "../BridgeXpc/PlistPayload.h"
#include "../BridgeXpc/Log.h"
#include <algorithm>
#include <cstring>
#include <string>

using t2::log::HexDump;

namespace t2::biometrickit {

using namespace std::chrono;

// Exact port of jmurth1234/t2-touchid-linux:
//   src/t2-biometric-ready.sh warm_up()
//   src/t2-fprintd.py T2Backend._run_probe() prefix
//   src/bridge-xpc-probe.py flags:
//     --initialize --reset-sensor --cancel-operation
//     --load-calibration --identity-list
//
// Wire, in order, with biometric_command() defaults (version=1, value=0
// unless noted, output_capacity=0 unless noted):
//   request([0])                         getBridgeVersion
//   request([10, min(api_version, 2)])   setClientVersion
//   biometric_command(2, value=2)        ResetSensor
//   biometric_command(12)                Cancel
//   request_with_events([11])            FDR blob
//   biometric_command(0x20, value=3, data=fdr)
//   biometric_command(0x42, data=uid:u32le, output_capacity=20*10)
//
// No cmd 0x53. No StartMatch. Payloads are the Linux ones, not invented.
bool VerificationEngine::RunLinuxReadySequence(
    bridgexpc::Connection* conn,
    std::vector<IdentityRecordV1>* outIdentities,
    std::vector<uint8_t>* outIdentityListRaw) {
    int64_t bridgeVersion = 0;
    if (!conn->GetBridgeVersion(&bridgeVersion, config_.ioTimeout)) {
        return false;
    }
    int64_t clientVersion = (bridgeVersion < 2) ? bridgeVersion : 2; // min(api_version, 2)
    if (!conn->SetClientVersion(clientVersion, config_.ioTimeout)) {
        return false;
    }

    std::vector<uint8_t> reply;

    if (config_.skipResetSensor) {
        T2_LOG("warmup", L"skipping ResetSensor (macOS live path never issues cmd 2)");
    } else {
        auto resetCmd = EncodeBmCommand(Command::ResetSensor, /*version=*/1, /*value=*/2);
        if (!conn->SendBiometricCommand(resetCmd, /*outputCapacity=*/0, &reply, config_.ioTimeout)) {
            T2_LOG("warmup", L"ResetSensor (cmd 2, value=2, capacity=0) failed");
            return false;
        }
        T2_LOG("warmup", L"ResetSensor OK");
    }

    auto cancelCmd = EncodeBmCommand(Command::Cancel, /*version=*/1, /*value=*/0);
    conn->SendBiometricCommand(cancelCmd, /*outputCapacity=*/0, &reply, config_.ioTimeout); // best-effort
    T2_LOG("warmup", L"Cancel (cmd 0x0c) issued");

    if (config_.skipLoadCalibration) {
        T2_LOG("warmup",
               L"skipping LoadCalibration (macOS live path never issues cmd 0x20; "
               L"bridgeOS calibrates at its own boot)");
    } else {
        std::vector<uint8_t> fdrBlob;
        if (!conn->GetFdrCalibration(&fdrBlob, config_.ioTimeout)) {
            T2_LOG("warmup", L"GetFdrCalibration (bridge method 11) failed");
            return false;
        }
        auto loadCalibrationCmd = EncodeBmCommand(Command::LoadCalibration, /*version=*/1, /*value=*/3, fdrBlob);
        if (!conn->SendBiometricCommand(loadCalibrationCmd, /*outputCapacity=*/0, &reply, config_.ioTimeout)) {
            T2_LOG("warmup", L"LoadCalibration (cmd 0x20, value=3, capacity=0, fdr=%zuB) failed",
                   fdrBlob.size());
            return false;
        }
        T2_LOG("warmup", L"LoadCalibration OK, fdr=%zuB", fdrBlob.size());
    }

    std::vector<uint8_t> idReq(4);
    std::memcpy(idReq.data(), &config_.macosUserId, 4);
    auto idCmd = EncodeBmCommand(Command::IdentityList, /*version=*/1, /*value=*/0, idReq);
    if (!conn->SendBiometricCommand(idCmd, kIdentityListOutputCapacity, &reply, config_.ioTimeout)) {
        T2_LOG("warmup", L"IdentityList (cmd 0x42, capacity=%u) failed",
               kIdentityListOutputCapacity);
        return false;
    }
    std::vector<IdentityRecordV1> identities;
    if (!ParseIdentityList(reply, &identities)) {
        T2_LOG("warmup", L"IdentityList reply malformed (reply=%zuB, not a multiple of 20)",
               reply.size());
        return false;
    }
    T2_LOG("warmup", L"identity list parsed: %zu identities (reply=%zuB)",
           identities.size(), reply.size());
    if (outIdentityListRaw) {
        *outIdentityListRaw = reply;
    }
    if (outIdentities) {
        *outIdentities = std::move(identities);
    }
    return true;
}

bool VerificationEngine::WarmUp(bridgexpc::Connection* conn,
                                std::vector<IdentityRecordV1>* outIdentities) {
    if (busy_) {
        return false;
    }
    busy_ = true;
    struct BusyGuard { bool* b; ~BusyGuard() { *b = false; } } guard{&busy_};

    T2_LOG("warmup",
           L"linux ready sequence (non-matching): initialize, reset-sensor, "
           L"cancel-operation, load-calibration, identity-list");
    return RunLinuxReadySequence(conn, outIdentities);
}

VerifyOutcome VerificationEngine::Verify(bridgexpc::Connection* conn,
                                          std::optional<std::array<uint8_t, 16>>* outMatchedUuid) {
    if (busy_) {
        return VerifyOutcome::Busy;
    }
    busy_ = true;
    struct BusyGuard { bool* b; ~BusyGuard() { *b = false; } } guard{&busy_};

    // Same prefix Linux fprintd sends on the verify connection
    // (--initialize --reset-sensor --cancel-operation --load-calibration
    // --identity-list) AFTER t2-biometric-ready already did it once on a
    // previous connection. Empty identity list is a hard fail here because
    // bridge-xpc-probe.py: "--match-seconds requires a non-empty --identity-list result".
    std::vector<IdentityRecordV1> identities;
    std::vector<uint8_t> firstUserRaw;
    if (!RunLinuxReadySequence(conn, &identities, &firstUserRaw)) {
        return VerifyOutcome::TransportError;
    }
    if (identities.empty()) {
        T2_LOG("verify", L"identity list empty - refusing StartMatch (Linux requires non-empty)");
        return VerifyOutcome::Malformed;
    }

    // 18.09.2026: REMOVED. The 0x51->0x42->0x51 stability gate that used
    // to live here belongs to a DIFFERENT code path — the
    // finger-selection production flow (t2_fprint_match_gate.prepare/
    // prepare_all), reached only via --match-finger-name /
    // --resolve-any-finger-name / --resolve-any-identity-slot on the
    // Linux reference, which this project's CLI has no equivalent of and
    // has never sent. The bare `bridge-xpc-probe.py --match-seconds`
    // path this project actually compares against goes straight from the
    // single --identity-list read to `biometric_command(sock, 4, ...)` —
    // no 0x51, no repeated 0x42. VERIFIED FROM SOURCE: prepare_all's
    // per_user_records is the same first-read bytes either way (it only
    // adds a local-Catacomb name-resolution check, no record filtering),
    // so this project's own StartMatch payload was already correct with
    // or without the gate — the gate only added 4 extra commands and
    // real round-trip time that the actual thing being compared against
    // never sent. Identities from the single --identity-list read above
    // (RunLinuxReadySequence) go straight into StartMatch below.
    T2_LOG("verify",
           L"proceeding straight to StartMatch with the %zu identities from "
           L"the single --identity-list read (%zuB raw) - bare "
           L"bridge-xpc-probe.py --match-seconds parity, no extra commands",
           identities.size(), firstUserRaw.size());

    std::vector<uint8_t> reply;
    // Kept for the CancelGuard below (post-match cleanup on every exit
    // path) — unrelated to the removed pre-match sequence.
    auto cancelCmd = EncodeBmCommand(Command::Cancel, 1, 0);

    // REVERTED (16.09.2026): the macOS-log-derived pre-match sequence that
    // used to live here (GetEnabledForUnlock/GetSksLockStateMac/
    // GetProtectedConfig/GetBiometrickitdInfo, a double Cancel, and a wait
    // for an async 89 Idle event before StartMatch) is GONE. Two back-to-
    // back real-hardware captures with it in place never once produced an
    // 80 MatchingCancelled or 89 Idle event before StartMatch — both times
    // the eventual 80 showed up only after StartMatch was already sent, as
    // the first event of the match stream itself, meaning that whole
    // sequence bought nothing but ~1s of dead time and four guaranteed
    // status=258 failures (48/39/46/40 are simply not usable on this
    // bridge/firmware, unlike the biometrickitd process macOS's own log was
    // allegedly captured from). That macOS capture itself is not trusted
    // (see MatchResult.cpp's DISTRUST NOTICE) — but even taking the
    // entitlement-gap theory on its own terms, Linux's actual, disassembly-
    // confirmed research (t2-touchid-linux, enrollment_research/
    // FINDINGS.md, "Enrollment authorization container and trust
    // boundaries") is evidence AGAINST it for this build: it documents that
    // biometrickitd's capability-bit check (`isClient:entitled:forMethod:`)
    // "returns true" on every valid permission-group path regardless of
    // the entitlement bit, and that the one confirmed use of status 258 in
    // that document is an invalid credential-set object/length in
    // ENROLLMENT auth parsing — unrelated to StartMatch or to these four
    // opcodes. So there is now a Linux-sourced reason to doubt the
    // entitlement-gap theory specifically, not just an absence of evidence
    // for it. This driver goes straight from --identity-list to
    // StartMatch — exactly what t2-fprintd.py/bridge-xpc-probe.py's real
    // --timed-match path does (VERIFIED FROM SOURCE:
    // biometric_command(sock, 4, data=match_data) is the very next call
    // after --identity-list, no Cancel, no wait, nothing else between).
    // config_.skipResetSensor/skipLoadCalibration also now default to
    // false for the same reason: Linux's warm_up always sends both;
    // skipping them was a macOS-capture-only assumption with the same
    // lack of confirmation as the sequence just removed.

    // start match (cmd 4) — Linux counted default: II60x + count + records
    // (132 B for 3 identities). Override with --match-layout inline|padded.

    // 17.09.2026: LINUX PARITY FIX. Every biometric_command()/
    // request_with_events() call in the reference returns its OWN local
    // events list (VERIFIED FROM SOURCE: reset_events, fdr_events,
    // calibration_events, identities_events, etc. are each a fresh list
    // scoped to that one call) - none of them ever feed into the match
    // session's own `events`, which starts empty exactly at
    // `match_reply, events = biometric_command(sock, 4, data=match_data)`.
    // This project's pendingEvents_ is shared across every
    // SendBiometricCommand/GetFdrCalibration call on this connection
    // (ResetSensor, warm-up Cancel, LoadCalibration, IdentityList), so
    // without this clear, WaitForEvent() below hands the match-session loop
    // whatever leftover events those warm-up calls happened to observe -
    // confirmed on the 16.09.2026 hardware capture, where the match
    // session's first two logged events (80 MatchingCancelled, unnamed 94)
    // were actually acked during LoadCalibration's own reply-wait, well
    // before StartMatch was even sent. DiscardPendingEvents() already
    // existed for exactly this (Connection.cpp/.h) but was never called.
    // Events queued during StartMatch's OWN SendBiometricCommand call just
    // below are unaffected - they land in pendingEvents_ after this point,
    // same as the reference's own per-call `events` for cmd 4.
    const size_t discardedPreMatchEvents = conn->DiscardPendingEvents();
    if (discardedPreMatchEvents > 0) {
        T2_LOG("verify",
               L"discarded %zu pre-StartMatch event(s) accumulated during warm-up "
               L"(Linux never attributes these to the match session)",
               discardedPreMatchEvents);
    }

    auto matchInitData = EncodeMatchInitData(config_.matchFlags, config_.macosUserId,
                                              identities, config_.matchLayout);
    T2_LOG("verify",
           L"start match LINUX 1:1: layout=%s payload=%zuB flags=%u (Linux counted for %zu identities expects %zuB)",
           MatchIdentityLayoutName(config_.matchLayout), matchInitData.size(),
           config_.matchFlags, identities.size(),
           sizeof(MatchInitDataV1) + sizeof(uint32_t) + identities.size() * sizeof(IdentityRecordV1));
    auto startCmd = EncodeBmCommand(Command::StartMatch, 1, 0, matchInitData);
    if (!conn->SendBiometricCommand(startCmd, 0, &reply, config_.ioTimeout)) {
        return VerifyOutcome::TransportError;
    }

    // Milestone 2B §11: from here on the StartMatch IPC itself succeeded,
    // so a match session may now be live on the device regardless of what
    // happens next. CancelMatch must be attempted on every exit path.
    struct CancelGuard {
        bridgexpc::Connection* conn;
        const std::vector<uint8_t>* cancelCmd;
        std::chrono::milliseconds ioTimeout;
        ~CancelGuard() {
            std::vector<uint8_t> discard;
            conn->SendBiometricCommand(*cancelCmd, 0, &discard, ioTimeout); // best-effort
        }
    } cancelGuard{conn, &cancelCmd, config_.ioTimeout};

    auto deadline = steady_clock::now() + config_.matchWindow;
    VerifyOutcome outcome = VerifyOutcome::Timeout; // default if loop exits via deadline

    bool sawFingerOn = false;
    size_t imagePipelineEvents = 0;
    size_t unnamedStatusEvents = 0;
    size_t fingerTouchCycles = 0;

    while (steady_clock::now() < deadline) {
        std::vector<uint8_t> eventPayload;
        if (!conn->WaitForEvent(&eventPayload, deadline)) {
            break;
        }

        auto statusData = bridgexpc::DecodeStatusEventData(eventPayload);
        if (!statusData) {
            continue;
        }
        uint32_t embeddedType = 0;
        std::vector<uint8_t> eventData;
        if (!ParseStatusEventHeader(*statusData, &embeddedType, &eventData)) {
            continue;
        }
        if (embeddedType != kEmbeddedTypeMatchResult) {
            const wchar_t* kind = EmbeddedTypeName(embeddedType);
            if (embeddedType == kEmbeddedTypeStatus) {
                StatusEventBody body = ParseStatusEventBody(eventData);
                if (body.statusCode) {
                    const uint32_t code = *body.statusCode;
                    if (code == 63) { sawFingerOn = true; fingerTouchCycles++; }
                    if (StatusCodeIsImagePipeline(code)) imagePipelineEvents++;
                    if (!StatusCodeName(code)) unnamedStatusEvents++;
                }
                T2_LOG("verify",
                       L"event_type=%s embedded_type=0x%08X body=%zuB status_code=%s status_name=%s status_data_length=%s ordinal_hypothesis=%s status_data=%s",
                       kind, embeddedType, eventData.size(),
                       body.statusCode ? std::to_wstring(*body.statusCode).c_str() : L"(n/a)",
                       body.statusCode
                           ? (StatusCodeName(*body.statusCode)
                                  ? StatusCodeName(*body.statusCode)
                                  : L"(unnamed, unverified table)")
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
                StatisticsEventBody stats = ParseStatisticsEventBody(eventData);
                T2_LOG("verify",
                       L"event_type=%s embedded_type=0x%08X body=%zuB stat_type=%s stat_value=%s stat_double=%s raw=%s",
                       kind, embeddedType, eventData.size(),
                       stats.type ? std::to_wstring(*stats.type).c_str() : L"(n/a)",
                       stats.rawValue ? std::to_wstring(*stats.rawValue).c_str() : L"(n/a)",
                       stats.asDouble ? std::to_wstring(*stats.asDouble).c_str() : L"(n/a)",
                       HexDump(eventData, eventData.size()).c_str());
            } else {
                T2_LOG("verify", L"event_type=%s embedded_type=0x%08X body=%zuB%s",
                       kind, embeddedType, eventData.size(),
                       eventData.size() < kMinMatchResultEventBytes
                           ? (L" " + HexDump(eventData, eventData.size())).c_str()
                           : L" (body withheld: size >= kMinMatchResultEventBytes, unverified content)");
            }
            continue;
        }

        T2_LOG("verify", L"event_type=match_result embedded_type=0x%08X body=%zuB",
               embeddedType, eventData.size());

        MatchResult mr = ParseMatchResult(embeddedType, eventData, identities);
        if (mr.outcome == MatchOutcome::Match) {
            T2_LOG("verify", L"match_result outcome=MATCH (identity matched, UUID not logged)");
            outcome = VerifyOutcome::Match;
            *outMatchedUuid = mr.matchedIdentityUuid;
            break;
        } else if (mr.outcome == MatchOutcome::NoMatch) {
            T2_LOG("verify",
                   eventData.size() < kMinMatchResultEventBytes
                       ? L"match_result outcome=NO_MATCH (body=%zuB, shorter than min=%zuB — "
                         L"treated as definite no-match per Linux reference, not a wait state)"
                       : L"match_result outcome=NO_MATCH (no enrolled UUID found in event, body=%zuB min=%zuB)",
                   eventData.size(), kMinMatchResultEventBytes);
            outcome = VerifyOutcome::NoMatch;
            break;
        }
        // mr.outcome == MatchOutcome::Malformed is unreachable here: this
        // call site only invokes ParseMatchResult after the caller's own
        // `embeddedType != kEmbeddedTypeMatchResult` check above already
        // `continue`d for anything else. Kept as a silent no-op (loop just
        // continues) rather than an assert, since Malformed's only purpose
        // is defensive robustness against a future call-site change.
    }

    // REMOVED (17.09.2026): no longer relabels Timeout as NoImageCaptured.
    // VERIFIED FROM SOURCE (t2-fprintd.py verdict_from_result): the
    // reference's own verdict is match_result-only; sawFingerOn/
    // imagePipelineEvents never gate its outcome. They stay below purely
    // as session-summary diagnostics.
    T2_LOG("verify",
           L"session summary: finger_touch_cycles=%zu image_pipeline_events=%zu unnamed_status_events=%zu "
           L"layout=%s flags=%u reset=%s cal=%s outcome=%d",
           fingerTouchCycles, imagePipelineEvents, unnamedStatusEvents,
           MatchIdentityLayoutName(config_.matchLayout), config_.matchFlags,
           config_.skipResetSensor ? L"skip" : L"yes",
           config_.skipLoadCalibration ? L"skip" : L"yes",
           static_cast<int>(outcome));

    return outcome;
}

} // namespace t2::biometrickit
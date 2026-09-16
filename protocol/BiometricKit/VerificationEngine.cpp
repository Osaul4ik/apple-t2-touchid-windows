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

namespace {

// Read-only diagnostic: biometric command 0x53, one-byte sensor-ready
// state. VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux,
// bridge-xpc-probe.py's --sensor-readiness: biometric_command(sock, 0x53,
// version=1, value=0, output_capacity=1), reply blob's single byte treated
// as bool sensor_ready). This project never called command 0x53 before
// 16.09.2026. It is read-only and safe to call unconditionally, regardless
// of the resetSensor/loadCalibration config - unlike those two, sending it
// cannot itself change sensor state.
//
// Purpose (16.09.2026 A/B, see project notes): find out whether the sensor
// is already "ready" before this project does anything, and whether
// LoadCalibration is what flips that bit. A false->true transition
// straddling LoadCalibration would localize the missing-image-pipeline
// problem to sensor init/calibration state rather than the match payload,
// layout, or status 81/78 (both already ruled out by prior captures).
std::optional<bool> QuerySensorReadiness(bridgexpc::Connection* conn,
                                          std::chrono::milliseconds timeout) {
    auto cmd = EncodeBmCommand(Command::SensorReadiness, /*version=*/1, /*value=*/0);
    std::vector<uint8_t> reply;
    if (!conn->SendBiometricCommand(cmd, /*outputCapacity=*/1, &reply, timeout)) {
        return std::nullopt;
    }
    if (reply.size() != 1) {
        return std::nullopt;
    }
    return reply[0] != 0;
}

const wchar_t* ReadinessLabel(const std::optional<bool>& r) {
    if (!r) return L"query failed";
    return *r ? L"1 (ready)" : L"0 (not ready)";
}

} // namespace

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

    // 16.09.2026: sensor-readiness A/B instrumentation. Queried here,
    // before ResetSensor/Cancel/LoadCalibration touch anything, so this is
    // the session's true "at rest" readiness - the other half of the pair
    // is queried after LoadCalibration below, only when that step actually
    // ran (there is nothing meaningful to compare it against otherwise).
    std::optional<bool> readinessAtStartup = QuerySensorReadiness(conn, config_.ioTimeout);
    std::optional<bool> readinessAfterCalibration; // stays empty unless loadCalibration ran
    T2_LOG("verify", L"sensor readiness (cmd 0x53, at startup): %s",
           ReadinessLabel(readinessAtStartup));

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
        readinessAfterCalibration = QuerySensorReadiness(conn, config_.ioTimeout);
        T2_LOG("verify", L"sensor readiness (cmd 0x53, after LoadCalibration): %s",
               ReadinessLabel(readinessAfterCalibration));
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
    size_t fingerTouchCycles = 0; // count of status_code==63 (FingerOn) events
    // 16.09.2026: two back-to-back hardware captures (132B legacy payload,
    // then the corrected 68B inline payload) produced BIT-IDENTICAL status
    // sequences - same 81/63/91/78/64 cycle, same statistics types
    // (4/35/25 then 30), same total absence of 55/72/95 and of statistics
    // types 0/1/2. Fixing the StartMatch payload size to match the macOS
    // capture changed nothing observable on the wire. That is strong
    // evidence the payload content is not what gates image capture -
    // whatever decides "does the sensor hand a captured image to the
    // matcher" happens upstream of this command entirely. See
    // docs/macos-verified-status-map.md section 7 ("second hardware
    // capture"). LoadCalibration (still opt-in, disabled by default because
    // the macOS *live* capture never re-issues it) is now the leading
    // remaining candidate specifically because Boot Camp Windows may skip
    // whatever step macOS's own boot performs to arm the sensor for a given
    // power cycle - something biometrickitd's own IPC traffic would never
    // show, since on macOS it already happened before biometrickitd ran.

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
            T2_LOG("verify", L"match_result outcome=NO_MATCH (no enrolled UUID found in event)");
            outcome = VerifyOutcome::NoMatch;
            break;
        }
        T2_LOG("verify", L"match_result outcome=MALFORMED body=%zuB (min required=%zuB) — "
               L"still waiting, not treated as NO_MATCH",
               eventData.size(), kMinMatchResultEventBytes);
    }

    if (outcome == VerifyOutcome::Timeout && sawFingerOn && imagePipelineEvents == 0) {
        outcome = VerifyOutcome::NoImageCaptured;
    }
    T2_LOG("verify",
           L"session summary: finger_touch_cycles=%zu image_pipeline_events=%zu unnamed_status_events=%zu "
           L"layout=%s reset_sensor=%d load_calibration=%d readiness_startup=%s readiness_after_calibration=%s outcome=%d",
           fingerTouchCycles, imagePipelineEvents, unnamedStatusEvents,
           MatchIdentityLayoutName(config_.matchLayout), config_.resetSensor ? 1 : 0,
           config_.loadCalibration ? 1 : 0, ReadinessLabel(readinessAtStartup),
           ReadinessLabel(readinessAfterCalibration), static_cast<int>(outcome));
    if (fingerTouchCycles >= 2 && imagePipelineEvents == 0 && !config_.loadCalibration) {
        T2_LOG("verify",
               L"%zu consecutive no-image touch cycles with LoadCalibration disabled - "
               L"strongly consider retrying with loadCalibration=true (--load-calibration)",
               fingerTouchCycles);
    }

    return outcome;
}

} // namespace t2::biometrickit
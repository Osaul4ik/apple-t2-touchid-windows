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

namespace {

bool Uuid16IsZero(const uint8_t* p) {
    for (int i = 0; i < 16; i++) {
        if (p[i] != 0) return false;
    }
    return true;
}

// Port of t2_fprint_match_gate._global_records: walk 40-byte
// global_identity_record_v1_t values, reject zero-UUID / duplicates /
// non-built-in group on the configured user, collect the leading 20-byte
// identity_record_v1_t of each configured entry.
bool ConfiguredGlobalIdentities(const std::vector<uint8_t>& globalRaw,
                                uint32_t appleUserId,
                                std::vector<std::array<uint8_t, 20>>* outConfigured) {
    outConfigured->clear();
    if (globalRaw.size() % 40 != 0) return false;
    std::vector<std::array<uint8_t, 20>> seen;
    for (size_t off = 0; off < globalRaw.size(); off += 40) {
        std::array<uint8_t, 20> identity{};
        std::memcpy(identity.data(), globalRaw.data() + off, 20);
        if (Uuid16IsZero(identity.data() + 4)) return false;
        for (const auto& s : seen) {
            if (s == identity) return false;
        }
        seen.push_back(identity);
        uint32_t userId = 0;
        std::memcpy(&userId, identity.data(), 4);
        if (userId != appleUserId) continue;
        uint32_t groupType = 0;
        std::memcpy(&groupType, globalRaw.data() + off + 20, 4);
        if (groupType != 0 && groupType != 1) return false;
        if (!Uuid16IsZero(globalRaw.data() + off + 24)) return false;
        outConfigured->push_back(identity);
    }
    return true;
}

bool SamePerUserSet(std::vector<std::array<uint8_t, 20>> configured,
                    const std::vector<IdentityRecordV1>& perUser) {
    std::vector<std::array<uint8_t, 20>> live;
    live.reserve(perUser.size());
    for (const auto& rec : perUser) {
        std::array<uint8_t, 20> raw{};
        std::memcpy(raw.data(), &rec, 20);
        live.push_back(raw);
    }
    std::sort(configured.begin(), configured.end());
    std::sort(live.begin(), live.end());
    return configured == live;
}

} // namespace

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

    // LINUX PARITY (docs/linux-reference-analysis.md §7, 16.09.2026 entry):
    // t2-fprintd.py's verify_fprint() — the real path every normal "any
    // finger" unlock takes (resolve_any_finger=True whenever
    // requested_finger == "any") — always runs 0x42 -> 0x51 -> 0x42 -> 0x51
    // (t2_fprint_match_gate.prepare_slots/prepare_all) before StartMatch,
    // and fails closed if the first/repeat snapshot of either command
    // disagrees. The bare bridge-xpc-probe.py --match-seconds CLI (no
    // --resolve-any-finger-name) skips this gate, but that is not the
    // code path fprintd's production unlock uses, so it is not the one
    // this driver should imitate. Identities sent to StartMatch are the
    // FIRST 0x42 read, never the repeat — the repeat and both 0x51 reads
    // exist only to prove the live inventory is stable.
    T2_LOG("verify",
           L"LINUX unlock-parity gate: verifying identity inventory is stable "
           L"(0x42 done, now 0x51 -> 0x42 -> 0x51) before StartMatch (%zu identities, %zuB raw)",
           identities.size(), firstUserRaw.size());

    auto readGlobalIdentityList = [&](std::vector<uint8_t>* outRaw) -> bool {
        auto globalCmd = EncodeBmCommand(Command::GlobalIdentityList, /*version=*/1, /*value=*/0);
        return conn->SendBiometricCommand(globalCmd, kGlobalIdentityListOutputCapacity, outRaw,
                                           config_.ioTimeout);
    };
    auto readUserIdentityList = [&](std::vector<uint8_t>* outRaw) -> bool {
        std::vector<uint8_t> idReq(4);
        std::memcpy(idReq.data(), &config_.macosUserId, 4);
        auto idCmd = EncodeBmCommand(Command::IdentityList, /*version=*/1, /*value=*/0, idReq);
        return conn->SendBiometricCommand(idCmd, kIdentityListOutputCapacity, outRaw, config_.ioTimeout);
    };

    std::vector<uint8_t> firstGlobalRaw, repeatUserRaw, repeatGlobalRaw;
    if (!readGlobalIdentityList(&firstGlobalRaw)) {
        T2_LOG("verify", L"GlobalIdentityList (cmd 0x51, first read) failed");
        return VerifyOutcome::TransportError;
    }
    if (!readUserIdentityList(&repeatUserRaw)) {
        T2_LOG("verify", L"IdentityList (cmd 0x42, repeat read) failed");
        return VerifyOutcome::TransportError;
    }
    if (!readGlobalIdentityList(&repeatGlobalRaw)) {
        T2_LOG("verify", L"GlobalIdentityList (cmd 0x51, repeat read) failed");
        return VerifyOutcome::TransportError;
    }

    std::vector<std::array<uint8_t, 20>> configuredFirst, configuredRepeat;
    if (!ConfiguredGlobalIdentities(firstGlobalRaw, config_.macosUserId, &configuredFirst) ||
        !ConfiguredGlobalIdentities(repeatGlobalRaw, config_.macosUserId, &configuredRepeat)) {
        T2_LOG("verify", L"global identity-list malformed (zero-UUID, duplicate, or "
               L"non-built-in group entry) — fail-closed, refusing StartMatch");
        return VerifyOutcome::UnstableIdentityInventory;
    }
    std::vector<IdentityRecordV1> repeatIdentities;
    if (!ParseIdentityList(repeatUserRaw, &repeatIdentities)) {
        T2_LOG("verify", L"repeat IdentityList reply malformed (%zuB, not a multiple of 20) — "
               L"fail-closed, refusing StartMatch", repeatUserRaw.size());
        return VerifyOutcome::UnstableIdentityInventory;
    }
    std::sort(configuredFirst.begin(), configuredFirst.end());
    std::sort(configuredRepeat.begin(), configuredRepeat.end());
    if (configuredFirst != configuredRepeat || !SamePerUserSet(configuredFirst, identities) ||
        !SamePerUserSet(configuredRepeat, repeatIdentities)) {
        T2_LOG("verify", L"live identity inventory is unstable (first/repeat 0x42 or 0x51 "
               L"snapshot disagreed) — fail-closed, refusing StartMatch");
        return VerifyOutcome::UnstableIdentityInventory;
    }
    T2_LOG("verify", L"identity inventory stable across 0x42->0x51->0x42->0x51 (%zu configured)",
           configuredFirst.size());

    auto cancelCmd = EncodeBmCommand(Command::Cancel, 1, 0);
    std::vector<uint8_t> reply;

    // macOS live-unlock pre-match sequence — VERIFIED FROM SOURCE, a real
    // macOS unified-log capture of biometrickitd on this exact machine/
    // firmware (16.09.2026, /mnt/user-data/uploads/touchid-unlock.log),
    // not the earlier docs/ macos-verified.md §4 command SET alone — that
    // gave the commands issued but not their order. The full ordered trace
    // for a successful unlock, exact timestamps:
    //   48 GetEnabledForUnlock
    //   39 GetSksLockStateMac(uid)
    //   46 GetProtectedConfig(uid)
    //   12 Cancel                        -> async status 80 MatchingCancelled
    //   39 GetSksLockStateMac(uid)        (repeat)
    //   40 GetBiometrickitdInfo
    //   46 GetProtectedConfig(uid)        (repeat)
    //   [cmd 84, inSize=20, undocumented - fires from an unrelated periodic
    //    statistics(type 29) callback, not part of this gate; not ported,
    //    no verified request/reply format exists for it]
    //   12 Cancel (again)                -> async status 89 SensorOperationModeIdle
    //   4 StartMatch (68B)               -> 90 Capture -> ... -> 55 ImageCaptured
    // StartMatch is issued ONLY after the SECOND Cancel, and that second
    // Cancel is the last thing sent before it - nothing else comes between.
    // The resulting 89 Idle transition is exactly the status this project's
    // own Windows captures have never once observed (docs/ macos-verified.md
    // §2's "failing Windows session" trace has no 80 and no 89 either).
    // Windows previously went straight from identity-list to StartMatch with
    // no Cancel adjacent to it at all. Only request sizes are documented
    // (48/40: inSize=0; 39/46: inSize=4, macosUserId) - no reply format is
    // documented for any of them, so none is parsed; outputCapacity=0
    // matches the existing convention for commands whose reply body this
    // project does not read (ResetSensor, Cancel, LoadCalibration, StartMatch
    // above/below). Best-effort, like the existing warm-up Cancel: a failure
    // here does not by itself justify aborting a verify that has a stable,
    // non-empty identity list.
    {
        std::vector<uint8_t> uidReq(4);
        std::memcpy(uidReq.data(), &config_.macosUserId, 4);

        auto enabledForUnlockCmd = EncodeBmCommand(Command::GetEnabledForUnlock, 1, 0);
        auto sksLockStateCmd = EncodeBmCommand(Command::GetSksLockStateMac, 1, 0, uidReq);
        auto protectedConfigCmd = EncodeBmCommand(Command::GetProtectedConfig, 1, 0, uidReq);
        auto biometrickitdInfoCmd = EncodeBmCommand(Command::GetBiometrickitdInfo, 1, 0);

        conn->SendBiometricCommand(enabledForUnlockCmd, 0, &reply, config_.ioTimeout);
        T2_LOG("verify", L"macOS pre-match: GetEnabledForUnlock (cmd 48) issued");

        conn->SendBiometricCommand(sksLockStateCmd, 0, &reply, config_.ioTimeout);
        T2_LOG("verify", L"macOS pre-match: GetSksLockStateMac (cmd 39) issued");

        conn->SendBiometricCommand(protectedConfigCmd, 0, &reply, config_.ioTimeout);
        T2_LOG("verify", L"macOS pre-match: GetProtectedConfig (cmd 46) issued");

        conn->SendBiometricCommand(cancelCmd, 0, &reply, config_.ioTimeout);
        T2_LOG("verify", L"macOS pre-match: Cancel (cmd 12), first - expect async MatchingCancelled");

        conn->SendBiometricCommand(sksLockStateCmd, 0, &reply, config_.ioTimeout);
        T2_LOG("verify", L"macOS pre-match: GetSksLockStateMac (cmd 39), repeat");

        conn->SendBiometricCommand(biometrickitdInfoCmd, 0, &reply, config_.ioTimeout);
        T2_LOG("verify", L"macOS pre-match: GetBiometrickitdInfo (cmd 40) issued");

        conn->SendBiometricCommand(protectedConfigCmd, 0, &reply, config_.ioTimeout);
        T2_LOG("verify", L"macOS pre-match: GetProtectedConfig (cmd 46), repeat");

        conn->SendBiometricCommand(cancelCmd, 0, &reply, config_.ioTimeout);
        T2_LOG("verify", L"macOS pre-match: Cancel (cmd 12), second (last before StartMatch) - "
               L"expect async SensorOperationModeIdle");
    }

    // LINUX PARITY: warm-up events must NOT enter the match event stream.
    // Placed after the macOS pre-match sequence above so any events those
    // five commands provoke are discarded too, not just the identity-gate
    // ones.
    {
        size_t dropped = conn->DiscardPendingEvents();
        if (dropped > 0) {
            T2_LOG("verify",
                   L"discarded %zu pre-StartMatch event(s) so match loop sees "
                   L"only post-StartMatch traffic",
                   dropped);
        }
    }

    // start match (cmd 4) — Linux counted default: II60x + count + records
    // (132 B for 3 identities). Override with --match-layout inline|padded.

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
           L"layout=%s flags=%u reset=%s cal=%s outcome=%d",
           fingerTouchCycles, imagePipelineEvents, unnamedStatusEvents,
           MatchIdentityLayoutName(config_.matchLayout), config_.matchFlags,
           config_.skipResetSensor ? L"skip" : L"yes",
           config_.skipLoadCalibration ? L"skip" : L"yes",
           static_cast<int>(outcome));

    return outcome;
}

} // namespace t2::biometrickit
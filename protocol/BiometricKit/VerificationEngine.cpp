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

    auto resetCmd = EncodeBmCommand(Command::ResetSensor, /*version=*/1, /*value=*/2);
    if (!conn->SendBiometricCommand(resetCmd, /*outputCapacity=*/0, &reply, config_.ioTimeout)) {
        T2_LOG("warmup", L"ResetSensor (cmd 2, value=2, capacity=0) failed");
        return false;
    }
    T2_LOG("warmup", L"ResetSensor OK");

    auto cancelCmd = EncodeBmCommand(Command::Cancel, /*version=*/1, /*value=*/0);
    conn->SendBiometricCommand(cancelCmd, /*outputCapacity=*/0, &reply, config_.ioTimeout); // best-effort
    T2_LOG("warmup", L"Cancel (cmd 0x0c) issued");

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

    // Non-matching identity warm-up immediately before StartMatch.
    // VERIFIED FROM SOURCE: bridge-xpc-probe.py match-seconds branch with
    // --resolve-any-finger-name (t2-fprintd.py verify_fprint() for requested
    // finger == "any" AND a complete projection). After the first 0x42 from
    // --identity-list it sends:
    //   biometric_command(sock, 0x51, output_capacity=40*10)
    //   biometric_command(sock, 0x42, data=uid, output_capacity=20*10)
    //   biometric_command(sock, 0x51, output_capacity=40*10)
    // then t2_fprint_match_gate.prepare_all fail-closes unless first==repeat
    // for both views AND the configured 0x51 slice equals the first 0x42
    // set. StartMatch still uses the FIRST 0x42 records, never the repeat.
    std::vector<uint8_t> firstGlobalRaw;
    auto globalCmd = EncodeBmCommand(Command::GlobalIdentityList, /*version=*/1, /*value=*/0);
    if (!conn->SendBiometricCommand(globalCmd, kGlobalIdentityListOutputCapacity,
                                    &firstGlobalRaw, config_.ioTimeout)) {
        T2_LOG("verify", L"GlobalIdentityList (cmd 0x51, capacity=%u) failed",
               kGlobalIdentityListOutputCapacity);
        return VerifyOutcome::TransportError;
    }
    if (firstGlobalRaw.size() % 40 != 0) {
        T2_LOG("verify", L"GlobalIdentityList reply malformed (reply=%zuB, not a multiple of 40)",
               firstGlobalRaw.size());
        return VerifyOutcome::Malformed;
    }

    std::vector<uint8_t> idReq(4);
    std::memcpy(idReq.data(), &config_.macosUserId, 4);
    auto idCmd = EncodeBmCommand(Command::IdentityList, /*version=*/1, /*value=*/0, idReq);
    std::vector<uint8_t> repeatedUserRaw;
    if (!conn->SendBiometricCommand(idCmd, kIdentityListOutputCapacity,
                                    &repeatedUserRaw, config_.ioTimeout)) {
        T2_LOG("verify", L"repeated IdentityList (cmd 0x42) failed");
        return VerifyOutcome::TransportError;
    }

    std::vector<uint8_t> repeatedGlobalRaw;
    if (!conn->SendBiometricCommand(globalCmd, kGlobalIdentityListOutputCapacity,
                                    &repeatedGlobalRaw, config_.ioTimeout)) {
        T2_LOG("verify", L"repeated GlobalIdentityList (cmd 0x51) failed");
        return VerifyOutcome::TransportError;
    }

    if (firstUserRaw != repeatedUserRaw || firstGlobalRaw != repeatedGlobalRaw) {
        T2_LOG("verify",
               L"live identity inventory is unstable "
               L"(user %zuB vs %zuB, global %zuB vs %zuB)",
               firstUserRaw.size(), repeatedUserRaw.size(),
               firstGlobalRaw.size(), repeatedGlobalRaw.size());
        return VerifyOutcome::Malformed;
    }

    std::vector<std::array<uint8_t, 20>> configured;
    if (!ConfiguredGlobalIdentities(firstGlobalRaw, config_.macosUserId, &configured) ||
        !SamePerUserSet(configured, identities)) {
        T2_LOG("verify",
               L"global and per-user identity inventories disagree "
               L"(configured=%zu per-user=%zu global=%zuB)",
               configured.size(), identities.size(), firstGlobalRaw.size());
        return VerifyOutcome::Malformed;
    }
    T2_LOG("verify",
           L"identity warm-up OK: 0x42/0x51/0x42/0x51 user=%zuB global=%zuB identities=%zu (StartMatch uses first 0x42)",
           firstUserRaw.size(), firstGlobalRaw.size(), identities.size());

    auto cancelCmd = EncodeBmCommand(Command::Cancel, 1, 0);

    // start match (cmd 4)
    //
    // 16.09.2026 FIX: the payload used to be MatchInitDataV1 + uint32 count
    // + records = 132 bytes for the 3 identities on this machine. The macOS
    // capture shows biometrickitd sending inSize=68 for the same command on
    // the same machine with the same 3 identities. 68 == 8 + 3*20, so the
    // identity records go inline after an 8-byte header with no count word.
    auto matchInitData = EncodeMatchInitData(0, config_.macosUserId, identities,
                                              config_.matchLayout);
    T2_LOG("verify", L"start match: layout=%s payload=%zuB (macOS reference for %zu identities = %zuB)",
           MatchIdentityLayoutName(config_.matchLayout), matchInitData.size(),
           identities.size(), sizeof(MatchOptionsV1) + identities.size() * sizeof(IdentityRecordV1));
    auto startCmd = EncodeBmCommand(Command::StartMatch, 1, 0, matchInitData);
    std::vector<uint8_t> reply;
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
           L"layout=%s linux_ready=1 (reset+cal+idlist) outcome=%d",
           fingerTouchCycles, imagePipelineEvents, unnamedStatusEvents,
           MatchIdentityLayoutName(config_.matchLayout), static_cast<int>(outcome));

    return outcome;
}

} // namespace t2::biometrickit

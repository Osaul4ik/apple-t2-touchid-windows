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

// CancelMatch after StartMatch is best-effort teardown only. Must not use
// VerifyConfig::ioTimeout (5s): a slow BridgeXPC reply held g_captureBusy
// for seconds after CancelIoEx (Win+L delay). File-scope so CancelGuard's
// destructor can see it — MSVC C2326 rejects a function-local constexpr
// from a local-class member function.
constexpr std::chrono::milliseconds kCancelBestEffortTimeout{300};

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
                                          std::optional<std::array<uint8_t, 16>>* outMatchedUuid,
                                          HANDLE cancelEvent) {
    if (busy_) {
        return VerifyOutcome::Busy;
    }
    busy_ = true;
    struct BusyGuard { bool* b; ~BusyGuard() { *b = false; } } guard{&busy_};

    // 20.09.2026: the caller (Queue.cpp) can be cancelled by Windows while it
    // is still discovering/connecting (a multi-second window). If that
    // already happened, do not spend another ~0.3s on reset-sensor /
    // load-calibration / identity reads (and then StartMatch + Cancel) for a
    // request Windows no longer wants - return at once so the capture slot
    // is free for the request that replaced it.
    if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
        T2_LOG("verify", L"cancel already signaled before warm-up - not starting a session");
        return VerifyOutcome::Cancelled;
    }

    // Same prefix Linux fprintd sends on the verify connection
    // (--initialize --reset-sensor --cancel-operation --load-calibration
    // --identity-list) AFTER t2-biometric-ready already did it once on a
    // previous connection. Empty identity list is a hard fail here because
    // bridge-xpc-probe.py: "--match-seconds requires a non-empty --identity-list result".
    std::vector<IdentityRecordV1> identities;
    std::vector<uint8_t> firstUserRaw;
    if (!RunLinuxReadySequence(conn, &identities, &firstUserRaw)) {
        if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
            return VerifyOutcome::Cancelled;
        }
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
                                           config_.ioTimeout, cancelEvent);
    };
    auto readUserIdentityList = [&](std::vector<uint8_t>* outRaw) -> bool {
        std::vector<uint8_t> idReq(4);
        std::memcpy(idReq.data(), &config_.macosUserId, 4);
        auto idCmd = EncodeBmCommand(Command::IdentityList, /*version=*/1, /*value=*/0, idReq);
        return conn->SendBiometricCommand(idCmd, kIdentityListOutputCapacity, outRaw,
                                          config_.ioTimeout, cancelEvent);
    };

    std::vector<uint8_t> firstGlobalRaw, repeatUserRaw, repeatGlobalRaw;
    if (!readGlobalIdentityList(&firstGlobalRaw)) {
        T2_LOG("verify", L"GlobalIdentityList (cmd 0x51, first read) failed");
        if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
            return VerifyOutcome::Cancelled;
        }
        return VerifyOutcome::TransportError;
    }
    if (!readUserIdentityList(&repeatUserRaw)) {
        T2_LOG("verify", L"IdentityList (cmd 0x42, repeat read) failed");
        if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
            return VerifyOutcome::Cancelled;
        }
        return VerifyOutcome::TransportError;
    }
    if (!readGlobalIdentityList(&repeatGlobalRaw)) {
        T2_LOG("verify", L"GlobalIdentityList (cmd 0x51, repeat read) failed");
        if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
            return VerifyOutcome::Cancelled;
        }
        return VerifyOutcome::TransportError;
    }

    std::vector<std::array<uint8_t, 20>> configuredFirst, configuredRepeat;
    if (!ConfiguredGlobalIdentities(firstGlobalRaw, config_.macosUserId, &configuredFirst) ||
        !ConfiguredGlobalIdentities(repeatGlobalRaw, config_.macosUserId, &configuredRepeat)) {
        T2_LOG("verify", L"global identity-list malformed (zero-UUID, duplicate, or "
               L"non-built-in group entry) - fail-closed, refusing StartMatch");
        return VerifyOutcome::UnstableIdentityInventory;
    }
    std::vector<IdentityRecordV1> repeatIdentities;
    if (!ParseIdentityList(repeatUserRaw, &repeatIdentities)) {
        T2_LOG("verify", L"repeat IdentityList reply malformed (%zuB, not a multiple of 20) - "
               L"fail-closed, refusing StartMatch", repeatUserRaw.size());
        return VerifyOutcome::UnstableIdentityInventory;
    }
    std::sort(configuredFirst.begin(), configuredFirst.end());
    std::sort(configuredRepeat.begin(), configuredRepeat.end());
    if (configuredFirst != configuredRepeat || !SamePerUserSet(configuredFirst, identities) ||
        !SamePerUserSet(configuredRepeat, repeatIdentities)) {
        T2_LOG("verify", L"live identity inventory is unstable (first/repeat 0x42 or 0x51 "
               L"snapshot disagreed) - fail-closed, refusing StartMatch");
        return VerifyOutcome::UnstableIdentityInventory;
    }
    T2_LOG("verify", L"identity inventory stable across 0x42->0x51->0x42->0x51 (%zu configured)",
           configuredFirst.size());

    // Kept for the CancelGuard below (post-match cleanup on every exit
    // path), and now also reused directly on each NO_MATCH restart —
    // unrelated to the removed pre-match sequence.
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
    // for it. This driver now does the identity-list-stable check above
    // and then goes STRAIGHT to StartMatch — exactly what
    // t2-fprintd.py/bridge-xpc-probe.py's real --timed-match path does
    // (VERIFIED FROM SOURCE: biometric_command(sock, 4, data=match_data) is
    // the very next call after the identity/stability gate, no Cancel, no
    // wait, nothing else between). config_.skipResetSensor/
    // skipLoadCalibration briefly defaulted to false for the same reason
    // (Linux's warm_up always sends both) — see VerificationEngine.h for
    // the 24.09.2026 re-revert back to true/true, once real-hardware A/B
    // (three back-to-back `verify --no-reset-sensor --no-load-calibration`
    // runs, all verify-match) gave the confirmation that was missing here.

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
    // (ResetSensor, warm-up Cancel, LoadCalibration, both IdentityList and
    // GlobalIdentityList reads for the stability gate above), so without
    // this clear, WaitForEvent() below hands the match-session loop
    // whatever leftover events those warm-up calls happened to observe -
    // confirmed on the 16.09.2026 hardware capture, where the match
    // session's first two logged events (80 MatchingCancelled, unnamed 94)
    // were actually acked during LoadCalibration's own reply-wait, well
    // before StartMatch was even sent. DiscardPendingEvents() already
    // existed for exactly this (Connection.cpp/.h) but was never called.
    // Events queued during StartMatch's OWN SendBiometricCommand call just
    // below are unaffected - they land in pendingEvents_ after this point,
    // same as the reference's own per-call `events` for cmd 4.
    // Sends (or re-sends) StartMatch for one attempt. Broken out of the
    // original single call so a bad touch (NO_MATCH) can restart a fresh
    // match session below without duplicating this block.
    auto sendStartMatch = [&]() -> bool {
        const size_t discardedPreMatchEvents = conn->DiscardPendingEvents();
        if (discardedPreMatchEvents > 0) {
            T2_LOG("verify",
                   L"discarded %zu pre-StartMatch event(s) accumulated since the last "
                   L"attempt (Linux never attributes these to the match session)",
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
        std::vector<uint8_t> startReply;
        return conn->SendBiometricCommand(startCmd, 0, &startReply, config_.ioTimeout, cancelEvent);
    };

    // Same reasoning as the check at the top: a cancel that landed during the
    // ~0.3s warm-up must not still arm the sensor (StartMatch) only to Cancel
    // it a moment later.
    if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
        T2_LOG("verify", L"cancel signaled during warm-up - skipping StartMatch");
        return VerifyOutcome::Cancelled;
    }

    if (!sendStartMatch()) {
        // ForceCloseActive / cancel mid-StartMatch surface as ConnectionLost
        // or a failed send; treat a concurrent cancel as Cancelled so Queue
        // can map power-suspend to TransportError.
        if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
            return VerifyOutcome::Cancelled;
        }
        if (conn->ConnectionLost()) {
            // Suspend ForceClose or peer drop during StartMatch.
            if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
                return VerifyOutcome::Cancelled;
            }
            return VerifyOutcome::TransportError;
        }
        return VerifyOutcome::TransportError;
    }

    // Milestone 2B §11: from here on the StartMatch IPC itself succeeded,
    // so a match session may now be live on the device regardless of what
    // happens next. CancelMatch must be attempted on every exit path.
    //
    // IMPORTANT (20.09.2026 hardware): do NOT use config_.ioTimeout (5s) here.
    // Cancel is best-effort teardown — see kCancelBestEffortTimeout above.
    // Same bound is used on the NoMatch restart path below.
    struct CancelGuard {
        bridgexpc::Connection* conn;
        const std::vector<uint8_t>* cancelCmd;
        ~CancelGuard() {
            std::vector<uint8_t> discard;
            conn->SendBiometricCommand(*cancelCmd, 0, &discard, kCancelBestEffortTimeout);
        }
    } cancelGuard{conn, &cancelCmd};

    // design doc §9.4, per explicit direction: this component does not own
    // the wait duration at all when Windows Hello is driving it (cancelEvent
    // present) - Windows issues CAPTURE_DATA and we simply wait; a wrong
    // finger restarts the scan immediately; the wait ends only on a real
    // Match or on Windows' own cancel (login finished some other way,
    // password fallback, session torn down). No self-imposed deadline, no
    // "safety net" second-guessing that contract - if Windows fails to ever
    // send a cancel, that is a bug to fix at that layer, not something to
    // paper over here with an internal timeout (a prior attempt at exactly
    // that safety net was observed, on real hardware, to do more harm than
    // good: it kept g_captureBusy held for its full duration on a capture
    // Windows had simply stopped caring about, delaying the next real
    // capture). The CLI one-shot `verify` (no cancelEvent) is unaffected -
    // it keeps its fixed config_.matchWindow deadline exactly as before.
    // Parenthesize the call so <windows.h>'s function-like `max(a,b)` macro
    // (this TU is deliberately built without NOMINMAX - see Connection.cpp
    // for why) never sees `max(` as a token and tries to expand it; that is
    // exactly what produced warning C4003 / errors C2589,C2059,C2737,C3536
    // here (the same class of bug Connection.cpp's ReadFrame clamp already
    // works around for std::min).
    constexpr auto kNoDeadline = (steady_clock::time_point::max)();
    const auto deadline = cancelEvent ? kNoDeadline : (steady_clock::now() + config_.matchWindow);
    VerifyOutcome outcome = VerifyOutcome::Timeout; // default if loop exits via deadline

    size_t imagePipelineEvents = 0;
    size_t unnamedStatusEvents = 0;
    size_t fingerTouchCycles = 0;
    size_t rejectedTouchAttempts = 0;

    while (steady_clock::now() < deadline) {
        std::vector<uint8_t> eventPayload;
        if (!conn->WaitForEvent(&eventPayload, deadline, cancelEvent)) {
            // design doc §9.4: distinguish "cancelEvent fired" from a plain
            // deadline/transport WaitForEvent failure, so the caller
            // (Queue.cpp) completes the IOCTL with WINBIO_E_CANCELED and —
            // more importantly for the bug this fixes — so this loop exits
            // within one kCancelPollSlice of the cancel instead of only
            // ever on the full matchWindow, freeing g_captureBusy for the
            // very next touch. WaitForSingleObject with a 0 timeout here is
            // just a poll (mirrors the same check inside WaitForEvent) —
            // not a second, independent wait.
            if (cancelEvent && bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
                outcome = VerifyOutcome::Cancelled;
            } else if (conn->ConnectionLost()) {
                // 20.09.2026: the BridgeXPC TCP session died under us (peer
                // closed/reset). That is a transport failure, not an
                // ordinary "no touch before the deadline" Timeout - report
                // it as such so Queue.cpp can open a fresh session instead
                // of completing the request as BAD_CAPTURE.
                T2_LOG("verify", L"BridgeXPC connection lost while waiting for a touch");
                outcome = VerifyOutcome::TransportError;
            }
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
                    if (code == 63) fingerTouchCycles++;
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
            rejectedTouchAttempts++;
            if (cancelEvent) {
                // design doc §9.4: Windows, not this component, owns the
                // overall wait — a wrong finger is not a reason to give up
                // and complete the WBDI CAPTURE_DATA request. Restart the
                // scan (fresh StartMatch) and keep waiting; only a real
                // Match or an actual cancel (password fallback, session
                // end, login succeeded some other way) ends the wait - no
                // internal deadline of our own. Without this, one bad touch
                // used to end the entire capture and leave the sensor
                // waiting for a WBF-issued re-poll that may never come,
                // matching the "wrong finger, then correct finger does
                // nothing" symptom this fixes.
                T2_LOG("verify",
                       L"match_result outcome=NO_MATCH (attempt #%zu) - wrong finger, "
                       L"restarting scan immediately; Windows controls the wait, not us",
                       rejectedTouchAttempts);
                std::vector<uint8_t> discard;
                // Same short bound as CancelGuard: a 5s cancel here would stall
                // the wrong-finger → re-arm path and feel like a hung sensor.
                conn->SendBiometricCommand(cancelCmd, 0, &discard, kCancelBestEffortTimeout);
                if (!sendStartMatch()) {
                    outcome = VerifyOutcome::TransportError;
                    break;
                }
                continue;
            }
            // CLI one-shot verify (no cancelEvent): unchanged behavior -
            // a single NO_MATCH ends this verify() call.
            T2_LOG("verify", L"match_result outcome=NO_MATCH (no enrolled UUID found in event)");
            outcome = VerifyOutcome::NoMatch;
            break;
        }
        T2_LOG("verify", L"match_result outcome=MALFORMED body=%zuB (min required=%zuB) - "
               L"still waiting, not treated as NO_MATCH",
               eventData.size(), kMinMatchResultEventBytes);
    }

    // REMOVED (17.09.2026): no longer relabels Timeout as NoImageCaptured.
    // VERIFIED FROM SOURCE (t2-fprintd.py verdict_from_result): the
    // reference's own verdict is match_result-only; the finger/image
    // counters never gate its outcome. They stay below purely as
    // session-summary diagnostics.
    T2_LOG("verify",
           L"session summary: finger_touch_cycles=%zu image_pipeline_events=%zu unnamed_status_events=%zu "
           L"rejected_touch_attempts=%zu layout=%s flags=%u reset=%s cal=%s outcome=%d",
           fingerTouchCycles, imagePipelineEvents, unnamedStatusEvents, rejectedTouchAttempts,
           MatchIdentityLayoutName(config_.matchLayout), config_.matchFlags,
           config_.skipResetSensor ? L"skip" : L"yes",
           config_.skipLoadCalibration ? L"skip" : L"yes",
           static_cast<int>(outcome));

    return outcome;
}

} // namespace t2::biometrickit
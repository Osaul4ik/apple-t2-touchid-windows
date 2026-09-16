// SPDX-License-Identifier: GPL-2.0-only
// VerificationEngine.h
#pragma once
#include "Commands.h"
#include "MatchResult.h"
#include "../BridgeXpc/Connection.h"
#include <chrono>

namespace t2::biometrickit {

enum class VerifyOutcome {
    Match,
    NoMatch,
    Timeout,
    TransportError,      // connect/HELO/version negotiation failure
    RejectedByDevice,     // start-match command itself was rejected (word[0]!=0) — never silent success
    Malformed,
    Busy,                 // Milestone 2 §23: only one active session allowed
    NoImageCaptured,      // finger was detected (FingerOn/FingerOff) but the SEP never
                          // reported ImageCaptured/ImageForProcessing/ImageWasAccepted —
                          // the sensor sees the finger and never scans it. Distinct from
                          // Timeout (= nothing happened at all) on purpose: these two have
                          // completely different causes and used to be indistinguishable.
};

struct VerifyConfig {
    uint32_t macosUserId = 501;              // configurable, NOT hardcoded per Milestone 1 §6 finding
    // VERIFIED FROM SOURCE: t2-fprintd.py's own argparse default for
    // --match-seconds is 20.0 (main(), "--match-seconds", type=float,
    // default=20.0), and _run_probe() never overrides it for a normal
    // verify() call - so every real verification on the reference
    // implementation runs with a 20s window, not 10s. This value was
    // previously an unverified placeholder (nothing in docs/ ever cited a
    // source for "10"). A 16.09.2026 hardware capture (3 back-to-back
    // `verify` runs, all timing out with only status/statistics events)
    // cut off at almost exactly 10s elapsed in every run - consistent with
    // this mismatch ending the match window, and the client's own Cancel
    // (cmd 0x0c), before SEP's normal idle/poll cycle for that session
    // would have run its course on real macOS. Still cannot rule out "no
    // finger was on the sensor during the window" as an independent or
    // additional cause - this fix addresses a real, source-verified
    // discrepancy, not a confirmed root cause.
    std::chrono::seconds matchWindow{20};
    std::chrono::milliseconds ioTimeout{5000};

    // 16.09.2026 macOS reference capture: across four minutes of live
    // Touch ID activity (including two successful unlocks) biometrickitd
    // issues commands 4, 12, 39, 40, 44, 46, 48, 56, 61, 62, 63, 74, 80
    // and 84 — and NEVER command 2 (ResetSensor) or command 0x20
    // (LoadCalibration). Both were being sent by this project before every
    // match on the strength of the Linux reference alone, whose firmware
    // the project's own README notes is not the same. On the failing
    // Windows capture the SEP answers the calibration load with an
    // unnamed status_code=94 and then rejects every subsequent capture, so
    // these two are now opt-in rather than unconditional. Turn them back
    // on to A/B the old behaviour, not because the protocol needs them.
    bool resetSensor = false;
    bool loadCalibration = false;

    // Wire format of the start-match payload. See MatchIdentityLayout.
    MatchIdentityLayout matchLayout = MatchIdentityLayout::InlineIdentities;
};

// One VerificationEngine instance == one in-flight session (Milestone 2
// §23 concurrency rule enforced by the diagnostic tool holding a single
// instance and refusing to start a second one while IsBusy()).
class VerificationEngine {
public:
    explicit VerificationEngine(const VerifyConfig& config) : config_(config) {}

    bool IsBusy() const { return busy_; }

    // Full sequence per Milestone 1 §2 / Milestone 2 §19:
    // connect -> HELO -> getBridgeVersion -> setClientVersion -> reset ->
    // cancel -> load FDR calibration -> load calibration into sensor ->
    // identity list -> start match -> event loop -> verdict -> cancel/stop
    // -> disconnect. Every step's failure maps to a fail-closed outcome;
    // nothing here ever converts a transport success into an implicit MATCH.
    VerifyOutcome Verify(bridgexpc::Connection* conn,
                          std::optional<std::array<uint8_t, 16>>* outMatchedUuid);

private:
    VerifyConfig config_;
    bool busy_ = false;
};

} // namespace t2::biometrickit
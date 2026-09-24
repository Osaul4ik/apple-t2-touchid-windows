// SPDX-License-Identifier: GPL-2.0-only
// VerificationEngine.h
#pragma once
#include "Commands.h"
#include "MatchResult.h"
#include "../BridgeXpc/Connection.h"
#include <chrono>
#include <vector>

namespace t2::biometrickit {

enum class VerifyOutcome {
    Match,
    NoMatch,
    Timeout,
    TransportError,      // connect/HELO/version negotiation failure
    RejectedByDevice,     // start-match command itself was rejected (word[0]!=0) — never silent success
    Malformed,
    Busy,                 // Milestone 2 §23: only one active session allowed
    Cancelled,             // design doc §9.4: cancelEvent fired (Windows called
                          // CancelIoEx on the pending WBDI request, e.g. LogonUI
                          // ending the session on a password-fallback login) —
                          // distinct from Timeout so Queue.cpp can complete the
                          // IOCTL with WINBIO_E_CANCELED instead of
                          // WINBIO_E_BAD_CAPTURE, and so g_captureBusy is freed
                          // on a cancel signal rather than only ever on the full
                          // matchWindow elapsing
    UnstableIdentityInventory, // port of Linux FprintMatchGateError("live identity
                          // inventory is unstable"): first/repeat 0x42 or 0x51 snapshot
                          // disagreed — fail-closed, StartMatch never sent
    // REMOVED (17.09.2026): NoImageCaptured used to relabel an ordinary
    // Timeout whenever sawFingerOn && imagePipelineEvents==0 — i.e.
    // whenever status codes 55/72/95 (ImageCaptured/ImageForProcessing/
    // ImageWasAccepted) never appeared. VERIFIED FROM SOURCE
    // (jmurth1234/t2-touchid-linux, src/t2-fprintd.py verdict_from_result):
    // the reference's own production verify path never inspects, waits
    // for, or requires those three status codes anywhere — it only scans
    // match_events for event_kind=="match_result" and falls through to
    // "verify-no-match" otherwise. The 55/72/95 sequence this project used
    // to gate on came solely from a macOS unified-log capture of
    // biometrickitd's own internal statusMessage: prints, never confirmed
    // as something a remote BridgeXPC client (this driver included) is
    // even supposed to receive. Keeping a distinct outcome for their
    // absence manufactured a diagnosis the reference itself doesn't make.
    // A timeout with sawFingerOn is now just Timeout, same as Linux calls
    // it verify-no-match; fingerTouchCycles/imagePipelineEvents are still
    // logged in the session summary for information, not used to pick the
    // outcome.
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

    // REVERTED (16.09.2026): defaulted to InlineIdentities (68B, no count)
    // on the strength of the same macOS unified-log capture already
    // discredited above (the pre-match sequence and skipResetSensor/
    // skipLoadCalibration derived from it). The comment this replaces
    // already records that this WAS A/B tested on real hardware against
    // LegacyCounted and the two produced "a bit-identical failure shape" —
    // i.e. switching does not reopen a previously-ruled-out cause, it just
    // stops preferring the macOS-shaped payload over Linux's own. Default
    // is now LegacyCounted (132B: 68-byte options + uint32 count + N*20B
    // records), matching bridge-xpc-probe.py's own default exactly
    // (VERIFIED FROM SOURCE: `--identity-blob-format` argparse default is
    // `"counted"`). InlineIdentities/PaddedNoIdentities remain available via
    // --match-layout for explicit A/B, now as the non-default variants.
    MatchIdentityLayout matchLayout = MatchIdentityLayout::LegacyCounted; // Linux-verified default

    // MatchInitDataV1 / MatchOptionsV1 flags field. Linux probe default is 0;
    // its help text notes "use 1 for an unlock match". Keep 0 as default to
    // match both Linux fprintd and the macOS capture; expose via CLI for A/B.
    uint32_t matchFlags = 0;

    // RE-REVERTED (24.09.2026): back to true/true. The 16.09.2026 revert
    // below (kept for history) restored Linux parity on the theory that
    // no real-hardware evidence had confirmed the macOS-log path over
    // Linux's warm_up(). That evidence now exists: `verify
    // --no-reset-sensor --no-load-calibration`, three back-to-back runs on
    // real T2 hardware (no intervening cold boot/sleep), every run logged
    // "reset=skip cal=skip" and returned verify-match — i.e. ResetSensor
    // and LoadCalibration are not required per-attempt at all here, not
    // even once per connection. Consistent with "bridgeOS calibrates at
    // its own boot" (cmd 0x20 applies calibration state that lives on the
    // bridge chip, not the host connection) — LoadCalibration alone was
    // ~200-260ms of the ~290ms fixed overhead measured before StartMatch
    // on the live WBF capture path (T2TouchIdBio/Queue.cpp), so this
    // roughly halves per-touch latency there, not just in the CLI.
    // NOT YET RE-VALIDATED: the three runs above were all against an
    // already-"warm" bridge session; a genuine cold boot and a sleep/wake
    // resume (the two paths that actually reach this code from Windows
    // Hello) have not been separately confirmed with skip=true as the
    // very first verify after either event. If either turns out to need
    // ResetSensor/LoadCalibration once (and only once) after such an
    // event, that would need to be handled at session/connection
    // lifecycle level (T2TouchIdBio/Queue.cpp or bridgexpc::Connection),
    // not by flipping these two flags back — see the per-touch cost this
    // change removes.
    //
    // REVERTED (16.09.2026, superseded above): previously defaulted to
    // true/true on the strength of a macOS unified-log capture (docs/
    // macos-verified.md §4) showing cmd 2/0x20 absent from a live unlock.
    // That capture also implied a whole pre-match command sequence (see
    // the now-removed block in Verify()) that two real-hardware runs
    // failed to validate — no evidence had then confirmed the macOS-log
    // path over Linux's own, and Linux's warm_up()
    // (t2-biometric-ready.sh / t2-fprintd.py _run_probe(), VERIFIED FROM
    // SOURCE) unconditionally sends both ResetSensor and LoadCalibration
    // before every identity-list read. Defaulting to skip=false restored
    // that Linux parity; CLI flags still allow forcing skip=false for an
    // explicit A/B against Linux's own always-resend behavior.
    bool skipResetSensor = true;
    bool skipLoadCalibration = true;
};

// One VerificationEngine instance == one in-flight session (Milestone 2
// §23 concurrency rule enforced by the diagnostic tool holding a single
// instance and refusing to start a second one while IsBusy()).
class VerificationEngine {
public:
    explicit VerificationEngine(const VerifyConfig& config) : config_(config) {}

    bool IsBusy() const { return busy_; }

    // Exact port of t2-biometric-ready.sh warm_up() / bridge-xpc-probe.py
    // argv `--initialize --reset-sensor --cancel-operation
    // --load-calibration --identity-list`. No StartMatch (cmd 4), no
    // sensor-readiness (cmd 0x53). Linux runs this on its own TCP
    // connection and then disconnects, BEFORE fprintd's first verify.
    // outIdentities is optional (CmdIdentities); WarmUp itself does not
    // require a non-empty list — the Linux ready script doesn't either.
    bool WarmUp(bridgexpc::Connection* conn,
                std::vector<IdentityRecordV1>* outIdentities = nullptr);

    // Full sequence per t2-fprintd.py T2Backend::_run_probe():
    // connect -> HELO -> getBridgeVersion -> setClientVersion -> reset ->
    // cancel -> load FDR calibration -> load calibration into sensor ->
    // identity list -> start match -> event loop -> verdict -> cancel/stop
    // -> disconnect. Every step's failure maps to a fail-closed outcome;
    // nothing here ever converts a transport success into an implicit MATCH.
    //
    // cancelEvent (design doc §9.4): optional, defaults to nullptr so the
    // CLI's one-shot `verify` (fixed matchWindow, no external cancel
    // source) is unaffected. When the WBDI caller (Queue.cpp) has one — an
    // event it signals from its WdfRequestMarkCancelable cancel routine —
    // it is forwarded to every Connection::WaitForEvent call in the match
    // loop below. Only the event-loop wait is covered; RunLinuxReadySequence
    // (reset/load-calibration/identity-list, all short fixed-timeout
    // request/reply round-trips, not the long touch-and-wait) is not, same
    // scope the design doc itself describes for this mechanism.
    VerifyOutcome Verify(bridgexpc::Connection* conn,
                         std::optional<std::array<uint8_t, 16>>* outMatchedUuid,
                         HANDLE cancelEvent = nullptr);

private:
    // Shared prefix of WarmUp and Verify. Byte-identical to the Linux
    // flag sequence above. Returns false on any transport/parse failure.
    // outIdentityListRaw, if non-null, receives the unparsed cmd 0x42
    // blob so Verify can byte-compare it against the repeated 0x42 that
    // Linux sends before StartMatch.
    bool RunLinuxReadySequence(bridgexpc::Connection* conn,
                               std::vector<IdentityRecordV1>* outIdentities,
                               std::vector<uint8_t>* outIdentityListRaw = nullptr);

    VerifyConfig config_;
    bool busy_ = false;
};

} // namespace t2::biometrickit
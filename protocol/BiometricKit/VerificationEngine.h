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
    RejectedByDevice,     // StartMatch's valid BridgeXPC command status was non-zero
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

    // 26.09.2026: set true ONLY by Queue.cpp's resume-restart path (the
    // verify attempt started immediately after OnSuspendResume discarded
    // the pre-suspend session), never for an ordinary first attempt.
    // Real-hardware capture: the machine is woken via its power button,
    // which IS the fingerprint sensor - so gating on "finger was lifted"
    // (FingerOff) or "finger was placed twice" cannot work, the wake
    // gesture itself is indistinguishable from a deliberate touch. What
    // actually happened: a touch begun just before suspend (SEP may
    // already have started processing it before our Cancel/teardown
    // reached it) surfaced as a match_result within the FIRST new
    // post-resume StartMatch session, unlocking the machine with no live
    // touch belonging to that new session at all. When this flag is set,
    // Verify() requires at least one live FingerOn(status_code 63) to
    // have been observed in THIS session before honoring any
    // match_result as VerifyOutcome::Match; a match_result that arrives
    // with zero FingerOn seen in this session is almost certainly a
    // leftover/queued artifact of the aborted pre-suspend transaction,
    // not a live decision on this session's own data - it is rejected
    // exactly like an ordinary NoMatch (Queue.cpp already restarts a
    // fresh full Linux-order transaction on NoMatch). Left false for
    // every other attempt: an ordinary first touch is trivially preceded
    // by its own FingerOn already, so this never rejects a real one.
    bool requireFingerLiftSinceResume = false;

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

    // Linux t2-fprintd's production verify passes --reset-sensor,
    // --cancel-operation and --load-calibration on every probe. Keep the
    // same command sequence for every Windows verify, including after resume.
    bool skipResetSensor = false;
    bool skipLoadCalibration = false;
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
                               std::vector<uint8_t>* outIdentityListRaw = nullptr,
                               HANDLE cancelEvent = nullptr);

    VerifyConfig config_;
    bool busy_ = false;
};

} // namespace t2::biometrickit
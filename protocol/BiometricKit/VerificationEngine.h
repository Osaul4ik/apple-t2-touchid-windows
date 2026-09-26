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

    // 26.09.2026 (root-cause pass, replaces two earlier, empirically
    // insufficient attempts at this same bug — see history below):
    // set by Queue.cpp fresh before EVERY StartMatch attempt, from
    // g_lastObservedSepOrdinal — the highest `ordinal` field (MatchResult.h
    // ParseStatusEventHeader's 24-byte envelope header, bytes [16:24)) this
    // process has observed in ANY event, ever, confirmed surviving a full
    // reconnect on real hardware (suspend/resume specifically not yet
    // confirmed the same way — see ParseStatusEventHeader's own comment).
    //
    // VerificationEngine::Verify rejects a match_result outright — treats it
    // exactly like NoMatch — unless its OWN `ordinal` is strictly greater
    // than this value. `ordinal` is the SEP's own monotonic count of events
    // it emits; it is not reset by our software tearing down and reopening
    // the BridgeXPC TCP connection (that reconnect is a software-side
    // convenience — see Connection.h's "one connection per attempt" note —
    // not a SEP-side state boundary). An event whose `ordinal` we've already
    // seen (or a lower one) being handed to us again is therefore not a new
    // touch: it is *the same SEP-side event*, delivered more than once.
    // This is a fact derived from data the SEP itself produced, not a guess
    // about elapsed time or how many attempts have run.
    //
    // History, so the next person doesn't retry any of these: (1) an
    // earlier revision keyed this off "zero live FingerOn(status_code 63)
    // events this session" — hardware log showed the SEP replays the
    // pre-suspend touch's FULL FingerOn->ImageCaptured->FingerOff->
    // match_result burst into the new session, so "this session saw a live
    // FingerOn" proved nothing. (2) the revision after that rejected
    // exactly the FIRST post-resume match_result and trusted every attempt
    // after it (an attempt-count bound); a later hardware reproduction
    // (several touches right before sleep, wake with no further touch,
    // unlock succeeding on the SECOND post-resume attempt) showed one
    // discard cycle is not always enough. A wall-clock window has the
    // identical problem one level removed (still a guess, just measured in
    // ms instead of attempts). (3) THIS field was first wired up to the
    // header's `sequence` bytes [0:8) rather than `ordinal` bytes [16:24) —
    // same struct, wrong 8 bytes — on the strength of the struct-layout
    // comment alone, without decoding real hardware data first. `sequence`
    // turned out to be 0 in every event this bridge daemon emits, so the
    // very first check after driver load already failed closed
    // (0 <= 0 is true) and no fingerprint unlock could ever succeed again,
    // suspend/resume or not — reported same day. `ordinal` is confirmed (by
    // decoding a real hardware capture) to actually vary and increase
    // monotonically. Comparison-by-value has no attempt-count or
    // elapsed-time bound to guess, but it is only as good as extracting the
    // right bytes — this file's own history is the reminder to verify
    // against real captured data, not just the reverse-engineered struct
    // layout comment, before trusting a new field.
    //
    // Known remaining gap (unavoidable with this protocol, not a threshold
    // to tune): a touch the SEP finished scoring but whose event never
    // reached us at all before the pre-suspend connection was torn down
    // leaves us with no `ordinal` sample for it — we cannot compare against
    // an event we never saw. Nothing purely software-side closes this
    // without a SEP-side "give me your current ordinal counter" primitive,
    // which this reverse-engineered protocol is not known to expose. Flag
    // for further hardware investigation, not assumed solved by this change.
    uint64_t rejectOrdinalAtOrBelow = 0;

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
    //
    // outHighestOrdinalSeen (26.09.2026, optional, defaults to nullptr for
    // the CLI): set to the highest event `ordinal` value (MatchResult.h)
    // observed anywhere in this call, win or lose — updated as events
    // stream in, so it is always current by the time Verify returns, on
    // every exit path (deadline, cancel, transport loss, or a real verdict).
    // The caller (Queue.cpp) folds this into g_lastObservedSepOrdinal so
    // the NEXT attempt's config_.rejectOrdinalAtOrBelow reflects it.
    VerifyOutcome Verify(bridgexpc::Connection* conn,
                         std::optional<std::array<uint8_t, 16>>* outMatchedUuid,
                         HANDLE cancelEvent = nullptr,
                         uint64_t* outHighestOrdinalSeen = nullptr);

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
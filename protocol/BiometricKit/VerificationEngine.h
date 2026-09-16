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
    UnstableIdentityInventory, // port of Linux FprintMatchGateError("live identity
                          // inventory is unstable"): first/repeat 0x42 or 0x51 snapshot
                          // disagreed — fail-closed, StartMatch never sent
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

    // docs/ macos-verified.md §3, §7 (16.09.2026, same physical machine/
    // firmware): macOS itself puts exactly 68 bytes on the wire for
    // StartMatch with 3 identities (MatchOptionsV1 8B + N*IdentityRecordV1
    // 20B, no count field) — InlineIdentities reproduces that byte-for-byte.
    // A second hardware capture with this layout landed correctly on the
    // wire (confirmed: "inner=76B" = 8B BM header + 68B payload) but showed
    // a bit-identical failure shape to the 132-byte LegacyCounted form —
    // §7's own conclusion is explicit: "the StartMatch payload content/size
    // is not what gates image capture... the fix in section 3 is still
    // correct... and stays in place". LegacyCounted (132B, count+records) is
    // the pre-macOS-capture Linux-derived form, verified WRONG for this
    // firmware — kept only as an explicit A/B variant, never the default.
    MatchIdentityLayout matchLayout = MatchIdentityLayout::InlineIdentities; // macOS-verified default

    // MatchInitDataV1 / MatchOptionsV1 flags field. Linux probe default is 0;
    // its help text notes "use 1 for an unlock match". Keep 0 as default to
    // match both Linux fprintd and the macOS capture; expose via CLI for A/B.
    uint32_t matchFlags = 0;

    // docs/ macos-verified.md §4 (16.09.2026 macOS live-unlock capture,
    // same machine): "Across the whole capture: 4, 12, 39, 40, 44, 46, 48,
    // 56, 61, 62, 63, 74, 80, 84. Never 2 (ResetSensor) and never 0x20
    // (LoadCalibration)... Both are now opt-in." So the macOS-verified
    // default is to skip both; Linux always sends both, which is why the
    // Linux-parity path (skip=false) existed, but this project talks to
    // real bridgeOS firmware, not the Linux reference target, and the two
    // disagree here — the hardware capture wins. §7's "Next diagnostic
    // step" explicitly re-enables LoadCalibration via CLI on top of this
    // default (--load-calibration) as the next A/B to try, precisely
    // because this default is skip=true, not skip=false. Identity list +
    // StartMatch still always run.
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
    VerifyOutcome Verify(bridgexpc::Connection* conn,
                         std::optional<std::array<uint8_t, 16>>* outMatchedUuid);

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
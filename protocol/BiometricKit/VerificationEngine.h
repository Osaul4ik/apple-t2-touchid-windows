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
};

struct VerifyConfig {
    uint32_t macosUserId = 501;              // configurable, NOT hardcoded per Milestone 1 §6 finding
    std::chrono::seconds matchWindow{10};
    std::chrono::milliseconds ioTimeout{5000};
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

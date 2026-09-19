// SPDX-License-Identifier: GPL-2.0-only
// Connection.h
#pragma once
#include "Frame.h"
#include "PlistPayload.h"
#include <winsock2.h>
#include <ws2ipdef.h>
#include <string>
#include <chrono>
#include <deque>

namespace t2::bridgexpc {

enum class ConnectResult {
    Ok,
    ConnectFailed,
    HeloTimeout,
    HeloMalformed,
};

// One connection per verification attempt (Milestone 1 finding: the Linux
// reference opens a brand-new TCP connection per probe invocation, not a
// long-lived session) — this class deliberately does not try to be
// reusable/long-lived either, to match verified behavior rather than
// optimize against unverified assumptions.
class Connection {
public:
    Connection() = default;
    ~Connection();

    // interfaceIndex selects the T2 CDC-NCM adapter's IPv6 scope id — do not
    // let the OS pick an arbitrary interface for a link-local address.
    ConnectResult Connect(const in6_addr& linkLocalAddress, unsigned long interfaceIndex,
                          uint16_t port, std::chrono::milliseconds connectTimeout);

    // Every operation below has an explicit timeout (Milestone 2, section 22)
    // and returns false on ANY failure — never partial success.
    bool GetBridgeVersion(int64_t* outVersion, std::chrono::milliseconds timeout);
    bool SetClientVersion(int64_t version, std::chrono::milliseconds timeout);

    // Sends bridge-level method 11 ("read FDR calibration blob") and
    // returns the calibration bytes (VERIFIED FROM SOURCE:
    // bridge-xpc-probe.py's --load-calibration path uses
    // request_with_events(sock, [11]) and treats the reply as [blob]).
    // Returns false on transport error OR on a structurally valid but
    // empty blob — matching the Linux reference's explicit
    // "bridgeOS returned no usable FDR calibration data" fail-closed check.
    bool GetFdrCalibration(std::vector<uint8_t>* outBlob, std::chrono::milliseconds timeout);

    // Sends [3,0,innerBmBytes,outputCapacity]. The bridgexpc-level reply is
    // itself [status, blob] (see PlistPayload.h's DecodeStatusBlobPayload);
    // this unwraps that automatically, fails closed on a non-zero status,
    // and returns the raw blob bytes in *outReply — callers (identity-list
    // parsing, VerificationEngine's raw int32 startResult read) do not
    // need to decode anything further themselves.
    // bkremoted can push async, non-reply events ahead of the actual reply.
    // Acknowledge them while waiting for the matching reply, but RETAIN them
    // in the connection's pending-event queue so WaitForEvent() can deliver
    // them later. This mirrors Linux biometric_command(), which returns the
    // events observed while waiting for a command reply to the caller.
    bool SendBiometricCommand(const std::vector<uint8_t>& innerBmMessage,
                               uint32_t outputCapacity,
                               std::vector<uint8_t>* outReply,
                               std::chrono::milliseconds timeout);

    // Blocking receive loop used during an active match session. First
    // drains any event already retained in pendingEvents_ (acked while
    // GetFdrCalibration/SendBiometricCommand were waiting on an earlier
    // command's reply, per the Linux-parity note above) before blocking on
    // a fresh ReadFrame; either way the returned payload is already
    // acknowledged and the caller decides whether it is match_result-shaped.
    // false on timeout, malformed frame, or connection loss — the caller
    // (BiometricKit verify engine) must treat false as fail-closed, never
    // as an implicit NO_MATCH signal by itself (see MatchResult.h).
    bool WaitForEvent(std::vector<uint8_t>* outEventPayload,
                       std::chrono::steady_clock::time_point deadline);

    // Discard events retained during LoadCalibration / identity warm-up
    // BEFORE StartMatch is issued. Linux keeps load_calibration_events
    // separate from the match event stream; feeding those pre-match
    // statuses (MatchingCancelled, 94, …) into the verify loop as if they
    // belonged to the match session is a Windows-only divergence that can
    // leave the sensor state machine in an unexpected ordinal sequence.
    // Returns how many events were dropped (for logging).
    size_t DiscardPendingEvents();

    void Close();

private:
    SOCKET socket_ = INVALID_SOCKET;

    bool ReadFrame(RawFrame* out, std::chrono::milliseconds timeout);
    bool WriteFrame(FrameType type, const std::vector<uint8_t>& body);
    bool AcknowledgeEvent(const std::string& requestId);
    // Same event-before-reply loop as SendBiometricCommand/GetFdr:
    // ACK+queue async events, return only the matching reply envelope.
    bool ReadUntilMatchingReply(const std::string& expectedReqId,
                                MessageEnvelope* outEnv,
                                std::chrono::milliseconds timeout,
                                const wchar_t* logTag);
    std::deque<std::vector<uint8_t>> pendingEvents_;
};

} // namespace t2::bridgexpc
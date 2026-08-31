// SPDX-License-Identifier: GPL-2.0-only
// Connection.h
#pragma once
#include "Frame.h"
#include "PlistPayload.h"
#include <winsock2.h>
#include <ws2ipdef.h>
#include <string>
#include <chrono>

namespace t2::bridgexpc {

enum class ConnectResult {
    Ok,
    ConnectFailed,
    HeloTimeout,
    HeloMalformed,
    VersionNegotiationFailed,
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

    // Sends [3,0,innerBmBytes,outputCapacity] and returns the raw reply
    // payload bytes (BiometricKit.cpp interprets the "BM" wrapper).
    bool SendBiometricCommand(const std::vector<uint8_t>& innerBmMessage,
                               uint32_t outputCapacity,
                               std::vector<uint8_t>* outReply,
                               std::chrono::milliseconds timeout);

    // Blocking receive loop used during an active match session: returns
    // async bridge-side events (already acknowledged internally) until
    // either a match_result-shaped event arrives or the deadline passes.
    // false on timeout, malformed frame, or connection loss — the caller
    // (BiometricKit verify engine) must treat false as fail-closed, never
    // as an implicit NO_MATCH signal by itself (see MatchResult.h).
    bool WaitForEvent(std::vector<uint8_t>* outEventPayload,
                       std::chrono::steady_clock::time_point deadline);

    void Close();

private:
    SOCKET socket_ = INVALID_SOCKET;
    int64_t negotiatedVersion_ = 0;

    bool ReadFrame(RawFrame* out, std::chrono::milliseconds timeout);
    bool WriteFrame(FrameType type, const std::vector<uint8_t>& body);
    bool AcknowledgeEvent(const std::string& requestId);
};

} // namespace t2::bridgexpc

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
    // this unwraps that automatically and returns raw blob bytes in *outReply.
    // By default a non-zero command status fails closed. Callers that pass
    // outCommandStatus can inspect a valid non-zero reply themselves (used by
    // StartMatch to distinguish device rejection from transport failure).
    // bkremoted can push async, non-reply events ahead of the actual reply.
    // Acknowledge them while waiting for the matching reply, but RETAIN them
    // in the connection's pending-event queue so WaitForEvent() can deliver
    // them later. This mirrors Linux biometric_command(), which returns the
    // events observed while waiting for a command reply to the caller.
    bool SendBiometricCommand(const std::vector<uint8_t>& innerBmMessage,
                               uint32_t outputCapacity,
                               std::vector<uint8_t>* outReply,
                               std::chrono::milliseconds timeout,
                               int64_t* outCommandStatus = nullptr);

    // Blocking receive loop used during an active match session. First
    // drains any event already retained in pendingEvents_ (acked while
    // GetFdrCalibration/SendBiometricCommand were waiting on an earlier
    // command's reply, per the Linux-parity note above) before blocking on
    // a fresh ReadFrame; either way the returned payload is already
    // acknowledged and the caller decides whether it is match_result-shaped.
    // false on timeout, malformed frame, or connection loss — the caller
    // (BiometricKit verify engine) must treat false as fail-closed, never
    // as an implicit NO_MATCH signal by itself (see MatchResult.h).
    //
    // cancelEvent (design doc §9.4 "Таймаут CAPTURE_DATA і скасування"):
    // optional, defaults to nullptr (existing CLI behavior — wait for the
    // full deadline, unchanged). When non-null, the wait is sliced into
    // kCancelPollSlice chunks and cancelEvent is polled between them; a
    // signaled event makes WaitForEvent return false almost immediately
    // instead of blocking up to `deadline`. This is a deliberate
    // approximation of "wait on the SEP event and the cancel HANDLE at
    // once": the underlying SOCKET is a plain blocking socket (Milestone 1
    // reasoning, see Connect()'s SO_RCVTIMEO use), so a single recv() call
    // cannot be interrupted mid-flight by a Win32 event the way an
    // overlapped I/O WaitForMultipleObjects could. Bounding recv()'s own
    // timeout to the poll slice keeps a real SEP event from starving the
    // cancel check, at the cost of adding up to one slice of latency to
    // cancellation — see the constant's own comment in Connection.cpp for
    // why that trade is acceptable here (freeing g_captureBusy is what
    // actually matters, not sub-100ms cancel latency).
    bool WaitForEvent(std::vector<uint8_t>* outEventPayload,
                       std::chrono::steady_clock::time_point deadline,
                       HANDLE cancelEvent = nullptr);

    // Discard events retained during LoadCalibration / identity warm-up
    // BEFORE StartMatch is issued. Linux keeps load_calibration_events
    // separate from the match event stream; feeding those pre-match
    // statuses (MatchingCancelled, 94, …) into the verify loop as if they
    // belonged to the match session is a Windows-only divergence that can
    // leave the sensor state machine in an unexpected ordinal sequence.
    // Returns how many events were dropped (for logging).
    //
    // 26.09.2026: each discarded event still carries the same 24-byte
    // sequence header any other event does (MatchResult.h
    // ParseStatusEventHeader) — a stale pre-suspend event sitting in this
    // queue at warm-up time is exactly the kind of thing
    // VerifyConfig::rejectOrdinalAtOrBelow needs to know about, even
    // though its CONTENTS correctly never reach the match loop. This class
    // stays plist/BiometricKit-agnostic (it does not link that layer), so
    // it hands back the raw discarded payloads for the caller (which
    // already depends on both layers) to decode — see
    // VerificationEngine.cpp's call site.
    size_t DiscardPendingEvents(std::vector<std::vector<uint8_t>>* outDiscardedPayloads = nullptr);

    void Close();

    // Windows.h's WAIT_OBJECT_0 macro expands to (STATUS_WAIT_0 + 0), and
    // STATUS_WAIT_0 is undeclared in this build (VERIFIED ON A REAL BUILD,
    // not a guess: T2TouchIdBio.vcxproj compiles this file with
    // UMDF_USING_NTSTATUS, which routes WDF status codes through
    // <ntstatus.h>; to avoid that clashing with winnt.h's own small set of
    // STATUS_* Win32 wait-macro definitions, this build leaves them
    // undeclared — MSVC error C2065 'STATUS_WAIT_0': undeclared identifier
    // at the WAIT_OBJECT_0 call site). A signaled WaitForSingleObject
    // returns 0 by documented contract on every Windows version — that IS
    // what WAIT_OBJECT_0 names — so comparing to 0 directly is exactly as
    // correct, just without the macro this build can't use. Centralized
    // here (rather than at each WaitForSingleObject call site in
    // Connection.cpp / VerificationEngine.cpp) so the workaround and its
    // rationale live in one place instead of being duplicated.
    static bool IsEventSignaled(HANDLE h) {
        return h != nullptr && WaitForSingleObject(h, 0) == 0;
    }

    // True once WaitForEvent() saw a HARD receive failure on this connection
    // (peer closed/reset the TCP session, or a frame was torn/malformed) as
    // opposed to a plain "nothing arrived yet" poll timeout. A lost
    // connection can never deliver a match_result again, so callers must
    // stop waiting on it (and may open a fresh connection) instead of
    // treating it like an idle wait. Cleared by Connect().
    bool ConnectionLost() const { return connectionLost_; }

private:
    SOCKET socket_ = INVALID_SOCKET;
    bool connectionLost_ = false;

    // Why ReadFrame() returned false. IdleTimeout = SO_RCVTIMEO expired
    // with ZERO bytes of a new frame received (the stream is still in sync,
    // simply nothing to read yet); everything else means the stream is dead
    // or desynchronized and must not be read from again as if nothing
    // happened.
    enum class ReadFailure { None, IdleTimeout, Closed, Error };

    // quietIdleTimeout: WaitForEvent() polls with a short SO_RCVTIMEO slice
    // (kCancelPollSlice) purely so it can re-check its cancel event, so an
    // idle-slice timeout there is expected every slice and must not be
    // logged (it used to flood the log at 5 lines/second for as long as the
    // sensor sat waiting for a finger).
    bool ReadFrame(RawFrame* out, std::chrono::milliseconds timeout,
                   ReadFailure* why = nullptr, bool quietIdleTimeout = false);
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
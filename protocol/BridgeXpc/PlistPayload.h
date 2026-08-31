// SPDX-License-Identifier: GPL-2.0-only
// PlistPayload.h
//
// MESSAGE frame bodies are binary property lists (VERIFIED FROM SOURCE:
// bridge-xpc-probe.py uses plistlib.dumps(value, fmt=plistlib.FMT_BINARY)).
// Per Milestone 2 section 15, this project does not hand-roll a bplist
// parser: it wraps libplist (github.com/libimobiledevice/libplist, LGPL-2.1
// — license must be reviewed/accepted separately before linking into a
// shipping build; PoC-only use here). If libplist is unavailable in the
// build environment, this header's implementation should be swapped for
// another well-maintained bplist library rather than a new parser.
//
// This wrapper only exposes the narrow shapes BridgeXpc/BiometricKit
// actually need. Nothing here trusts nesting depth or object count from
// the remote side without libplist's own bounds (which are the library's
// responsibility, not reimplemented here).

#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <variant>

namespace t2::bridgexpc {

// VERIFIED FROM SOURCE: every top-level BridgeXPC envelope is
// [1, is_reply, request_id, payload] — the leading 1 is a fixed envelope
// version, distinct from the outer Frame.h protocol version.
constexpr int64_t kEnvelopeVersion = 1;

struct MessageEnvelope {
    int64_t version = 0;
    bool isReply = false;
    std::string requestId;             // UUID string, validated by caller
    std::vector<uint8_t> payloadPlist; // opaque nested plist bytes/re-encoded
};

// Returns std::nullopt on any malformed input (wrong top-level type, wrong
// element count, wrong element types, oversized nesting per libplist's own
// limits) — never throws, never partially fills the struct.
std::optional<MessageEnvelope> ParseMessageBody(const std::vector<uint8_t>& bplistBody);

// Encodes a reply/ack envelope, e.g. [1, true, requestId, [0]] used to
// acknowledge bridge-side status callbacks (VERIFIED FROM SOURCE:
// bridge-xpc-probe.py's request_with_events ack loop).
std::vector<uint8_t> EncodeAckEnvelope(const std::string& requestId);

// Encodes a request envelope [1, false, newRandomUuid, payload], where
// payload is [leadingInts..., trailingBlob (if present), trailingInts...].
// Covers every shape this project actually sends (VERIFIED FROM SOURCE):
//   getBridgeVersion:    leadingInts={0}
//   setClientVersion:    leadingInts={10, version}
//   biometric command:   leadingInts={3, 0}, trailingBlob=inner,
//                        trailingInts={outputCapacity}   -> [3,0,inner,cap]
//   FDR calibration read: leadingInts={11}
std::vector<uint8_t> EncodeRequestEnvelope(const std::string& requestId,
                                            const std::vector<int64_t>& leadingInts,
                                            const std::vector<uint8_t>* trailingBlob = nullptr,
                                            const std::vector<int64_t>& trailingInts = {});

// Decodes a payload that is a plain array of integers (e.g. the
// getBridgeVersion reply [0, api_version]). std::nullopt on any shape
// mismatch (wrong top-level type, or any element not an integer).
std::optional<std::vector<int64_t>> DecodeIntArrayPayload(const std::vector<uint8_t>& payloadPlist);

// Decodes a payload that is a one-element array [blob] and returns the
// blob — the shape of the bridge-level FDR calibration reply to
// request(sock, [11]). VERIFIED FROM SOURCE: bridge-xpc-probe.py's
// --calibration-info path checks isinstance(reply, list) and len(reply)==1
// with reply[0] required to be a bytes object. std::nullopt if the shape
// doesn't match (including if the element isn't a Data node) — an empty
// (zero-length) blob is still returned, not treated as nullopt; the
// caller (VerificationEngine) is responsible for rejecting an empty blob
// before using it, matching --load-calibration's own "not fdr_reply[0]"
// check.
std::optional<std::vector<uint8_t>> DecodeSingleBlobPayload(const std::vector<uint8_t>& payloadPlist);

// Decodes the async bridge-event payload shape used for serviceStatus
// callbacks: a 5-element array [9, bridge_status, data, x, x] (VERIFIED
// FROM SOURCE: bridge-xpc-probe.py's summarize_event). Returns the raw
// `data` bytes (element index 2) only when the shape matches exactly —
// std::nullopt on any other shape (caller must fail closed, not guess).
std::optional<std::vector<uint8_t>> DecodeStatusEventData(const std::vector<uint8_t>& payloadPlist);

} // namespace t2::bridgexpc

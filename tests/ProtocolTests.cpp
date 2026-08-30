// ProtocolTests.cpp
//
// Hardware-independent tests (Milestone 2 §28 "Invalid" test matrix +
// Milestone 1's test_t2_fprintd.py fail-closed tests, ported to C++).
// Minimal self-contained runner — no external test framework dependency
// assumed for this PoC tree; swap for a real framework (Catch2/GTest)
// before this becomes a permanent CI suite.
#define NOMINMAX
#include "../protocol/BridgeXpc/Frame.h"
#include "../protocol/BridgeXpc/PlistPayload.h"
#include "../protocol/BiometricKit/MatchResult.h"
#include <iostream>
#include <cstring>
#include <cassert>

using namespace t2;

static int g_failures = 0;
#define CHECK(cond) do { \
    if (!(cond)) { \
        std::wcerr << L"FAIL: " << __FILE__ << L":" << __LINE__ << L" " << L#cond << L"\n"; \
        g_failures++; \
    } \
} while (0)

static void TestFrameHeader_Valid() {
    uint8_t buf[16];
    uint16_t magic = bridgexpc::kFrameMagic;
    uint16_t version = bridgexpc::kProtocolVersion;
    uint32_t type = 2;
    uint64_t len = 100;
    std::memcpy(buf + 0, &magic, 2);
    std::memcpy(buf + 2, &version, 2);
    std::memcpy(buf + 4, &type, 4);
    std::memcpy(buf + 8, &len, 8);

    bridgexpc::FrameHeader hdr;
    CHECK(bridgexpc::ParseFrameHeader(buf, sizeof(buf), &hdr) == bridgexpc::ParseResult::Ok);
    CHECK(hdr.bodyLength == 100);
}

static void TestFrameHeader_Truncated() {
    uint8_t buf[10] = {0};
    bridgexpc::FrameHeader hdr;
    CHECK(bridgexpc::ParseFrameHeader(buf, sizeof(buf), &hdr) == bridgexpc::ParseResult::Incomplete);
}

static void TestFrameHeader_BadMagic() {
    uint8_t buf[16] = {0};
    uint16_t wrongMagic = 0x1234;
    std::memcpy(buf + 0, &wrongMagic, 2);
    bridgexpc::FrameHeader hdr;
    CHECK(bridgexpc::ParseFrameHeader(buf, sizeof(buf), &hdr) == bridgexpc::ParseResult::BadMagic);
}

static void TestFrameHeader_BadVersion() {
    uint8_t buf[16] = {0};
    uint16_t magic = bridgexpc::kFrameMagic;
    uint16_t wrongVersion = 99;
    std::memcpy(buf + 0, &magic, 2);
    std::memcpy(buf + 2, &wrongVersion, 2);
    bridgexpc::FrameHeader hdr;
    CHECK(bridgexpc::ParseFrameHeader(buf, sizeof(buf), &hdr) == bridgexpc::ParseResult::BadVersion);
}

static void TestFrameHeader_OversizedBody() {
    uint8_t buf[16] = {0};
    uint16_t magic = bridgexpc::kFrameMagic;
    uint16_t version = bridgexpc::kProtocolVersion;
    uint32_t type = 2;
    uint64_t hugeLen = bridgexpc::kMaxFrameBodyBytes + 1;
    std::memcpy(buf + 0, &magic, 2);
    std::memcpy(buf + 2, &version, 2);
    std::memcpy(buf + 4, &type, 4);
    std::memcpy(buf + 8, &hugeLen, 8);
    bridgexpc::FrameHeader hdr;
    CHECK(bridgexpc::ParseFrameHeader(buf, sizeof(buf), &hdr) == bridgexpc::ParseResult::BodyTooLarge);
}

static void TestFrameHeader_UnknownType() {
    uint8_t buf[16] = {0};
    uint16_t magic = bridgexpc::kFrameMagic;
    uint16_t version = bridgexpc::kProtocolVersion;
    uint32_t type = 99;
    std::memcpy(buf + 0, &magic, 2);
    std::memcpy(buf + 2, &version, 2);
    std::memcpy(buf + 4, &type, 4);
    bridgexpc::FrameHeader hdr;
    CHECK(bridgexpc::ParseFrameHeader(buf, sizeof(buf), &hdr) == bridgexpc::ParseResult::UnknownFrameType);
}

// --- MatchResult: mirrors test_t2_fprintd.py fail-closed cases ---

static biometrickit::IdentityRecordV1 MakeIdentity(uint32_t userId, uint8_t fill) {
    biometrickit::IdentityRecordV1 id{};
    id.userId = userId;
    id.uuid.fill(fill);
    return id;
}

static void TestMatchResult_WrongEmbeddedType() {
    std::vector<uint8_t> payload(biometrickit::kMinMatchResultEventBytes, 0);
    auto ids = std::vector<biometrickit::IdentityRecordV1>{MakeIdentity(501, 0xAA)};
    auto r = biometrickit::ParseMatchResult(biometrickit::kEmbeddedTypeStatus, payload, ids);
    CHECK(r.outcome == biometrickit::MatchOutcome::Malformed);
}

static void TestMatchResult_TooShort() {
    std::vector<uint8_t> payload(biometrickit::kMinMatchResultEventBytes - 1, 0);
    auto ids = std::vector<biometrickit::IdentityRecordV1>{MakeIdentity(501, 0xAA)};
    auto r = biometrickit::ParseMatchResult(biometrickit::kEmbeddedTypeMatchResult, payload, ids);
    CHECK(r.outcome == biometrickit::MatchOutcome::Malformed);
}

static void TestMatchResult_NoEnrolledIdentities_IsNoMatchNotError() {
    std::vector<uint8_t> payload(biometrickit::kMinMatchResultEventBytes, 0);
    std::vector<biometrickit::IdentityRecordV1> noIdentities;
    auto r = biometrickit::ParseMatchResult(biometrickit::kEmbeddedTypeMatchResult, payload, noIdentities);
    CHECK(r.outcome == biometrickit::MatchOutcome::NoMatch);
}

static void TestMatchResult_UnenrolledUuidFailsClosed() {
    std::vector<uint8_t> payload(biometrickit::kMinMatchResultEventBytes, 0);
    // Embed a UUID that does NOT match any enrolled identity.
    std::array<uint8_t, 16> strangerUuid;
    strangerUuid.fill(0x77);
    std::memcpy(payload.data() + 100, strangerUuid.data(), 16);

    auto ids = std::vector<biometrickit::IdentityRecordV1>{MakeIdentity(501, 0xAA)};
    auto r = biometrickit::ParseMatchResult(biometrickit::kEmbeddedTypeMatchResult, payload, ids);
    CHECK(r.outcome == biometrickit::MatchOutcome::NoMatch);
}

static void TestMatchResult_EnrolledUuidMatches() {
    std::vector<uint8_t> payload(biometrickit::kMinMatchResultEventBytes, 0);
    auto id = MakeIdentity(501, 0xAA);
    std::memcpy(payload.data() + 200, id.uuid.data(), 16);

    auto ids = std::vector<biometrickit::IdentityRecordV1>{id};
    auto r = biometrickit::ParseMatchResult(biometrickit::kEmbeddedTypeMatchResult, payload, ids);
    CHECK(r.outcome == biometrickit::MatchOutcome::Match);
    CHECK(r.matchedIdentityUuid.has_value());
}

// --- ParseStatusEventHeader: §5 wiring fix ---

static void TestStatusEventHeader_TooShort() {
    std::vector<uint8_t> data(23, 0); // one byte short of the 24-byte header
    uint32_t embeddedType = 0;
    std::vector<uint8_t> eventData;
    CHECK(!biometrickit::ParseStatusEventHeader(data, &embeddedType, &eventData));
}

static void TestStatusEventHeader_ExtractsEmbeddedTypeAndSlicesBody() {
    std::vector<uint8_t> data(24 + 8, 0);
    uint32_t embeddedType = biometrickit::kEmbeddedTypeMatchResult;
    std::memcpy(data.data() + 8, &embeddedType, sizeof(embeddedType)); // offset 8, per <QIIQ>
    for (size_t i = 0; i < 8; i++) data[24 + i] = static_cast<uint8_t>(0xC0 + i);

    uint32_t outType = 0;
    std::vector<uint8_t> outData;
    CHECK(biometrickit::ParseStatusEventHeader(data, &outType, &outData));
    CHECK(outType == biometrickit::kEmbeddedTypeMatchResult);
    CHECK(outData.size() == 8);
    CHECK(outData[0] == 0xC0);
}

// --- PlistPayload: §3 encode/decode round trip ---

static void TestPlistPayload_EnvelopeRoundTrip() {
    auto encoded = bridgexpc::EncodeRequestEnvelope("TEST-REQ-ID", {10, 2});
    auto env = bridgexpc::ParseMessageBody(encoded);
    CHECK(env.has_value());
    if (env) {
        CHECK(env->version == bridgexpc::kEnvelopeVersion);
        CHECK(env->isReply == false);
        CHECK(env->requestId == "TEST-REQ-ID");
        auto ints = bridgexpc::DecodeIntArrayPayload(env->payloadPlist);
        CHECK(ints.has_value());
        if (ints) {
            CHECK(ints->size() == 2);
            CHECK((*ints)[0] == 10);
            CHECK((*ints)[1] == 2);
        }
    }
}

static void TestPlistPayload_BiometricCommandShape() {
    std::vector<uint8_t> inner = {0xDE, 0xAD, 0xBE, 0xEF};
    auto encoded = bridgexpc::EncodeRequestEnvelope("TEST-REQ-ID-2", {3, 0}, &inner, {64});
    auto env = bridgexpc::ParseMessageBody(encoded);
    CHECK(env.has_value());
    // Payload is [3, 0, <data>, 64] — not a pure int array, so
    // DecodeIntArrayPayload must reject it (mixed-type array).
    if (env) {
        auto ints = bridgexpc::DecodeIntArrayPayload(env->payloadPlist);
        CHECK(!ints.has_value());
    }
}

static void TestPlistPayload_MalformedTopLevelRejected() {
    // Not an array at all — a bare bplist integer.
    auto badEnvelope = bridgexpc::EncodeRequestEnvelope("X", {}); // valid envelope, but payload empty array
    // Corrupt: truncate to a few bytes so it can't possibly be a valid
    // 4-element bplist array.
    std::vector<uint8_t> truncated(badEnvelope.begin(), badEnvelope.begin() + std::min<size_t>(4, badEnvelope.size()));
    auto env = bridgexpc::ParseMessageBody(truncated);
    CHECK(!env.has_value());
}

int wmain() {
    TestFrameHeader_Valid();
    TestFrameHeader_Truncated();
    TestFrameHeader_BadMagic();
    TestFrameHeader_BadVersion();
    TestFrameHeader_OversizedBody();
    TestFrameHeader_UnknownType();

    TestMatchResult_WrongEmbeddedType();
    TestMatchResult_TooShort();
    TestMatchResult_NoEnrolledIdentities_IsNoMatchNotError();
    TestMatchResult_UnenrolledUuidFailsClosed();
    TestMatchResult_EnrolledUuidMatches();

    TestStatusEventHeader_TooShort();
    TestStatusEventHeader_ExtractsEmbeddedTypeAndSlicesBody();

    TestPlistPayload_EnvelopeRoundTrip();
    TestPlistPayload_BiometricCommandShape();
    TestPlistPayload_MalformedTopLevelRejected();

    if (g_failures == 0) {
        std::wcout << L"All tests passed.\n";
        return 0;
    }
    std::wcerr << g_failures << L" test(s) failed.\n";
    return 1;
}

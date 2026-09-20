// SPDX-License-Identifier: GPL-2.0-only
// T2TouchIdEngineAdapter.cpp - Windows Biometric Framework Engine Adapter for
// the Apple T2 Touch ID sensor (design doc 7.4).
//
// STAGE 1 (this file): make the biometric unit LOAD. Event 1109 /
// 0x80070002 in Microsoft-Windows-Biometrics/Operational means WBF could not
// bring up the unit; the unit config (INF) names T2TouchIdEngineAdapter.dll
// as its engine, so this DLL has to exist, export WbioQueryEngineInterface
// and survive Attach. Nothing here talks to the SEP yet.
//
// STAGE 1b: the first cut advertised WINBIO_ENGINE_INTERFACE_VERSION_1 with
// Size covering only the V1 tail (through ControlUnitPrivileged). WBF's
// adapter-integrity check rejects that on Windows 10/11 -
// WINBIO_E_ADAPTER_INTEGRITY_FAILURE (0x8009803d), logged as Event 1109/
// 0x80070002 same as a missing DLL - because winbio_adapter.h requires
// VERSION_3 or VERSION_4 from Windows 10 onward (Windows 7 was the only
// VERSION_1 target). Fixed by advertising VERSION_3 and implementing the
// V2.0/V3.0 members winbio_adapter.h adds after ControlUnitPrivileged
// (NotifyPowerChange, Reserved_1, then PipelineInit through
// SetAccountPolicy) - all of them, not just the lifecycle ones, since a
// null entry WBF decides to call would crash wbiosrvc rather than fail
// cleanly. See the interface-table comment below for exactly which.
//
// STAGE 2/3 (this revision): sample handling, verify/identify and enrollment.
// The SEP does the actual fingerprint match; what reaches this adapter is a
// WINBIO_BIR whose Vendor Data Block carries t2::biometrickit::T2VendorSamplePayload
// (VendorWire.h): the fail-closed VerifyOutcome plus macosUserId. An enrolled
// record is {macosUserId} stored through WBF's storage adapter (design doc 4).
//
// Fail-closed rules (design doc 5) - a wrong "success" here is a login bypass,
// a wrong "no match" is only an annoyance:
//   * a match is reported only from a sample that AcceptSampleData parsed
//     strictly, whose Outcome is Match, whose Kind is a real touch
//     (EnrollConfirm samples - no touch - can only complete an enrollment),
//     and whose macosUserId equals the enrolled record's;
//   * a sample is consumed by the first operation that uses it and dropped by
//     ClearContext, so an old verdict can never be replayed;
//   * two enrolled records for the same macosUserId (ambiguous identity) fail
//     the identify instead of guessing an account;
//   * every storage/parse failure ends as UNKNOWN_ID / BAD_CAPTURE, never Match.
//
// Every callback writes one line to the debugger (DebugView, "Capture Global
// Win32"; wbiosrvc is a normal service process). That trace is the point of
// this stage: it shows which callbacks WBF really calls, in which order, so
// stage 2 implements what is used instead of what is guessed.
//
// Signatures are taken from winbio_adapter.h of Windows Kits 10.0.26100.0
// (PIBIO_ENGINE_*_FN typedefs) and cross-checked with the Microsoft WBDI
// sample engine adapter (Windows-driver-samples, biometrics/adapters/
// engine_adapter, removed from master in 2024; last present in c73af47~1).
#include <windows.h>
#include <stddef.h>
#include <stdarg.h>
#include <strsafe.h>

// winbio_adapter.h's inline Wbio*() helpers use ARGUMENT_PRESENT, which
// user-mode windows.h does not define: it has to exist BEFORE the include
// (the Microsoft sample defines it in its precomp.h for the same reason).
#ifndef ARGUMENT_PRESENT
#define ARGUMENT_PRESENT(x) ((x) != NULL)
#endif

#include <winbio_adapter.h>
#include <winbio_err.h>

#ifndef WINBIO_I_MORE_DATA
#define WINBIO_I_MORE_DATA ((HRESULT)0x00090001L)   // winbio_err.h; guarded in case the SDK spells it differently
#endif

#include <cstring>
#include "../WbdiBir.h"

// ---------------------------------------------------------------------------
// Private per-pipeline context. winbio_adapter.h only forward-declares
// struct _WINIBIO_ENGINE_CONTEXT (sic); the adapter owns the definition.
// ---------------------------------------------------------------------------
struct _WINIBIO_ENGINE_CONTEXT {
    ULONG Signature;      // 'T2EC', catches a foreign / stale EngineContext
    ULONG CallCount;      // number of callbacks seen on this pipeline (trace only)

    // The last sample accepted by AcceptSampleData. Consumed (cleared) by the
    // operation that uses it and by ClearContext.
    BOOLEAN SampleValid;
    UCHAR   SamplePurpose;      // WINBIO_BIR_PURPOSE as WBF passed it
    UCHAR   SampleKind;         // t2::biometrickit::kSampleKind*
    ULONG   SampleOutcome;      // wire VerifyOutcome
    ULONG   SampleMacosUserId;

    // Enrollment in progress (CreateEnrollment .. CommitEnrollment/Discard).
    BOOLEAN EnrollActive;
    BOOLEAN EnrollReady;        // one accepted EnrollConfirm sample is all this sensor needs
    ULONG   EnrollMacosUserId;
};
static const ULONG kContextSignature = 0x43453254; // "T2EC" little-endian

namespace {

// {756DB001-3595-4EE9-A2DC-BF42F041CEB5} - AdapterId of this engine.
const GUID kAdapterId =
    { 0x756db001, 0x3595, 0x4ee9, { 0xa2, 0xdc, 0xbf, 0x42, 0xf0, 0x41, 0xce, 0xb5 } };

// ---------------------------------------------------------------------------
// DebugView trace. Every line starts with "T2TouchIdEngine:" (DebugView filter:
// T2TouchId*) followed by [pid:tid]. wbiosrvc is a normal service process, so
// run DebugView as Administrator with Capture -> Capture Global Win32.
//   -> Name   : callback entered
//        ...  : selected arguments
//   <- Name   : callback returned, with the HRESULT WBF will see
// ---------------------------------------------------------------------------
void EngLog(_In_z_ const char* fmt, ...)
{
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    const HRESULT fmtHr = StringCchVPrintfA(msg, ARRAYSIZE(msg), fmt, ap);
    va_end(ap);
    if (FAILED(fmtHr)) {
        return;
    }
    char line[400];
    if (SUCCEEDED(StringCchPrintfA(line, ARRAYSIZE(line), "T2TouchIdEngine: [%lu:%lu] %s\n",
                                   static_cast<unsigned long>(GetCurrentProcessId()),
                                   static_cast<unsigned long>(GetCurrentThreadId()), msg))) {
        OutputDebugStringA(line);
    }
}

const char* HrName(HRESULT hr)
{
    switch (hr) {
    case S_OK:           return "S_OK";
    case E_NOTIMPL:      return "E_NOTIMPL";
    case E_POINTER:      return "E_POINTER";
    case E_INVALIDARG:   return "E_INVALIDARG";
    case E_UNEXPECTED:   return "E_UNEXPECTED";
    case E_OUTOFMEMORY:  return "E_OUTOFMEMORY";
    default:             return "?";
    }
}

void Trace(_In_z_ const char* fn, _In_opt_ PWINBIO_PIPELINE pipeline)
{
    unsigned long calls = 0;
    if (pipeline != nullptr && pipeline->EngineContext != nullptr &&
        pipeline->EngineContext->Signature == kContextSignature) {
        calls = ++pipeline->EngineContext->CallCount;
    }
    EngLog("-> %s pipeline=%p call#%lu", fn, static_cast<void*>(pipeline), calls);
}

// Logs the value a callback is about to hand back to WBF and passes it through.
HRESULT TraceRet(_In_z_ const char* fn, HRESULT hr)
{
    EngLog("<- %s hr=0x%08lx %s", fn, static_cast<unsigned long>(hr), HrName(hr));
    return hr;
}

// Zero the Identity out-parameter the way an empty result looks.
void ZeroIdentity(_Out_ PWINBIO_IDENTITY identity)
{
    if (ARGUMENT_PRESENT(identity)) {
        RtlZeroMemory(identity, sizeof(*identity));
    }
}

PWINIBIO_ENGINE_CONTEXT GetContext(_In_opt_ PWINBIO_PIPELINE pipeline)
{
    if (pipeline == nullptr) {
        return nullptr;
    }
    PWINIBIO_ENGINE_CONTEXT ctx = pipeline->EngineContext;
    return (ctx != nullptr && ctx->Signature == kContextSignature) ? ctx : nullptr;
}

void ClearSample(_Inout_ PWINIBIO_ENGINE_CONTEXT ctx)
{
    ctx->SampleValid = FALSE;
    ctx->SamplePurpose = 0;
    ctx->SampleKind = 0;
    ctx->SampleOutcome = t2::biometrickit::kWireOutcomeInvalid;
    ctx->SampleMacosUserId = 0;
}

void ResetEnrollment(_Inout_ PWINIBIO_ENGINE_CONTEXT ctx)
{
    ctx->EnrollActive = FALSE;
    ctx->EnrollReady = FALSE;
    ctx->EnrollMacosUserId = 0;
}

const UCHAR kEnrollPurposes = WINBIO_PURPOSE_ENROLL | WINBIO_PURPOSE_ENROLL_FOR_VERIFICATION |
                              WINBIO_PURPOSE_ENROLL_FOR_IDENTIFICATION;
const UCHAR kMatchPurposes  = WINBIO_PURPOSE_VERIFY | WINBIO_PURPOSE_IDENTIFY;

// A sample that proves a real touch matched: what verify/identify may act on.
bool SampleIsTouchMatch(const _WINIBIO_ENGINE_CONTEXT& ctx)
{
    return ctx.SampleValid &&
           ctx.SampleKind == t2::biometrickit::kSampleKindVerify &&
           ctx.SampleOutcome == t2::biometrickit::kWireOutcomeMatch &&
           (ctx.SamplePurpose & kMatchPurposes) != 0 &&
           (ctx.SamplePurpose & kEnrollPurposes) == 0;
}

// The no-touch sample that completes an enrollment. Never usable for matching.
bool SampleIsEnrollConfirm(const _WINIBIO_ENGINE_CONTEXT& ctx)
{
    return ctx.SampleValid &&
           ctx.SampleKind == t2::biometrickit::kSampleKindEnrollConfirm &&
           ctx.SampleOutcome == t2::biometrickit::kWireOutcomeMatch &&
           (ctx.SamplePurpose & kEnrollPurposes) != 0;
}

// The stored "template": no biometric data, just which macOS user the SEP
// verifies for this Windows identity (design doc 4).
#pragma pack(push, 1)
struct T2EnrolledTemplateV1 {
    ULONG Version;
    ULONG MacosUserId;
    UCHAR Reserved[8];
};
#pragma pack(pop)
static_assert(sizeof(T2EnrolledTemplateV1) == 16, "stored template layout must stay stable");
const ULONG kTemplateVersion = 1;

bool ReadTemplate(const WINBIO_STORAGE_RECORD& record, _Out_ ULONG* macosUserId)
{
    *macosUserId = 0;
    if (record.TemplateBlob == nullptr || record.TemplateBlobSize < sizeof(T2EnrolledTemplateV1)) {
        return false;
    }
    T2EnrolledTemplateV1 t{};
    std::memcpy(&t, record.TemplateBlob, sizeof(t));
    if (t.Version != kTemplateVersion) {
        return false;
    }
    *macosUserId = t.MacosUserId;
    return true;
}

// Selects the records to look at and returns how many there are.
//   subject != nullptr : the records of that identity/subfactor (verify)
//   subject == nullptr : every record (identify, duplicate check)
HRESULT OpenRecordSet(_Inout_ PWINBIO_PIPELINE pipeline, _In_opt_ PWINBIO_IDENTITY subject,
                      WINBIO_BIOMETRIC_SUBTYPE subFactor, _Out_ SIZE_T* count)
{
    *count = 0;
    HRESULT hr;
    if (subject != nullptr) {
        hr = WbioStorageQueryBySubject(pipeline, subject, subFactor);
        EngLog("     storage QueryBySubject hr=0x%08lx", static_cast<unsigned long>(hr));
    } else {
        hr = WbioStorageQueryByContent(pipeline, subFactor, nullptr, 0);
        EngLog("     storage QueryByContent(all) hr=0x%08lx", static_cast<unsigned long>(hr));
        if (FAILED(hr)) {
            WINBIO_IDENTITY wildcard{};
            wildcard.Type = WINBIO_ID_TYPE_WILDCARD;
            wildcard.Value.Wildcard = WINBIO_IDENTITY_WILDCARD;
            hr = WbioStorageQueryBySubject(pipeline, &wildcard, subFactor);
            EngLog("     storage QueryBySubject(wildcard) hr=0x%08lx", static_cast<unsigned long>(hr));
        }
    }
    if (FAILED(hr)) {
        return hr;
    }
    hr = WbioStorageGetRecordCount(pipeline, count);
    EngLog("     storage GetRecordCount hr=0x%08lx count=%llu", static_cast<unsigned long>(hr),
           static_cast<unsigned long long>(*count));
    if (FAILED(hr)) {
        *count = 0;
    }
    return hr;
}

// Walks the current record set. fn(record) returns true to stop. The record's
// memory belongs to the storage adapter and is valid only until the next
// storage call, so fn must copy what it keeps.
template <typename Fn>
void ForEachRecord(_Inout_ PWINBIO_PIPELINE pipeline, SIZE_T count, Fn&& fn)
{
    for (SIZE_T i = 0; i < count; ++i) {
        HRESULT hr = (i == 0) ? WbioStorageFirstRecord(pipeline) : WbioStorageNextRecord(pipeline);
        if (FAILED(hr)) {
            EngLog("     storage %s record hr=0x%08lx (index %llu) - stopping", i == 0 ? "First" : "Next",
                   static_cast<unsigned long>(hr), static_cast<unsigned long long>(i));
            return;
        }
        WINBIO_STORAGE_RECORD record{};
        hr = WbioStorageGetCurrentRecord(pipeline, &record);
        if (FAILED(hr)) {
            EngLog("     storage GetCurrentRecord hr=0x%08lx (index %llu) - stopping",
                   static_cast<unsigned long>(hr), static_cast<unsigned long long>(i));
            return;
        }
        if (fn(record)) {
            return;
        }
    }
}

void ZeroMatchOutputs(_Out_opt_ PUCHAR* payload, _Out_opt_ PSIZE_T payloadSize,
                      _Out_opt_ PUCHAR* hash, _Out_opt_ PSIZE_T hashSize,
                      _Out_opt_ PWINBIO_REJECT_DETAIL reject)
{
    if (ARGUMENT_PRESENT(payload))     { *payload = nullptr; }
    if (ARGUMENT_PRESENT(payloadSize)) { *payloadSize = 0; }
    if (ARGUMENT_PRESENT(hash))        { *hash = nullptr; }
    if (ARGUMENT_PRESENT(hashSize))    { *hashSize = 0; }
    if (ARGUMENT_PRESENT(reject))      { *reject = 0; }
}

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------
HRESULT WINAPI EngineAttach(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("Attach", Pipeline);
    if (!ARGUMENT_PRESENT(Pipeline)) {
        return TraceRet("Attach", E_POINTER);
    }
    if (Pipeline->EngineContext != nullptr) {
        // Attach on a pipeline that already has an engine context is a
        // framework bug or a double attach; do not leak / overwrite.
        return TraceRet("Attach", E_UNEXPECTED);
    }
    PWINIBIO_ENGINE_CONTEXT ctx = static_cast<PWINIBIO_ENGINE_CONTEXT>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ctx)));
    if (ctx == nullptr) {
        return TraceRet("Attach", E_OUTOFMEMORY);
    }
    ctx->Signature = kContextSignature;
    Pipeline->EngineContext = ctx;
    return TraceRet("Attach", S_OK);
}

HRESULT WINAPI EngineDetach(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("Detach", Pipeline);
    if (!ARGUMENT_PRESENT(Pipeline)) {
        return TraceRet("Detach", E_POINTER);
    }
    PWINIBIO_ENGINE_CONTEXT ctx = Pipeline->EngineContext;
    if (ctx == nullptr) {
        return TraceRet("Detach", E_UNEXPECTED);
    }
    Pipeline->EngineContext = nullptr;
    if (ctx->Signature == kContextSignature) {
        ctx->Signature = 0;
        HeapFree(GetProcessHeap(), 0, ctx);
    }
    return TraceRet("Detach", S_OK);
}

HRESULT WINAPI EngineClearContext(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("ClearContext", Pipeline);
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr) {
        return TraceRet("ClearContext", E_POINTER);
    }
    // Drops the pending sample so an old verdict can never be reused. The
    // enrollment state is kept: WBF may clear the context between the capture
    // and the commit of one enrollment; CreateEnrollment / DiscardEnrollment /
    // CommitEnrollment are what reset it.
    ClearSample(ctx);
    return TraceRet("ClearContext", S_OK);
}

// ---------------------------------------------------------------------------
// Static capability queries. Values are the least surprising ones that let the
// unit come up; each is an assumption that the trace will confirm or refute.
// ---------------------------------------------------------------------------
HRESULT WINAPI EngineQueryPreferredFormat(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REGISTERED_FORMAT StandardFormat,
    _Out_ PWINBIO_UUID VendorFormat)
{
    Trace("QueryPreferredFormat", Pipeline);
    if (!ARGUMENT_PRESENT(StandardFormat) || !ARGUMENT_PRESENT(VendorFormat)) {
        return TraceRet("QueryPreferredFormat", E_POINTER);
    }
    // Must equal SupportedFormat[0] reported by the sensor (umdf/Queue.cpp,
    // GET_ATTRIBUTES) or WBF has no common format. Placeholder until the
    // vendor BIR format from design doc 5 exists - change both together.
    StandardFormat->Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    StandardFormat->Type  = WINBIO_ANSI_381_FORMAT_TYPE;
    RtlZeroMemory(VendorFormat, sizeof(*VendorFormat));
    return TraceRet("QueryPreferredFormat", S_OK);
}

HRESULT WINAPI EngineQueryIndexVectorSize(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T IndexElementCount)
{
    Trace("QueryIndexVectorSize", Pipeline);
    if (!ARGUMENT_PRESENT(IndexElementCount)) {
        return TraceRet("QueryIndexVectorSize", E_POINTER);
    }
    // ASSUMPTION: 0 = engine does not build a search index for the storage
    // adapter (matching is 1:1 in the SEP, design doc 4).
    *IndexElementCount = 0;
    return TraceRet("QueryIndexVectorSize", S_OK);
}

HRESULT WINAPI EngineQueryHashAlgorithms(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T AlgorithmCount,
    _Out_ PSIZE_T AlgorithmBufferSize,
    _Outptr_result_bytebuffer_all_(*AlgorithmBufferSize)
    _At_(*AlgorithmBuffer, _Post_ _NullNull_terminated_) PUCHAR* AlgorithmBuffer)
{
    Trace("QueryHashAlgorithms", Pipeline);
    if (!ARGUMENT_PRESENT(AlgorithmCount) || !ARGUMENT_PRESENT(AlgorithmBufferSize) ||
        !ARGUMENT_PRESENT(AlgorithmBuffer)) {
        return TraceRet("QueryHashAlgorithms", E_POINTER);
    }
    // No template hashing: matching is done by the SEP, no template leaves it.
    *AlgorithmCount      = 0;
    *AlgorithmBufferSize = 0;
    *AlgorithmBuffer     = nullptr;
    return TraceRet("QueryHashAlgorithms", S_OK);
}

HRESULT WINAPI EngineSetHashAlgorithm(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ SIZE_T AlgorithmBufferSize,
    _In_reads_z_(AlgorithmBufferSize) PUCHAR AlgorithmBuffer)
{
    Trace("SetHashAlgorithm", Pipeline);
    EngLog("     algorithmBufferSize=%llu", static_cast<unsigned long long>(AlgorithmBufferSize));
    UNREFERENCED_PARAMETER(AlgorithmBufferSize);
    UNREFERENCED_PARAMETER(AlgorithmBuffer);
    return TraceRet("SetHashAlgorithm", E_NOTIMPL); // never offered any algorithm to choose from
}

HRESULT WINAPI EngineQuerySampleHint(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T SampleHint)
{
    Trace("QuerySampleHint", Pipeline);
    if (!ARGUMENT_PRESENT(SampleHint)) {
        return TraceRet("QuerySampleHint", E_POINTER);
    }
    *SampleHint = 1; // one capture is enough for a verify (SEP matches internally)
    return TraceRet("QuerySampleHint", S_OK);
}

// ---------------------------------------------------------------------------
// Sample path. WBF's sensor adapter hands the BIR the driver returned to
// AcceptSampleData; the matching operations (Verify/Identify) and the
// enrollment operations then consume it. See the file header for the rules.
// ---------------------------------------------------------------------------
void TraceBirHead(_In_reads_bytes_(size) const void* data, SIZE_T size)
{
    const SIZE_T n = size < 48 ? size : 48;
    char hex[48 * 2 + 1] = {};
    static const char digits[] = "0123456789abcdef";
    const UCHAR* bytes = static_cast<const UCHAR*>(data);
    for (SIZE_T i = 0; i < n; ++i) {
        hex[i * 2]     = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    EngLog("     sample head (%llu of %llu bytes): %s", static_cast<unsigned long long>(n),
           static_cast<unsigned long long>(size), hex);
}

HRESULT WINAPI EngineAcceptSampleData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_reads_bytes_(SampleSize) PWINBIO_BIR SampleBuffer,
    _In_ SIZE_T SampleSize,
    _In_ WINBIO_BIR_PURPOSE Purpose,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    Trace("AcceptSampleData", Pipeline);
    EngLog("     sampleSize=%llu purpose=0x%02x", static_cast<unsigned long long>(SampleSize), static_cast<unsigned>(Purpose));
    if (ARGUMENT_PRESENT(RejectDetail)) {
        *RejectDetail = 0;
    }
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr || !ARGUMENT_PRESENT(SampleBuffer)) {
        return TraceRet("AcceptSampleData", E_POINTER);
    }
    ClearSample(ctx);   // a new sample always replaces the previous one

    t2::wbdi::ParsedVendorBir bir;
    if (!t2::wbdi::ParseVendorBir(SampleBuffer, SampleSize, &bir)) {
        EngLog("     BIR rejected: malformed (not the WINBIO_BIR + vendor block the driver builds)");
        TraceBirHead(SampleBuffer, SampleSize);
        return TraceRet("AcceptSampleData", WINBIO_E_BAD_CAPTURE);
    }
    t2::biometrickit::T2VendorSamplePayload payload;
    if (!t2::biometrickit::DeserializeVendorPayload(bir.Payload, bir.PayloadSize, &payload)) {
        EngLog("     vendor payload rejected: bad size/version/fields (payloadSize=%llu)",
               static_cast<unsigned long long>(bir.PayloadSize));
        TraceBirHead(SampleBuffer, SampleSize);
        return TraceRet("AcceptSampleData", WINBIO_E_BAD_CAPTURE);
    }
    EngLog("     BIR ok: headerPurpose=0x%02x headerFlags=0x%02x outcome=%lu kind=%u macosUserId=%lu",
           static_cast<unsigned>(bir.Purpose), static_cast<unsigned>(bir.Flags),
           static_cast<unsigned long>(payload.Outcome), static_cast<unsigned>(payload.Kind),
           static_cast<unsigned long>(payload.MacosUserId));
    if (payload.Outcome != t2::biometrickit::kWireOutcomeMatch) {
        // The driver only ever sends a sample for a Match; anything else here
        // is not something to build a verdict on.
        EngLog("     outcome is not Match - refusing the sample");
        return TraceRet("AcceptSampleData", WINBIO_E_BAD_CAPTURE);
    }

    ctx->SampleValid = TRUE;
    ctx->SamplePurpose = Purpose;
    ctx->SampleKind = payload.Kind;
    ctx->SampleOutcome = payload.Outcome;
    ctx->SampleMacosUserId = payload.MacosUserId;
    return TraceRet("AcceptSampleData", S_OK);
}

HRESULT WINAPI EngineExportEngineData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ WINBIO_BIR_DATA_FLAGS Flags,
    _Outptr_result_bytebuffer_all_(*SampleSize) PWINBIO_BIR* SampleBuffer,
    _Out_ PSIZE_T SampleSize)
{
    Trace("ExportEngineData", Pipeline);
    EngLog("     flags=0x%02x", static_cast<unsigned>(Flags));
    UNREFERENCED_PARAMETER(Flags);
    // No feature set / template that could be exported exists: the SEP owns
    // the biometric data and never hands it out.
    if (ARGUMENT_PRESENT(SampleBuffer)) { *SampleBuffer = nullptr; }
    if (ARGUMENT_PRESENT(SampleSize))   { *SampleSize = 0; }
    return TraceRet("ExportEngineData", E_NOTIMPL);
}

// ---------------------------------------------------------------------------
// Verify / identify.
// ---------------------------------------------------------------------------
HRESULT WINAPI EngineVerifyFeatureSet(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_IDENTITY Identity,
    _In_ WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Out_ PBOOLEAN Match,
    _Outptr_result_bytebuffer_all_(*PayloadBlobSize) PUCHAR* PayloadBlob,
    _Out_ PSIZE_T PayloadBlobSize,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR* HashValue,
    _Out_ PSIZE_T HashSize,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    Trace("VerifyFeatureSet", Pipeline);
    EngLog("     subFactor=0x%02x", static_cast<unsigned>(SubFactor));
    if (ARGUMENT_PRESENT(Match)) { *Match = FALSE; }   // never a match unless proven below
    ZeroMatchOutputs(PayloadBlob, PayloadBlobSize, HashValue, HashSize, RejectDetail);

    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr || !ARGUMENT_PRESENT(Identity) || !ARGUMENT_PRESENT(Match)) {
        return TraceRet("VerifyFeatureSet", E_POINTER);
    }
    const bool touchMatch = SampleIsTouchMatch(*ctx);
    const ULONG sampleUser = ctx->SampleMacosUserId;
    ClearSample(ctx);   // consumed: this sample can never authorize a second operation
    if (!touchMatch) {
        EngLog("     no acceptable touch-match sample pending -> fail closed");
        return TraceRet("VerifyFeatureSet", WINBIO_E_INVALID_OPERATION);
    }

    SIZE_T count = 0;
    const HRESULT qhr = OpenRecordSet(Pipeline, Identity, SubFactor, &count);
    if (FAILED(qhr) || count == 0) {
        EngLog("     no enrolled record for this identity/subfactor");
        return TraceRet("VerifyFeatureSet", WINBIO_E_UNKNOWN_ID);
    }
    bool matched = false;
    ForEachRecord(Pipeline, count, [&](const WINBIO_STORAGE_RECORD& record) {
        ULONG enrolledUser = 0;
        if (ReadTemplate(record, &enrolledUser) && enrolledUser == sampleUser) {
            matched = true;
            return true;
        }
        return false;
    });
    EngLog("     verify: sample macosUserId=%lu -> %s", static_cast<unsigned long>(sampleUser),
           matched ? "MATCH" : "no match");
    *Match = matched ? TRUE : FALSE;
    return TraceRet("VerifyFeatureSet", S_OK);
}

HRESULT WINAPI EngineIdentifyFeatureSet(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_IDENTITY Identity,
    _Out_ PWINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Outptr_result_bytebuffer_all_(*PayloadBlobSize) PUCHAR* PayloadBlob,
    _Out_ PSIZE_T PayloadBlobSize,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR* HashValue,
    _Out_ PSIZE_T HashSize,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    Trace("IdentifyFeatureSet", Pipeline);
    ZeroIdentity(Identity);
    if (ARGUMENT_PRESENT(SubFactor)) { *SubFactor = 0; }
    ZeroMatchOutputs(PayloadBlob, PayloadBlobSize, HashValue, HashSize, RejectDetail);

    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr || !ARGUMENT_PRESENT(Identity) || !ARGUMENT_PRESENT(SubFactor)) {
        return TraceRet("IdentifyFeatureSet", E_POINTER);
    }
    const bool touchMatch = SampleIsTouchMatch(*ctx);
    const ULONG sampleUser = ctx->SampleMacosUserId;
    ClearSample(ctx);   // consumed
    if (!touchMatch) {
        EngLog("     no acceptable touch-match sample pending -> fail closed");
        return TraceRet("IdentifyFeatureSet", WINBIO_E_INVALID_OPERATION);
    }

    SIZE_T count = 0;
    const HRESULT qhr = OpenRecordSet(Pipeline, nullptr, WINBIO_SUBTYPE_ANY, &count);
    if (FAILED(qhr) || count == 0) {
        // Also the normal answer while nobody is enrolled yet (the check
        // Settings runs before it starts an enrollment).
        EngLog("     no enrolled records -> UNKNOWN_ID");
        return TraceRet("IdentifyFeatureSet", WINBIO_E_UNKNOWN_ID);
    }

    ULONG matches = 0;
    WINBIO_IDENTITY found{};
    WINBIO_BIOMETRIC_SUBTYPE foundSub = 0;
    ForEachRecord(Pipeline, count, [&](const WINBIO_STORAGE_RECORD& record) {
        ULONG enrolledUser = 0;
        if (ReadTemplate(record, &enrolledUser) && enrolledUser == sampleUser && record.Identity != nullptr) {
            if (matches == 0) {
                found = *record.Identity;     // copy now: the record's memory dies at the next storage call
                foundSub = record.SubFactor;
            }
            ++matches;
        }
        return false;   // scan all: a second match means the identity is ambiguous
    });

    if (matches == 0) {
        EngLog("     identify: macosUserId=%lu is not enrolled -> UNKNOWN_ID", static_cast<unsigned long>(sampleUser));
        return TraceRet("IdentifyFeatureSet", WINBIO_E_UNKNOWN_ID);
    }
    if (matches > 1) {
        // Two Windows identities enrolled against the same macOS user: the SEP
        // cannot tell them apart, so guessing an account would be a login bypass.
        EngLog("     identify: %lu records share macosUserId=%lu -> ambiguous, failing closed",
               matches, static_cast<unsigned long>(sampleUser));
        return TraceRet("IdentifyFeatureSet", WINBIO_E_UNKNOWN_ID);
    }
    *Identity = found;
    *SubFactor = foundSub;
    EngLog("     identify: macosUserId=%lu -> enrolled identity (type %lu)",
           static_cast<unsigned long>(sampleUser), static_cast<unsigned long>(found.Type));
    return TraceRet("IdentifyFeatureSet", S_OK);
}

// ---------------------------------------------------------------------------
// Enrollment (design doc 4): "enroll" = the driver confirmed the SEP has an
// identity for macosUserId (EnrollConfirm sample, no touch), and the record
// stored through WBF's storage adapter is {macosUserId}. One sample completes it.
// ---------------------------------------------------------------------------
HRESULT WINAPI EngineCreateEnrollment(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("CreateEnrollment", Pipeline);
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr) {
        return TraceRet("CreateEnrollment", E_POINTER);
    }
    ResetEnrollment(ctx);      // an abandoned earlier enrollment is simply replaced
    ClearSample(ctx);
    ctx->EnrollActive = TRUE;
    return TraceRet("CreateEnrollment", S_OK);
}

HRESULT WINAPI EngineUpdateEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    Trace("UpdateEnrollment", Pipeline);
    if (ARGUMENT_PRESENT(RejectDetail)) { *RejectDetail = 0; }
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr) {
        return TraceRet("UpdateEnrollment", E_POINTER);
    }
    if (!ctx->EnrollActive) {
        return TraceRet("UpdateEnrollment", WINBIO_E_INVALID_OPERATION);
    }
    const bool confirm = SampleIsEnrollConfirm(*ctx);
    const ULONG sampleUser = ctx->SampleMacosUserId;
    ClearSample(ctx);
    if (!confirm) {
        EngLog("     no EnrollConfirm sample pending -> BAD_CAPTURE");
        return TraceRet("UpdateEnrollment", WINBIO_E_BAD_CAPTURE);
    }
    ctx->EnrollMacosUserId = sampleUser;
    ctx->EnrollReady = TRUE;
    EngLog("     enrollment ready for macosUserId=%lu", static_cast<unsigned long>(sampleUser));
    return TraceRet("UpdateEnrollment", S_OK);   // S_OK = complete, no more samples needed
}

HRESULT WINAPI EngineGetEnrollmentStatus(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    Trace("GetEnrollmentStatus", Pipeline);
    if (ARGUMENT_PRESENT(RejectDetail)) { *RejectDetail = 0; }
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr) {
        return TraceRet("GetEnrollmentStatus", E_POINTER);
    }
    if (!ctx->EnrollActive) {
        return TraceRet("GetEnrollmentStatus", WINBIO_E_INVALID_OPERATION);
    }
    return TraceRet("GetEnrollmentStatus", ctx->EnrollReady ? S_OK : WINBIO_I_MORE_DATA);
}

HRESULT WINAPI EngineGetEnrollmentHash(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR* HashValue,
    _Out_ PSIZE_T HashSize)
{
    Trace("GetEnrollmentHash", Pipeline);
    // No hash algorithm is ever offered (QueryHashAlgorithms reports none).
    if (ARGUMENT_PRESENT(HashValue)) { *HashValue = nullptr; }
    if (ARGUMENT_PRESENT(HashSize))  { *HashSize = 0; }
    return TraceRet("GetEnrollmentHash", E_NOTIMPL);
}

HRESULT WINAPI EngineCheckForDuplicate(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_IDENTITY Identity,
    _Out_ PWINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Out_ PBOOLEAN Duplicate)
{
    Trace("CheckForDuplicate", Pipeline);
    ZeroIdentity(Identity);
    if (ARGUMENT_PRESENT(SubFactor)) { *SubFactor = 0; }
    if (ARGUMENT_PRESENT(Duplicate)) { *Duplicate = FALSE; }
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr || !ARGUMENT_PRESENT(Identity) || !ARGUMENT_PRESENT(SubFactor) ||
        !ARGUMENT_PRESENT(Duplicate)) {
        return TraceRet("CheckForDuplicate", E_POINTER);
    }
    if (!ctx->EnrollActive || !ctx->EnrollReady) {
        return TraceRet("CheckForDuplicate", WINBIO_E_INVALID_OPERATION);
    }

    SIZE_T count = 0;
    const HRESULT qhr = OpenRecordSet(Pipeline, nullptr, WINBIO_SUBTYPE_ANY, &count);
    if (FAILED(qhr) || count == 0) {
        EngLog("     nothing enrolled yet -> not a duplicate");
        return TraceRet("CheckForDuplicate", S_OK);
    }
    const ULONG enrolling = ctx->EnrollMacosUserId;
    ForEachRecord(Pipeline, count, [&](const WINBIO_STORAGE_RECORD& record) {
        ULONG enrolledUser = 0;
        if (ReadTemplate(record, &enrolledUser) && enrolledUser == enrolling && record.Identity != nullptr) {
            *Identity = *record.Identity;
            *SubFactor = record.SubFactor;
            *Duplicate = TRUE;
            return true;
        }
        return false;
    });
    EngLog("     duplicate check for macosUserId=%lu -> %s", static_cast<unsigned long>(enrolling),
           *Duplicate ? "DUPLICATE" : "unique");
    return TraceRet("CheckForDuplicate", S_OK);
}

HRESULT WINAPI EngineCommitEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_IDENTITY Identity,
    _In_ WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _In_reads_bytes_(PayloadBlobSize) PUCHAR PayloadBlob,
    _In_ SIZE_T PayloadBlobSize)
{
    Trace("CommitEnrollment", Pipeline);
    EngLog("     subFactor=0x%02x payloadSize=%llu", static_cast<unsigned>(SubFactor), static_cast<unsigned long long>(PayloadBlobSize));
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr || !ARGUMENT_PRESENT(Identity)) {
        return TraceRet("CommitEnrollment", E_POINTER);
    }
    if (!ctx->EnrollActive || !ctx->EnrollReady) {
        EngLog("     no completed enrollment to commit");
        return TraceRet("CommitEnrollment", WINBIO_E_INVALID_OPERATION);
    }

    T2EnrolledTemplateV1 tmpl{};
    tmpl.Version = kTemplateVersion;
    tmpl.MacosUserId = ctx->EnrollMacosUserId;

    WINBIO_STORAGE_RECORD record{};
    record.Identity = Identity;
    record.SubFactor = SubFactor;
    record.IndexVector = nullptr;          // QueryIndexVectorSize reports 0
    record.IndexElementCount = 0;
    record.TemplateBlob = reinterpret_cast<PUCHAR>(&tmpl);
    record.TemplateBlobSize = sizeof(tmpl);
    record.PayloadBlob = PayloadBlob;
    record.PayloadBlobSize = PayloadBlobSize;

    const HRESULT hr = WbioStorageAddRecord(Pipeline, &record);
    EngLog("     storage AddRecord hr=0x%08lx (identity type %lu, macosUserId=%lu)", static_cast<unsigned long>(hr),
           static_cast<unsigned long>(Identity->Type), static_cast<unsigned long>(tmpl.MacosUserId));
    if (SUCCEEDED(hr)) {
        ResetEnrollment(ctx);
    }
    return TraceRet("CommitEnrollment", hr);
}

HRESULT WINAPI EngineDiscardEnrollment(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("DiscardEnrollment", Pipeline);
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx != nullptr) {
        ResetEnrollment(ctx);
        ClearSample(ctx);
    }
    return TraceRet("DiscardEnrollment", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

// ---------------------------------------------------------------------------
// Vendor control channel - not used.
// ---------------------------------------------------------------------------
HRESULT ControlUnitCommon(
    _In_z_ const char* fn,
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG ControlCode,
    _Out_ PSIZE_T ReceiveDataSize,
    _Out_ PULONG OperationStatus)
{
    Trace(fn, Pipeline);
    EngLog("     controlCode=0x%08lx", static_cast<unsigned long>(ControlCode));
    UNREFERENCED_PARAMETER(ControlCode);
    if (ARGUMENT_PRESENT(ReceiveDataSize)) { *ReceiveDataSize = 0; }
    if (ARGUMENT_PRESENT(OperationStatus)) { *OperationStatus = 0; }
    return TraceRet(fn, E_NOTIMPL);
}

HRESULT WINAPI EngineControlUnit(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG ControlCode,
    _In_reads_bytes_(SendBufferSize) PUCHAR SendBuffer,
    _In_ SIZE_T SendBufferSize,
    _Out_writes_bytes_to_(ReceiveBufferSize, *ReceiveDataSize) PUCHAR ReceiveBuffer,
    _In_ SIZE_T ReceiveBufferSize,
    _Out_ PSIZE_T ReceiveDataSize,
    _Out_ PULONG OperationStatus)
{
    UNREFERENCED_PARAMETER(SendBuffer);
    UNREFERENCED_PARAMETER(SendBufferSize);
    UNREFERENCED_PARAMETER(ReceiveBuffer);
    UNREFERENCED_PARAMETER(ReceiveBufferSize);
    return ControlUnitCommon("ControlUnit", Pipeline, ControlCode, ReceiveDataSize, OperationStatus);
}

HRESULT WINAPI EngineControlUnitPrivileged(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG ControlCode,
    _In_reads_bytes_(SendBufferSize) PUCHAR SendBuffer,
    _In_ SIZE_T SendBufferSize,
    _Out_writes_bytes_to_(ReceiveBufferSize, *ReceiveDataSize) PUCHAR ReceiveBuffer,
    _In_ SIZE_T ReceiveBufferSize,
    _Out_ PSIZE_T ReceiveDataSize,
    _Out_ PULONG OperationStatus)
{
    UNREFERENCED_PARAMETER(SendBuffer);
    UNREFERENCED_PARAMETER(SendBufferSize);
    UNREFERENCED_PARAMETER(ReceiveBuffer);
    UNREFERENCED_PARAMETER(ReceiveBufferSize);
    return ControlUnitCommon("ControlUnitPrivileged", Pipeline, ControlCode, ReceiveDataSize, OperationStatus);
}

// ---------------------------------------------------------------------------
// V2.0 - power notification. Informational only; nothing here depends on
// power state yet, so just observe and succeed.
// ---------------------------------------------------------------------------
HRESULT WINAPI EngineNotifyPowerChange(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG PowerEventType)
{
    Trace("NotifyPowerChange", Pipeline);
    EngLog("     powerEventType=%lu", static_cast<unsigned long>(PowerEventType));
    UNREFERENCED_PARAMETER(PowerEventType);
    return TraceRet("NotifyPowerChange", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

// Reserved_1 is documented as "reserved, must be set to NULL" - it is not a
// callback slot to implement, so no EngineReserved1 function exists; the
// interface table below assigns the field nullptr directly.

// ---------------------------------------------------------------------------
// V3.0 - pipeline lifecycle. WBF aborts unit activation/configuration on
// any non-S_OK from these (per winbio_adapter.h), and there is no deferred
// work to do yet, so they succeed unconditionally once Pipeline is present.
// ---------------------------------------------------------------------------
HRESULT WINAPI EnginePipelineInit(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("PipelineInit", Pipeline);
    return TraceRet("PipelineInit", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

HRESULT WINAPI EnginePipelineCleanup(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("PipelineCleanup", Pipeline);
    return TraceRet("PipelineCleanup", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

HRESULT WINAPI EngineActivate(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("Activate", Pipeline);
    return TraceRet("Activate", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

HRESULT WINAPI EngineDeactivate(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("Deactivate", Pipeline);
    return TraceRet("Deactivate", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

// QueryExtendedInfo is called once during unit configuration (and again on
// WinBioGetProperty(WINBIO_PROPERTY_EXTENDED_ENGINE_INFO)); winbio_adapter.h
// lists only E_POINTER/E_INVALIDARG as valid failures, so - unlike the
// matching path - this one must succeed for the unit to come up.
HRESULT WINAPI EngineQueryExtendedInfo(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_writes_bytes_(EngineInfoSize) PWINBIO_EXTENDED_ENGINE_INFO EngineInfo,
    _In_ SIZE_T EngineInfoSize)
{
    Trace("QueryExtendedInfo", Pipeline);
    EngLog("     engineInfoSize=%llu (need %llu)", static_cast<unsigned long long>(EngineInfoSize), static_cast<unsigned long long>(sizeof(WINBIO_EXTENDED_ENGINE_INFO)));
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(EngineInfo)) {
        return TraceRet("QueryExtendedInfo", E_POINTER);
    }
    if (EngineInfoSize < sizeof(WINBIO_EXTENDED_ENGINE_INFO)) {
        return TraceRet("QueryExtendedInfo", E_INVALIDARG);
    }
    RtlZeroMemory(EngineInfo, sizeof(*EngineInfo));
    EngineInfo->GenericEngineCapabilities = 0; // no iterative-improvement / spoof-detection claims yet
    EngineInfo->Factor = WINBIO_TYPE_FINGERPRINT; // matches Queue.cpp's SensorType
    // Enrollment needs exactly one sample (the driver's EnrollConfirm); the
    // positional requirements (center/edges) do not apply - the SEP has no
    // image to cover.
    EngineInfo->Specific.Fingerprint.EnrollmentRequirements.GeneralSamples = 1;
    return TraceRet("QueryExtendedInfo", S_OK);
}

// IdentifyAll is the multi-person "who is in camera frame" callback for
// presence-style factors (design doc's sensor is WINBIO_TYPE_FINGERPRINT,
// single-subject); WBF should never call this for us, so fail closed like
// the rest of the unimplemented matching path rather than fabricate presences.
HRESULT WINAPI EngineIdentifyAll(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T PresenceCount,
    _Out_ PWINBIO_PRESENCE* PresenceArray)
{
    Trace("IdentifyAll", Pipeline);
    if (ARGUMENT_PRESENT(PresenceCount)) { *PresenceCount = 0; }
    if (ARGUMENT_PRESENT(PresenceArray)) { *PresenceArray = nullptr; }
    return TraceRet("IdentifyAll", E_NOTIMPL);
}

HRESULT WINAPI EngineSetEnrollmentSelector(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONGLONG SelectorValue)
{
    Trace("SetEnrollmentSelector", Pipeline);
    EngLog("     selector=0x%llx", static_cast<unsigned long long>(SelectorValue));
    UNREFERENCED_PARAMETER(SelectorValue); // single-subject sensor, nothing to select
    return TraceRet("SetEnrollmentSelector", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

// Unreachable in practice: WBF only calls this right after a successful
// EngineAdapterCreateEnrollment, and CreateEnrollment above always returns
// E_NOTIMPL until stage 3. Kept fail-closed for the same reason as the rest
// of the enrollment path.
HRESULT WINAPI EngineSetEnrollmentParameters(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_EXTENDED_ENROLLMENT_PARAMETERS Parameters)
{
    Trace("SetEnrollmentParameters", Pipeline);
    EngLog("     parameters=%p", static_cast<const void*>(Parameters));
    UNREFERENCED_PARAMETER(Parameters);   // tunes sample requirements for other factors; nothing to tune here
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx == nullptr) {
        return TraceRet("SetEnrollmentParameters", E_POINTER);
    }
    return TraceRet("SetEnrollmentParameters", ctx->EnrollActive ? S_OK : WINBIO_E_INVALID_OPERATION);
}

// No enrollment is ever in progress (CreateEnrollment always fails), so per
// winbio_adapter.h this reports "not currently enrolling" and still
// succeeds - returning an error here is not one of the documented outcomes.
HRESULT WINAPI EngineQueryExtendedEnrollmentStatus(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_writes_bytes_(EnrollmentStatusSize) PWINBIO_EXTENDED_ENROLLMENT_STATUS EnrollmentStatus,
    _In_ SIZE_T EnrollmentStatusSize)
{
    Trace("QueryExtendedEnrollmentStatus", Pipeline);
    EngLog("     statusSize=%llu (need %llu)", static_cast<unsigned long long>(EnrollmentStatusSize), static_cast<unsigned long long>(sizeof(WINBIO_EXTENDED_ENROLLMENT_STATUS)));
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(EnrollmentStatus)) {
        return TraceRet("QueryExtendedEnrollmentStatus", E_POINTER);
    }
    if (EnrollmentStatusSize < sizeof(WINBIO_EXTENDED_ENROLLMENT_STATUS)) {
        return TraceRet("QueryExtendedEnrollmentStatus", E_INVALIDARG);
    }
    RtlZeroMemory(EnrollmentStatus, sizeof(*EnrollmentStatus));
    EnrollmentStatus->Factor = WINBIO_TYPE_FINGERPRINT;
    PWINIBIO_ENGINE_CONTEXT ctx = GetContext(Pipeline);
    if (ctx != nullptr && ctx->EnrollActive) {
        EnrollmentStatus->TemplateStatus = ctx->EnrollReady ? S_OK : WINBIO_I_MORE_DATA;
        EnrollmentStatus->PercentComplete = ctx->EnrollReady ? 100 : 0;
        EnrollmentStatus->Specific.Fingerprint.GeneralSamples = ctx->EnrollReady ? 0 : 1;   // samples still needed
    } else {
        EnrollmentStatus->TemplateStatus = WINBIO_E_INVALID_OPERATION;   // not enrolling
    }
    EngLog("     templateStatus=0x%08lx percent=%lu", static_cast<unsigned long>(EnrollmentStatus->TemplateStatus),
           static_cast<unsigned long>(EnrollmentStatus->PercentComplete));
    return TraceRet("QueryExtendedEnrollmentStatus", S_OK);
}

// No private in-memory template cache exists, so there is nothing to
// invalidate; this is not a matching decision, just cache-lifecycle
// bookkeeping, so it succeeds unconditionally.
HRESULT WINAPI EngineRefreshCache(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("RefreshCache", Pipeline);
    return TraceRet("RefreshCache", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

// E_NOTIMPL is the documented "no dynamic calibration needed" answer (WBF
// converts it to S_OK internally) - not a fail-closed workaround.
HRESULT WINAPI EngineSelectCalibrationFormat(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_reads_(FormatCount) PWINBIO_UUID FormatArray,
    _In_ SIZE_T FormatCount,
    _Out_ PWINBIO_UUID SelectedFormat,
    _Out_ PSIZE_T MaxBufferSize)
{
    Trace("SelectCalibrationFormat", Pipeline);
    EngLog("     formatCount=%llu", static_cast<unsigned long long>(FormatCount));
    UNREFERENCED_PARAMETER(FormatArray);
    UNREFERENCED_PARAMETER(FormatCount);
    if (ARGUMENT_PRESENT(SelectedFormat)) { RtlZeroMemory(SelectedFormat, sizeof(*SelectedFormat)); }
    if (ARGUMENT_PRESENT(MaxBufferSize))  { *MaxBufferSize = 0; }
    return TraceRet("SelectCalibrationFormat", E_NOTIMPL);
}

// Unreachable given SelectCalibrationFormat's E_NOTIMPL above - WBF only
// runs the dynamic-calibration loop (and calls this) if calibration was
// selected. Kept as a fail-closed stub for the same integrity reason as the
// other V3 members: a null entry here would crash wbiosrvc if ever called.
HRESULT WINAPI EngineQueryCalibrationData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PBOOLEAN DiscardAndRepeatCapture,
    _Out_writes_bytes_to_(MaxBufferSize, *CalibrationBufferSize) PUCHAR CalibrationBuffer,
    _Out_ PSIZE_T CalibrationBufferSize,
    _In_ SIZE_T MaxBufferSize)
{
    Trace("QueryCalibrationData", Pipeline);
    UNREFERENCED_PARAMETER(CalibrationBuffer);
    UNREFERENCED_PARAMETER(MaxBufferSize);
    if (ARGUMENT_PRESENT(DiscardAndRepeatCapture)) { *DiscardAndRepeatCapture = FALSE; }
    if (ARGUMENT_PRESENT(CalibrationBufferSize))   { *CalibrationBufferSize = 0; }
    return TraceRet("QueryCalibrationData", E_NOTIMPL);
}

// Anti-spoof policy intake, not a matching decision (winbio_adapter.h: "errors
// returned by the method are logged but ignored"). Called on every unit
// activation, so it has to be a real S_OK, not a stub that errors.
HRESULT WINAPI EngineSetAccountPolicy(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_reads_(PolicyItemCount) PWINBIO_ACCOUNT_POLICY PolicyItemArray,
    _In_ SIZE_T PolicyItemCount)
{
    Trace("SetAccountPolicy", Pipeline);
    EngLog("     policyItemCount=%llu", static_cast<unsigned long long>(PolicyItemCount));
    UNREFERENCED_PARAMETER(PolicyItemArray);
    UNREFERENCED_PARAMETER(PolicyItemCount);
    return TraceRet("SetAccountPolicy", ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER);
}

// ---------------------------------------------------------------------------
// Interface table: VERSION_3, populated through SetAccountPolicy - every
// member winbio_adapter.h adds up to and including V3.0 (Windows 10). Size
// is sizeof(WINBIO_ENGINE_INTERFACE) per the MSDN Size field docs ("set this
// value to the size of the WINBIO_ENGINE_INTERFACE structure"), not just the
// V3 tail: WBF gates on Version to decide which members it may call, so the
// V4+ tail (CreateKey, IdentifyFeatureSetSecure, ...) can stay zero-filled -
// aggregate init below leaves every member after SetAccountPolicy at
// nullptr automatically. Advertising VERSION_1 with Size covering only
// through ControlUnitPrivileged is exactly what WBF rejected as
// WINBIO_E_ADAPTER_INTEGRITY_FAILURE on this Windows build.
// ---------------------------------------------------------------------------
WINBIO_ENGINE_INTERFACE g_EngineInterface = {
    WINBIO_ENGINE_INTERFACE_VERSION_3,
    WINBIO_ADAPTER_TYPE_ENGINE,
    sizeof(WINBIO_ENGINE_INTERFACE),
    kAdapterId,

    EngineAttach,
    EngineDetach,
    EngineClearContext,
    EngineQueryPreferredFormat,
    EngineQueryIndexVectorSize,
    EngineQueryHashAlgorithms,
    EngineSetHashAlgorithm,
    EngineQuerySampleHint,
    EngineAcceptSampleData,
    EngineExportEngineData,
    EngineVerifyFeatureSet,
    EngineIdentifyFeatureSet,
    EngineCreateEnrollment,
    EngineUpdateEnrollment,
    EngineGetEnrollmentStatus,
    EngineGetEnrollmentHash,
    EngineCheckForDuplicate,
    EngineCommitEnrollment,
    EngineDiscardEnrollment,
    EngineControlUnit,
    EngineControlUnitPrivileged,

    // V2.0 (Windows 8+)
    EngineNotifyPowerChange,
    nullptr, // Reserved_1 - documented as "reserved, must be set to NULL"

    // V3.0 (Windows 10+)
    EnginePipelineInit,
    EnginePipelineCleanup,
    EngineActivate,
    EngineDeactivate,
    EngineQueryExtendedInfo,
    EngineIdentifyAll,
    EngineSetEnrollmentSelector,
    EngineSetEnrollmentParameters,
    EngineQueryExtendedEnrollmentStatus,
    EngineRefreshCache,
    EngineSelectCalibrationFormat,
    EngineQueryCalibrationData,
    EngineSetAccountPolicy
};

} // namespace

BOOL APIENTRY DllMain(HMODULE ModuleHandle, DWORD ReasonForCall, LPVOID Reserved)
{
    UNREFERENCED_PARAMETER(Reserved);
    if (ReasonForCall == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(ModuleHandle);
        EngLog("DLL loaded (module=%p)", static_cast<void*>(ModuleHandle));
    }
    return TRUE;
}

// Must be exported under exactly this name (see the .def): WBF resolves it via
// GetProcAddress(WINBIO_QUERY_ENGINE_INTERFACE_FN_NAME).
extern "C" HRESULT WINAPI WbioQueryEngineInterface(_Out_ PWINBIO_ENGINE_INTERFACE* EngineInterface)
{
    EngLog("WbioQueryEngineInterface (advertising VERSION_3, size=%llu)",
           static_cast<unsigned long long>(sizeof(WINBIO_ENGINE_INTERFACE)));
    if (EngineInterface == nullptr) {
        return E_POINTER;
    }
    *EngineInterface = &g_EngineInterface;
    return S_OK;
}
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
// Fail-closed rule (design doc 5): no callback may ever report a match. Every
// matching / enrollment entry point returns E_NOTIMPL with its outputs zeroed
// until the VerificationEngine wiring exists. A wrong "success" here would be
// a login bypass, a wrong "not implemented" is only a missing feature.
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
#include <strsafe.h>

// winbio_adapter.h's inline Wbio*() helpers use ARGUMENT_PRESENT, which
// user-mode windows.h does not define: it has to exist BEFORE the include
// (the Microsoft sample defines it in its precomp.h for the same reason).
#ifndef ARGUMENT_PRESENT
#define ARGUMENT_PRESENT(x) ((x) != NULL)
#endif

#include <winbio_adapter.h>

// ---------------------------------------------------------------------------
// Private per-pipeline context. winbio_adapter.h only forward-declares
// struct _WINIBIO_ENGINE_CONTEXT (sic); the adapter owns the definition.
// ---------------------------------------------------------------------------
struct _WINIBIO_ENGINE_CONTEXT {
    ULONG Signature;      // 'T2EC', catches a foreign / stale EngineContext
    ULONG CallCount;      // number of callbacks seen on this pipeline (trace only)
};
static const ULONG kContextSignature = 0x43453254; // "T2EC" little-endian

namespace {

// {756DB001-3595-4EE9-A2DC-BF42F041CEB5} - AdapterId of this engine.
const GUID kAdapterId =
    { 0x756db001, 0x3595, 0x4ee9, { 0xa2, 0xdc, 0xbf, 0x42, 0xf0, 0x41, 0xce, 0xb5 } };

void Trace(_In_z_ const char* fn, _In_opt_ PWINBIO_PIPELINE pipeline)
{
    char buf[160];
    if (SUCCEEDED(StringCchPrintfA(buf, ARRAYSIZE(buf),
                                   "T2TouchIdEngine: %s pipeline=%p\n", fn, (void*)pipeline))) {
        OutputDebugStringA(buf);
    }
    if (pipeline != nullptr && pipeline->EngineContext != nullptr &&
        pipeline->EngineContext->Signature == kContextSignature) {
        pipeline->EngineContext->CallCount++;
    }
}

// Zero the Identity out-parameter the way an empty result looks.
void ZeroIdentity(_Out_ PWINBIO_IDENTITY identity)
{
    if (ARGUMENT_PRESENT(identity)) {
        RtlZeroMemory(identity, sizeof(*identity));
    }
}

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------
HRESULT WINAPI EngineAttach(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("Attach", Pipeline);
    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }
    if (Pipeline->EngineContext != nullptr) {
        // Attach on a pipeline that already has an engine context is a
        // framework bug or a double attach; do not leak / overwrite.
        return E_UNEXPECTED;
    }
    PWINIBIO_ENGINE_CONTEXT ctx = static_cast<PWINIBIO_ENGINE_CONTEXT>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ctx)));
    if (ctx == nullptr) {
        return E_OUTOFMEMORY;
    }
    ctx->Signature = kContextSignature;
    Pipeline->EngineContext = ctx;
    return S_OK;
}

HRESULT WINAPI EngineDetach(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("Detach", Pipeline);
    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }
    PWINIBIO_ENGINE_CONTEXT ctx = Pipeline->EngineContext;
    if (ctx == nullptr) {
        return E_UNEXPECTED;
    }
    Pipeline->EngineContext = nullptr;
    if (ctx->Signature == kContextSignature) {
        ctx->Signature = 0;
        HeapFree(GetProcessHeap(), 0, ctx);
    }
    return S_OK;
}

HRESULT WINAPI EngineClearContext(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("ClearContext", Pipeline);
    // No sample / feature set / enrollment is held yet, nothing to clear.
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
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
        return E_POINTER;
    }
    // Must equal SupportedFormat[0] reported by the sensor (umdf/Queue.cpp,
    // GET_ATTRIBUTES) or WBF has no common format. Placeholder until the
    // vendor BIR format from design doc 5 exists - change both together.
    StandardFormat->Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    StandardFormat->Type  = WINBIO_ANSI_381_FORMAT_TYPE;
    RtlZeroMemory(VendorFormat, sizeof(*VendorFormat));
    return S_OK;
}

HRESULT WINAPI EngineQueryIndexVectorSize(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T IndexElementCount)
{
    Trace("QueryIndexVectorSize", Pipeline);
    if (!ARGUMENT_PRESENT(IndexElementCount)) {
        return E_POINTER;
    }
    // ASSUMPTION: 0 = engine does not build a search index for the storage
    // adapter (matching is 1:1 in the SEP, design doc 4).
    *IndexElementCount = 0;
    return S_OK;
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
        return E_POINTER;
    }
    // No template hashing: matching is done by the SEP, no template leaves it.
    *AlgorithmCount      = 0;
    *AlgorithmBufferSize = 0;
    *AlgorithmBuffer     = nullptr;
    return S_OK;
}

HRESULT WINAPI EngineSetHashAlgorithm(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ SIZE_T AlgorithmBufferSize,
    _In_reads_z_(AlgorithmBufferSize) PUCHAR AlgorithmBuffer)
{
    Trace("SetHashAlgorithm", Pipeline);
    UNREFERENCED_PARAMETER(AlgorithmBufferSize);
    UNREFERENCED_PARAMETER(AlgorithmBuffer);
    return E_NOTIMPL; // never offered any algorithm to choose from
}

HRESULT WINAPI EngineQuerySampleHint(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T SampleHint)
{
    Trace("QuerySampleHint", Pipeline);
    if (!ARGUMENT_PRESENT(SampleHint)) {
        return E_POINTER;
    }
    *SampleHint = 1; // one capture is enough for a verify (SEP matches internally)
    return S_OK;
}

// ---------------------------------------------------------------------------
// Sample / match path - fail closed until stage 2 (VerificationEngine).
// ---------------------------------------------------------------------------
HRESULT WINAPI EngineAcceptSampleData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_reads_bytes_(SampleSize) PWINBIO_BIR SampleBuffer,
    _In_ SIZE_T SampleSize,
    _In_ WINBIO_BIR_PURPOSE Purpose,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    Trace("AcceptSampleData", Pipeline);
    UNREFERENCED_PARAMETER(SampleBuffer);
    UNREFERENCED_PARAMETER(SampleSize);
    UNREFERENCED_PARAMETER(Purpose);
    if (ARGUMENT_PRESENT(RejectDetail)) {
        *RejectDetail = 0;
    }
    return E_NOTIMPL;
}

HRESULT WINAPI EngineExportEngineData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ WINBIO_BIR_DATA_FLAGS Flags,
    _Outptr_result_bytebuffer_all_(*SampleSize) PWINBIO_BIR* SampleBuffer,
    _Out_ PSIZE_T SampleSize)
{
    Trace("ExportEngineData", Pipeline);
    UNREFERENCED_PARAMETER(Flags);
    if (ARGUMENT_PRESENT(SampleBuffer)) { *SampleBuffer = nullptr; }
    if (ARGUMENT_PRESENT(SampleSize))   { *SampleSize = 0; }
    return E_NOTIMPL;
}

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
    UNREFERENCED_PARAMETER(Identity);
    UNREFERENCED_PARAMETER(SubFactor);
    if (ARGUMENT_PRESENT(Match))           { *Match = FALSE; }   // never a match
    if (ARGUMENT_PRESENT(PayloadBlob))     { *PayloadBlob = nullptr; }
    if (ARGUMENT_PRESENT(PayloadBlobSize)) { *PayloadBlobSize = 0; }
    if (ARGUMENT_PRESENT(HashValue))       { *HashValue = nullptr; }
    if (ARGUMENT_PRESENT(HashSize))        { *HashSize = 0; }
    if (ARGUMENT_PRESENT(RejectDetail))    { *RejectDetail = 0; }
    return E_NOTIMPL;
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
    if (ARGUMENT_PRESENT(SubFactor))       { *SubFactor = 0; }
    if (ARGUMENT_PRESENT(PayloadBlob))     { *PayloadBlob = nullptr; }
    if (ARGUMENT_PRESENT(PayloadBlobSize)) { *PayloadBlobSize = 0; }
    if (ARGUMENT_PRESENT(HashValue))       { *HashValue = nullptr; }
    if (ARGUMENT_PRESENT(HashSize))        { *HashSize = 0; }
    if (ARGUMENT_PRESENT(RejectDetail))    { *RejectDetail = 0; }
    return E_NOTIMPL;
}

// ---------------------------------------------------------------------------
// Enrollment - stage 3 (design doc 4: "enroll" = confirm the SEP identity list
// for macosUserId and store {macosUserId, matchedUuid}, no raw data).
// ---------------------------------------------------------------------------
HRESULT WINAPI EngineCreateEnrollment(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("CreateEnrollment", Pipeline);
    return E_NOTIMPL;
}

HRESULT WINAPI EngineUpdateEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    Trace("UpdateEnrollment", Pipeline);
    if (ARGUMENT_PRESENT(RejectDetail)) { *RejectDetail = 0; }
    return E_NOTIMPL;
}

HRESULT WINAPI EngineGetEnrollmentStatus(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    Trace("GetEnrollmentStatus", Pipeline);
    if (ARGUMENT_PRESENT(RejectDetail)) { *RejectDetail = 0; }
    return E_NOTIMPL;
}

HRESULT WINAPI EngineGetEnrollmentHash(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR* HashValue,
    _Out_ PSIZE_T HashSize)
{
    Trace("GetEnrollmentHash", Pipeline);
    if (ARGUMENT_PRESENT(HashValue)) { *HashValue = nullptr; }
    if (ARGUMENT_PRESENT(HashSize))  { *HashSize = 0; }
    return E_NOTIMPL;
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
    return E_NOTIMPL;
}

HRESULT WINAPI EngineCommitEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_IDENTITY Identity,
    _In_ WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _In_reads_bytes_(PayloadBlobSize) PUCHAR PayloadBlob,
    _In_ SIZE_T PayloadBlobSize)
{
    Trace("CommitEnrollment", Pipeline);
    UNREFERENCED_PARAMETER(Identity);
    UNREFERENCED_PARAMETER(SubFactor);
    UNREFERENCED_PARAMETER(PayloadBlob);
    UNREFERENCED_PARAMETER(PayloadBlobSize);
    return E_NOTIMPL;
}

HRESULT WINAPI EngineDiscardEnrollment(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("DiscardEnrollment", Pipeline);
    return S_OK; // nothing is ever created, so discarding is trivially done
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
    UNREFERENCED_PARAMETER(ControlCode);
    if (ARGUMENT_PRESENT(ReceiveDataSize)) { *ReceiveDataSize = 0; }
    if (ARGUMENT_PRESENT(OperationStatus)) { *OperationStatus = 0; }
    return E_NOTIMPL;
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
    UNREFERENCED_PARAMETER(PowerEventType);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
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
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI EnginePipelineCleanup(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("PipelineCleanup", Pipeline);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI EngineActivate(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("Activate", Pipeline);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI EngineDeactivate(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("Deactivate", Pipeline);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
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
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(EngineInfo)) {
        return E_POINTER;
    }
    if (EngineInfoSize < sizeof(WINBIO_EXTENDED_ENGINE_INFO)) {
        return E_INVALIDARG;
    }
    RtlZeroMemory(EngineInfo, sizeof(*EngineInfo));
    EngineInfo->GenericEngineCapabilities = 0; // no iterative-improvement / spoof-detection claims yet
    EngineInfo->Factor = WINBIO_TYPE_FINGERPRINT; // matches Queue.cpp's SensorType
    // Specific.Fingerprint.Capabilities and EnrollmentRequirements stay zeroed
    // (least-assumption placeholder) until enrollment (stage 3) defines real
    // sample-coverage requirements.
    return S_OK;
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
    return E_NOTIMPL;
}

HRESULT WINAPI EngineSetEnrollmentSelector(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONGLONG SelectorValue)
{
    Trace("SetEnrollmentSelector", Pipeline);
    UNREFERENCED_PARAMETER(SelectorValue); // single-subject sensor, nothing to select
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
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
    UNREFERENCED_PARAMETER(Parameters);
    return E_NOTIMPL;
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
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(EnrollmentStatus)) {
        return E_POINTER;
    }
    if (EnrollmentStatusSize < sizeof(WINBIO_EXTENDED_ENROLLMENT_STATUS)) {
        return E_INVALIDARG;
    }
    RtlZeroMemory(EnrollmentStatus, sizeof(*EnrollmentStatus));
    EnrollmentStatus->TemplateStatus = WINBIO_E_INVALID_OPERATION;
    EnrollmentStatus->Factor = WINBIO_TYPE_FINGERPRINT;
    return S_OK;
}

// No private in-memory template cache exists, so there is nothing to
// invalidate; this is not a matching decision, just cache-lifecycle
// bookkeeping, so it succeeds unconditionally.
HRESULT WINAPI EngineRefreshCache(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    Trace("RefreshCache", Pipeline);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
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
    UNREFERENCED_PARAMETER(FormatArray);
    UNREFERENCED_PARAMETER(FormatCount);
    if (ARGUMENT_PRESENT(SelectedFormat)) { RtlZeroMemory(SelectedFormat, sizeof(*SelectedFormat)); }
    if (ARGUMENT_PRESENT(MaxBufferSize))  { *MaxBufferSize = 0; }
    return E_NOTIMPL;
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
    return E_NOTIMPL;
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
    UNREFERENCED_PARAMETER(PolicyItemArray);
    UNREFERENCED_PARAMETER(PolicyItemCount);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
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
        OutputDebugStringA("T2TouchIdEngine: DLL loaded\n");
    }
    return TRUE;
}

// Must be exported under exactly this name (see the .def): WBF resolves it via
// GetProcAddress(WINBIO_QUERY_ENGINE_INTERFACE_FN_NAME).
extern "C" HRESULT WINAPI WbioQueryEngineInterface(_Out_ PWINBIO_ENGINE_INTERFACE* EngineInterface)
{
    OutputDebugStringA("T2TouchIdEngine: WbioQueryEngineInterface\n");
    if (EngineInterface == nullptr) {
        return E_POINTER;
    }
    *EngineInterface = &g_EngineInterface;
    return S_OK;
}
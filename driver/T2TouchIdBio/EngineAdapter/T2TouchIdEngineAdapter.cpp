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
// Interface table: V1.0 members only, in the order winbio_adapter.h declares
// them. The struct is larger in this SDK (V2..V6 tail, zero-filled) but the
// interface version we advertise is 1, so Size covers exactly the V1 part
// (what a Windows 7 SDK build of this adapter would have reported). If WBF
// rejects V1 on this Windows build, the Operational log says so and the next
// step is V3 (PipelineInit/Activate/QueryExtendedInfo, ...).
// ---------------------------------------------------------------------------
WINBIO_ENGINE_INTERFACE g_EngineInterface = {
    WINBIO_ENGINE_INTERFACE_VERSION_1,
    WINBIO_ADAPTER_TYPE_ENGINE,
    offsetof(WINBIO_ENGINE_INTERFACE, ControlUnitPrivileged) + sizeof(PIBIO_ENGINE_CONTROL_UNIT_PRIVILEGED_FN),
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
    EngineControlUnitPrivileged
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
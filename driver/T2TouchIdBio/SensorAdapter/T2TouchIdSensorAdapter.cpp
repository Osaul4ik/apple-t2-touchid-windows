// SPDX-License-Identifier: GPL-2.0-only
// T2TouchIdSensorAdapter - WBF Sensor Adapter for Apple T2 Touch ID.
//
// Replaces in-box WinBioSensorAdapter.dll so we own StartCapture / Cancel /
// NotifyPowerChange. After Sx, WBF re-issues StartCapture through this
// adapter (SuspendAndWaitForPlatformResume path) instead of depending on a
// CAPTURE that straddled sleep (security hole) or a dead LogonUI session.
//
// Talks WBDI to T2TouchIdBio UMDF via Pipeline->SensorHandle:
//   IOCTL_BIOMETRIC_CAPTURE_DATA (overlapped)
//   IOCTL_BIOMETRIC_GET_SENSOR_STATUS
//   IOCTL_BIOMETRIC_RESET
//   CancelIoEx on cancel / suspend

#include <windows.h>
#include <stddef.h>
#include <stdarg.h>
#include <strsafe.h>

#ifndef ARGUMENT_PRESENT
#define ARGUMENT_PRESENT(x) ((x) != NULL)
#endif

#include <winbio_adapter.h>
#include <winbio_err.h>
#include <winbio_ioctl.h>
#include <winbio_types.h>

#include <cstring>

namespace {

constexpr ULONG kSensorCtxSig = 'T2SC';
// GUID for this adapter (unique; not the sample GUID).
const GUID kAdapterId = {
    0xb039a556, 0x3eec, 0x475a, {0xab, 0xbd, 0x3a, 0xa5, 0xc5, 0xf5, 0x50, 0xdb}};

void SensLog(const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    StringCchVPrintfA(buf, ARRAYSIZE(buf), fmt, ap);
    va_end(ap);
    char line[560];
    StringCchPrintfA(line, ARRAYSIZE(line), "T2TouchIdSensor: %s\n", buf);
    OutputDebugStringA(line);
}

struct _WINIBIO_SENSOR_CONTEXT {
    ULONG Signature;
    OVERLAPPED Overlapped;
    HANDLE OverlappedEvent;
    PUCHAR CaptureBuffer;
    SIZE_T CaptureBufferSize;
    DWORD BytesTransferred;
    BOOL CaptureInProgress;
    WINBIO_BIR_PURPOSE LastPurpose;
};

using SensorCtx = _WINIBIO_SENSOR_CONTEXT;

SensorCtx* GetContext(PWINBIO_PIPELINE Pipeline)
{
    if (!ARGUMENT_PRESENT(Pipeline) || Pipeline->SensorContext == nullptr) {
        return nullptr;
    }
    auto* ctx = reinterpret_cast<SensorCtx*>(Pipeline->SensorContext);
    if (ctx->Signature != kSensorCtxSig) {
        return nullptr;
    }
    return ctx;
}

void FreeCaptureBuffer(SensorCtx* ctx)
{
    if (ctx->CaptureBuffer) {
        HeapFree(GetProcessHeap(), 0, ctx->CaptureBuffer);
        ctx->CaptureBuffer = nullptr;
        ctx->CaptureBufferSize = 0;
    }
    ctx->BytesTransferred = 0;
}

HRESULT WINAPI SensorAttach(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    SensLog("Attach pipeline=%p", Pipeline);
    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }
    if (Pipeline->SensorContext != nullptr) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }
    auto* ctx = static_cast<SensorCtx*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SensorCtx)));
    if (!ctx) {
        return E_OUTOFMEMORY;
    }
    ctx->Signature = kSensorCtxSig;
    ctx->OverlappedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ctx->OverlappedEvent) {
        HeapFree(GetProcessHeap(), 0, ctx);
        return E_OUTOFMEMORY;
    }
    ctx->Overlapped.hEvent = ctx->OverlappedEvent;
    Pipeline->SensorContext = ctx;
    return S_OK;
}

HRESULT WINAPI SensorDetach(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    SensLog("Detach pipeline=%p", Pipeline);
    SensorCtx* ctx = GetContext(Pipeline);
    if (!ctx) {
        return E_POINTER;
    }
    if (ctx->CaptureInProgress && ARGUMENT_PRESENT(Pipeline) &&
        Pipeline->SensorHandle != INVALID_HANDLE_VALUE &&
        Pipeline->SensorHandle != nullptr) {
        CancelIoEx(Pipeline->SensorHandle, &ctx->Overlapped);
        DWORD ignored = 0;
        GetOverlappedResult(Pipeline->SensorHandle, &ctx->Overlapped, &ignored, TRUE);
        ctx->CaptureInProgress = FALSE;
    }
    FreeCaptureBuffer(ctx);
    if (ctx->OverlappedEvent) {
        CloseHandle(ctx->OverlappedEvent);
    }
    HeapFree(GetProcessHeap(), 0, ctx);
    Pipeline->SensorContext = nullptr;
    return S_OK;
}

HRESULT WINAPI SensorClearContext(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    SensorCtx* ctx = GetContext(Pipeline);
    if (!ctx) {
        return E_POINTER;
    }
    FreeCaptureBuffer(ctx);
    return S_OK;
}

HRESULT WINAPI SensorQueryStatus(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_SENSOR_STATUS Status)
{
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(Status)) {
        return E_POINTER;
    }
    *Status = WINBIO_SENSOR_READY;
    if (Pipeline->SensorHandle == nullptr ||
        Pipeline->SensorHandle == INVALID_HANDLE_VALUE) {
        return S_OK;
    }
    WINBIO_DIAGNOSTICS diag = {};
    DWORD bytes = 0;
    if (DeviceIoControl(Pipeline->SensorHandle, IOCTL_BIOMETRIC_GET_SENSOR_STATUS,
                        nullptr, 0, &diag, sizeof(diag), &bytes, nullptr)) {
        if (bytes >= sizeof(diag)) {
            *Status = diag.SensorStatus;
        }
    }
    return S_OK;
}

HRESULT WINAPI SensorReset(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    SensLog("Reset pipeline=%p", Pipeline);
    SensorCtx* ctx = GetContext(Pipeline);
    if (!ctx) {
        return E_POINTER;
    }
    if (ctx->CaptureInProgress && Pipeline->SensorHandle) {
        CancelIoEx(Pipeline->SensorHandle, &ctx->Overlapped);
        DWORD ignored = 0;
        GetOverlappedResult(Pipeline->SensorHandle, &ctx->Overlapped, &ignored, TRUE);
        ctx->CaptureInProgress = FALSE;
    }
    FreeCaptureBuffer(ctx);
    if (Pipeline->SensorHandle &&
        Pipeline->SensorHandle != INVALID_HANDLE_VALUE) {
        WINBIO_BLANK_PAYLOAD blank = {};
        DWORD bytes = 0;
        DeviceIoControl(Pipeline->SensorHandle, IOCTL_BIOMETRIC_RESET, nullptr, 0,
                        &blank, sizeof(blank), &bytes, nullptr);
    }
    return S_OK;
}

HRESULT WINAPI SensorSetMode(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ WINBIO_SENSOR_MODE Mode)
{
    UNREFERENCED_PARAMETER(Mode);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI SensorSetIndicatorStatus(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ WINBIO_INDICATOR_STATUS IndicatorStatus)
{
    UNREFERENCED_PARAMETER(IndicatorStatus);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI SensorGetIndicatorStatus(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_INDICATOR_STATUS IndicatorStatus)
{
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(IndicatorStatus)) {
        return E_POINTER;
    }
    *IndicatorStatus = WINBIO_INDICATOR_ON;
    return S_OK;
}

HRESULT WINAPI SensorStartCapture(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ WINBIO_BIR_PURPOSE Purpose,
    _Out_ LPOVERLAPPED* Overlapped)
{
    SensLog("StartCapture pipeline=%p purpose=0x%x", Pipeline,
            static_cast<unsigned>(Purpose));
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(Overlapped)) {
        return E_POINTER;
    }
    *Overlapped = nullptr;
    SensorCtx* ctx = GetContext(Pipeline);
    if (!ctx) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }
    if (ctx->CaptureInProgress) {
        return WINBIO_E_DATA_COLLECTION_IN_PROGRESS;
    }
    if (!Pipeline->SensorHandle ||
        Pipeline->SensorHandle == INVALID_HANDLE_VALUE) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    FreeCaptureBuffer(ctx);
    // Typical BIR payload from our UMDF is ~444 bytes; allocate headroom.
    constexpr SIZE_T kCaptureCap = 4096;
    ctx->CaptureBuffer = static_cast<PUCHAR>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kCaptureCap));
    if (!ctx->CaptureBuffer) {
        return E_OUTOFMEMORY;
    }
    ctx->CaptureBufferSize = kCaptureCap;
    ctx->LastPurpose = Purpose;

    WINBIO_CAPTURE_PARAMETERS params = {};
    params.PayloadSize = sizeof(params);
    params.Purpose = Purpose;
    // Match UMDF CAPTURE_DATA path (Queue.cpp / hardware logs).
    params.Format.Owner = 0x001b;
    params.Format.Type = 0x0401;
    params.Flags = WINBIO_DATA_FLAG_RAW;

    ZeroMemory(&ctx->Overlapped, sizeof(ctx->Overlapped));
    ResetEvent(ctx->OverlappedEvent);
    ctx->Overlapped.hEvent = ctx->OverlappedEvent;

    const BOOL ok = DeviceIoControl(
        Pipeline->SensorHandle, IOCTL_BIOMETRIC_CAPTURE_DATA, &params,
        sizeof(params), ctx->CaptureBuffer, static_cast<DWORD>(ctx->CaptureBufferSize),
        nullptr, &ctx->Overlapped);
    const DWORD err = GetLastError();
    if (!ok && err != ERROR_IO_PENDING) {
        SensLog("StartCapture DeviceIoControl failed err=%lu",
                static_cast<unsigned long>(err));
        FreeCaptureBuffer(ctx);
        return HRESULT_FROM_WIN32(err);
    }
    ctx->CaptureInProgress = TRUE;
    *Overlapped = &ctx->Overlapped;
    return S_OK;
}

HRESULT WINAPI SensorFinishCapture(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    SensLog("FinishCapture pipeline=%p", Pipeline);
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }
    *RejectDetail = 0;
    SensorCtx* ctx = GetContext(Pipeline);
    if (!ctx) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }
    if (!ctx->CaptureInProgress) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    DWORD transferred = 0;
    const BOOL ok = GetOverlappedResult(Pipeline->SensorHandle, &ctx->Overlapped,
                                        &transferred, TRUE);
    ctx->CaptureInProgress = FALSE;
    if (!ok) {
        const DWORD err = GetLastError();
        SensLog("FinishCapture GetOverlappedResult err=%lu",
                static_cast<unsigned long>(err));
        FreeCaptureBuffer(ctx);
        if (err == ERROR_OPERATION_ABORTED || err == ERROR_CANCELLED) {
            return WINBIO_E_CANCELED;
        }
        return HRESULT_FROM_WIN32(err);
    }
    ctx->BytesTransferred = transferred;
    if (transferred < sizeof(WINBIO_CAPTURE_DATA)) {
        FreeCaptureBuffer(ctx);
        return WINBIO_E_NO_CAPTURE_DATA;
    }
    auto* capture = reinterpret_cast<PWINBIO_CAPTURE_DATA>(ctx->CaptureBuffer);
    if (FAILED(capture->WinBioHresult)) {
        const HRESULT hr = capture->WinBioHresult;
        *RejectDetail = capture->RejectDetail;
        SensLog("FinishCapture WinBioHresult=0x%08lx",
                static_cast<unsigned long>(hr));
        // Keep buffer only for S_OK Export path.
        if (hr != WINBIO_E_CANCELED) {
            // non-success: drop
        }
        FreeCaptureBuffer(ctx);
        return hr;
    }
    *RejectDetail = capture->RejectDetail;
    return S_OK;
}

HRESULT WINAPI SensorExportSensorData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_BIR* SampleBuffer,
    _Out_ PSIZE_T SampleSize)
{
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(SampleBuffer) ||
        !ARGUMENT_PRESENT(SampleSize)) {
        return E_POINTER;
    }
    *SampleBuffer = nullptr;
    *SampleSize = 0;
    SensorCtx* ctx = GetContext(Pipeline);
    if (!ctx || !ctx->CaptureBuffer || ctx->BytesTransferred < sizeof(WINBIO_CAPTURE_DATA)) {
        return WINBIO_E_NO_CAPTURE_DATA;
    }
    auto* capture = reinterpret_cast<PWINBIO_CAPTURE_DATA>(ctx->CaptureBuffer);
    if (capture->CaptureData.Size == 0 ||
        capture->CaptureData.Size > ctx->BytesTransferred) {
        return WINBIO_E_NO_CAPTURE_DATA;
    }
    // CaptureData.Data is the BIR; hand ownership to WBF via process heap.
    const SIZE_T birSize = capture->CaptureData.Size;
    void* copy = HeapAlloc(GetProcessHeap(), 0, birSize);
    if (!copy) {
        return E_OUTOFMEMORY;
    }
    memcpy(copy, capture->CaptureData.Data, birSize);
    *SampleBuffer = static_cast<PWINBIO_BIR>(copy);
    *SampleSize = birSize;
    FreeCaptureBuffer(ctx);
    return S_OK;
}

HRESULT WINAPI SensorCancel(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    SensLog("Cancel pipeline=%p", Pipeline);
    SensorCtx* ctx = GetContext(Pipeline);
    if (!ctx) {
        return E_POINTER;
    }
    if (ctx->CaptureInProgress && Pipeline->SensorHandle) {
        CancelIoEx(Pipeline->SensorHandle, &ctx->Overlapped);
    }
    return S_OK;
}

HRESULT WINAPI SensorPushDataToEngine(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ WINBIO_BIR_PURPOSE Purpose,
    _In_ WINBIO_BIR_DATA_FLAGS Flags,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail)
{
    UNREFERENCED_PARAMETER(Flags);
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }
    *RejectDetail = 0;
    // Standard path: ExportSensorData then Engine AcceptSampleData is done by
    // framework when we return S_OK after placing BIR - for push, call engine.
    if (!Pipeline->EngineInterface || !Pipeline->EngineInterface->AcceptSampleData) {
        return E_NOTIMPL;
    }
    PWINBIO_BIR bir = nullptr;
    SIZE_T birSize = 0;
    HRESULT hr = SensorExportSensorData(Pipeline, &bir, &birSize);
    if (FAILED(hr)) {
        return hr;
    }
    hr = Pipeline->EngineInterface->AcceptSampleData(Pipeline, bir, birSize, Purpose,
                                                     RejectDetail);
    // AcceptSampleData takes ownership semantics per engine - engine adapter
    // copies what it needs; free our heap BIR.
    HeapFree(GetProcessHeap(), 0, bir);
    return hr;
}

HRESULT WINAPI SensorControlUnit(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG ControlCode,
    _In_reads_bytes_(SendBufferSize) PUCHAR SendBuffer,
    _In_ SIZE_T SendBufferSize,
    _Out_writes_bytes_to_(ReceiveBufferSize, *ReceiveDataSize) PUCHAR ReceiveBuffer,
    _In_ SIZE_T ReceiveBufferSize,
    _Out_ PSIZE_T ReceiveDataSize,
    _Out_ PULONG OperationStatus)
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(ControlCode);
    UNREFERENCED_PARAMETER(SendBuffer);
    UNREFERENCED_PARAMETER(SendBufferSize);
    UNREFERENCED_PARAMETER(ReceiveBuffer);
    UNREFERENCED_PARAMETER(ReceiveBufferSize);
    if (ARGUMENT_PRESENT(ReceiveDataSize)) {
        *ReceiveDataSize = 0;
    }
    if (ARGUMENT_PRESENT(OperationStatus)) {
        *OperationStatus = 0;
    }
    return E_NOTIMPL;
}

HRESULT WINAPI SensorControlUnitPrivileged(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG ControlCode,
    _In_reads_bytes_(SendBufferSize) PUCHAR SendBuffer,
    _In_ SIZE_T SendBufferSize,
    _Out_writes_bytes_to_(ReceiveBufferSize, *ReceiveDataSize) PUCHAR ReceiveBuffer,
    _In_ SIZE_T ReceiveBufferSize,
    _Out_ PSIZE_T ReceiveDataSize,
    _Out_ PULONG OperationStatus)
{
    return SensorControlUnit(Pipeline, ControlCode, SendBuffer, SendBufferSize,
                             ReceiveBuffer, ReceiveBufferSize, ReceiveDataSize,
                             OperationStatus);
}

// Critical for post-Sx re-arm: cancel in-flight capture on suspend; clear
// state on resume so WBF's next StartCapture is a clean arm.
HRESULT WINAPI SensorNotifyPowerChange(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG PowerEventType)
{
    SensLog("NotifyPowerChange pipeline=%p type=%lu", Pipeline,
            static_cast<unsigned long>(PowerEventType));
    SensorCtx* ctx = GetContext(Pipeline);
    if (!ctx) {
        return E_POINTER;
    }
    if (PowerEventType == PBT_APMSUSPEND) {
        if (ctx->CaptureInProgress && Pipeline->SensorHandle) {
            CancelIoEx(Pipeline->SensorHandle, &ctx->Overlapped);
            // Do not wait here - FinishCapture/Cancel path will complete.
        }
        FreeCaptureBuffer(ctx);
    } else if (PowerEventType == PBT_APMRESUMEAUTOMATIC ||
               PowerEventType == PBT_APMRESUMESUSPEND ||
               PowerEventType == PBT_APMRESUMECRITICAL) {
        FreeCaptureBuffer(ctx);
        ctx->CaptureInProgress = FALSE;
        if (Pipeline->SensorHandle &&
            Pipeline->SensorHandle != INVALID_HANDLE_VALUE) {
            WINBIO_BLANK_PAYLOAD blank = {};
            DWORD bytes = 0;
            DeviceIoControl(Pipeline->SensorHandle, IOCTL_BIOMETRIC_RESET, nullptr, 0,
                            &blank, sizeof(blank), &bytes, nullptr);
        }
    }
    return S_OK;
}

HRESULT WINAPI SensorPipelineInit(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI SensorPipelineCleanup(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI SensorActivate(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    SensLog("Activate pipeline=%p", Pipeline);
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI SensorDeactivate(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    SensLog("Deactivate pipeline=%p", Pipeline);
    SensorCtx* ctx = GetContext(Pipeline);
    if (ctx && ctx->CaptureInProgress && Pipeline->SensorHandle) {
        CancelIoEx(Pipeline->SensorHandle, &ctx->Overlapped);
    }
    return ARGUMENT_PRESENT(Pipeline) ? S_OK : E_POINTER;
}

HRESULT WINAPI SensorQueryExtendedInfo(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_writes_bytes_(SensorInfoSize) PWINBIO_EXTENDED_SENSOR_INFO SensorInfo,
    _In_ SIZE_T SensorInfoSize)
{
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(SensorInfo)) {
        return E_POINTER;
    }
    if (SensorInfoSize < sizeof(WINBIO_EXTENDED_SENSOR_INFO)) {
        return WINBIO_E_MORE_DATA;
    }
    ZeroMemory(SensorInfo, SensorInfoSize);
    SensorInfo->GenericSensorCapabilities = 0;
    SensorInfo->Factor = WINBIO_TYPE_FINGERPRINT;
    return S_OK;
}

// Remaining V3 slots used by some units - safe stubs.
HRESULT WINAPI SensorQueryCalibrationFormats(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Outptr_result_bytebuffer_(*FormatArraySize) PWINBIO_UUID* FormatArray,
    _Out_ PSIZE_T FormatArraySize,
    _Out_ PSIZE_T PreferredCalibrationFormat)
{
    UNREFERENCED_PARAMETER(Pipeline);
    if (ARGUMENT_PRESENT(FormatArray)) {
        *FormatArray = nullptr;
    }
    if (ARGUMENT_PRESENT(FormatArraySize)) {
        *FormatArraySize = 0;
    }
    if (ARGUMENT_PRESENT(PreferredCalibrationFormat)) {
        *PreferredCalibrationFormat = 0;
    }
    return E_NOTIMPL;
}

HRESULT WINAPI SensorSetCalibrationFormat(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ REFGUID Format)
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(Format);
    return E_NOTIMPL;
}

HRESULT WINAPI SensorAcceptCalibrationData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_DATA CalibrationData)
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(CalibrationData);
    return E_NOTIMPL;
}

WINBIO_SENSOR_INTERFACE g_SensorInterface = {
    WINBIO_SENSOR_INTERFACE_VERSION_3,
    WINBIO_ADAPTER_TYPE_SENSOR,
    sizeof(WINBIO_SENSOR_INTERFACE),
    kAdapterId,
    SensorAttach,
    SensorDetach,
    SensorClearContext,
    SensorQueryStatus,
    SensorReset,
    SensorSetMode,
    SensorSetIndicatorStatus,
    SensorGetIndicatorStatus,
    SensorStartCapture,
    SensorFinishCapture,
    SensorExportSensorData,
    SensorCancel,
    SensorPushDataToEngine,
    SensorControlUnit,
    SensorControlUnitPrivileged,
    SensorNotifyPowerChange,
    SensorPipelineInit,
    SensorPipelineCleanup,
    SensorActivate,
    SensorDeactivate,
    SensorQueryExtendedInfo,
    SensorQueryCalibrationFormats,
    SensorSetCalibrationFormat,
    SensorAcceptCalibrationData,
};

} // namespace

BOOL APIENTRY DllMain(HMODULE ModuleHandle, DWORD ReasonForCall, LPVOID Reserved)
{
    UNREFERENCED_PARAMETER(Reserved);
    if (ReasonForCall == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(ModuleHandle);
        SensLog("DLL loaded module=%p", ModuleHandle);
    }
    return TRUE;
}

extern "C" HRESULT WINAPI WbioQuerySensorInterface(
    _Out_ PWINBIO_SENSOR_INTERFACE* SensorInterface)
{
    SensLog("WbioQuerySensorInterface size=%llu",
            static_cast<unsigned long long>(sizeof(WINBIO_SENSOR_INTERFACE)));
    if (!ARGUMENT_PRESENT(SensorInterface)) {
        return E_POINTER;
    }
    *SensorInterface = &g_SensorInterface;
    return S_OK;
}

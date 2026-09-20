// SPDX-License-Identifier: GPL-2.0-only
// Queue.cpp - WBDI IOCTL dispatch.
#include "Internal.h"
#include "../WbdiBir.h"
#include <atomic>
#include <mutex>
#include <optional>
#include <array>
#include <algorithm>
#include <vector>
#include <cstddef>

// ---------------------------------------------------------------------------
// Type names below were checked against winbio_ioctl.h / winbio_types.h of
// Windows Kits 10.0.26100.0 (the CI "Dump WinBio WBDI headers" artifact).
// ---------------------------------------------------------------------------
using T2BioSensorAttributes = WINBIO_SENSOR_ATTRIBUTES;   // out of GET_ATTRIBUTES

// GET_SENSOR_STATUS OUT payload is WINBIO_DIAGNOSTICS (winbio_ioctl.h, Windows
// Kits 10.0.26100.0): { DWORD PayloadSize; HRESULT WinBioHresult;
// WINBIO_SENSOR_STATUS SensorStatus; WINBIO_DATA VendorDiagnostics; }.
// The former local mirror (16 bytes) was wrong: the real struct also carries
// the WINBIO_DATA tail, so PayloadSize has to be sizeof(WINBIO_DIAGNOSTICS).
using T2BioDiagnostics = WINBIO_DIAGNOSTICS;

namespace {

// Placeholder identity strings shown by WinBio / Settings.
constexpr wchar_t kManufacturer[] = L"Osaul4ik";
constexpr wchar_t kModel[]        = L"Apple T2 Touch ID (SEP)";
constexpr wchar_t kSerial[]       = L"T2-0001";

void FillAttributes(T2BioSensorAttributes& a)
{
    RtlZeroMemory(&a, sizeof(a));
    a.PayloadSize   = sizeof(a);
    a.WinBioHresult = S_OK;
    a.WinBioVersion.MajorVersion = WINBIO_WBDI_MAJOR_VERSION;
    a.WinBioVersion.MinorVersion = WINBIO_WBDI_MINOR_VERSION;

    a.SensorType    = WINBIO_TYPE_FINGERPRINT;
    a.SensorSubType = WINBIO_FP_SENSOR_SUBTYPE_TOUCH;

    // Sensor only: matching happens in the T2 SEP, and our "engine" is a thin
    // matchedUuid comparison (design doc 7.4), not a WBDI-visible capability.
    a.Capabilities  = WINBIO_CAPABILITY_SENSOR;

    (void)StringCchCopyW(a.ManufacturerName, ARRAYSIZE(a.ManufacturerName), kManufacturer);
    (void)StringCchCopyW(a.ModelName,        ARRAYSIZE(a.ModelName),        kModel);
    (void)StringCchCopyW(a.SerialNumber,     ARRAYSIZE(a.SerialNumber),     kSerial);
    a.FirmwareVersion.MajorVersion = 0;
    a.FirmwareVersion.MinorVersion = 1;

    // PLACEHOLDER: real data format is a vendor BIR (design doc 5:
    // VerifyOutcome + matchedUuid, no raw fingerprint), which needs its own
    // registered format owner. ANSI-381 is here only so the entry is well-formed
    // for the "does WinBio see the device" gate.
    a.SupportedFormatEntries = 1;
    a.SupportedFormat[0].Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    a.SupportedFormat[0].Type  = WINBIO_ANSI_381_FORMAT_TYPE;
}

// WBDI size-probe convention (Microsoft WudfBioUsbSample, Device.cpp
// OnGetAttributes / OnGetSensorStatus; the sample was removed from
// Windows-driver-samples master in 2024, last present in c73af47~1):
//   - output buffer missing or smaller than a DWORD: fail with E_INVALIDARG
//     semantics (here STATUS_INVALID_PARAMETER),
//   - output buffer smaller than the payload: write the REQUIRED size into
//     PayloadSize, complete with SUCCESS and Information = sizeof(DWORD);
//     the caller then re-issues with a buffer of PayloadSize bytes.
// The previous code asked WdfRequestRetrieveOutputBuffer for the full payload
// size up front, so a small-buffer probe would have failed with
// STATUS_BUFFER_TOO_SMALL instead of reporting the required size.
template <typename Payload>
Payload* RetrieveProbedPayload(_In_ WDFREQUEST Request, _Out_ bool* fitsFully)
{
    *fitsFully = false;
    Payload* out = nullptr;
    size_t outLen = 0;
    const NTSTATUS status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(DWORD), reinterpret_cast<PVOID*>(&out), &outLen);
    if (!NT_SUCCESS(status) || out == nullptr) {
        T2BioLog("  output buffer unusable (status=0x%08x) -> completing with error", status);
        WdfRequestComplete(Request, NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status);
        return nullptr;
    }
    if (outLen < sizeof(Payload)) {
        T2BioLog("  size probe: have=%llu need=%llu -> reporting required size",
                 static_cast<unsigned long long>(outLen), static_cast<unsigned long long>(sizeof(Payload)));
        out->PayloadSize = static_cast<DWORD>(sizeof(Payload)); // required size, first member of both payloads
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return nullptr;
    }
    *fitsFully = true;
    return out;
}

void HandleGetAttributes(_In_ WDFREQUEST Request)
{
    bool fits = false;
    T2BioSensorAttributes* out = RetrieveProbedPayload<T2BioSensorAttributes>(Request, &fits);
    if (!fits) {
        return; // already completed (error or size probe)
    }
    FillAttributes(*out);
    T2BioLog("  GET_ATTRIBUTES ok payload=%lu", static_cast<unsigned long>(out->PayloadSize));
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, out->PayloadSize);
}

void HandleGetSensorStatus(_In_ WDFREQUEST Request)
{
    bool fits = false;
    T2BioDiagnostics* out = RetrieveProbedPayload<T2BioDiagnostics>(Request, &fits);
    if (!fits) {
        return;
    }
    RtlZeroMemory(out, sizeof(*out));
    out->PayloadSize   = sizeof(*out);
    out->WinBioHresult = S_OK;
    // Always READY. Do NOT report ACCEPT here: a one-shot ACCEPT armed by a
    // delivered sample was tried (2026-09-20) and leaked into the poll WBF
    // makes before the NEXT capture (enrollment), which then never sent it.
    // The trace showed AcceptSampleData firing straight after the capture
    // completed, with no status poll in between - the sample's own
    // SensorStatus=ACCEPT in the CAPTURE_DATA payload is what counts.
    // Real readiness logic (design doc 3) later:
    // open GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT, IOCTL_T2_GET_STATUS, and
    // Global\T2SepReady from T2SepBootstrap.
    out->SensorStatus  = WINBIO_SENSOR_READY;
    out->VendorDiagnostics.Size = 0;
    T2BioLog("  GET_SENSOR_STATUS ok sensorStatus=%d (READY)", static_cast<int>(out->SensorStatus));
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, out->PayloadSize);
}

} // namespace (GET_ATTRIBUTES / GET_SENSOR_STATUS helpers)

// ---------------------------------------------------------------------------
// IOCTL_BIOMETRIC_CAPTURE_DATA (design doc 3, 4, 5, 6).
//
// KNOWN GAPS vs the design doc, left explicit rather than silently patched
// over (matching this project's own fail-closed / no-guessing style):
//
//   - Section 9.4 (cancel-on-CancelIo, unbounded wait for the lock screen)
//     IS implemented (EvtCaptureCancel/WdfRequestMarkCancelable below), and
//     VerificationEngine::Verify() now waits with NO internal deadline at
//     all whenever a cancelEvent is supplied (always true here) - a
//     wrong-finger NO_MATCH restarts the scan immediately instead of ending
//     the capture, and the wait otherwise ends only on a real Match or on
//     Windows' own CancelIoEx. kCaptureMatchWindow below is therefore not a
//     wait bound in normal operation at all; it only matters as a
//     last-resort fallback if the cancelEvent itself failed to be created.
//   - Section 4's multi-user case (several macOS fingers under different
//     macosUserId on one T2) is not handled: kDefaultMacosUserId is the
//     only identity this build ever asks the SEP about. Per design doc 4
//     this is an accepted MVP limit (1 Windows account = 1 finger), not an
//     oversight - but it means Enroll always confirms/denies against the
//     SAME macosUserId regardless of which Windows account is enrolling.
//   - PickDefaultT2Endpoint (via FindT2NcmEndpoints, Discovery/Adapter.cpp)
//     can shell out to ping.exe once to provoke an IPv6 neighbor-table
//     entry (see Adapter.cpp) if none exists yet. That is an ordinary,
//     already-hardware-verified CLI behavior, but running it from inside a
//     WBDI driver hosted by WUDFHost - possibly during a LogonUI secure
//     desktop session (design doc 2's own open risk) - is new territory
//     this design doc never explicitly signed off on. Flagging it here
//     instead of assuming it is fine.
// ---------------------------------------------------------------------------
namespace {

using t2::biometrickit::VerificationEngine;
using t2::biometrickit::VerifyConfig;
using t2::biometrickit::VerifyOutcome;
using t2::biometrickit::IdentityRecordV1;

// design doc 4: MVP is "1 Windows account = 1 macosUserId", not yet wired to
// any per-account config store. Change this (and rebuild) to match whichever
// macOS user id was actually enrolled, until a real settings UI exists.
constexpr uint32_t kDefaultMacosUserId = 501;

// No longer a "safety net" for the normal Hello wait: VerificationEngine::
// Verify() now waits with NO deadline at all whenever cancelEvent is
// non-null (the case here) - Windows alone decides when CAPTURE_DATA ends,
// via CancelIoEx, per explicit design direction (§9.4). This constant only
// still matters as a last-resort fallback bound for the (unexpected) case
// where GetCaptureCancelEvent() returns null - e.g. the process-wide cancel
// event failed to create at startup - so the capture does not wait forever
// with no way to be cancelled at all in that specific failure mode.
constexpr std::chrono::seconds kCaptureMatchWindow{60};

// Only one CAPTURE_DATA may be in flight at a time (design doc 6, mirroring
// VerificationEngine::IsBusy()'s existing single-session rule at the WBDI
// layer too, since the parallel dispatch queue can hand this IOCTL to more
// than one worker thread at once).
std::atomic<bool> g_captureBusy{false};

// 20.09.2026: WBF issues exactly TWO CAPTURE_DATA verify requests per unlock
// (hardware log: Match → complete → new CAPTURE begin within 15–30 ms). The
// second is not a second finger touch — framework double-check. Answer #1
// with a real SEP Match, arm a one-shot replay, answer #2 with the same
// result (no connect / StartMatch / cancel-poll). After consume, the next
// CAPTURE is a real verify again. No wall-clock TTL: the contract is
// "real + one replay", matching the stable WBF pair.
struct RecentMatchCache {
    std::mutex mu;
    bool pendingReplay = false;
    std::optional<std::array<uint8_t, 16>> matchedUuid;
};
RecentMatchCache g_recentMatch;

void ArmMatchReplay(const std::optional<std::array<uint8_t, 16>>& uuid)
{
    std::lock_guard<std::mutex> lock(g_recentMatch.mu);
    g_recentMatch.matchedUuid = uuid;
    g_recentMatch.pendingReplay = true;
}

bool ConsumeMatchReplay(std::optional<std::array<uint8_t, 16>>* outUuid)
{
    std::lock_guard<std::mutex> lock(g_recentMatch.mu);
    if (!g_recentMatch.pendingReplay) return false;
    *outUuid = g_recentMatch.matchedUuid;
    g_recentMatch.pendingReplay = false;
    return true;
}

void ClearMatchReplay()
{
    std::lock_guard<std::mutex> lock(g_recentMatch.mu);
    g_recentMatch.pendingReplay = false;
}

struct CaptureBusyGuard {
    bool acquired = false;
    CaptureBusyGuard() { TryAcquire(); }
    // Idempotent: also used to keep retrying while a cancelled predecessor
    // unwinds (WaitForCancelledPredecessor below).
    bool TryAcquire() {
        if (!acquired) {
            bool expected = false;
            acquired = g_captureBusy.compare_exchange_strong(expected, true);
        }
        return acquired;
    }
    ~CaptureBusyGuard() {
        if (acquired) {
            g_captureBusy.store(false, std::memory_order_relaxed);
        }
    }
};

// design doc §9.4 / §10: one process-wide manual-reset event, mirroring
// g_captureBusy's own "only one CAPTURE_DATA in flight" simplification —
// there is at most one outstanding capture to cancel, so one event is
// enough; a per-request event would only matter once this driver ever
// allows concurrent captures, which it explicitly does not (comment above).
// Lazily created on first use (function-local static is thread-safe init,
// same guarantee WdfRequestComplete/etc. rely on for one-time WDF setup
// elsewhere in this file) rather than from DriverEntry, so this file stays
// self-contained and doesn't need a new Driver.cpp touchpoint.
HANDLE GetCaptureCancelEvent()
{
    static HANDLE h = CreateEventW(nullptr, /*bManualReset=*/TRUE, /*bInitialState=*/FALSE, nullptr);
    return h; // CreateEventW failure -> nullptr; every caller already treats
              // a null/unsignaled HANDLE as "no cancel support this boot"
              // (WaitForSingleObject/SetEvent on NULL just fail, harmlessly)
              // rather than crash, so this isn't checked here.
}

// EVT_WDF_REQUEST_CANCEL for the in-flight CAPTURE_DATA request. WDF invokes
// this when Windows calls CancelIoEx on the pending IOCTL — per design doc
// §9.4, that is exactly what happens when a password-fallback login (or any
// other credential provider) ends the LogonUI session while our biometric
// tile is still waiting on a touch: WinBio cancels every outstanding async
// credential-provider operation, ours included. This is standard WDF
// cancel-routine contract, not something this driver invents: once called,
// THIS routine now owns completing Request — HandleCaptureVerify's own
// WdfRequestUnmarkCancelable call (see below) is how it finds out that
// happened and must not touch Request again.
VOID EvtCaptureCancel(_In_ WDFREQUEST Request)
{
    T2BioLog("CAPTURE_DATA: EvtCaptureCancel fired (Windows called CancelIoEx)");
    HANDLE cancelEvent = GetCaptureCancelEvent();
    if (cancelEvent) {
        SetEvent(cancelEvent); // wakes the blocked Verify()/WaitForEvent() loop
                                // within kCancelPollSlice (Connection.cpp)
    }
    // WdfRequestComplete here, not CompleteCaptureData: WBDI's own contract
    // for a cancelled request is STATUS_CANCELLED at the WDF layer, not a
    // WINBIO_CAPTURE_DATA payload — there is no capture result to report.
    WdfRequestComplete(Request, STATUS_CANCELLED);
}

enum class SlotWait { Acquired, StillBusy, RequestCancelled };

// Upper bound for how long a NEW CAPTURE_DATA waits for a CANCELLED
// predecessor to hand back the single capture slot. The predecessor's WDF
// request is already completed (EvtCaptureCancel does that at once), but its
// worker thread is still unwinding - worst case it is inside the port scan
// (~4s when the discovery cache is cold) - and WBF re-issues CAPTURE_DATA
// within a few milliseconds of the cancel (hardware log: 12ms after the
// cancel, 1-7ms after every completed identify).
constexpr ULONGLONG kPredecessorUnwindWaitMs = 8000;

// 20.09.2026: WBF cancels the in-session identify and immediately starts the
// lock-screen one (or vice versa). Before this, that second request lost the
// race for g_captureBusy whenever the first worker had not finished unwinding
// yet and was answered WINBIO_E_DATA_COLLECTION_IN_PROGRESS / SENSOR_BUSY -
// a hard failure of the very request Windows needs to be serviced right after
// a lock/unlock. Only applies when the in-flight capture really was
// cancelled (its cancel event is set); a genuinely concurrent second capture
// still gets BUSY at once, exactly as before.
SlotWait WaitForCancelledPredecessor(_In_ WDFREQUEST Request, CaptureBusyGuard& guard)
{
    HANDLE cancelEvent = GetCaptureCancelEvent();
    if (!t2::bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
        return SlotWait::StillBusy;
    }
    T2BioLog("CAPTURE_DATA: previous capture was cancelled and is still unwinding - waiting for "
             "it (max %llu ms) instead of failing with DATA_COLLECTION_IN_PROGRESS",
             static_cast<unsigned long long>(kPredecessorUnwindWaitMs));

    // This request can be cancelled while it waits too.
    WdfRequestMarkCancelable(Request, EvtCaptureCancel);
    SlotWait result = SlotWait::StillBusy;
    const ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < kPredecessorUnwindWaitMs) {
        if (guard.TryAcquire()) {
            result = SlotWait::Acquired;
            break;
        }
        Sleep(10);
    }
    if (WdfRequestUnmarkCancelable(Request) == STATUS_CANCELLED) {
        // EvtCaptureCancel already completed Request; if we did get the slot
        // the caller's CaptureBusyGuard releases it on return.
        T2BioLog("CAPTURE_DATA: cancelled while waiting for the previous capture to unwind");
        return SlotWait::RequestCancelled;
    }
    T2BioLog("CAPTURE_DATA: predecessor wait finished after %llu ms (%s)",
             static_cast<unsigned long long>(GetTickCount64() - start),
             result == SlotWait::Acquired ? "slot acquired" : "still busy");
    return result;
}

// Which capture a CAPTURE_DATA request asked for; also what the returned BIR
// header echoes back.
struct CaptureKey {
    WINBIO_BIR_PURPOSE Purpose = 0;
    WINBIO_BIR_DATA_FLAGS Flags = 0;
};

// WBDI size-probe convention for CAPTURE_DATA (WDK, IOCTL_BIOMETRIC_CAPTURE_DATA):
// "If the driver receives a DWORD-sized output buffer, the driver must
// immediately return the buffer size necessary to complete the operation."
// The probe therefore must NOT start a capture and must not block. The earlier
// revision ran the whole SEP touch on the probe and parked the verdict for the
// retry; that made the probe take seconds (WBF expects it instantly) and is the
// wrong contract. The real request - the one whose buffer is large enough -
// is the one that waits for the touch, exactly like Microsoft's sample
// (WudfBioUsbSample: probe -> PayloadSize, immediately; capture -> pending).
// The size is constant: the vendor payload has a fixed layout, so the largest
// possible reply (a Match BIR) is known up front.
size_t CaptureDataHeaderBytes()
{
    return offsetof(WINBIO_CAPTURE_DATA, CaptureData) + offsetof(WINBIO_DATA, Data);
}

HRESULT MapVerifyOutcomeToHresult(VerifyOutcome outcome)
{
    // Design doc 5's table. Nothing here ever maps a transport/protocol
    // failure to a Match - that mapping does not exist in this switch.
    switch (outcome) {
    case VerifyOutcome::Match:                    return S_OK;
    case VerifyOutcome::NoMatch:                  return WINBIO_E_NO_MATCH;
    case VerifyOutcome::Timeout:                  return WINBIO_E_BAD_CAPTURE;
    case VerifyOutcome::TransportError:           return WINBIO_E_DEVICE_FAILURE;
    case VerifyOutcome::RejectedByDevice:         return WINBIO_E_DEVICE_FAILURE;
    case VerifyOutcome::Busy:                     return WINBIO_E_DATA_COLLECTION_IN_PROGRESS;
    case VerifyOutcome::UnstableIdentityInventory: return WINBIO_E_DEVICE_FAILURE;
    case VerifyOutcome::Malformed:                return E_FAIL;
    // design doc §9.4: Windows called CancelIoEx on the pending CAPTURE_DATA
    // (see EvtCaptureCancel below) — this is the outcome that used to be
    // unreachable because nothing ever signaled g_captureCancelEvent.
    case VerifyOutcome::Cancelled:                return WINBIO_E_CANCELED;
    }
    return E_FAIL;
}

// Completes the request with a WINBIO_CAPTURE_DATA whose CaptureData blob is
// `payload` (may be empty on a pure-error completion). Handles the same
// grow-then-retry size probe as HandleGetAttributes/HandleGetSensorStatus,
// scaled for CaptureData's variable-length tail.
void CompleteCaptureData(_In_ WDFREQUEST Request, HRESULT winBioHresult,
                          WINBIO_SENSOR_STATUS sensorStatus, WINBIO_REJECT_DETAIL rejectDetail,
                          const std::vector<uint8_t>& payload)
{
    const size_t headerBytes = offsetof(WINBIO_CAPTURE_DATA, CaptureData) +
                               offsetof(WINBIO_DATA, Data);
    const size_t needed = headerBytes + payload.size();

    T2BioLog("  CAPTURE_DATA complete: winBioHresult=0x%08x sensorStatus=%d reject=%d payload=%llu",
             static_cast<unsigned>(winBioHresult), static_cast<int>(sensorStatus),
             static_cast<int>(rejectDetail), static_cast<unsigned long long>(payload.size()));

    PWINBIO_CAPTURE_DATA out = nullptr;
    size_t outLen = 0;
    const NTSTATUS status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(DWORD), reinterpret_cast<PVOID*>(&out), &outLen);
    if (!NT_SUCCESS(status) || out == nullptr) {
        T2BioLog("  CAPTURE_DATA: output buffer unusable (status=0x%08x)", status);
        WdfRequestComplete(Request, NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status);
        return;
    }
    if (outLen < needed) {
        // Should not happen: the probe reported the maximum size, so a
        // well-behaved caller's buffer already fits every reply. Fall back to
        // the size-report answer instead of writing past the buffer; the
        // result of this capture is dropped (never replayed later).
        T2BioLog("  CAPTURE_DATA: buffer too small for the result (have=%llu need=%llu) -> reporting required size",
                 static_cast<unsigned long long>(outLen), static_cast<unsigned long long>(needed));
        out->PayloadSize = static_cast<DWORD>(needed);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return;
    }

    RtlZeroMemory(out, needed);
    out->PayloadSize = static_cast<DWORD>(needed);
    out->WinBioHresult = winBioHresult;
    out->SensorStatus = sensorStatus;
    out->RejectDetail = rejectDetail;
    out->CaptureData.Size = static_cast<DWORD>(payload.size());
    if (!payload.empty()) {
        RtlCopyMemory(out->CaptureData.Data, payload.data(), payload.size());
    }
    {
        // Diagnostic: exact head of what WBF's sensor adapter receives.
        char hex[96 * 2 + 1] = {};
        static const char digits[] = "0123456789abcdef";
        const size_t n = needed < 96 ? needed : 96;
        const UCHAR* b = reinterpret_cast<const UCHAR*>(out);
        for (size_t i = 0; i < n; ++i) { hex[i * 2] = digits[b[i] >> 4]; hex[i * 2 + 1] = digits[b[i] & 0x0f]; }
        T2BioLog("  CAPTURE_DATA head (%llu of %llu bytes): %s", static_cast<unsigned long long>(n),
                 static_cast<unsigned long long>(needed), hex);
    }
    T2BioLog("  CAPTURE_DATA delivered: %llu bytes (winBioHresult=0x%08x)",
             static_cast<unsigned long long>(needed), static_cast<unsigned>(winBioHresult));
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, static_cast<ULONG_PTR>(needed));
}

// Shared connect step for both purposes below. Returns false (and has
// already logged why) if the SEP/T2 side cannot be reached at all - the
// caller maps that to WINBIO_E_DEVICE_FAILURE, never to a Match/NoMatch
// verdict, because "couldn't ask the SEP" is not an answer from the SEP.
bool ConnectForCapture(t2::bridgexpc::Connection* outConn)
{
    // Timings: on the 20.09.2026 hardware log this step alone was a constant
    // ~3.8s per CAPTURE_DATA (full port scan, cache never hit), during which
    // the sensor is not armed and a touch is silently lost.
    const ULONGLONG t0 = GetTickCount64();
    t2::discovery::NcmEndpoint ep;
    if (!t2::discovery::PickDefaultT2Endpoint(&ep)) {
        T2BioLog("CAPTURE_DATA: no T2 NCM adapter found");
        return false;
    }
    const ULONGLONG t1 = GetTickCount64();
    if (!t2::discovery::ConnectToBiometricKitBridge(ep, outConn)) {
        T2BioLog("CAPTURE_DATA: BiometricKit BridgeXPC discovery/connect failed "
                 "(endpoint lookup %llu ms, discovery+connect %llu ms)",
                 static_cast<unsigned long long>(t1 - t0),
                 static_cast<unsigned long long>(GetTickCount64() - t1));
        return false;
    }
    T2BioLog("CAPTURE_DATA: connected to BiometricKit BridgeXPC "
             "(endpoint lookup %llu ms, discovery+connect %llu ms)",
             static_cast<unsigned long long>(t1 - t0),
             static_cast<unsigned long long>(GetTickCount64() - t1));
    return true;
}

// A/B switch for the BIR layout (see WbdiBir.h BirOptions). Read on every capture so a
// registry edit takes effect without a rebuild. Missing value = shipped default (3).
//   HKLM\SOFTWARE\T2TouchIdBio\BirVariant  (REG_DWORD)
//     bit 0: add WINBIO_DATA_FLAG_OPTION_MASK_PRESENT to the BIR header flags
//     bit 1: include the placeholder ANSI-381 standard block
t2::wbdi::BirOptions LoadBirOptions()
{
    DWORD variant = 3;
    DWORD cb = sizeof(variant);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\T2TouchIdBio", L"BirVariant",
                     RRF_RT_REG_DWORD, nullptr, &variant, &cb) != ERROR_SUCCESS) {
        variant = 3;
    }
    T2BioLog("  BIR layout variant=%u (bit0=option-mask flag, bit1=ANSI-381 block)",
             static_cast<unsigned>(variant));
    return t2::wbdi::BirOptionsFromVariant(variant);
}

// PURPOSE_ENROLL / _ENROLL_FOR_VERIFICATION / _ENROLL_FOR_IDENTIFICATION
// (design doc 4): does NOT collect a new biometric sample. Runs the same
// WarmUp() identity-list read the CLI's `warmup`/`identities` commands use
// and requires a non-empty identity list for kDefaultMacosUserId - i.e. it
// confirms the SEP already has this macOS user enrolled (enrollment stays
// on macOS, per README), it does not create a new enrollment on the SEP.
// The vendor payload carries no matchedUuid (WarmUp doesn't match anything);
// the Storage adapter (not yet written - design doc 7 item 3) is what would
// actually persist {macosUserId} as this account's "template" record.
void HandleCaptureEnroll(_In_ WDFREQUEST Request, const CaptureKey& key)
{
    T2BioLog("CAPTURE_DATA(enroll): begin, macosUserId=%u", static_cast<unsigned>(kDefaultMacosUserId));
    t2::bridgexpc::Connection conn;
    if (!ConnectForCapture(&conn)) {
        CompleteCaptureData(Request, WINBIO_E_DEVICE_FAILURE, WINBIO_SENSOR_FAILURE, 0, {});
        return;
    }

    VerifyConfig cfg;
    cfg.macosUserId = kDefaultMacosUserId;
    VerificationEngine engine(cfg);
    std::vector<IdentityRecordV1> identities;
    const bool warmedUp = engine.WarmUp(&conn, &identities);

    if (!warmedUp) {
        T2BioLog("CAPTURE_DATA(enroll): WarmUp failed (BridgeXPC identity-list read)");
        CompleteCaptureData(Request, WINBIO_E_DEVICE_FAILURE, WINBIO_SENSOR_FAILURE, 0, {});
        return;
    }
    const bool hasIdentity = std::any_of(identities.begin(), identities.end(),
        [](const IdentityRecordV1& r) { return r.userId == kDefaultMacosUserId; });
    if (!hasIdentity) {
        // Fail-closed per design doc 5's spirit: an empty/mismatched
        // identity list is not "enrolled", never silently accepted.
        T2BioLog("CAPTURE_DATA(enroll): SEP has no identity for macosUserId=%u (found %u total)",
                 static_cast<unsigned>(kDefaultMacosUserId), static_cast<unsigned>(identities.size()));
        // WINBIO_E_UNKNOWN_ID (winbio_err.h): the requested identity is not
        // among the identities the SEP reports.
        CompleteCaptureData(Request, WINBIO_E_UNKNOWN_ID, WINBIO_SENSOR_READY, 0, {});
        return;
    }

    T2BioLog("CAPTURE_DATA(enroll): confirmed identity for macosUserId=%u", kDefaultMacosUserId);
    // Kind=EnrollConfirm: no touch happened, so the engine adapter accepts
    // this sample only in UpdateEnrollment and never for verify/identify.
    std::vector<uint8_t> payload = t2::biometrickit::SerializeVendorPayload(
        VerifyOutcome::Match /* "confirmed", not a fingerprint match - see comment above */,
        kDefaultMacosUserId, std::nullopt, t2::biometrickit::kSampleKindEnrollConfirm);
    const std::vector<uint8_t> bir = t2::wbdi::BuildVendorBir(key.Purpose, key.Flags, payload, LoadBirOptions());
    T2BioLog("CAPTURE_DATA(enroll): BIR built, %llu bytes (vendor payload %llu)",
             static_cast<unsigned long long>(bir.size()), static_cast<unsigned long long>(payload.size()));
    // WBDI (winbio_ioctl.h / IOCTL_BIOMETRIC_CAPTURE_DATA): a delivered sample is
    // reported with SensorStatus = WINBIO_SENSOR_ACCEPT. With READY (3) the hardware
    // log showed WBF re-issuing CAPTURE_DATA in a loop and never calling the engine's
    // AcceptSampleData (hypothesis: READY reads as "no accepted sample"; unverified).
    CompleteCaptureData(Request, S_OK, WINBIO_SENSOR_ACCEPT, 0, bir);
}

// PURPOSE_VERIFY: the real per-touch path. Runs the full
// VerificationEngine::Verify() sequence and maps its fail-closed
// VerifyOutcome straight onto the WinBioHresult this IOCTL completes with.
void HandleCaptureVerify(_In_ WDFREQUEST Request, const CaptureKey& key)
{
    T2BioLog("CAPTURE_DATA(verify): begin, macosUserId=%u, window=%llds",
             static_cast<unsigned>(kDefaultMacosUserId),
             static_cast<long long>(kCaptureMatchWindow.count()));

    // Fast path: second CAPTURE of the WBF pair. Real Match already armed a
    // one-shot replay — return the same result, no sensor session.
    {
        std::optional<std::array<uint8_t, 16>> replayUuid;
        if (ConsumeMatchReplay(&replayUuid)) {
            T2BioLog("CAPTURE_DATA(verify): replaying Match (WBF 2nd CAPTURE of pair) - no sensor session");
            const std::vector<uint8_t> payload = t2::biometrickit::SerializeVendorPayload(
                VerifyOutcome::Match, kDefaultMacosUserId, replayUuid,
                t2::biometrickit::kSampleKindVerify);
            const std::vector<uint8_t> bir =
                t2::wbdi::BuildVendorBir(key.Purpose, key.Flags, payload, LoadBirOptions());
            CompleteCaptureData(Request, S_OK, WINBIO_SENSOR_ACCEPT, 0, bir);
            return;
        }
    }

    // design doc §9.4: register this specific request as cancelable BEFORE
    // doing anything that can block (Connect included — a cancel arriving
    // during discovery/connect should still complete the IOCTL promptly,
    // even though today only the Verify() event-loop wait actually watches
    // cancelEvent; see the header comment on VerificationEngine::Verify).
    // ResetEvent first: this is a process-wide, reused-across-sessions
    // event (GetCaptureCancelEvent's own comment), so a stale signal left
    // over from the PREVIOUS capture's cancellation must not immediately
    // cancel this brand-new one.
    HANDLE cancelEvent = GetCaptureCancelEvent();
    if (cancelEvent) {
        ResetEvent(cancelEvent);
    }
    WdfRequestMarkCancelable(Request, EvtCaptureCancel);

    VerifyConfig cfg;
    cfg.macosUserId = kDefaultMacosUserId;
    cfg.matchWindow = kCaptureMatchWindow;
    std::optional<std::array<uint8_t, 16>> matchedUuid;
    VerifyOutcome outcome = VerifyOutcome::TransportError;   // also what a failed connect completes as

    // 20.09.2026: this request is supposed to stay pending until a touch or
    // Windows' own CancelIoEx (design doc 9.4). If the T2 drops the TCP
    // session while we wait (Connection::ConnectionLost()), reopen it and
    // re-arm instead of failing the whole request - a fresh StartMatch
    // still needs a fresh touch, so nothing is ever carried over from the
    // dead session. Only a genuinely lost connection is retried (not a
    // command timeout, not a failed connect), and never after a cancel.
    constexpr int kMaxSessionAttempts = 3;
    for (int attempt = 1; attempt <= kMaxSessionAttempts; ++attempt) {
        t2::bridgexpc::Connection conn;
        if (!ConnectForCapture(&conn)) {
            outcome = VerifyOutcome::TransportError;   // completed as DEVICE_FAILURE below (or dropped if cancelled)
            break;
        }
        if (t2::bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
            // Windows cancelled us while we were still discovering/connecting;
            // do not touch the T2 at all for a request nobody wants any more.
            T2BioLog("CAPTURE_DATA(verify): cancelled during connect - not starting a session");
            outcome = VerifyOutcome::Cancelled;
            break;
        }
        VerificationEngine engine(cfg);
        matchedUuid.reset();
        outcome = engine.Verify(&conn, &matchedUuid, cancelEvent);
        if (outcome != VerifyOutcome::TransportError || !conn.ConnectionLost() ||
            t2::bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
            break;
        }
        T2BioLog("CAPTURE_DATA(verify): BridgeXPC session dropped while waiting (attempt %d of %d) - reconnecting",
                 attempt, kMaxSessionAttempts);
        Sleep(200);
    }

    if (WdfRequestUnmarkCancelable(Request) == STATUS_CANCELLED) {
        // Same reasoning as the connect-phase check above: Request is
        // already completed. outcome is almost certainly Cancelled too
        // (Verify() polls the same event), but even if it raced and came
        // back some other way, Request is no longer ours to complete -
        // touching it again here would be a double-complete bug.
        if (outcome == VerifyOutcome::Match) {
            // Real-hardware-observed (2026-09-20): Windows can call
            // CancelIoEx on this very request at almost the same instant
            // the SEP delivers a genuine match_result. WDF only allows one
            // completion, so a successful touch is lost here - the user
            // sees no reaction and has to touch again. Not recoverable at
            // this layer (the request is already gone); flagged loudly so
            // it reads as "a real fingerprint got dropped", not routine
            // cancellation. Still stash the Match so a CAPTURE that arrives
            // a few ms later (the usual WBF double-shot) can replay it.
            T2BioLog("CAPTURE_DATA(verify): *** genuine MATCH discarded - lost a race with "
                     "Windows' own CancelIoEx on this request (request already completed "
                     "as CANCELLED before we could report the match) ***");
            // Arm replay so the usual immediate 2nd CAPTURE still gets the Match.
            ArmMatchReplay(matchedUuid);
        } else {
            T2BioLog("CAPTURE_DATA(verify): cancelled, outcome=%d discarded (request already completed)",
                     static_cast<int>(outcome));
            ClearMatchReplay();
        }
        return;
    }

    const HRESULT hr = MapVerifyOutcomeToHresult(outcome);
    T2BioLog("CAPTURE_DATA(verify): outcome=%d -> hresult=0x%08x", static_cast<int>(outcome),
             static_cast<unsigned>(hr));
    // ACCEPT only for a delivered sample (a real Match); see the note in
    // HandleCaptureEnroll. Failures stay FAILURE, everything else READY.
    const WINBIO_SENSOR_STATUS sensorStatus =
        (outcome == VerifyOutcome::TransportError || outcome == VerifyOutcome::RejectedByDevice ||
         outcome == VerifyOutcome::UnstableIdentityInventory)
            ? WINBIO_SENSOR_FAILURE
            : (outcome == VerifyOutcome::Match ? WINBIO_SENSOR_ACCEPT : WINBIO_SENSOR_READY);
    // A sample goes to WBF only for a real Match; every other outcome completes
    // with its error HRESULT and no data (fail-closed: no BIR to misread).
    std::vector<uint8_t> bir;
    if (outcome == VerifyOutcome::Match) {
        const std::vector<uint8_t> payload = t2::biometrickit::SerializeVendorPayload(
            outcome, kDefaultMacosUserId, matchedUuid, t2::biometrickit::kSampleKindVerify);
        bir = t2::wbdi::BuildVendorBir(key.Purpose, key.Flags, payload, LoadBirOptions());
        T2BioLog("CAPTURE_DATA(verify): BIR built, %llu bytes (vendor payload %llu)",
                 static_cast<unsigned long long>(bir.size()), static_cast<unsigned long long>(payload.size()));
        ArmMatchReplay(matchedUuid); // next CAPTURE = 2nd of the WBF pair
    } else {
        ClearMatchReplay();
    }
    CompleteCaptureData(Request, hr, sensorStatus, 0, bir);
}

void HandleCaptureData(_In_ WDFREQUEST Request)
{
    PWINBIO_CAPTURE_PARAMETERS in = nullptr;
    size_t inLen = 0;
    const NTSTATUS status = WdfRequestRetrieveInputBuffer(
        Request, sizeof(WINBIO_CAPTURE_PARAMETERS), reinterpret_cast<PVOID*>(&in), &inLen);
    if (!NT_SUCCESS(status) || in == nullptr || inLen < sizeof(WINBIO_CAPTURE_PARAMETERS)) {
        T2BioLog("CAPTURE_DATA: bad input buffer (status=0x%08x len=%llu need=%llu) -> STATUS_INVALID_PARAMETER",
                 status, static_cast<unsigned long long>(inLen),
                 static_cast<unsigned long long>(sizeof(WINBIO_CAPTURE_PARAMETERS)));
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    T2BioLog("CAPTURE_DATA: purpose=0x%02x flags=0x%02x format owner=0x%04x type=0x%04x",
             static_cast<unsigned>(in->Purpose), static_cast<unsigned>(in->Flags),
             static_cast<unsigned>(in->Format.Owner), static_cast<unsigned>(in->Format.Type));

    CaptureKey key;
    key.Purpose = in->Purpose;
    key.Flags = in->Flags;

    // Size probe: answer at once, no capture, no busy-slot (see the
    // size-probe note above CaptureDataHeaderBytes()).
    {
        const size_t maxReply = CaptureDataHeaderBytes() +
            t2::wbdi::VendorBirSize(sizeof(t2::biometrickit::T2VendorSamplePayload), LoadBirOptions());
        PWINBIO_CAPTURE_DATA probeOut = nullptr;
        size_t probeLen = 0;
        const NTSTATUS pst = WdfRequestRetrieveOutputBuffer(
            Request, sizeof(DWORD), reinterpret_cast<PVOID*>(&probeOut), &probeLen);
        if (!NT_SUCCESS(pst) || probeOut == nullptr) {
            T2BioLog("CAPTURE_DATA: output buffer unusable (status=0x%08x) -> completing with error", pst);
            WdfRequestComplete(Request, NT_SUCCESS(pst) ? STATUS_INVALID_PARAMETER : pst);
            return;
        }
        if (probeLen < maxReply) {
            T2BioLog("  CAPTURE_DATA size probe: have=%llu need=%llu -> answering immediately, no capture",
                     static_cast<unsigned long long>(probeLen), static_cast<unsigned long long>(maxReply));
            probeOut->PayloadSize = static_cast<DWORD>(maxReply);
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }
    }

    CaptureBusyGuard guard;
    if (!guard.acquired) {
        switch (WaitForCancelledPredecessor(Request, guard)) {
        case SlotWait::Acquired:
            break;                     // predecessor finished unwinding: carry on normally
        case SlotWait::RequestCancelled:
            return;                    // Request was already completed by EvtCaptureCancel
        case SlotWait::StillBusy:
            break;                     // fall through to the BUSY answer below
        }
    }
    if (!guard.acquired) {
        T2BioLog("CAPTURE_DATA: another capture is already in flight -> DATA_COLLECTION_IN_PROGRESS");
        // Mirrors VerificationEngine::IsBusy()'s existing rule, at the WBDI
        // layer this time (design doc 6): a second CAPTURE_DATA arriving
        // while one is already in flight is a normal WBDI occurrence, not
        // an error to log loudly about.
        CompleteCaptureData(Request, WINBIO_E_DATA_COLLECTION_IN_PROGRESS, WINBIO_SENSOR_BUSY, 0, {});
        return;
    }

    switch (in->Purpose) {
    case WINBIO_PURPOSE_VERIFY:
    case WINBIO_PURPOSE_IDENTIFY:
        // WBF's own flows use IDENTIFY (Windows Hello sign-in, and the check
        // Settings runs before an enrollment), not only VERIFY. For this
        // sensor both are the same 1:1 SEP verification for macosUserId; the
        // engine adapter turns the match into an identity from the enrolled
        // records, so IDENTIFY does not mean the SEP searches other users.
        HandleCaptureVerify(Request, key);
        return;
    case WINBIO_PURPOSE_ENROLL:
    case WINBIO_PURPOSE_ENROLL_FOR_VERIFICATION:
    case WINBIO_PURPOSE_ENROLL_FOR_IDENTIFICATION:
        HandleCaptureEnroll(Request, key);
        return;
    default:
        // AUDIT / NO_PURPOSE_AVAILABLE: a request for anything else is a
        // WBF/engine config mismatch, not something to guess an answer for.
        T2BioLog("CAPTURE_DATA: unsupported purpose 0x%02x -> E_NOTIMPL", static_cast<unsigned>(in->Purpose));
        CompleteCaptureData(Request, E_NOTIMPL, WINBIO_SENSOR_FAILURE, 0, {});
        return;
    }
}

} // namespace

namespace {

const char* IoctlName(ULONG code)
{
    switch (code) {
    case IOCTL_BIOMETRIC_GET_ATTRIBUTES:   return "GET_ATTRIBUTES";
    case IOCTL_BIOMETRIC_RESET:            return "RESET";
    case IOCTL_BIOMETRIC_CALIBRATE:        return "CALIBRATE";
    case IOCTL_BIOMETRIC_GET_SENSOR_STATUS:return "GET_SENSOR_STATUS";
    case IOCTL_BIOMETRIC_CAPTURE_DATA:     return "CAPTURE_DATA";
    case IOCTL_BIOMETRIC_GET_PRIVATE_SENSOR_TYPE: return "GET_PRIVATE_SENSOR_TYPE (optional)";
    default:                               return "(unsupported)";
    }
}

} // namespace

extern "C" VOID T2BioEvtIoDeviceControl(_In_ WDFQUEUE Queue,
                                        _In_ WDFREQUEST Request,
                                        _In_ size_t OutputBufferLength,
                                        _In_ size_t InputBufferLength,
                                        _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);

    T2BioLog("IOCTL %s (0x%08x) in=%llu out=%llu", IoctlName(IoControlCode), IoControlCode,
             static_cast<unsigned long long>(InputBufferLength),
             static_cast<unsigned long long>(OutputBufferLength));

    switch (IoControlCode) {
    case IOCTL_BIOMETRIC_GET_ATTRIBUTES:
        HandleGetAttributes(Request);
        return;

    case IOCTL_BIOMETRIC_GET_SENSOR_STATUS:
        HandleGetSensorStatus(Request);
        return;

    case IOCTL_BIOMETRIC_RESET:
        // No sensor state to reset yet.
        T2BioLog("  RESET -> STATUS_SUCCESS");
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;

    case IOCTL_BIOMETRIC_CAPTURE_DATA:
        HandleCaptureData(Request);
        return;

    default:
        // IOCTL_BIOMETRIC_CALIBRATE is never sent while status never says
        // "not calibrated"; anything else is unsupported.
        T2BioLog("  unsupported IOCTL 0x%08x -> STATUS_NOT_SUPPORTED", IoControlCode);
        WdfRequestComplete(Request, STATUS_NOT_SUPPORTED);
        return;
    }
}
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

// ---------------------------------------------------------------------------
// WINBIO_SENSOR_ACCEPT after a capture.
//
// WDK (WINBIO_CAPTURE_DATA / WINBIO_SENSOR_STATUS): ACCEPT means "the sensor
// just successfully completed a capture operation ... only returned
// immediately after a capture operation; the sensor then returns to READY".
// WBF's sensor adapter learns that a sample was taken by asking the sensor,
// i.e. by the GET_SENSOR_STATUS it sends right after CAPTURE_DATA completes
// (an independent WBDI + engine adapter developer reports the same ordering:
// CAPTURE_DATA, CAPTURE_DATA, GET_SENSOR_STATUS, then AcceptSampleData - and
// had to make GET_SENSOR_STATUS return ACCEPT exactly once after a capture to
// get there; Microsoft Q&A 318028). Reporting ACCEPT only inside the
// CAPTURE_DATA payload is not enough: the hardware trace showed
// CAPTURE_DATA(ACCEPT, 444 B BIR) -> ClearContext -> GET_SENSOR_STATUS=READY
// -> CAPTURE_DATA again, with AcceptSampleData never called.
//
// So a delivered sample arms a one-shot flag; the next GET_SENSOR_STATUS
// reports ACCEPT and disarms it (READY afterwards). The flag expires so a
// sample nobody asked about cannot make an unrelated later poll claim ACCEPT.
// ---------------------------------------------------------------------------
constexpr ULONGLONG kAcceptStatusTtlMs = 5000;
std::mutex g_acceptStatusLock;
bool       g_acceptStatusArmed = false;
ULONGLONG  g_acceptStatusArmedAtMs = 0;

void ArmAcceptStatus()
{
    std::lock_guard<std::mutex> lock(g_acceptStatusLock);
    g_acceptStatusArmed = true;
    g_acceptStatusArmedAtMs = GetTickCount64();
}

void DisarmAcceptStatus()
{
    std::lock_guard<std::mutex> lock(g_acceptStatusLock);
    g_acceptStatusArmed = false;
}

// True exactly once per armed sample (and only while it is fresh).
bool ConsumeAcceptStatus()
{
    std::lock_guard<std::mutex> lock(g_acceptStatusLock);
    if (!g_acceptStatusArmed) {
        return false;
    }
    g_acceptStatusArmed = false;
    return (GetTickCount64() - g_acceptStatusArmedAtMs) <= kAcceptStatusTtlMs;
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
    // READY, except for the one poll right after a delivered capture, which
    // must say ACCEPT (see the ACCEPT block above). Real readiness logic
    // (design doc 3) later: open GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT,
    // IOCTL_T2_GET_STATUS, and Global\T2SepReady from T2SepBootstrap.
    const bool accept = ConsumeAcceptStatus();
    out->SensorStatus  = accept ? WINBIO_SENSOR_ACCEPT : WINBIO_SENSOR_READY;
    out->VendorDiagnostics.Size = 0;
    T2BioLog("  GET_SENSOR_STATUS ok sensorStatus=%d (%s)", static_cast<int>(out->SensorStatus),
             accept ? "ACCEPT: one-shot after a delivered sample" : "READY");
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
//     is NOT implemented here. This handler blocks the dispatching thread
//     for up to kCaptureMatchWindow and then gives up - it does not yet
//     register an IWDFIoRequest cancel callback, so a Windows-initiated
//     CancelIo on a pending request will not be observed early. The queue
//     is parallel-dispatch (Driver.cpp), so this only blocks ONE request's
//     worker at a time, not the whole device, but it is still a real
//     divergence from "wait exactly as long as LogonUI is willing to wait".
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

// Stopgap for design doc 9.4 (see file-header comment above): longer than
// the CLI's one-shot 20s default so a Settings enroll/verify click isn't cut
// off mid-gesture, but still bounded, unlike a real LogonUI-driven wait.
constexpr std::chrono::seconds kCaptureMatchWindow{45};

// Only one CAPTURE_DATA may be in flight at a time (design doc 6, mirroring
// VerificationEngine::IsBusy()'s existing single-session rule at the WBDI
// layer too, since the parallel dispatch queue can hand this IOCTL to more
// than one worker thread at once).
std::atomic<bool> g_captureBusy{false};

struct CaptureBusyGuard {
    bool acquired;
    CaptureBusyGuard() {
        bool expected = false;
        acquired = g_captureBusy.compare_exchange_strong(expected, true);
    }
    ~CaptureBusyGuard() {
        if (acquired) {
            g_captureBusy.store(false, std::memory_order_relaxed);
        }
    }
};

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
    if (SUCCEEDED(winBioHresult) && sensorStatus == WINBIO_SENSOR_ACCEPT) {
        // The next GET_SENSOR_STATUS must say ACCEPT (block near the top of this
        // file) - armed BEFORE the completion so it cannot lose the race with
        // WBF's follow-up poll.
        ArmAcceptStatus();
    }
    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, static_cast<ULONG_PTR>(needed));
}

// Shared connect step for both purposes below. Returns false (and has
// already logged why) if the SEP/T2 side cannot be reached at all - the
// caller maps that to WINBIO_E_DEVICE_FAILURE, never to a Match/NoMatch
// verdict, because "couldn't ask the SEP" is not an answer from the SEP.
bool ConnectForCapture(t2::bridgexpc::Connection* outConn)
{
    t2::discovery::NcmEndpoint ep;
    if (!t2::discovery::PickDefaultT2Endpoint(&ep)) {
        T2BioLog("CAPTURE_DATA: no T2 NCM adapter found");
        return false;
    }
    if (!t2::discovery::ConnectToBiometricKitBridge(ep, outConn)) {
        T2BioLog("CAPTURE_DATA: BiometricKit BridgeXPC discovery/connect failed");
        return false;
    }
    T2BioLog("CAPTURE_DATA: connected to BiometricKit BridgeXPC");
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
    t2::bridgexpc::Connection conn;
    if (!ConnectForCapture(&conn)) {
        CompleteCaptureData(Request, WINBIO_E_DEVICE_FAILURE, WINBIO_SENSOR_FAILURE, 0, {});
        return;
    }

    VerifyConfig cfg;
    cfg.macosUserId = kDefaultMacosUserId;
    cfg.matchWindow = kCaptureMatchWindow;
    VerificationEngine engine(cfg);
    std::optional<std::array<uint8_t, 16>> matchedUuid;
    const VerifyOutcome outcome = engine.Verify(&conn, &matchedUuid);

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
        DisarmAcceptStatus();
        T2BioLog("  RESET -> STATUS_SUCCESS (pending ACCEPT status dropped)");
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
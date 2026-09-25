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
#include <thread>

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

// Real readiness logic (formerly a TODO comment in HandleGetSensorStatus):
// reads the driver-held bootstrap status T2SepBootstrapService reports via
// IOCTL_T2_SET_BOOTSTRAP_STATUS (public.h T2_BOOTSTRAP_STATUS) instead of
// the two separate checks ("open GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT,
// IOCTL_T2_GET_STATUS, and Global\T2SepReady") originally sketched there -
// one IOCTL already tells us both "is the transport up" and "did the SEP
// actually unlock", with a specific reason attached when it didn't.
//
// Returns true (leaves outSensorStatus/outHresult untouched) only when the
// SEP has fully unlocked this boot (T2SepReasonOk). Every other case - not
// reported yet, or reported an actual failure - returns false with a
// WBDI-meaningful status filled in, so callers can complete the IOCTL
// without a hardcoded WINBIO_SENSOR_READY that got ahead of reality.
bool CheckSepReady(_Out_ WINBIO_SENSOR_STATUS* outSensorStatus, _Out_ HRESULT* outHresult)
{
    using t2::applekeystore::AksResult;
    using t2::applekeystore::Client;

    Client client;
    if (client.Open() != AksResult::Ok) {
        // Driver not loaded / device not present at all - nothing to poll,
        // nothing to capture from.
        T2BioLog("  SEP readiness: T2TouchIdTransport device not found -> FAILURE");
        *outSensorStatus = WINBIO_SENSOR_FAILURE;
        *outHresult = WINBIO_E_DEVICE_FAILURE;
        return false;
    }

    T2_BOOTSTRAP_STATUS status{};
    if (client.GetBootstrapStatus(&status) != AksResult::Ok) {
        T2BioLog("  SEP readiness: GetBootstrapStatus IOCTL failed -> FAILURE");
        *outSensorStatus = WINBIO_SENSOR_FAILURE;
        *outHresult = WINBIO_E_DEVICE_FAILURE;
        return false;
    }

    switch (status.Reason) {
    case T2SepReasonOk:
        return true;

    case T2SepReasonUnknown:
        // T2SepBootstrap hasn't reported anything yet this boot - either
        // it's still running, or (much less likely) it hasn't started yet.
        // Not a failure - just not there yet. WINBIO_SENSOR_BUSY matches
        // WBDI's own documented meaning for this status value: "the device
        // could still be initializing after it has been turned on."
        T2BioLog("  SEP readiness: bootstrap status Unknown (still booting?) -> BUSY");
        *outSensorStatus = WINBIO_SENSOR_BUSY;
        *outHresult = WINBIO_E_DEVICE_BUSY;
        return false;

    case T2SepReasonVaultMissing:
    case T2SepReasonDpapi:
    case T2SepReasonRegisterOolFailed:
    case T2SepReasonSepHang:
    case T2SepReasonSepRejected:
    default:
        T2BioLog("  SEP readiness: bootstrap reason=%d step=%d sep_status=%d -> FAILURE",
                 static_cast<int>(status.Reason), static_cast<int>(status.Step),
                 static_cast<int>(status.SepStatus));
        *outSensorStatus = WINBIO_SENSOR_FAILURE;
        *outHresult = WINBIO_E_DEVICE_FAILURE;
        return false;
    }
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

    // Real readiness logic (see CheckSepReady below): reports BUSY while
    // T2SepBootstrap is still running/hasn't reported yet this boot, or
    // FAILURE if it reported an actual problem — never a hardcoded READY
    // before the SEP has genuinely finished unlocking.
    WINBIO_SENSOR_STATUS sensorStatus = WINBIO_SENSOR_READY;
    HRESULT hr = S_OK;
    if (!CheckSepReady(&sensorStatus, &hr)) {
        out->WinBioHresult = hr;
        out->SensorStatus = sensorStatus;
        out->VendorDiagnostics.Size = 0;
        T2BioLog("  GET_SENSOR_STATUS: SEP not ready -> sensorStatus=%d hr=0x%08x",
                 static_cast<int>(out->SensorStatus), static_cast<unsigned>(hr));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, out->PayloadSize);
        return;
    }

    out->WinBioHresult = S_OK;
    // Do NOT report ACCEPT here: a one-shot ACCEPT armed by a delivered
    // sample was tried (2026-09-20) and leaked into the poll WBF makes
    // before the NEXT capture (enrollment), which then never sent it.
    // The trace showed AcceptSampleData firing straight after the capture
    // completed, with no status poll in between - the sample's own
    // SensorStatus=ACCEPT in the CAPTURE_DATA payload is what counts.
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

// Incremented before the suspend callback signals the pending capture. A
// capture compares this generation after it unwinds so a sleep cancellation
// remains distinguishable from a user/LogonUI cancellation all the way to the
// WBDI completion mapping.
std::atomic<ULONGLONG> g_suspendGeneration{0};

// 20.09.2026: WBF issues exactly TWO CAPTURE_DATA verify requests per unlock
// (hardware log: Match → complete → new CAPTURE begin within 15–30 ms). The
// second is not a second finger touch — framework double-check. Answer #1
// with a real SEP Match, arm a one-shot replay, answer #2 with the same
// result (no connect / StartMatch / cancel-poll).
//
// TTL (kMatchReplayTtlMs): without a time bound a cancelled/stale arm could
// satisfy an unrelated later CAPTURE (e.g. after Win+L or resume). Hardware
// pair spacing is 15–30 ms; 500 ms is generous for the pair and tight enough
// that a lock-screen re-arm cannot inherit a previous unlock's Match.
struct RecentMatchCache {
    std::mutex mu;
    bool pendingReplay = false;
    ULONGLONG armedAtMs = 0;
    std::optional<std::array<uint8_t, 16>> matchedUuid;
};
RecentMatchCache g_recentMatch;
constexpr ULONGLONG kMatchReplayTtlMs = 500;

// Consumed by the next real verify CAPTURE so ResetSensor+LoadCalibration
// run once after process start and after every resume (skip flags are
// otherwise true for steady-state latency — see VerificationEngine.h).
// Starts true: WUDFHost may load long after bridgeOS is "warm", but the first
// Hello capture of this host process still needs a known-good sensor arm.
std::atomic<bool> g_needPostResumeWarmup{true};

void ArmMatchReplay(const std::optional<std::array<uint8_t, 16>>& uuid)
{
    std::lock_guard<std::mutex> lock(g_recentMatch.mu);
    g_recentMatch.matchedUuid = uuid;
    g_recentMatch.pendingReplay = true;
    g_recentMatch.armedAtMs = GetTickCount64();
}

// Returns true and fills *outUuid for the 2nd CAPTURE of the pair.
bool ConsumeMatchReplay(std::optional<std::array<uint8_t, 16>>* outUuid)
{
    std::lock_guard<std::mutex> lock(g_recentMatch.mu);
    if (!g_recentMatch.pendingReplay) return false;
    const ULONGLONG age = GetTickCount64() - g_recentMatch.armedAtMs;
    if (age > kMatchReplayTtlMs) {
        g_recentMatch.pendingReplay = false;
        g_recentMatch.matchedUuid.reset();
        return false;
    }
    *outUuid = g_recentMatch.matchedUuid;
    g_recentMatch.pendingReplay = false;
    return true;
}

void ClearMatchReplay()
{
    std::lock_guard<std::mutex> lock(g_recentMatch.mu);
    g_recentMatch.pendingReplay = false;
    g_recentMatch.matchedUuid.reset();
}

// Sticky NCM endpoint for this WUDFHost process (see ConnectForCapture).
// Declared here so OnSuspendResume can invalidate it across Sx.
struct StickyNcmEndpoint {
    std::mutex mu;
    bool valid = false;
    t2::discovery::NcmEndpoint ep{};
};
StickyNcmEndpoint g_stickyNcm;

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

// 24.09.2026: EvtIoStop (below in this file / Driver.cpp) turned out to be
// dead code for THIS device in practice. T2TouchIdBio.inf installs under
// root\T2TouchIdBio - a root-enumerated *virtual* device with no bus behind
// it and, per that INF's own comment, deliberately no SystemWakeEnabled /
// DeviceIdle* keys (those are for real USB sensors). A root-enumerated
// device with no wake/idle policy is never told by the framework to leave
// D0 for an ordinary system sleep - the Root bus driver does not propagate
// Sx transitions to it the way a real ACPI/PCI/USB bus does. Hardware log
// (24.09.2026) confirms this directly: across a full sleep/resume cycle
// (T2TouchIdTransport's D0Exit/D0Entry and T2Ncm's MiniportPause/Restart
// both fire correctly - they sit on real buses), this driver never logs a
// single EvtIoStop, and a CAPTURE_DATA(verify) that was already in
// StartMatch before sleep simply keeps waiting THROUGH the entire sleep and
// delivers a match afterward - WinBio's engine happily accepts it
// (AcceptSampleData/IdentifyFeatureSet succeed) even though nothing
// re-validated that the touch belongs to a session still meaningful after a
// full suspend/resume. Observed effect: waking with no lock screen at all
// (a touch/match belonging to the pre-sleep session gets treated as a valid
// sign-in the instant the system resumes).
//
// Since this device's own D0 state is not a reliable signal, the fix hooks
// the OS-level, per-process suspend notification instead of the per-device
// one: PowerRegisterSuspendResumeNotification (Powrprof.dll) delivers
// PBT_APMSUSPEND to every registered process shortly before the machine
// actually suspends, regardless of any individual device's power state -
// WUDFHost.exe hosting this driver is an ordinary Win32 service process, so
// it qualifies. On PBT_APMSUSPEND this reuses the exact same wakeup
// EvtCaptureCancel/T2BioEvtIoStop already use: set the shared cancelEvent so
// the blocked VerificationEngine::Verify() wait notices within
// kCancelPollSlice and unwinds through HandleCaptureVerify's own normal
// completion path (Cancelled outcome) *before* the process is frozen for
// sleep. The WBDI request completes with WINBIO_E_CANCELED, not BAD_CAPTURE:
// a power transition did not produce a fingerprint sample. After resume this
// driver only arms one-shot warm-up for the next real WBF request. WBF/LogonUI
// owns whether and when that new CAPTURE_DATA request is issued; the driver
// must not invent an authentication request or synthesize a match.
HPOWERNOTIFY g_suspendResumeNotify = nullptr;

ULONG CALLBACK OnSuspendResume(_In_opt_ PVOID Context, _In_ ULONG Type, _In_opt_ PVOID Setting)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Setting);
    if (Type == PBT_APMSUSPEND) {
        T2BioLog("OnSuspendResume: PBT_APMSUSPEND - waking any pending CAPTURE_DATA "
                 "before the process is frozen for sleep");
        g_suspendGeneration.fetch_add(1, std::memory_order_relaxed);
        ClearMatchReplay(); // never replay a pre-sleep Match after resume
        {
            // NCM/ifIndex may change across Sx; force rediscovery on resume.
            std::lock_guard<std::mutex> lock(g_stickyNcm.mu);
            g_stickyNcm.valid = false;
        }
        HANDLE cancelEvent = GetCaptureCancelEvent();
        if (cancelEvent) {
            SetEvent(cancelEvent); // same wakeup EvtCaptureCancel/T2BioEvtIoStop
                                    // use - see header comment above
        }
    } else if (Type == PBT_APMRESUMESUSPEND || Type == PBT_APMRESUMEAUTOMATIC) {
        // Resume hygiene (no service restarts — WBF owns Activate/CAPTURE):
        // 1) Force WarmUp on the next real verify (SEP cancel residue after Sx).
        // 2) Drop sticky NCM / match-replay (adapter and session are new).
        // 3) Reset the process-wide cancel event — leave it signaled and the
        //    first post-resume CAPTURE can observe a stale cancel before its
        //    own ResetEvent runs (worker scheduling).
        // 4) Clear g_captureBusy — if the cancel worker was frozen mid-unwind
        //    across Sx, busy stays true forever and WBF only sees
        //    DATA_COLLECTION_IN_PROGRESS (or stops arming). Hardware log
        //    24.09.2026: ~14s with zero CAPTURE after resume until a full
        //    Deactivate/Activate cycle (PIN path).
        g_needPostResumeWarmup.store(true, std::memory_order_relaxed);
        ClearMatchReplay();
        {
            std::lock_guard<std::mutex> lock(g_stickyNcm.mu);
            g_stickyNcm.valid = false;
        }
        HANDLE cancelEvent = GetCaptureCancelEvent();
        if (cancelEvent) {
            ResetEvent(cancelEvent);
        }
        g_captureBusy.store(false, std::memory_order_relaxed);
        T2BioLog("OnSuspendResume: resume - WarmUp armed, cancel cleared, captureBusy released; awaiting WBF CAPTURE_DATA");
    }
    return 0; // return value is unused for suspend/resume notifications
}

// 24.09.2026: who completes a cancelled CAPTURE_DATA.
//
// EvtCaptureCancel completes the request at once (WBF must not wait for the
// worker to unwind). The worker used to find that out by calling
// WdfRequestUnmarkCancelable - but WDF forbids calling that after
// EvtRequestCancel has called WdfRequestComplete: the request is gone. While
// the verify wait blocked the callback thread the cancel routine could only run
// after the worker's Unmark, so it held by accident. With the wait on a worker
// thread the cancel routine runs promptly, completes the request while the
// worker is still unwinding, and the worker's Unmark / CompleteCaptureData then
// hit a completed request - the WUDFHost process died on the first cancel
// (hardware log: a new DriverEntry pid after every EvtCaptureCancel, then
// Code 43 once the restart limit was reached).
//
// One atomic per request now decides who completes it, so the worker never
// touches a request the cancel routine has taken:
//   0 = pending
//   1 = the cancel routine won: it completes the request, the worker must not
//       touch it again
//   2 = the worker won (it is finishing): the cancel routine only wakes the
//       wait; if the framework says the request was cancelled after all, the
//       worker completes it with STATUS_CANCELLED itself
// The registry lets the cancel routine find the state from the bare WDFREQUEST
// it is given; entries are added before WdfRequestMarkCancelable and removed
// before the worker completes/returns, and the state itself lives on the
// worker's stack, so the routine only touches it under g_cancelTrackMu.
struct CancelTrack {
    std::atomic<int> owner{0};
};
std::mutex g_cancelTrackMu;
std::vector<std::pair<WDFREQUEST, CancelTrack*>> g_cancelTracks;

// EVT_WDF_REQUEST_CANCEL for the in-flight CAPTURE_DATA request. WDF invokes
// this when Windows calls CancelIoEx on the pending IOCTL — per design doc
// §9.4, that is exactly what happens when a password-fallback login (or any
// other credential provider) ends the LogonUI session while our biometric
// tile is still waiting on a touch: WinBio cancels every outstanding async
// credential-provider operation, ours included.
VOID EvtCaptureCancel(_In_ WDFREQUEST Request)
{
    T2BioLog("CAPTURE_DATA: EvtCaptureCancel fired (Windows called CancelIoEx)");
    HANDLE cancelEvent = GetCaptureCancelEvent();
    if (cancelEvent) {
        SetEvent(cancelEvent); // wakes the blocked Verify()/WaitForEvent() loop
                                // within kCancelPollSlice (Connection.cpp)
    }
    bool owns = false;
    {
        std::lock_guard<std::mutex> lock(g_cancelTrackMu);
        for (auto& e : g_cancelTracks) {
            if (e.first == Request) {
                int expected = 0;
                owns = e.second->owner.compare_exchange_strong(expected, 1);
                break;
            }
        }
    }
    if (owns) {
        // WdfRequestComplete here, not CompleteCaptureData: WBDI's own contract
        // for a cancelled request is STATUS_CANCELLED at the WDF layer, not a
        // WINBIO_CAPTURE_DATA payload — there is no capture result to report.
        WdfRequestComplete(Request, STATUS_CANCELLED);
    }
}

// Marks a request cancelable for the duration of a wait and settles who
// completes it (see CancelTrack). Arm() once, then Release() exactly once.
class CancelableScope {
public:
    explicit CancelableScope(WDFREQUEST request) : request_(request) {}
    CancelableScope(const CancelableScope&) = delete;
    CancelableScope& operator=(const CancelableScope&) = delete;
    ~CancelableScope() { Unregister(); }

    // If the request was already cancelled, EvtCaptureCancel runs before this
    // returns (WdfRequestMarkCancelable's documented behaviour) - registered
    // first, so it finds its state.
    void Arm()
    {
        {
            std::lock_guard<std::mutex> lock(g_cancelTrackMu);
            g_cancelTracks.emplace_back(request_, &track_);
        }
        registered_ = true;
        WdfRequestMarkCancelable(request_, EvtCaptureCancel);
    }

    // true  -> not cancelled; the caller still owns Request and completes it.
    // false -> cancelled: Request is completed with STATUS_CANCELLED (by
    //          EvtCaptureCancel, or here) and must not be touched any more.
    bool Release()
    {
        int expected = 0;
        if (!track_.owner.compare_exchange_strong(expected, 2)) {
            Unregister();
            return false;              // the cancel routine owns the completion
        }
        const NTSTATUS st = WdfRequestUnmarkCancelable(request_);
        Unregister();
        if (st == STATUS_CANCELLED) {
            WdfRequestComplete(request_, STATUS_CANCELLED);
            return false;
        }
        return true;
    }

private:
    void Unregister()
    {
        if (!registered_) return;
        std::lock_guard<std::mutex> lock(g_cancelTrackMu);
        for (auto it = g_cancelTracks.begin(); it != g_cancelTracks.end(); ++it) {
            if (it->second == &track_) {
                g_cancelTracks.erase(it);
                break;
            }
        }
        registered_ = false;
    }

    WDFREQUEST request_;
    CancelTrack track_;
    bool registered_ = false;
};

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
    CancelableScope scope(Request);
    scope.Arm();
    SlotWait result = SlotWait::StillBusy;
    const ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < kPredecessorUnwindWaitMs) {
        if (guard.TryAcquire()) {
            result = SlotWait::Acquired;
            break;
        }
        Sleep(10);
    }
    if (!scope.Release()) {
        // Request is already completed as CANCELLED; if we did get the slot
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
    // Sleep/resume is not a failed fingerprint sample. Returning BAD_CAPTURE
    // caused the WBF session to be torn down on the affected build; report a
    // canceled operation so only WBF can decide when to issue a fresh capture.
    case VerifyOutcome::PowerTransition:           return WINBIO_E_CANCELED;
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
// Sticky adapter selection: g_stickyNcm (declared near RecentMatchCache).
bool ConnectForCapture(t2::bridgexpc::Connection* outConn)
{
    const ULONGLONG t0 = GetTickCount64();

    t2::discovery::NcmEndpoint stickyEp{};
    bool haveSticky = false;
    {
        std::lock_guard<std::mutex> lock(g_stickyNcm.mu);
        if (g_stickyNcm.valid) {
            stickyEp = g_stickyNcm.ep;
            haveSticky = true;
        }
    }
    if (haveSticky) {
        if (t2::discovery::ConnectToBiometricKitBridge(stickyEp, outConn)) {
            T2BioLog("CAPTURE_DATA: connected via sticky NCM endpoint "
                     "(discovery+connect %llu ms)",
                     static_cast<unsigned long long>(GetTickCount64() - t0));
            return true;
        }
        T2BioLog("CAPTURE_DATA: sticky NCM endpoint failed - rediscovering");
        std::lock_guard<std::mutex> lock(g_stickyNcm.mu);
        g_stickyNcm.valid = false;
    }

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
    {
        std::lock_guard<std::mutex> lock(g_stickyNcm.mu);
        g_stickyNcm.ep = ep;
        g_stickyNcm.valid = true;
    }
    T2BioLog("CAPTURE_DATA: connected to BiometricKit BridgeXPC "
             "(endpoint lookup %llu ms, discovery+connect %llu ms)",
             static_cast<unsigned long long>(t1 - t0),
             static_cast<unsigned long long>(GetTickCount64() - t1));
    return true;
}

// 24.09.2026: "the T2 is not reachable yet" is not an answer from the SEP and
// not a sensor fault. After a cold boot the SEP is unlocked (CheckSepReady
// passes) several seconds before the NCM link + BiometricKit BridgeXPC on the
// T2 side answer (cold-boot hardware log: SEP ready, then BridgeXPC
// discovery/connect failed after 6.9 s).
// The lock-screen CAPTURE_DATA used to end right there with DEVICE_FAILURE /
// SENSOR_FAILURE, WBF did not re-arm it, and the fingerprint stayed dead on
// the lock screen until the next session (i.e. after a PIN unlock).
//
// A verify CAPTURE_DATA is supposed to stay pending until a touch or Windows'
// own CancelIoEx (design doc 9.4), so an unreachable T2 is waited out the same
// way: retry with backoff, cancel-aware, and only give up (-> the old
// DEVICE_FAILURE) after kConnectRetryWindowMs so a T2 that is genuinely gone
// (NCM driver failed, no adapter) does not scan forever.
// P3.12: sticky NCM + PortCache → steady-state connect 0–16 ms on hardware.
// 120s was pre-cache; 30s still covers cold-boot NCM lag without a long hang
// when the adapter is truly missing.
constexpr ULONGLONG kConnectRetryWindowMs = 30000;
constexpr DWORD kConnectRetryFirstMs = 200;
constexpr DWORD kConnectRetryMaxMs = 2000;

enum class ConnectWait { Connected, Cancelled, GaveUp };

ConnectWait ConnectForCaptureWithRetry(HANDLE cancelEvent, t2::bridgexpc::Connection* outConn)
{
    const ULONGLONG start = GetTickCount64();
    DWORD backoffMs = kConnectRetryFirstMs;
    for (unsigned attempt = 1;; ++attempt) {
        if (ConnectForCapture(outConn)) {
            if (attempt > 1) {
                T2BioLog("CAPTURE_DATA: BridgeXPC reachable after %u attempts (%llu ms)",
                         attempt, static_cast<unsigned long long>(GetTickCount64() - start));
            }
            return ConnectWait::Connected;
        }
        if (t2::bridgexpc::Connection::IsEventSignaled(cancelEvent)) {
            return ConnectWait::Cancelled;
        }
        const ULONGLONG waited = GetTickCount64() - start;
        if (waited >= kConnectRetryWindowMs) {
            T2BioLog("CAPTURE_DATA: BridgeXPC still unreachable after %llu ms - giving up",
                     static_cast<unsigned long long>(waited));
            return ConnectWait::GaveUp;
        }
        T2BioLog("CAPTURE_DATA: BridgeXPC not reachable yet (attempt %u, %llu ms) - retrying in %lu ms",
                 attempt, static_cast<unsigned long long>(waited), static_cast<unsigned long>(backoffMs));
        if (cancelEvent) {
            if (WaitForSingleObject(cancelEvent, backoffMs) == WAIT_OBJECT_0) {
                return ConnectWait::Cancelled;
            }
        } else {
            Sleep(backoffMs);
        }
        backoffMs = (backoffMs * 2 > kConnectRetryMaxMs) ? kConnectRetryMaxMs : backoffMs * 2;
    }
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
    // Same cancel-aware connect retry as verify: cold-boot NCM lag must not
    // turn enroll into an immediate DEVICE_FAILURE (Settings → Fingerprint).
    HANDLE cancelEvent = GetCaptureCancelEvent();
    if (cancelEvent) {
        ResetEvent(cancelEvent);
    }
    CancelableScope cancelScope(Request);
    cancelScope.Arm();
    t2::bridgexpc::Connection conn;
    const ConnectWait cw = ConnectForCaptureWithRetry(cancelEvent, &conn);
    if (cw == ConnectWait::Cancelled) {
        if (cancelScope.Release()) {
            WdfRequestComplete(Request, STATUS_CANCELLED);
        }
        return;
    }
    if (cw != ConnectWait::Connected) {
        if (cancelScope.Release()) {
            CompleteCaptureData(Request, WINBIO_E_DEVICE_FAILURE, WINBIO_SENSOR_FAILURE, 0, {});
        }
        return;
    }
    if (!cancelScope.Release()) {
        return; // already completed by cancel routine
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
    CancelableScope cancelScope(Request);
    cancelScope.Arm();

    VerifyConfig cfg;
    cfg.macosUserId = kDefaultMacosUserId;
    cfg.matchWindow = kCaptureMatchWindow;
    // Post-resume / post-boot: force ResetSensor + LoadCalibration until a
    // CAPTURE actually finishes with a user-visible outcome (Match/NoMatch/…).
    // Do NOT clear the flag on Cancelled/TransportError — after sleep WBF
    // often issues CAPTURE then CancelIoEx before the user can touch (engine
    // Deactivate + credential UI lag). Clearing on that cancel left every
    // later CAPTURE on skip=true while SEP was still in MatchingCancelled
    // residue; PIN-unlock + re-lock "fixed" it only because a fresh Activate
    // eventually got a full session. Hardware log 24.09.2026.
    const bool postResumeWarmup =
        g_needPostResumeWarmup.load(std::memory_order_relaxed);
    const ULONGLONG suspendGenerationAtStart =
        g_suspendGeneration.load(std::memory_order_relaxed);
    if (postResumeWarmup) {
        cfg.skipResetSensor = false;
        cfg.skipLoadCalibration = false;
        T2BioLog("CAPTURE_DATA(verify): post-resume WarmUp armed (reset+calibration; "
                 "flag kept until non-cancel outcome)");
    }
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
        const ConnectWait cw = ConnectForCaptureWithRetry(cancelEvent, &conn);
        if (cw == ConnectWait::Cancelled) {
            T2BioLog("CAPTURE_DATA(verify): cancelled while waiting for BridgeXPC - not starting a session");
            outcome = VerifyOutcome::Cancelled;
            break;
        }
        if (cw == ConnectWait::GaveUp) {
            outcome = VerifyOutcome::TransportError;   // completed as DEVICE_FAILURE below
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

    if (outcome == VerifyOutcome::Cancelled &&
        g_suspendGeneration.load(std::memory_order_relaxed) != suspendGenerationAtStart) {
        outcome = VerifyOutcome::PowerTransition;
        T2BioLog("CAPTURE_DATA(verify): suspend generation changed during capture; "
                 "completing as WINBIO_E_CANCELED + SENSOR_READY");
    }

    if (!cancelScope.Release()) {
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
            // cancellation.
            //
            // Do NOT ArmMatchReplay here. CancelIoEx on a Match is typical of
            // Win+L / session teardown, not of WBF's post-unlock double CAPTURE.
            // Arming replay after cancel made the *next* CAPTURE (lock-screen
            // arm) complete as Match immediately — lock hung ~10s or
            // lock+auto-unlock when the user touched the sensor (2026-09-20 log:
            // MATCH discarded → cancel → "replaying Match" → Identify OK →
            // another CAPTURE waiting on the sensor).
            T2BioLog("CAPTURE_DATA(verify): *** genuine MATCH discarded - lost a race with "
                     "Windows' own CancelIoEx on this request (request already completed "
                     "as CANCELLED before we could report the match) ***");
        } else {
            T2BioLog("CAPTURE_DATA(verify): cancelled, outcome=%d discarded (request already completed)",
                     static_cast<int>(outcome));
        }
        // Any cancel ends the "real + one replay" pair; next CAPTURE must verify.
        ClearMatchReplay();
        // Keep post-resume WarmUp for the next CAPTURE (see arming comment above).
        if (postResumeWarmup &&
            (outcome == VerifyOutcome::Cancelled ||
             outcome == VerifyOutcome::PowerTransition ||
             outcome == VerifyOutcome::TransportError)) {
            g_needPostResumeWarmup.store(true, std::memory_order_relaxed);
            T2BioLog("CAPTURE_DATA(verify): post-resume WarmUp retained after cancel/transport");
        }
        return;
    }

    // Real terminal outcome (Match, NoMatch, bad capture, etc.): SEP path
    // was exercised; drop the forced WarmUp for steady-state latency.
    if (outcome != VerifyOutcome::Cancelled &&
        outcome != VerifyOutcome::PowerTransition &&
        outcome != VerifyOutcome::TransportError) {
        g_needPostResumeWarmup.store(false, std::memory_order_relaxed);
    } else if (postResumeWarmup) {
        g_needPostResumeWarmup.store(true, std::memory_order_relaxed);
        T2BioLog("CAPTURE_DATA(verify): post-resume WarmUp retained after cancel/transport");
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

// Everything CAPTURE_DATA does once the size probe and the SEP-ready gate have
// passed: claim the single capture slot, then verify / enroll. Runs on a
// worker thread (StartCaptureWorker), never inside the WDF callback.
void ProcessCapture(_In_ WDFREQUEST Request, const CaptureKey& key)
{
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

    switch (key.Purpose) {
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
        T2BioLog("CAPTURE_DATA: unsupported purpose 0x%02x -> E_NOTIMPL", static_cast<unsigned>(key.Purpose));
        CompleteCaptureData(Request, E_NOTIMPL, WINBIO_SENSOR_FAILURE, 0, {});
        return;
    }
}

// 24.09.2026: CAPTURE_DATA(verify) must not wait inside EvtIoDeviceControl.
// By design it stays pending with no deadline (design doc 9.4) - and while it
// did so on the framework's callback thread, Windows' CancelIoEx (Win+L,
// switching to the lock screen, password fallback) apparently could not be
// serviced: hardware log, 24.09.2026 - the fourth CAPTURE sat in StartMatch,
// Win+L did nothing, no EvtCaptureCancel was logged, and the cancel only
// surfaced after the next touch had produced a Match ("genuine MATCH
// discarded" then "EvtCaptureCancel fired" 9 ms apart). Most consistent
// reading: Windows waited for the cancel to complete, the cancel waited for
// the callback to return, and the callback waited for a finger. (Not proven
// at the UMDF level - verify on hardware: EvtCaptureCancel should now be
// logged at the moment of Win+L, not after the next touch.)
//
// The request is therefore handed to a worker thread and the callback returns
// at once. EvtCaptureCancel still completes a cancelled request with
// STATUS_CANCELLED right away, but the worker must now learn about it through
// CancelableScope (see CancelTrack) rather than by touching the request. The
// worker marks the request cancelable itself, after ResetEvent(cancelEvent) -
// a cancel that arrived before that makes WdfRequestMarkCancelable invoke
// EvtCaptureCancel immediately, which sets the freshly reset event, so it is
// not lost.
std::atomic<int> g_captureWorkers{0};

void StartCaptureWorker(_In_ WDFREQUEST Request, const CaptureKey& key)
{
    g_captureWorkers.fetch_add(1);
    try {
        std::thread([Request, key]() {
            ProcessCapture(Request, key);
            g_captureWorkers.fetch_sub(1);
        }).detach();
    } catch (...) {
        g_captureWorkers.fetch_sub(1);
        T2BioLog("CAPTURE_DATA: could not start the capture worker -> DEVICE_FAILURE");
        CompleteCaptureData(Request, WINBIO_E_DEVICE_FAILURE, WINBIO_SENSOR_FAILURE, 0, {});
    }
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

    // Gate: never touch the SEP - no ConnectForCapture, no busy-slot, no
    // actual fingerprint read - until T2SepBootstrap has reported the SEP
    // fully unlocked this boot. Checked after the size-probe reply above
    // (that one never touches the SEP either, so it's fine before this
    // gate) and before CaptureBusyGuard, so a not-ready request doesn't
    // consume the single in-flight capture slot or race a real one.
    {
        WINBIO_SENSOR_STATUS sensorStatus = WINBIO_SENSOR_READY;
        HRESULT hr = S_OK;
        if (!CheckSepReady(&sensorStatus, &hr)) {
            T2BioLog("CAPTURE_DATA: SEP not ready yet -> sensorStatus=%d hr=0x%08x, refusing capture",
                     static_cast<int>(sensorStatus), static_cast<unsigned>(hr));
            CompleteCaptureData(Request, hr, sensorStatus, 0, {});
            return;
        }
    }

    // Hand the request to a worker and return: the wait for a touch must not
    // occupy the WDF callback thread (see StartCaptureWorker).
    StartCaptureWorker(Request, key);
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

    case IOCTL_BIOMETRIC_RESET: {
        // WBF may RESET after power transitions. Drop all session-local
        // state so the next CAPTURE is a clean arm (same hygiene as resume).
        ClearMatchReplay();
        {
            std::lock_guard<std::mutex> lock(g_stickyNcm.mu);
            g_stickyNcm.valid = false;
        }
        HANDLE cancelEvent = GetCaptureCancelEvent();
        if (cancelEvent) {
            ResetEvent(cancelEvent);
        }
        g_captureBusy.store(false, std::memory_order_relaxed);
        g_needPostResumeWarmup.store(true, std::memory_order_relaxed);
        T2BioLog("  RESET -> session cleared, WarmUp armed, STATUS_SUCCESS");
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

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

// EVT_WDF_IO_QUEUE_IO_STOP. The framework calls this for every request the
// driver has not yet completed when the device is about to leave D0 (system
// sleep, selective suspend, connected-standby) or the queue is being purged
// (device removal). Until this callback existed, this driver had none at
// all, so WDF fell back to its documented default for a power-managed
// queue: wait for every outstanding request to complete, be acknowledged,
// or be requeued before letting the device leave D0.
//
// The one request ever left outstanding here is CAPTURE_DATA(verify)
// (HandleCaptureVerify above): by design (§9.4) it blocks with NO deadline
// until a touch or Windows' own CancelIoEx. A system sleep triggers
// neither, so with no EvtIoStop, sleep entry wound up waiting on a
// fingerprint touch that was never coming (hardware log: last CAPTURE_DATA
// sits in StartMatch, then two "IPC detected that the message to host timed
// out"). UMDF eventually kills the stalled WUDFHost.exe host process
// (Event 10110, Problem=3, ExitCode=259); enough of those and Device
// Manager gives up on the device for the rest of the boot (Event 10111,
// RestartCount=5) -> Code 43, fingerprint unlock dead until reboot.
//
// The fix does not invent a new cancellation path: it reuses the one
// Windows' own CancelIoEx already drives correctly and that is proven on
// hardware (EvtCaptureCancel / GetCaptureCancelEvent() above) - just
// triggered from a different origin (device leaving D0) instead of only
// from WinBio cancelling the IOCTL. Setting the same manual-reset event
// wakes the blocked VerificationEngine::Verify() wait (Connection.cpp,
// bounded by kCancelPollSlice) almost immediately, exactly as it does for a
// real CancelIoEx. This routine does NOT mark/unmark the request's
// cancelable state or call WdfRequestComplete itself - HandleCaptureVerify's
// own WdfRequestUnmarkCancelable / CompleteCaptureData path (above) still
// owns and completes the request once its worker thread unwinds; there is
// no lower I/O target to forward/cancel down to (the T2's SEP is reached
// over a user-mode BridgeXPC/TCP session, not a WDM device stack), so
// WdfRequestCancelSentRequest does not apply here.
// WdfRequestStopAcknowledge(Request, FALSE) tells the framework "the driver
// acknowledges the stop and will finish this request on its own" - that is
// what unblocks D0Exit/removal immediately, without waiting for the
// request's actual completion.
extern "C" VOID T2BioEvtIoStop(_In_ WDFQUEUE Queue,
                               _In_ WDFREQUEST Request,
                               _In_ ULONG ActionFlags)
{
    UNREFERENCED_PARAMETER(Queue);

    T2BioLog("EvtIoStop: ActionFlags=0x%08x cancelable=%d",
             static_cast<unsigned>(ActionFlags),
             (ActionFlags & WdfRequestStopRequestCancelable) ? 1 : 0);

    if (ActionFlags & WdfRequestStopRequestCancelable) {
        HANDLE cancelEvent = GetCaptureCancelEvent();
        if (cancelEvent) {
            SetEvent(cancelEvent); // same wakeup EvtCaptureCancel uses for a
                                    // real CancelIoEx - see header comment
        }
    }
    // If ActionFlags does NOT have WdfRequestStopRequestCancelable set, the
    // request is between WdfRequestCreate/dispatch and HandleCaptureVerify's
    // own WdfRequestMarkCancelable call (a narrow window) - nothing to wake
    // yet, but the driver still owns and will complete it shortly on its
    // own, so acknowledging now is still correct.

    WdfRequestStopAcknowledge(Request, FALSE); // FALSE: do not requeue, the
                                                // driver retains and
                                                // completes this itself
}

// Called once from DriverEntry (Driver.cpp) - see OnSuspendResume's header
// comment in this file for why this driver needs a process-wide suspend
// notification in addition to EvtIoStop. Registration failure is logged and
// otherwise ignored (not fatal to the driver's core WBDI function - it only
// means a capture left pending across a sleep can again straddle it).
extern "C" VOID T2BioRegisterSuspendResumeNotification(VOID)
{
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS params = {};
    params.Callback = OnSuspendResume;
    params.Context = nullptr;
    const DWORD err = PowerRegisterSuspendResumeNotification(
        DEVICE_NOTIFY_CALLBACK, reinterpret_cast<HANDLE>(&params), &g_suspendResumeNotify);
    if (err != ERROR_SUCCESS) {
        T2BioLog("PowerRegisterSuspendResumeNotification failed, error=%lu", static_cast<unsigned long>(err));
        g_suspendResumeNotify = nullptr;
    } else {
        T2BioLog("PowerRegisterSuspendResumeNotification ok");
    }
}

// Called from EvtDriverUnload (Driver.cpp) before the suspend/resume hook is
// dropped: capture workers are detached threads running code from this DLL, so
// wake any that is still waiting for a touch (same wakeup as EvtCaptureCancel)
// and give them a bounded moment to unwind before the host may unload us.
extern "C" VOID T2BioDrainCaptureWorkers(VOID)
{
    if (g_captureWorkers.load() == 0) {
        return;
    }
    T2BioLog("EvtDriverUnload: waiting for %d capture worker(s) to unwind", g_captureWorkers.load());
    HANDLE cancelEvent = GetCaptureCancelEvent();
    if (cancelEvent) {
        SetEvent(cancelEvent);
    }
    const ULONGLONG start = GetTickCount64();
    while (g_captureWorkers.load() != 0 && GetTickCount64() - start < 3000) {
        Sleep(10);
    }
}

// Called once from EvtDriverUnload (Driver.cpp).
extern "C" VOID T2BioUnregisterSuspendResumeNotification(VOID)
{
    if (g_suspendResumeNotify) {
        PowerUnregisterSuspendResumeNotification(g_suspendResumeNotify);
        g_suspendResumeNotify = nullptr;
    }
}

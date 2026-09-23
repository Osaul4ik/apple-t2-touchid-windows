// SPDX-License-Identifier: GPL-2.0-only
// T2SepBootstrapService.cpp
//
// Design reference: docs/windows-hello-design.md §9.2. Runs the exact
// manual sequence the user already validated by hand:
//   register-ool -> load-keybag -> set-system-keybag -> unlock handle ->
//   unlock special-user-bag -> SEP ready
// once per cold boot, entirely in-process against protocol/AppleKeyStore's
// Client (no CreateProcess of t2touchid.exe, no password on any argv).
//
// Service semantics deliberately kept minimal: this is a "do the sequence
// once, then sit idle" service, not a monitor/retry daemon. A normal
// SERVICE_AUTO_START service already only runs its start routine once per
// cold boot and is left alone (not restarted) across sleep/resume — that is
// exactly the "reboot/shutdown -> again, sleep -> no" requirement from the
// design doc, with zero extra state to persist. Do NOT configure SCM
// "restart on failure" for this service (sc.exe failure actions / the
// service INF's AddService directive) — a crash-restart would attempt to
// unlock an already-unlocked SEP; see IsAlreadyPrepared() below for the
// idempotency guard that makes a restart harmless rather than relying on
// SCM configuration alone.

// winsock2.h must be the very first Windows header this translation unit
// pulls in, same reason as driver/T2TouchIdBio/umdf/Internal.h and
// tools/t2touchid/main.cpp: protocol/Discovery and protocol/BridgeXpc
// headers (pulled in below for the post-unlock warm-up step) include
// winsock2.h/ws2tcpip.h themselves, and if <windows.h> is seen first,
// winsock.h wins the header-guard race and the later winsock2.h include
// becomes a redefinition-error mess. WIN32_LEAN_AND_MEAN keeps <windows.h>
// from re-pulling winsock.h on its own.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <fstream>
#include <ctime>
#include <thread>

#include "SepVaultFormat.h"
#include "../../protocol/AppleKeyStore/Client.h"
#include "../../protocol/Discovery/BridgeDiscovery.h"
#include "../../protocol/BiometricKit/VerificationEngine.h"

#pragma comment(lib, "crypt32.lib")

namespace {

constexpr wchar_t kServiceName[] = L"T2SepBootstrap";
constexpr wchar_t kVaultPath[] = L"C:\\ProgramData\\T2TouchId\\sep-vault.bin";
// Plain root-of-C: path instead of the previous C:\ProgramData\T2TouchId\
// location: ProgramData is hidden by default and needs an elevated/explicit
// path to browse to, which made "service installed but SEP still not
// unlocked" hard to diagnose - nothing to look at without already knowing
// where to look. C:\LogSEP.txt is trivially findable after a reboot.
constexpr wchar_t kLogPath[] = L"C:\\LogSEP.txt";

// Named event the WBDI driver's IOCTL_BIOMETRIC_GET_SENSOR_STATUS handler
// waits/polls on (design doc §9.2 step 8). "Global\" so it is visible
// across sessions — this service runs in Session 0, the WBDI driver host
// may not.
constexpr wchar_t kReadyEventName[] = L"Global\\T2SepReady";

SERVICE_STATUS gStatus = {};
SERVICE_STATUS_HANDLE gStatusHandle = nullptr;

// Plain timestamped file log, not the Windows Event Log. A proper event
// source needs a registered message-table DLL to avoid "description not
// found" noise in Event Viewer — that registration is follow-up work, not
// a blocker for this service actually functioning. This is the same
// pragmatic call the driver side already made with DbgPrintEx over a
// filtered ETW provider (see driver.h's T2_LOG comment): something that
// unconditionally records the failure reason beats a nicer mechanism that
// isn't wired up yet.
void Log(const wchar_t* msg) {
    std::wofstream f(kLogPath, std::ios::app);
    if (!f) return;
    time_t t = time(nullptr);
    wchar_t buf[32] = {};
    tm tmBuf{};
    localtime_s(&tmBuf, &t);
    wcsftime(buf, 32, L"%Y-%m-%d %H:%M:%S", &tmBuf);
    f << L"[" << buf << L"] " << msg << L"\n";
}

// Reports the current step's outcome to the driver's in-memory bootstrap
// status (public.h T2_BOOTSTRAP_STATUS, IOCTL_T2_SET_BOOTSTRAP_STATUS) so
// SepVaultGui can ask the driver "what happened" instead of parsing a
// status file this service used to maintain on disk. client must already
// be Open(); if the IOCTL itself fails, that's logged and otherwise
// swallowed — a failure to *report* status must never turn into a reason
// to fail the bootstrap sequence itself.
//
// reason is one of a small fixed set the GUI understands (see public.h):
//   ok                   - SEP fully unlocked, event signaled
//   vault-missing        - sep-vault.bin absent/corrupt, run SepVaultGui
//   dpapi                - CryptUnprotectData failed (vault copied from
//                          another machine, or ProgramData ACL tampered)
//   register-ool-failed  - transport/driver-level failure before any SEP
//                          exchange was attempted
//   sep-hang             - an AKS exchange (load-keybag / set-system-keybag /
//                          unlock) never got a reply from the SEP at all
//                          (AksResult != Ok). This is the "boot macOS, let
//                          it fault, reboot into Windows" case — the SEP
//                          coprocessor itself is wedged, not the driver or
//                          this service.
//   sep-rejected         - the SEP replied and explicitly rejected the
//                          request (sep_status != 0) - wrong password,
//                          wrong keybag, or a stale handle. Re-running
//                          SepVaultGui with the correct user.kb/password is
//                          the fix, not a macOS reboot.
//
// "driver not loaded" is deliberately NOT a reason value here: if the
// device interface can't even be opened, there is no driver instance to
// hold this status in memory in the first place - SepVaultGui detects
// that case itself the same way (its own Open() attempt), rather than the
// service somehow reporting it through the channel that doesn't exist yet.
void ReportStatus(t2::applekeystore::Client& client, T2_SEP_BOOTSTRAP_REASON reason,
                   T2_SEP_BOOTSTRAP_STEP step, int8_t sepStatus) {
    using t2::applekeystore::AksResult;
    if (client.SetBootstrapStatus(reason, step, sepStatus) != AksResult::Ok) {
        Log(L"bootstrap: SetBootstrapStatus IOCTL failed (status not reported to driver)");
    }
}

// Runs the exact same discovery+connect+WarmUp() sequence as the CLI's
// `warmup` command (main.cpp CmdWarmup/DiscoverBiometricKitBridge), minus
// argv parsing, once right after the SEP unlocks. Purpose: prime
// protocol/Discovery's port cache (SaveCachedPort, see PortCache.h) BEFORE
// Windows' first real IOCTL_BIOMETRIC_CAPTURE_DATA arrives.
//
// Why this matters: ConnectForCapture()'s own comment in
// driver/T2TouchIdBio/umdf/Queue.cpp records a real hardware trace where an
// uncached first capture cost ~3.8s of full port-scan latency, during which
// "the sensor is not armed and a touch is silently lost." A cache hit
// (TryCachedBridgePort) skips that scan entirely. Warming the cache here
// moves that cost from "in the middle of the user's first login attempt"
// to "in the background, overlapped with the rest of Windows' own boot/
// logon sequence" — by the time WinBio/Windows Hello gets around to asking
// for a fingerprint, the port is (usually) already known.
//
// Runs on a detached background thread (see call site) so a slow or failed
// discovery (T2 NCM adapter not enumerated yet, no neighbor entry yet -
// see PickDefaultT2Endpoint -> FindNeighborPeer's own built-in ff02::1
// retry) never delays ServiceMain reaching SERVICE_RUNNING. A failure here
// is not fatal to anything: it just means the first real capture pays the
// full discovery cost it always used to pay, same as before this existed.
void WarmUpBiometricKitBridge() {
    using namespace t2::discovery;
    using namespace t2::bridgexpc;
    using namespace t2::biometrickit;

    const ULONGLONG t0 = GetTickCount64();

    NcmEndpoint ep;
    if (!PickDefaultT2Endpoint(&ep)) {
        Log(L"warmup: no T2 NCM adapter found yet - skipping "
            L"(first real capture will pay full discovery cost)");
        return;
    }

    Connection bridge;
    if (!ConnectToBiometricKitBridge(ep, &bridge)) {
        wchar_t buf[96];
        swprintf_s(buf, L"warmup: BiometricKit BridgeXPC discovery/connect failed (%llu ms)",
                   static_cast<unsigned long long>(GetTickCount64() - t0));
        Log(buf);
        return;
    }

    // Same default as Queue.cpp's kDefaultMacosUserId (multi-account SEP is
    // a known unhandled gap there too - see its own comment). Warm-up's
    // only observable side effect on the SEP side is the identity-list
    // read; it does not start a match and does not require this UID to
    // already have an enrolled identity to be worth caching the port for.
    VerifyConfig cfg;
    VerificationEngine engine(cfg);
    std::vector<IdentityRecordV1> identities;
    if (!engine.WarmUp(&bridge, &identities)) {
        wchar_t buf[96];
        swprintf_s(buf, L"warmup: WarmUp() failed (%llu ms)",
                   static_cast<unsigned long long>(GetTickCount64() - t0));
        Log(buf);
        return;
    }

    wchar_t buf[128];
    swprintf_s(buf, L"warmup: OK in %llu ms, port cached, identities=%zu",
               static_cast<unsigned long long>(GetTickCount64() - t0), identities.size());
    Log(buf);
}

// RAII zeroing wrapper. Every buffer that ever holds decrypted keybag bytes
// or the plaintext password goes through this — mirrors the guarantee
// Client::Unlock() already gives its own argument (Client.h: "zeroed by
// this call before returning"), extended to cover the bytes we own before
// they ever reach Unlock().
struct ZeroingBuffer {
    std::vector<uint8_t> data;
    ~ZeroingBuffer() {
        if (!data.empty()) {
            SecureZeroMemory(data.data(), data.size());
        }
    }
};

// CryptUnprotectData wrapper. blob must have been produced by SepVaultGui
// with CRYPTPROTECT_LOCAL_MACHINE — that scope is a deliberate, final
// choice (design doc §9.3: no TPM on this hardware, DPAPI-machine is the
// accepted floor, not a placeholder for something stronger later).
bool Unprotect(const std::vector<uint8_t>& blob, std::vector<uint8_t>* outPlain) {
    if (blob.empty()) return false;
    DATA_BLOB in{};
    in.pbData = const_cast<BYTE*>(blob.data());
    in.cbData = static_cast<DWORD>(blob.size());
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_LOCAL_MACHINE, &out)) {
        return false;
    }
    outPlain->assign(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return true;
}

// Idempotency guard (see file header comment): if the ready event already
// exists AND is already signaled, a previous run in this same boot session
// already finished successfully — do not touch the SEP a second time.
// Kernel objects under "Global\" live for the lifetime of the session, not
// the process, so this survives an SCM restart-on-failure of this service
// within the same boot, which is exactly the case we need to guard.
bool AlreadyPrepared(HANDLE readyEvent) {
    return WaitForSingleObject(readyEvent, 0) == WAIT_OBJECT_0;
}

// Runs the full sequence once. Returns true only on a clean, fully-unlocked
// SEP — every intermediate failure is fail-closed (mirrors
// VerificationEngine's own stated philosophy: never convert a transport or
// SEP-level rejection into an implicit success further up the stack).
bool RunBootstrapSequence(HANDLE readyEvent) {
    using t2::applekeystore::AksResult;
    using t2::applekeystore::Client;

    Log(L"bootstrap: sequence starting");

    // Opened first, before anything else: every later failure branch needs
    // an open client to call ReportStatus() through IOCTL_T2_SET_BOOTSTRAP_STATUS.
    // If this itself fails, there is no device to report through in the
    // first place - see ReportStatus's header comment - so that one case
    // stays log-only, same as before.
    Client client;
    if (client.Open() != AksResult::Ok) {
        Log(L"bootstrap: could not open T2TouchIdTransport device interface "
            L"— driver not loaded yet? (PnP race — see design doc §10)");
        return false;
    }
    Log(L"bootstrap: T2TouchIdTransport device interface opened OK");

    auto vault = t2::sepvault::ReadVaultFile(kVaultPath);
    if (!vault.ok) {
        Log(L"bootstrap: sep-vault.bin missing or malformed — run SepVaultGui first");
        ReportStatus(client, T2SepReasonVaultMissing, T2SepStepReadVault, 0);
        return false;
    }
    Log(L"bootstrap: sep-vault.bin read OK");

    ZeroingBuffer keybag;
    ZeroingBuffer password;
    if (!Unprotect(vault.protectedKeybag, &keybag.data)) {
        Log(L"bootstrap: CryptUnprotectData failed for keybag blob "
            L"(wrong machine? vault copied from another install?)");
        ReportStatus(client, T2SepReasonDpapi, T2SepStepUnprotectKeybag, 0);
        return false;
    }
    if (!Unprotect(vault.protectedPassword, &password.data)) {
        Log(L"bootstrap: CryptUnprotectData failed for password blob");
        ReportStatus(client, T2SepReasonDpapi, T2SepStepUnprotectPassword, 0);
        return false;
    }
    Log(L"bootstrap: keybag and password unprotected OK");

    if (client.RegisterOol() != AksResult::Ok) {
        Log(L"bootstrap: register-ool failed");
        ReportStatus(client, T2SepReasonRegisterOolFailed, T2SepStepRegisterOol, 0);
        return false;
    }
    Log(L"bootstrap: register-ool OK");

    int32_t handle = 0;
    int8_t sepStatus = 0;
    if (client.LoadKeybag(keybag.data, &handle, /*session=*/1, &sepStatus) != AksResult::Ok) {
        // Exchange() itself never completed - the mailbox never posted a
        // reply (see mailbox.c T2_SEP_TIMEOUT_US). sepStatus is whatever
        // Exchange() left it at (its own default 0), NOT a real SEP
        // response, so do not present it as one - this is a wedged SEP,
        // the same family as the "SEP failed to power-gate" panic macOS
        // itself hits, and it needs the same hardware-level reset that a
        // macOS boot forces. Retrying from this service will not help;
        // see the file header comment on why this is one-shot-per-boot.
        wchar_t buf[128];
        swprintf_s(buf, L"bootstrap: load-keybag failed, sep_status=%d (SEP unresponsive)", sepStatus);
        Log(buf);
        ReportStatus(client, T2SepReasonSepHang, T2SepStepLoadKeybag, sepStatus);
        return false;
    }
    if (sepStatus != 0) {
        // Exchange completed - the SEP is alive and answered, and
        // explicitly rejected this load-keybag. Previously this fell
        // through as an implicit success (only AksResult was checked),
        // logging "OK" with a meaningless handle and letting the next
        // steps fail confusingly instead of here, with the actual reason.
        wchar_t buf[128];
        swprintf_s(buf, L"bootstrap: load-keybag rejected by SEP, sep_status=%d (bad keybag/session?)", sepStatus);
        Log(buf);
        ReportStatus(client, T2SepReasonSepRejected, T2SepStepLoadKeybag, sepStatus);
        return false;
    }
    {
        wchar_t buf[96];
        swprintf_s(buf, L"bootstrap: load-keybag OK, handle=%d, sep_status=%d", handle, sepStatus);
        Log(buf);
    }

    if (client.MakeSystemKeybag(handle, vault.specialUserBag, /*session=*/1, &sepStatus)
            != AksResult::Ok) {
        wchar_t buf[160];
        swprintf_s(buf, L"bootstrap: set-system-keybag failed, sep_status=%d (SEP unresponsive)", sepStatus);
        Log(buf);
        ReportStatus(client, T2SepReasonSepHang, T2SepStepSetSystemKeybag, sepStatus);
        return false;
    }
    if (sepStatus != 0) {
        wchar_t buf[160];
        swprintf_s(buf, L"bootstrap: set-system-keybag rejected by SEP, sep_status=%d", sepStatus);
        Log(buf);
        ReportStatus(client, T2SepReasonSepRejected, T2SepStepSetSystemKeybag, sepStatus);
        return false;
    }
    Log(L"bootstrap: set-system-keybag OK");

    // Same password unlocks both bags (confirmed against this project's own
    // hardware trace — see design doc §9.1). Client::Unlock() zeroes
    // password.data's full capacity on return per its own contract, but it
    // does that on ITS OWN parameter copy semantics — pass a fresh copy for
    // the second call since the first call is documented to zero what it
    // was given.
    std::vector<uint8_t> passwordForHandle = password.data;
    if (client.Unlock(handle, passwordForHandle, /*session=*/1, &sepStatus) != AksResult::Ok) {
        wchar_t buf[128];
        swprintf_s(buf, L"bootstrap: unlock(handle) failed, sep_status=%d (SEP unresponsive)", sepStatus);
        Log(buf);
        ReportStatus(client, T2SepReasonSepHang, T2SepStepUnlockHandle, sepStatus);
        return false;
    }
    if (sepStatus != 0) {
        wchar_t buf[128];
        swprintf_s(buf, L"bootstrap: unlock(handle) rejected by SEP, sep_status=%d (wrong password?)", sepStatus);
        Log(buf);
        ReportStatus(client, T2SepReasonSepRejected, T2SepStepUnlockHandle, sepStatus);
        return false;
    }
    Log(L"bootstrap: unlock(handle) OK");

    std::vector<uint8_t> passwordForSpecialBag = password.data; // password.data not yet zeroed — see above
    if (client.Unlock(vault.specialUserBag, passwordForSpecialBag, /*session=*/1, &sepStatus)
            != AksResult::Ok) {
        wchar_t buf[160];
        swprintf_s(buf, L"bootstrap: unlock(special bag) failed, sep_status=%d (SEP unresponsive)", sepStatus);
        Log(buf);
        ReportStatus(client, T2SepReasonSepHang, T2SepStepUnlockSpecialBag, sepStatus);
        return false;
    }
    if (sepStatus != 0) {
        wchar_t buf[160];
        swprintf_s(buf, L"bootstrap: unlock(special bag) rejected by SEP, sep_status=%d (wrong password?)", sepStatus);
        Log(buf);
        ReportStatus(client, T2SepReasonSepRejected, T2SepStepUnlockSpecialBag, sepStatus);
        return false;
    }
    Log(L"bootstrap: unlock(special bag) OK");

    Log(L"bootstrap: SEP ready");
    ReportStatus(client, T2SepReasonOk, T2SepStepReady, 0);
    SetEvent(readyEvent);
    return true;
}

DWORD WINAPI ServiceCtrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            gStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(gStatusHandle, &gStatus);
            gStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(gStatusHandle, &gStatus);
            return NO_ERROR;
        default:
            return NO_ERROR;
    }
}

VOID WINAPI ServiceMain(DWORD, LPWSTR*) {
    gStatusHandle = RegisterServiceCtrlHandlerExW(kServiceName,
        reinterpret_cast<LPHANDLER_FUNCTION_EX>(ServiceCtrlHandler), nullptr);
    if (!gStatusHandle) return;

    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = SERVICE_START_PENDING;
    gStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(gStatusHandle, &gStatus);

    Log(L"bootstrap: T2SepBootstrap service starting");

    // bInheritHandle=FALSE, DACL null (default) is fine: this event only
    // needs to be readable by other privileged components on the same
    // machine (the WBDI driver host, itself running as SYSTEM/LocalService
    // equivalents) — no cross-user isolation requirement here beyond what
    // "Global\" already implies for non-admin callers, which is out of
    // scope for a status-only event.
    HANDLE readyEvent = CreateEventW(nullptr, /*manualReset=*/TRUE,
                                      /*initialState=*/FALSE, kReadyEventName);
    if (!readyEvent) {
        // Previously silent: the service would just sit idle with zero
        // clue in the log about why the SEP was never unlocked. Log the
        // actual CreateEventW error so this doesn't look identical to
        // "sequence ran and failed silently".
        wchar_t buf[96];
        swprintf_s(buf, L"bootstrap: CreateEventW(%ls) failed, error=%lu",
                   kReadyEventName, GetLastError());
        Log(buf);
    } else if (AlreadyPrepared(readyEvent)) {
        // Nothing to report here: the driver's in-memory BootstrapStatus
        // already holds "ok" from whichever earlier run in this same boot
        // signaled the event in the first place (see driver.h field
        // comment - it lives in the device context, not this process, so
        // it survives this service restarting). Re-sending the same value
        // would only cost an IOCTL round-trip for no new information.
        Log(L"bootstrap: Global\\T2SepReady already signaled this session — skipping (SEP already unlocked)");
    } else {
        bool ok = RunBootstrapSequence(readyEvent);
        if (ok) {
            // Fire-and-forget, detached: see WarmUpBiometricKitBridge's own
            // header comment for why this must not block ServiceMain from
            // reaching SERVICE_RUNNING below. Started the instant the SEP
            // is unlocked - the earliest point warm-up can possibly begin -
            // specifically so it has the most possible head start against
            // Windows' own boot/logon sequence before a real capture
            // request can arrive. "мінімум очікування."
            std::thread(WarmUpBiometricKitBridge).detach();
        }
        // Deliberately does not retry or loop on failure here (file header
        // comment) — a failed bootstrap leaves the event unsignaled, WinBio
        // sees the sensor as not ready, and the design doc's own fallback
        // holds: the user still has their password. Diagnosis is the log
        // file, not a crash-restart loop.
    }

    gStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(gStatusHandle, &gStatus);

    // Nothing left to do — the sequence above is the entire job. Stay
    // resident and idle so SCM doesn't consider the service exited; actual
    // work is one-shot per boot per the design doc.
    while (gStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(5000);
    }
    if (readyEvent) CloseHandle(readyEvent);
}

} // namespace

int wmain() {
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        // Not started by SCM (e.g. run directly for local testing) — SCM
        // dispatcher failure with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
        // is expected in that case, not logged as a real bootstrap failure.
        return static_cast<int>(GetLastError());
    }
    return 0;
}
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

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <fstream>
#include <ctime>

#include "SepVaultFormat.h"
#include "../../protocol/AppleKeyStore/Client.h"

#pragma comment(lib, "crypt32.lib")

namespace {

constexpr wchar_t kServiceName[] = L"T2SepBootstrap";
constexpr wchar_t kVaultPath[] = L"C:\\ProgramData\\T2TouchId\\sep-vault.bin";
constexpr wchar_t kLogPath[] = L"C:\\ProgramData\\T2TouchId\\bootstrap.log";

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
    CreateDirectoryW(L"C:\\ProgramData\\T2TouchId", nullptr); // ignore ERROR_ALREADY_EXISTS
    std::wofstream f(kLogPath, std::ios::app);
    if (!f) return;
    time_t t = time(nullptr);
    wchar_t buf[32] = {};
    tm tmBuf{};
    localtime_s(&tmBuf, &t);
    wcsftime(buf, 32, L"%Y-%m-%d %H:%M:%S", &tmBuf);
    f << L"[" << buf << L"] " << msg << L"\n";
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

    auto vault = t2::sepvault::ReadVaultFile(kVaultPath);
    if (!vault.ok) {
        Log(L"bootstrap: sep-vault.bin missing or malformed — run SepVaultGui first");
        return false;
    }

    ZeroingBuffer keybag;
    ZeroingBuffer password;
    if (!Unprotect(vault.protectedKeybag, &keybag.data)) {
        Log(L"bootstrap: CryptUnprotectData failed for keybag blob "
            L"(wrong machine? vault copied from another install?)");
        return false;
    }
    if (!Unprotect(vault.protectedPassword, &password.data)) {
        Log(L"bootstrap: CryptUnprotectData failed for password blob");
        return false;
    }

    Client client;
    if (client.Open() != AksResult::Ok) {
        Log(L"bootstrap: could not open T2TouchIdTransport device interface "
            L"— driver not loaded yet? (PnP race — see design doc §10)");
        return false;
    }

    if (client.RegisterOol() != AksResult::Ok) {
        Log(L"bootstrap: register-ool failed");
        return false;
    }

    int32_t handle = 0;
    int8_t sepStatus = 0;
    if (client.LoadKeybag(keybag.data, &handle, /*session=*/1, &sepStatus) != AksResult::Ok) {
        wchar_t buf[128];
        swprintf_s(buf, L"bootstrap: load-keybag failed, sep_status=%d", sepStatus);
        Log(buf);
        return false;
    }

    if (client.MakeSystemKeybag(handle, vault.specialUserBag, /*session=*/1, &sepStatus)
            != AksResult::Ok) {
        wchar_t buf[160];
        swprintf_s(buf, L"bootstrap: set-system-keybag failed, sep_status=%d", sepStatus);
        Log(buf);
        return false;
    }

    // Same password unlocks both bags (confirmed against this project's own
    // hardware trace — see design doc §9.1). Client::Unlock() zeroes
    // password.data's full capacity on return per its own contract, but it
    // does that on ITS OWN parameter copy semantics — pass a fresh copy for
    // the second call since the first call is documented to zero what it
    // was given.
    std::vector<uint8_t> passwordForHandle = password.data;
    if (client.Unlock(handle, passwordForHandle, /*session=*/1, &sepStatus) != AksResult::Ok) {
        wchar_t buf[128];
        swprintf_s(buf, L"bootstrap: unlock(handle) failed, sep_status=%d", sepStatus);
        Log(buf);
        return false;
    }

    std::vector<uint8_t> passwordForSpecialBag = password.data; // password.data not yet zeroed — see above
    if (client.Unlock(vault.specialUserBag, passwordForSpecialBag, /*session=*/1, &sepStatus)
            != AksResult::Ok) {
        wchar_t buf[160];
        swprintf_s(buf, L"bootstrap: unlock(special bag) failed, sep_status=%d", sepStatus);
        Log(buf);
        return false;
    }

    Log(L"bootstrap: SEP ready");
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

    // bInheritHandle=FALSE, DACL null (default) is fine: this event only
    // needs to be readable by other privileged components on the same
    // machine (the WBDI driver host, itself running as SYSTEM/LocalService
    // equivalents) — no cross-user isolation requirement here beyond what
    // "Global\" already implies for non-admin callers, which is out of
    // scope for a status-only event.
    HANDLE readyEvent = CreateEventW(nullptr, /*manualReset=*/TRUE,
                                      /*initialState=*/FALSE, kReadyEventName);
    if (readyEvent && !AlreadyPrepared(readyEvent)) {
        RunBootstrapSequence(readyEvent);
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
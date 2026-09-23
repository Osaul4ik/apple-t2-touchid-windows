// SPDX-License-Identifier: GPL-2.0-only
// T2SepCoInstaller.cpp
//
// Co-installer for T2TouchIdTransport.inf (see
// [T2TouchIdTransport_Device.NT.CoInstallers] / [T2SepCoInstaller_AddReg]).
// Contract used here is the documented WDK co-installer one (DI_FUNCTION /
// COINSTALLER_CONTEXT_DATA, both from <setupapi.h>): PnP loads this DLL and
// calls its registered entry point once per DIF_ code during device
// install/removal. We only act on DIF_INSTALLDEVICE, and specifically its
// POST-processing call (Context->PostProcessing == TRUE) - the class
// installer has by then already run [T2TouchIdTransport_Device.NT]'s
// CopyFiles (so T2SepBootstrap.exe/SepVaultGui.exe are on disk) and started
// the T2TouchIdTransport kernel service. Only at that point does it make
// sense to register/refresh the T2SepBootstrap Win32 service.
//
// NOT BUILT OR HARDWARE-TESTED YET - written in an environment with no
// Windows/WDK toolchain, strictly from the documented co-installer
// contract (MSDN "Writing a Co-installer", DI_FUNCTION/
// COINSTALLER_CONTEXT_DATA). Needs a real msbuild pass and an actual
// driver install (pnputil /add-driver ... /install) before it earns the
// "VERIFIED FROM SOURCE" tag the rest of this codebase uses - treat this
// file as a first draft to build and exercise on real hardware, not as
// already-proven code.
//
// Hard rule, and the reason for every early-return below: this must NEVER
// turn an ancillary-service problem into a device-installation failure. A
// co-installer that returns anything other than NO_ERROR / the prior
// installer's own result from a DIF_INSTALLDEVICE post-processing call can
// fail the ENTIRE device install - so every failure here is logged to
// coinstaller.log and swallowed, never propagated upward. This mirrors
// T2SepBootstrapService.cpp's own "Тиша при провалі" handling (design doc
// section on that): the service's own log/Global\T2SepReady event is the
// real source of truth for whether the bootstrap sequence succeeded, not
// this installer step.

#include <windows.h>
#include <setupapi.h>
#include <string>
#include <cstdio>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

constexpr wchar_t kServiceName[] = L"T2SepBootstrap";
constexpr wchar_t kServiceDisplayName[] = L"T2 SEP Bootstrap";
constexpr wchar_t kLogPath[] = L"C:\\ProgramData\\T2TouchId\\coinstaller.log";

void Log(const wchar_t* msg) {
    CreateDirectoryW(L"C:\\ProgramData\\T2TouchId", nullptr); // ignore ERROR_ALREADY_EXISTS
    HANDLE h = CreateFileW(kLogPath, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[320];
    int n = swprintf_s(buf, L"[%04u-%02u-%02u %02u:%02u:%02u] %ls\r\n",
                        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
    if (n > 0) {
        DWORD written = 0;
        WriteFile(h, buf, static_cast<DWORD>(n) * sizeof(wchar_t), &written, nullptr);
    }
    CloseHandle(h);
}

// Fixed install location, matching [T2SepBootstrap_CopyFiles] +
// [DestinationDirs] in the INF (DIRID 11 + subdirectory "T2SepBootstrap" ->
// %SystemRoot%\System32\T2SepBootstrap\). Deliberately NOT re-derived via
// the driver-store resolution APIs used for the .sys itself
// (SetupDiGetActualSectionToInstall and friends): those answer "where did
// THIS driver PACKAGE land in the store", not "where did an arbitrary
// CopyFiles section's files go" - chasing that from a co-installer is a
// second fragile path-resolution step for no benefit when the INF already
// pins the exact target directory below.
bool GetBootstrapExePath(std::wstring* outPath) {
    wchar_t sysDir[MAX_PATH];
    UINT len = GetSystemDirectoryW(sysDir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;
    *outPath = std::wstring(sysDir) + L"\\T2SepBootstrap\\T2SepBootstrap.exe";
    return true;
}

// Idempotent: creates the service if it's not there yet, or just repoints
// an existing one at the (possibly moved/updated) binary path on a
// re-install/upgrade, instead of failing outright on ERROR_SERVICE_EXISTS.
// Deliberately does NOT set any SC_ACTION failure/recovery configuration -
// same reasoning as T2SepBootstrapService.cpp's file header: a crash-
// restart of a one-shot-per-boot service would try to unlock an
// already-unlocked SEP. Every failure path below is Log()-and-return; see
// the file header for why.
void EnsureBootstrapServiceInstalled() {
    std::wstring exePath;
    if (!GetBootstrapExePath(&exePath)) {
        Log(L"coinstaller: could not resolve System32 path for T2SepBootstrap.exe");
        return;
    }
    if (GetFileAttributesW(exePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log(L"coinstaller: T2SepBootstrap.exe not found at expected path - "
            L"did the INF's CopyFiles section actually stage it?");
        return;
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        Log(L"coinstaller: OpenSCManagerW failed");
        return;
    }

    // Quoted unconditionally: the path always contains at least one space
    // (the standard "C:\Windows" %SystemRoot% expansion), and quoting
    // costs nothing if it somehow didn't.
    std::wstring quotedPath = L"\"" + exePath + L"\"";

    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_CHANGE_CONFIG | SERVICE_START);
    if (svc) {
        if (!ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                   quotedPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                   kServiceDisplayName)) {
            Log(L"coinstaller: ChangeServiceConfigW failed on existing T2SepBootstrap service");
        } else {
            Log(L"coinstaller: T2SepBootstrap service already present, binPath refreshed");
        }
    } else {
        svc = CreateServiceW(
            scm, kServiceName, kServiceDisplayName,
            SERVICE_START, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL, quotedPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            wchar_t buf[128];
            swprintf_s(buf, L"coinstaller: CreateServiceW failed, error=%lu", GetLastError());
            Log(buf);
            CloseServiceHandle(scm);
            return;
        }
        Log(L"coinstaller: T2SepBootstrap service installed (SERVICE_AUTO_START)");
    }

    // Best-effort immediate start: covers the case where this install ran
    // mid-session (device already present, driver package just replaced)
    // rather than at a fresh cold boot - the bootstrap sequence can run
    // right away instead of waiting for the next reboot. The service's own
    // Log()/Global\T2SepReady event is the real success signal, not this
    // call's return value, so a start failure here is logged and ignored.
    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            wchar_t buf[128];
            swprintf_s(buf, L"coinstaller: StartServiceW failed (non-fatal), error=%lu", err);
            Log(buf);
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

} // namespace

extern "C" __declspec(dllexport) DWORD CALLBACK T2SepCoInstallerEntry(
    _In_ DI_FUNCTION InstallFunction,
    _In_ HDEVINFO DeviceInfoSet,
    _In_opt_ PSP_DEVINFO_DATA DeviceInfoData,
    _Inout_opt_ PCOINSTALLER_CONTEXT_DATA Context) {
    UNREFERENCED_PARAMETER(DeviceInfoSet);
    UNREFERENCED_PARAMETER(DeviceInfoData);

    if (InstallFunction != DIF_INSTALLDEVICE || !Context) {
        // Only DIF_INSTALLDEVICE is handled here; every other DIF_ code is
        // the class installer's job. NO_ERROR is the documented
        // "not handled by this co-installer, proceed normally" response.
        return NO_ERROR;
    }

    if (!Context->PostProcessing) {
        // Pre-processing call: the class installer hasn't run yet (files
        // not copied, T2TouchIdTransport service not started). Request a
        // second, post-processing call instead of acting now.
        return ERROR_DI_POSTPROCESSING_REQUIRED;
    }

    // Post-processing call: the class installer already ran. If IT failed,
    // don't layer the bootstrap service on top of a half-installed device -
    // pass the failure through unchanged and do nothing else.
    if (Context->InstallResult != NO_ERROR) {
        return Context->InstallResult;
    }

    EnsureBootstrapServiceInstalled();

    // Always hand back the class installer's own (successful) result -
    // never fail device installation over an ancillary-service problem.
    // See file header.
    return Context->InstallResult;
}
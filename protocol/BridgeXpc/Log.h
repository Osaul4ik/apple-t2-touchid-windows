// SPDX-License-Identifier: GPL-2.0-only
// Log.h — lightweight diagnostic logging for BridgeXPC + shared registry gates.
//
// Registry (HKLM\SOFTWARE\T2TouchId\Logging), DWORD 0/1 — toggled from the
// SepVault GUI. Missing key/value = disabled (off until the user enables it).
//   Bio        — T2TouchIdBio UMDF (CAPTURE, WBF)
//   Transport  — "SEP" switch: T2TouchIdTransport.sys (kernel DbgPrint; see
//                driver) AND the T2SepBootstrap service (OutputDebugString)
//   Ncm        — T2Ncm.sys + T2NcmCtrl.sys (kernel DbgPrint; see driver)
//   BridgeXpc  — this file / Connection.cpp (connect, HELO, frames)
//   Power      — sleep / resume / shutdown / D0 traces (Bio + user-mode)
//   SyncEmit   — force the old synchronous OutputDebugString per line. The UMDF driver
//                emits through a background writer by default (EnableAsync below); set
//                SyncEmit=1 when chasing a crash so the last lines cannot be lost.
//   Diag       — MASTER switch "cold-boot diagnostics": turns ALL of the above on
//                (user-mode here; T2TouchIdTransport.sys and T2Ncm.sys read it too
//                at DriverEntry / D0Entry) and enables the extra T2_DIAG lines
//                (uptime-stamped, so they line up with a DebugView boot log).
//   DiagEventLog — mirror the T2_DIAG lines (only those: curated, low volume) as ETW events
//                (provider T2TouchIdDiag, kDiagProviderGuid below). A trace session records
//                them across a cold boot when DebugView was not running yet; the session
//                (an Autologger) is installed with tools\Get-T2Diag.ps1 -Install and read
//                back with tools\Get-T2Diag.ps1. ETW, not the legacy Event Log: the UMDF
//                driver build bans RegisterEventSource/ReportEvent (C28735 "Banned Crimson
//                API"), and the UMDF host (LocalService) could not reliably create files
//                under ProgramData either (see PortCache.cpp). The flag keeps its old name.
//
// Console echo is OFF by default; --verbose / T2TOUCHID_VERBOSE=1 enables it.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntprov.h>      // ETW provider API (EventRegister / EventWriteString)
#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <chrono>
#include <cstring>

namespace t2::log {

inline constexpr wchar_t kLogRegPath[] = L"SOFTWARE\\T2TouchId\\Logging";

inline bool& ConsoleEnabled() {
    static bool enabled = false;
    return enabled;
}

inline void InitFromEnvironment(bool cliVerboseFlag) {
    if (cliVerboseFlag) {
        ConsoleEnabled() = true;
        return;
    }
    wchar_t buf[8]{};
    DWORD n = GetEnvironmentVariableW(L"T2TOUCHID_VERBOSE", buf, 8);
    if (n > 0 && buf[0] == L'1') {
        ConsoleEnabled() = true;
    }
}

// Default false when the value is absent (logging off until the GUI enables it)
// until the GUI writes an explicit 0.
inline bool RegistryFlag(const wchar_t* valueName, bool defaultValue = false) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kLogRegPath, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return defaultValue;
    }
    DWORD data = defaultValue ? 1u : 0u;
    DWORD type = 0;
    DWORD cb = sizeof(data);
    const LONG err = RegQueryValueExW(key, valueName, nullptr, &type,
                                      reinterpret_cast<LPBYTE>(&data), &cb);
    RegCloseKey(key);
    if (err != ERROR_SUCCESS || (type != REG_DWORD && type != REG_BINARY)) {
        return defaultValue;
    }
    return data != 0;
}

// RegistryFlag() costs RegOpenKeyEx + RegQueryValueEx + RegCloseKey, and the
// gates below run on EVERY log line - including the per-frame lines inside
// the recv loop (Connection::WaitForEvent / ReadFrame) while a verify is
// armed. Cache each value for kFlagTtlMs: the SepVault GUI toggle still
// takes effect, just up to that long after the write, and the hot path
// becomes one GetTickCount64() + an atomic load. A racing refresh from two
// threads is benign (both store the same registry value).
inline constexpr ULONGLONG kFlagTtlMs = 2000;

struct CachedFlag {
    std::atomic<ULONGLONG> stampMs{0};   // 0 = never read
    std::atomic<bool> value{false};      // same default as RegistryFlag()
};

inline bool CachedRegistryFlag(CachedFlag& cache, const wchar_t* valueName) {
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG last = cache.stampMs.load(std::memory_order_relaxed);
    if (last != 0 && now - last < kFlagTtlMs) {
        return cache.value.load(std::memory_order_relaxed);
    }
    const bool v = RegistryFlag(valueName);
    cache.value.store(v, std::memory_order_relaxed);
    cache.stampMs.store(now != 0 ? now : 1, std::memory_order_relaxed);
    return v;
}

// Master switch (see header). Every per-category gate below is "its own flag OR Diag".
inline bool DiagEnabled() { static CachedFlag c; return CachedRegistryFlag(c, L"Diag"); }
inline bool DiagEventLogEnabled() { static CachedFlag c; return CachedRegistryFlag(c, L"DiagEventLog"); }

inline bool BridgeXpcEnabled() { static CachedFlag c; return DiagEnabled() || CachedRegistryFlag(c, L"BridgeXpc"); }
inline bool BioEnabled() { static CachedFlag c; return DiagEnabled() || CachedRegistryFlag(c, L"Bio"); }
inline bool PowerEnabled() { static CachedFlag c; return DiagEnabled() || CachedRegistryFlag(c, L"Power"); }
inline bool TransportEnabled() { static CachedFlag c; return DiagEnabled() || CachedRegistryFlag(c, L"Transport"); }
inline bool NcmEnabled() { static CachedFlag c; return DiagEnabled() || CachedRegistryFlag(c, L"Ncm"); }
inline bool SyncEmitForced() { static CachedFlag c; return CachedRegistryFlag(c, L"SyncEmit"); }

inline int64_t ElapsedUs() {
    static const auto start = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now() - start)
        .count();
}
inline int64_t ElapsedMs() { return ElapsedUs() / 1000; }

// ---- asynchronous emit ------------------------------------------------------
// OutputDebugString is a synchronous handshake with the debugger (DBWIN mutex + shared
// buffer). With DebugView attached one call costs ~1-4 ms (field log: ~4 ms per line,
// and a 224 ms stall between two consecutive lines of one thread with no I/O between
// them), and it was paid on the verify thread between acking one bridge event and
// reading the next. A host that opts in with EnableAsync() gets its lines copied into a
// bounded queue (microseconds) and written, in order, by one low-priority writer thread.
// Hosts that do not opt in (CLI, bootstrap service, engine adapter) keep the synchronous
// path unchanged, and so does everything while SyncEmit=1 or the console echo is on.
// The writer holds a reference on its own module until Shutdown(), so a DLL cannot be
// unloaded under it; the host must call Shutdown() from its unload callback.
inline constexpr size_t kAsyncMaxLines = 8192;

struct AsyncSink {
    std::mutex mu;
    std::deque<std::wstring> q;
    size_t dropped = 0;
    HANDLE wake = nullptr;       // auto-reset: queue became non-empty / stop requested
    HANDLE thread = nullptr;
    HMODULE module = nullptr;    // reference held by the writer thread
    std::atomic<bool> enabled{false};
    std::atomic<bool> stop{false};
};
inline AsyncSink& Sink() { static AsyncSink s; return s; }

inline DWORD WINAPI AsyncWriterMain(LPVOID) {
    AsyncSink& s = Sink();
    std::deque<std::wstring> batch;
    for (;;) {
        WaitForSingleObject(s.wake, INFINITE);
        size_t dropped = 0;
        {
            std::lock_guard<std::mutex> lock(s.mu);
            batch.swap(s.q);
            dropped = s.dropped;
            s.dropped = 0;
        }
        for (const std::wstring& l : batch) {
            OutputDebugStringW(l.c_str());
        }
        batch.clear();
        if (dropped != 0) {
            wchar_t msg[96];
            _snwprintf_s(msg, _TRUNCATE, L"T2TouchIdLog: dropped %zu line(s), async queue full\n", dropped);
            OutputDebugStringW(msg);
        }
        if (s.stop.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(s.mu);
            if (s.q.empty()) break;
        }
    }
    FreeLibraryAndExitThread(s.module, 0);
}

// Call once, early (DriverEntry). Returns false (and stays synchronous) on any failure.
inline bool EnableAsync() {
    AsyncSink& s = Sink();
    if (s.enabled.load(std::memory_order_acquire)) return true;
    s.stop.store(false, std::memory_order_relaxed);
    s.wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!s.wake) return false;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                            reinterpret_cast<LPCWSTR>(&AsyncWriterMain), &s.module)) {
        CloseHandle(s.wake);
        s.wake = nullptr;
        return false;
    }
    s.thread = CreateThread(nullptr, 0, AsyncWriterMain, nullptr, 0, nullptr);
    if (!s.thread) {
        FreeLibrary(s.module);
        s.module = nullptr;
        CloseHandle(s.wake);
        s.wake = nullptr;
        return false;
    }
    SetThreadPriority(s.thread, THREAD_PRIORITY_BELOW_NORMAL);
    s.enabled.store(true, std::memory_order_release);
    return true;
}

// Flushes the queue and ends the writer thread; lines emitted afterwards are synchronous.
// Call from the unload callback BEFORE the host may unload the module.
inline void Shutdown() {
    AsyncSink& s = Sink();
    if (!s.enabled.exchange(false, std::memory_order_acq_rel)) return;
    s.stop.store(true, std::memory_order_release);
    SetEvent(s.wake);
    if (WaitForSingleObject(s.thread, 3000) == WAIT_OBJECT_0) {
        CloseHandle(s.thread);
        s.thread = nullptr;
        CloseHandle(s.wake);
        s.wake = nullptr;
    }   // else: writer stuck in OutputDebugString - leak the handles rather than race it
}

inline bool AsyncActive() {
    return Sink().enabled.load(std::memory_order_acquire) && !ConsoleEnabled() && !SyncEmitForced();
}

inline void AsyncEnqueue(const wchar_t* line) {
    AsyncSink& s = Sink();
    bool wasEmpty = false;
    {
        std::lock_guard<std::mutex> lock(s.mu);
        if (s.q.size() >= kAsyncMaxLines) {
            ++s.dropped;                 // reported by the writer on its next pass
            return;
        }
        wasEmpty = s.q.empty();
        s.q.emplace_back(line);
    }
    if (wasEmpty) SetEvent(s.wake);
}

inline void EmitLine(const wchar_t* line) {
    if (AsyncActive()) {
        AsyncEnqueue(line);
        return;
    }
    OutputDebugStringW(line);
    if (ConsoleEnabled()) {
        std::wcerr << line;
    }
}

// Narrow-line variant for callers that format in ANSI (T2BioLog). Lines are ASCII.
inline void EmitLineA(const char* line) {
    if (AsyncActive()) {
        wchar_t w[512];
        size_t n = 0;
        for (; line[n] != '\0' && n < ARRAYSIZE(w) - 1; ++n) {
            w[n] = static_cast<unsigned char>(line[n]);
        }
        w[n] = L'\0';
        AsyncEnqueue(w);
        return;
    }
    OutputDebugStringA(line);
}

// Seconds since Windows booted. Deliberately NOT process-relative: the kernel DebugView
// boot log counts seconds from boot too, so a T2_DIAG line "up=8.412s" sits at the same
// place on that timeline (e.g. "T2SepBootstrap finished at 8.5 s, CAPTURE_DATA arrived
// at 7.9 s").
inline double UptimeSec() {
    return static_cast<double>(GetTickCount64()) / 1000.0;
}

// ETW provider "T2TouchIdDiag" (manifest-free: every event is one Unicode string). Nothing is
// stored unless a trace session listens - tools\Get-T2Diag.ps1 -Install creates an Autologger
// that does, from early boot.
inline constexpr GUID kDiagProviderGuid =
    { 0x7b1d6f0e, 0x3c52, 0x4c7a, { 0x9a, 0x5e, 0x2f, 0x4d, 0x8e, 0x1b, 0x6a, 0x93 } };

// One line as an ETW event (level 4 = informational). The registration is opened once per
// process and kept for the process lifetime; a failed registration just disables the mirror.
inline void WriteDiagEventLog(const wchar_t* line) {
    static const REGHANDLE h = [] {
        REGHANDLE r = 0;
        if (EventRegister(&kDiagProviderGuid, nullptr, nullptr, &r) != ERROR_SUCCESS) {
            r = 0;
        }
        return r;
    }();
    if (h != 0) {
        EventWriteString(h, 4, 0, line);
    }
}

// Diagnostic line (cold-boot investigation). Only when the master Diag switch is on.
// DebugView + (if DiagEventLog is on) the ETW provider above. Prefix:
//   "T2TouchIdDiag: [pid:tid up=<s since boot>][tag] msg"
inline void Diagf(const wchar_t* tag, const wchar_t* fmt, ...) {
    if (!DiagEnabled()) {
        return;
    }
    wchar_t msg[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(msg, _TRUNCATE, fmt, args);
    va_end(args);

    wchar_t line[1200];
    _snwprintf_s(line, _TRUNCATE, L"T2TouchIdDiag: [%lu:%lu up=%.3fs][%s] %s\n",
                 GetCurrentProcessId(), GetCurrentThreadId(), UptimeSec(), tag, msg);
    EmitLine(line);
    if (DiagEventLogEnabled()) {
        WriteDiagEventLog(line);
    }
}

inline void Logf(const wchar_t* tag, const wchar_t* fmt, ...) {
    if (!BridgeXpcEnabled()) {
        return;
    }
    wchar_t msg[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(msg, _TRUNCATE, fmt, args);
    va_end(args);

    wchar_t line[1100];
    // Same shape as every other component: "<prefix>: [pid:tid] msg"
    // (T2TouchIdBio / T2TouchIdEngine / T2TouchIdBootstrap), so one DebugView
    // filter - T2TouchId* - catches all user-mode output.
    // +<ms>.<us>: sub-millisecond stamp, taken BEFORE the line is emitted.
    const int64_t us = ElapsedUs();
    _snwprintf_s(line, _TRUNCATE, L"T2TouchIdBridge: [%lu:%lu +%lld.%03lldms][%s] %s\n",
                 GetCurrentProcessId(), GetCurrentThreadId(),
                 static_cast<long long>(us / 1000), static_cast<long long>(us % 1000), tag, msg);
    EmitLine(line);
}

// Logf() formats into a 1024-wchar buffer and silently truncates, so hex
// past ~480 bytes never reaches the log anyway. Cap it here instead of
// formatting (and allocating) up to 3.3KB per event only to drop it.
inline constexpr size_t kMaxHexBytes = 480;

// Table-driven: the old version called swprintf_s once per byte
// (e.g. 3370 calls for a match_result event, 512 per status event).
inline std::wstring HexDump(const uint8_t* data, size_t size, size_t maxBytes = 32) {
    static constexpr wchar_t kDigits[] = L"0123456789abcdef";
    if (maxBytes > kMaxHexBytes) maxBytes = kMaxHexBytes;
    const size_t n = size < maxBytes ? size : maxBytes;
    std::wstring out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out[2 * i]     = kDigits[data[i] >> 4];
        out[2 * i + 1] = kDigits[data[i] & 0x0F];
    }
    if (size > n) out += L"...";
    return out;
}

inline std::wstring HexDump(const std::vector<uint8_t>& data, size_t maxBytes = 32) {
    return HexDump(data.data(), data.size(), maxBytes);
}

inline std::wstring Widen(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

} // namespace t2::log

// The gate sits in the macro (not only inside Logf) so that a disabled log
// line does not evaluate its arguments either: several call sites build a
// HexDump()/Widen() std::wstring inline (e.g. the 512-byte event dump in
// Connection::WaitForEvent = 512 swprintf_s calls per event), and with
// arguments evaluated eagerly that cost was paid even with logging off.
// Logf() keeps its own check for the direct ::t2::log::Logf() callers.
#define T2_LOG(tag, ...) \
    do { if (::t2::log::BridgeXpcEnabled()) ::t2::log::Logf(L##tag, __VA_ARGS__); } while (0)

// Cold-boot diagnostics (master Diag switch). Same eager-argument rule as T2_LOG.
#define T2_DIAG(tag, ...) \
    do { if (::t2::log::DiagEnabled()) ::t2::log::Diagf(L##tag, __VA_ARGS__); } while (0)
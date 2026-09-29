// SPDX-License-Identifier: GPL-2.0-only
// Log.h — lightweight diagnostic logging for BridgeXPC + shared registry gates.
//
// Registry (HKLM\SOFTWARE\T2TouchId\Logging), DWORD 0/1 — toggled from the
// SepVault GUI. Missing key/value = disabled (off until the user enables it).
//   Bio        — T2TouchIdBio UMDF (CAPTURE, WBF)
//   Transport  — T2TouchIdTransport.sys (kernel DbgPrint; see driver)
//   Ncm        — T2Ncm.sys (kernel DbgPrint; see driver)
//   BridgeXpc  — this file / Connection.cpp (connect, HELO, frames)
//   Power      — sleep / resume / shutdown / D0 traces (Bio + user-mode)
//
// Console echo is OFF by default; --verbose / T2TOUCHID_VERBOSE=1 enables it.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
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

inline bool BridgeXpcEnabled() { static CachedFlag c; return CachedRegistryFlag(c, L"BridgeXpc"); }
inline bool BioEnabled() { static CachedFlag c; return CachedRegistryFlag(c, L"Bio"); }
inline bool PowerEnabled() { static CachedFlag c; return CachedRegistryFlag(c, L"Power"); }
inline bool TransportEnabled() { static CachedFlag c; return CachedRegistryFlag(c, L"Transport"); }
inline bool NcmEnabled() { static CachedFlag c; return CachedRegistryFlag(c, L"Ncm"); }

inline int64_t ElapsedMs() {
    static const auto start = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
        .count();
}

inline void EmitLine(const wchar_t* line) {
    OutputDebugStringW(line);
    if (ConsoleEnabled()) {
        std::wcerr << line;
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
    _snwprintf_s(line, _TRUNCATE, L"[t2touchid +%lldms][%s] %s\n",
                 static_cast<long long>(ElapsedMs()), tag, msg);
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
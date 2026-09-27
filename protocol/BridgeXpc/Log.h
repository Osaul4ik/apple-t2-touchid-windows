// SPDX-License-Identifier: GPL-2.0-only
// Log.h — lightweight diagnostic logging for BridgeXPC + shared registry gates.
//
// Registry (HKLM\SOFTWARE\T2TouchId\Logging), DWORD 0/1 — toggled from the
// SepVault GUI. Missing key/value = enabled (keep DebugView behaviour until
// the user opts out).
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

// Default true when the value is absent so existing installs keep logging
// until the GUI writes an explicit 0.
inline bool RegistryFlag(const wchar_t* valueName, bool defaultValue = true) {
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

inline bool BridgeXpcEnabled() { return RegistryFlag(L"BridgeXpc"); }
inline bool BioEnabled() { return RegistryFlag(L"Bio"); }
inline bool PowerEnabled() { return RegistryFlag(L"Power"); }
inline bool TransportEnabled() { return RegistryFlag(L"Transport"); }
inline bool NcmEnabled() { return RegistryFlag(L"Ncm"); }

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

inline std::wstring HexDump(const std::vector<uint8_t>& data, size_t maxBytes = 32) {
    std::wstring out;
    size_t n = data.size() < maxBytes ? data.size() : maxBytes;
    out.reserve(n * 2 + 3);
    wchar_t b[4];
    for (size_t i = 0; i < n; ++i) {
        swprintf_s(b, L"%02x", data[i]);
        out += b;
    }
    if (data.size() > n) out += L"...";
    return out;
}

inline std::wstring Widen(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

} // namespace t2::log

#define T2_LOG(tag, ...) ::t2::log::Logf(L##tag, __VA_ARGS__)

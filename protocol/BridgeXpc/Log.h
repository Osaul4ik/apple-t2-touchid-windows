// SPDX-License-Identifier: GPL-2.0-only
// Log.h — lightweight diagnostic logging for the BridgeXPC transport.
//
// Every OutputDebugStringW call below is free to leave in permanently
// (DebugView-only visibility, near-zero cost when nobody's attached) and
// is meant to answer exactly the class of question "<command> failed" on
// its own gives no way to answer: which of the several internal steps
// inside Connect()/SendBiometricCommand()/etc. actually returned false,
// and with what OS-level detail (WSAGetLastError, frame type/length,
// request-id mismatch, reply shape).
//
// Console echo (T2_LOG) is OFF by default — `identities`/`verify` stay
// quiet on the happy path — and is turned on for the process by main.cpp
// when it sees `--verbose`/`-v` or the T2TOUCHID_VERBOSE=1 environment
// variable. DebugView output is unconditional: attach DebugView (running
// as Administrator, "Capture Global Win32") before running the command
// and every line below shows up there regardless of the console flag.
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

namespace t2::log {

inline bool& ConsoleEnabled() {
    static bool enabled = false;
    return enabled;
}

// Call once from wmain() before dispatching a command.
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

// Millisecond-resolution timestamp since process start — enough to see
// gaps between steps (e.g. "was the 5000ms LoadCalibration timeout
// actually hit, or did it fail fast?") without pulling in wall-clock
// formatting.
inline int64_t ElapsedMs() {
    static const auto start = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
        .count();
}

inline void Logf(const wchar_t* tag, const wchar_t* fmt, ...) {
    wchar_t msg[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(msg, _TRUNCATE, fmt, args);
    va_end(args);

    wchar_t line[1100];
    _snwprintf_s(line, _TRUNCATE, L"[t2touchid +%lldms][%s] %s\n",
                 static_cast<long long>(ElapsedMs()), tag, msg);

    // Always goes to DebugView - cheap, and it's the whole point of this
    // file (a way to see what happened without --verbose cluttering a
    // normal run, and without needing to repro under a debugger).
    OutputDebugStringW(line);
    if (ConsoleEnabled()) {
        std::wcerr << line;
    }
}

// Hex-dumps up to maxBytes of a buffer, with a trailing "..." marker if
// truncated. Never dumps more than maxBytes regardless of caller intent -
// this is a diagnostic aid, not a way to leak an entire multi-KB
// calibration blob into DebugView.
inline std::wstring HexDump(const std::vector<uint8_t>& data, size_t maxBytes = 32) {
    std::wstring out;
    size_t n = data.size() < maxBytes ? data.size() : maxBytes;
    out.reserve(n * 2 + 3);
    wchar_t b[4];
    for (size_t i = 0; i < n; ++i) {
        swprintf_s(b, L"%02x", data[i]);   // swprintf is banned (C28719)
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
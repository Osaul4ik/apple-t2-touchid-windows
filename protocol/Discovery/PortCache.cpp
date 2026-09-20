// SPDX-License-Identifier: GPL-2.0-only
// PortCache.cpp — see PortCache.h for the contract and why this exists.
//
// Storage format: %LOCALAPPDATA%\t2touchid\portcache.ini, one entry per
// line as "AA:BB:CC:DD:EE:FF=12345". Deliberately plain text, not a
// registry key or anything more structured — this is a single scalar
// value per adapter and a human being may well want to `type` the file
// while debugging a discovery issue.
#include "PortCache.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <utility>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <mutex>

namespace t2::discovery {
namespace {

// 20.09.2026: process-lifetime cache, consulted BEFORE the file below.
//
// Why it exists: the file cache lives under %LOCALAPPDATA%, which for the
// UMDF host (WUDFHost.exe, LocalService, sandboxed) is either unset or not
// writable, and the failure is silent by design. Hardware log evidence: every
// single CAPTURE_DATA in one WUDFHost process paid a constant ~3.8s between
// "CAPTURE_DATA: begin" and the BridgeXPC HELO (a full 16k-port scan), and no
// "connect() to port ... failed" line ever appeared - i.e. the cached-port
// fast path was never even attempted. The WUDFHost process outlives every
// capture, so a plain static map is enough to make every capture after the
// first skip the scan. Like the file, it is only a hint: the caller still
// verifies the port with a live HELO and falls back to a scan on any miss.
struct MemPorts { uint16_t port = 0; uint16_t rsd = 0; };
std::mutex g_memMu;
std::map<std::string, MemPorts>& MemCache() {
    static std::map<std::string, MemPorts> m;
    return m;
}

std::string FormatMacKey(const unsigned char mac[6]) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string ToUpperAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                    [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

// 20.09.2026: the cache now lives in %ProgramData%\\t2touchid (machine-wide),
// not %LOCALAPPDATA%. The UMDF driver host (WUDFHost, LocalService) has a
// different/absent per-user profile than the interactive user running the
// CLI, so a per-user cache was never shared with (or usable by) the driver
// and every CAPTURE_DATA fell back to a full port scan. Returns "" if
// neither variable is set - callers then just scan.
std::string CacheDir() {
    char buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) n = GetEnvironmentVariableA("ALLUSERSPROFILE", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return "";
    std::string dir = buf;
    dir += "\\t2touchid";
    return dir;
}

// Old per-user location, still read (never written) so an existing CLI
// cache keeps working until the new file is populated.
std::string LegacyCacheFilePath() {
    char buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return "";
    return std::string(buf) + "\\t2touchid\\portcache.ini";
}

std::string CacheFilePath() {
    std::string dir = CacheDir();
    if (dir.empty()) return "";
    return dir + "\\portcache.ini";
}

// Reads every "KEY=VALUE" line into an ordered vector (order preserved so
// SaveCachedPort can rewrite the file without reshuffling unrelated
// adapters' entries — mainly a diff-friendliness nicety, not a
// correctness requirement). Missing/unreadable file just yields an empty
// vector, same as an empty cache.
std::vector<std::pair<std::string, std::string>> ReadEntries(const std::string& path) {
    std::vector<std::pair<std::string, std::string>> entries;
    if (path.empty()) return entries;
    std::ifstream in(path);
    if (!in.is_open()) return entries;
    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;
        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) continue;
        std::string key = ToUpperAscii(Trim(trimmed.substr(0, eq)));
        std::string value = Trim(trimmed.substr(eq + 1));
        if (key.empty() || value.empty()) continue;
        entries.emplace_back(std::move(key), std::move(value));
    }
    return entries;
}

bool WriteEntries(const std::string& path,
                   const std::vector<std::pair<std::string, std::string>>& entries) {
    if (path.empty()) return false;
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) return false;
    out << "# t2touchid port cache - last known-good BiometricKit BridgeXPC\n"
           "# port[,RemoteXPC port] per T2 adapter (keyed by MAC). Safe to delete; the tool\n"
           "# just falls back to a full port scan next run.\n";
    for (const auto& kv : entries) {
        out << kv.first << "=" << kv.second << "\n";
    }
    return true;
}

} // namespace

bool LoadCachedPort(const NcmEndpoint& endpoint, uint16_t* outPort, uint16_t* outRsdPort) {
    if (!endpoint.hasMac) return false; // no stable key to look up

    {
        std::lock_guard<std::mutex> lock(g_memMu);
        auto it = MemCache().find(FormatMacKey(endpoint.mac));
        if (it != MemCache().end() && it->second.port != 0) {
            if (outPort) *outPort = it->second.port;
            if (outRsdPort) *outRsdPort = it->second.rsd;
            return true;
        }
    }

    std::string key = FormatMacKey(endpoint.mac);
    auto entries = ReadEntries(CacheFilePath());          // new machine-wide file first
    {
        auto legacy = ReadEntries(LegacyCacheFilePath()); // then the old per-user one
        entries.insert(entries.end(), legacy.begin(), legacy.end());
    }
    for (const auto& kv : entries) {
        if (kv.first != key) continue;
        // Value is "<servicePort>" (legacy) or "<servicePort>,<rsdPort>".
        std::string first = kv.second;
        std::string second;
        size_t comma = kv.second.find(',');
        if (comma != std::string::npos) {
            first = Trim(kv.second.substr(0, comma));
            second = Trim(kv.second.substr(comma + 1));
        }
        int value = 0;
        try {
            value = std::stoi(first);
        } catch (...) {
            return false; // corrupt entry - treat as no cache, not a crash
        }
        if (value <= 0 || value > 65535) return false;
        int rsd = 0;
        if (!second.empty()) {
            try { rsd = std::stoi(second); } catch (...) { rsd = 0; }
            if (rsd <= 0 || rsd > 65535) rsd = 0;
        }
        if (outPort) *outPort = static_cast<uint16_t>(value);
        if (outRsdPort) *outRsdPort = static_cast<uint16_t>(rsd);
        return true;
    }
    return false;
}

void SaveCachedPort(const NcmEndpoint& endpoint, uint16_t port, uint16_t rsdPort) {
    if (!endpoint.hasMac) return; // nothing stable to key this entry on
    if (port == 0) return;

    {
        // Always remember it for this process, even if the file below can't
        // be written (see the note on g_memMu).
        std::lock_guard<std::mutex> lock(g_memMu);
        MemPorts& m = MemCache()[FormatMacKey(endpoint.mac)];
        m.port = port;
        m.rsd = rsdPort;
    }

    std::string dir = CacheDir();
    if (dir.empty()) return;
    // Best-effort: ERROR_ALREADY_EXISTS is the expected/common case after
    // the first run and is not a failure worth reporting.
    CreateDirectoryA(dir.c_str(), nullptr);

    std::string path = CacheFilePath();
    if (path.empty()) return;

    std::string key = FormatMacKey(endpoint.mac);
    std::string value = std::to_string(port);
    if (rsdPort != 0) value += "," + std::to_string(rsdPort);

    auto entries = ReadEntries(path);
    bool updated = false;
    for (auto& kv : entries) {
        if (kv.first == key) {
            kv.second = value;
            updated = true;
            break;
        }
    }
    if (!updated) entries.emplace_back(key, value);

    WriteEntries(path, entries); // failure here is silent by design — see header
}

} // namespace t2::discovery
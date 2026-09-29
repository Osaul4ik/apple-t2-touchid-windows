// SPDX-License-Identifier: GPL-2.0-only
// PortCache.cpp — see PortCache.h for the contract and why this exists.
//
// Storage format: %ProgramData%\t2touchid\portcache.ini, one entry per
// line as "AA:BB:CC:DD:EE:FF=12345" or "AA:BB:CC:DD:EE:FF=12345,6789".
// Deliberately plain text — a single scalar per adapter; safe to delete
// (next successful connect re-creates it after a full port scan).
//
// Contract for callers (BridgeDiscovery / CLI):
//   - LoadCachedPort returns false when the file is missing, unreadable,
//     has no entry for this MAC, or the entry has an empty / invalid port.
//     That is the signal to run a full scan — never treat a missing or
//     empty cache as a reason to block.
//   - SaveCachedPort is best-effort but must actually create the directory
//     and file when possible (UMDF runs as LocalService; %ProgramData% is
//     the shared location that both CLI and driver can use).
#include "PortCache.h"
#include "../BridgeXpc/Log.h"
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

// Process-lifetime cache, consulted BEFORE the file below.
//
// Why it exists: the file cache under %ProgramData% is shared, but a failed
// or delayed first write still left every CAPTURE_DATA in the same WUDFHost
// process paying a full 16k-port scan. The process outlives every capture,
// so a plain static map makes every capture after the first skip the scan.
// Like the file, it is only a hint: the caller still verifies the port with
// a live HELO and falls back to a scan on any miss.
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

// Machine-wide cache under %ProgramData%\t2touchid so the UMDF host
// (WUDFHost, LocalService) and the interactive CLI share one file.
// Returns "" if neither ProgramData nor ALLUSERSPROFILE is set — callers
// then just scan.
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

// Parse "port" or "port,rsdPort". Returns false when the service port is
// missing, non-numeric, or out of the valid TCP range (0 is not a valid
// BridgeXPC port). Empty / corrupt value ⇒ cache miss ⇒ full scan.
bool ParsePortValue(const std::string& raw, uint16_t* outPort, uint16_t* outRsd) {
    std::string first = raw;
    std::string second;
    size_t comma = raw.find(',');
    if (comma != std::string::npos) {
        first = Trim(raw.substr(0, comma));
        second = Trim(raw.substr(comma + 1));
    }
    if (first.empty()) return false;
    int value = 0;
    try {
        value = std::stoi(first);
    } catch (...) {
        return false;
    }
    if (value <= 0 || value > 65535) return false;
    int rsd = 0;
    if (!second.empty()) {
        try { rsd = std::stoi(second); } catch (...) { rsd = 0; }
        if (rsd <= 0 || rsd > 65535) rsd = 0;
    }
    if (outPort) *outPort = static_cast<uint16_t>(value);
    if (outRsd) *outRsd = static_cast<uint16_t>(rsd);
    return true;
}

// Reads every "KEY=VALUE" line into an ordered vector. Missing/unreadable
// file or lines with empty values yield no entries (cache miss).
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
        // Empty value (e.g. "AA:BB:...=") is intentionally skipped — that is
        // a cache miss and must trigger a full scan, not a connect to port 0.
        if (key.empty() || value.empty()) continue;
        entries.emplace_back(std::move(key), std::move(value));
    }
    return entries;
}

// Atomic-ish write: write to path.tmp then replace path. Avoids leaving a
// truncated portcache.ini if the process dies mid-write (which would look
// like "file exists but no port" on the next unlock).
bool WriteEntries(const std::string& path,
                   const std::vector<std::pair<std::string, std::string>>& entries) {
    if (path.empty()) return false;
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out.is_open()) return false;
        out << "# t2touchid port cache - last known-good BiometricKit BridgeXPC\n"
               "# port[,RemoteXPC port] per T2 adapter (keyed by MAC). Safe to delete; the tool\n"
               "# just falls back to a full port scan next run.\n";
        for (const auto& kv : entries) {
            // Never persist an empty value — that would re-create the
            // "file exists, port not written" hang on the next boot.
            if (kv.first.empty() || kv.second.empty()) continue;
            out << kv.first << "=" << kv.second << "\n";
        }
        out.flush();
        if (!out.good()) {
            out.close();
            DeleteFileA(tmp.c_str());
            return false;
        }
    }
    // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
    if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        // Fallback: direct rewrite if MoveFileEx fails (e.g. cross-volume).
        std::ofstream out(path, std::ios::trunc);
        if (!out.is_open()) {
            DeleteFileA(tmp.c_str());
            return false;
        }
        std::ifstream in(tmp);
        if (in.is_open()) {
            out << in.rdbuf();
        }
        out.close();
        DeleteFileA(tmp.c_str());
        return static_cast<bool>(out);
    }
    return true;
}

bool EnsureCacheDir(const std::string& dir) {
    if (dir.empty()) return false;
    if (CreateDirectoryA(dir.c_str(), nullptr)) return true;
    const DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS) return true;
    return GetFileAttributesA(dir.c_str()) != INVALID_FILE_ATTRIBUTES;
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
    auto entries = ReadEntries(CacheFilePath());          // machine-wide file first
    {
        auto legacy = ReadEntries(LegacyCacheFilePath()); // then old per-user one
        entries.insert(entries.end(), legacy.begin(), legacy.end());
    }

    // File missing, empty, or only comments/blank lines ⇒ entries empty ⇒
    // return false ⇒ caller runs a full port scan. Same if our MAC has no
    // line, or the line has an empty / non-numeric / out-of-range port.
    for (const auto& kv : entries) {
        if (kv.first != key) continue;
        uint16_t port = 0, rsd = 0;
        if (!ParsePortValue(kv.second, &port, &rsd)) {
            // Corrupt or empty port for this MAC: skip this line (do not
            // treat as a hit). Keep scanning entries in case a later line
            // for the same MAC is valid; if none are, fall through to false.
            continue;
        }
        if (outPort) *outPort = port;
        if (outRsdPort) *outRsdPort = rsd;
        // Warm the process cache so the next CAPTURE in this WUDFHost skips
        // the file read as well.
        {
            std::lock_guard<std::mutex> lock(g_memMu);
            MemPorts& m = MemCache()[key];
            m.port = port;
            m.rsd = rsd;
        }
        return true;
    }
    return false;
}

void SaveCachedPort(const NcmEndpoint& endpoint, uint16_t port, uint16_t rsdPort) {
    if (!endpoint.hasMac) return; // nothing stable to key this entry on
    if (port == 0) return;         // never persist an empty/zero port

    const std::string key = FormatMacKey(endpoint.mac);

    {
        // Always remember it for this process, even if the file below can't
        // be written (UMDF sandbox / ACL edge cases).
        std::lock_guard<std::mutex> lock(g_memMu);
        MemPorts& m = MemCache()[key];
        m.port = port;
        m.rsd = rsdPort;
    }

    std::string dir = CacheDir();
    if (dir.empty()) {
        T2_LOG("discovery", L"SaveCachedPort: no ProgramData - file cache disabled");
        return;
    }
    if (!EnsureCacheDir(dir)) {
        T2_LOG("discovery", L"SaveCachedPort: CreateDirectory(%hs) failed err=%lu",
               dir.c_str(), GetLastError());
        return;
    }

    std::string path = CacheFilePath();
    if (path.empty()) return;

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

    if (!WriteEntries(path, entries)) {
        T2_LOG("discovery", L"SaveCachedPort: write %hs failed err=%lu - next boot will re-scan",
               path.c_str(), GetLastError());
        return;
    }
    T2_LOG("discovery", L"SaveCachedPort: wrote %hs port=%u rsd=%u",
           path.c_str(), static_cast<unsigned>(port), static_cast<unsigned>(rsdPort));
}

} // namespace t2::discovery

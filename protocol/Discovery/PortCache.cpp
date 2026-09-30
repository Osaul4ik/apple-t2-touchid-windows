// SPDX-License-Identifier: GPL-2.0-only
// PortCache.cpp — see PortCache.h for the contract and why this exists.
//
// Storage: one REG_SZ value per T2 adapter under
//   HKLM\SOFTWARE\T2TouchId\Network\PortCache
// value name = adapter MAC "AA:BB:CC:DD:EE:FF", data = "12345" or "12345,6789"
// (BridgeXPC port[,RemoteXPC port]). Deliberately plain text — a single scalar
// per adapter; safe to delete (next successful connect re-creates it after a
// full port scan).
//
// Why the registry and not a file: the UMDF host (WUDFHost, LocalService) could
// not reliably create %ProgramData%\t2touchid\portcache.ini, so the cache never
// got written and every cold boot paid a full scan. The registry is where this
// project already keeps everything the service and the CLI/GUI share
// (PeerIpv6, AutoSwitch — see TransportMode.h), and Set-T2NcmStaticIp.ps1
// already grants LocalService write access to the Network key with
// ContainerInherit, so this subkey inherits it.
//
// Contract for callers (BridgeDiscovery / CLI):
//   - LoadCachedPort returns false when there is no value for this MAC or the
//     value has an empty / invalid port. That is the signal to run a full scan
//     — never treat a missing or empty cache as a reason to block.
//   - SaveCachedPort is best-effort; a failure is logged with the Win32 error
//     (5 = the LocalService ACL is missing) and the in-process map still works.
#include "PortCache.h"
#include "../BridgeXpc/Log.h"
#include "../BridgeXpc/TransportMode.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <cstdio>
#include <atomic>
#include <map>
#include <mutex>

namespace t2::discovery {
namespace {

// Process-lifetime cache, consulted BEFORE the registry below.
//
// Why it exists: a failed or delayed first registry write would still leave
// every CAPTURE_DATA in the same WUDFHost process paying a full 16k-port scan.
// The process outlives every capture, so a plain static map makes every capture
// after the first skip the scan. Like the registry value, it is only a hint:
// the caller still verifies the port with a live HELO and falls back to a scan
// on any miss.
struct MemPorts { uint16_t port = 0; uint16_t rsd = 0; bool suspect = false; };
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

// Keys and values here are pure ASCII (hex, ':', digits, ','), so a plain
// per-character widen/narrow is exact.
std::wstring Widen(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

std::string Narrow(const wchar_t* w) {
    std::string s;
    for (; *w; ++w) s.push_back(static_cast<char>(*w));
    return s;
}

std::wstring PortCacheRegPath() {
    return std::wstring(t2::transport::kNetworkRegPath) + L"\\PortCache";
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

// Reads this MAC's value. Missing key/value, wrong type or no read access all
// come back false (cache miss).
bool ReadRegValue(const std::string& macKey, std::string* out) {
    wchar_t buf[64] = {};
    DWORD cb = sizeof(buf) - sizeof(wchar_t); // keep room for a terminator
    const std::wstring path = PortCacheRegPath();
    const std::wstring name = Widen(macKey);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, path.c_str(), name.c_str(), RRF_RT_REG_SZ,
                     nullptr, buf, &cb) != ERROR_SUCCESS) {
        return false;
    }
    *out = Narrow(buf);
    return true;
}

// One health line per outage (v2 section 5): a port cache that cannot be written
// (err 5 = the LocalService ACL is missing) is the reason EVERY boot pays a scan,
// so it must be visible once - but not repeated on every save.
std::atomic<bool> g_regFailureReported{false};
void ReportRegistryHealth(const wchar_t* api, const wchar_t* path, LSTATUS rc) {
    if (g_regFailureReported.exchange(true, std::memory_order_relaxed)) return;
    T2_LOG("health", L"PortCache registry write failed (%s on %s, err=%lu%s): the port is cached in "
           L"memory only, so every boot re-scans. Re-run tools\\Set-T2NcmStaticIp.ps1 as "
           L"administrator to fix the key ACL.",
           api, path, static_cast<unsigned long>(rc),
           rc == ERROR_ACCESS_DENIED ? L" = access denied" : L"");
}

} // namespace

bool LoadCachedPort(const NcmEndpoint& endpoint, uint16_t* outPort, uint16_t* outRsdPort,
                    bool* outSuspect) {
    if (outSuspect) *outSuspect = false;
    if (!endpoint.hasMac) return false; // no stable key to look up

    const std::string key = FormatMacKey(endpoint.mac);
    {
        std::lock_guard<std::mutex> lock(g_memMu);
        auto it = MemCache().find(key);
        if (it != MemCache().end() && it->second.port != 0) {
            if (outPort) *outPort = it->second.port;
            if (outRsdPort) *outRsdPort = it->second.rsd;
            if (outSuspect) *outSuspect = it->second.suspect;
            return true;
        }
    }

    // No value, or an empty / non-numeric / out-of-range port ⇒ return false ⇒
    // caller runs a full port scan.
    std::string raw;
    uint16_t port = 0, rsd = 0;
    if (!ReadRegValue(key, &raw) || !ParsePortValue(raw, &port, &rsd)) {
        return false;
    }
    if (outPort) *outPort = port;
    if (outRsdPort) *outRsdPort = rsd;
    // Warm the process cache so the next CAPTURE in this WUDFHost skips the
    // registry read as well.
    {
        std::lock_guard<std::mutex> lock(g_memMu);
        MemPorts& m = MemCache()[key];
        m.port = port;
        m.rsd = rsd;
    }
    return true;
}

void MarkCachedPortSuspect(const NcmEndpoint& endpoint, bool suspect) {
    if (!endpoint.hasMac) return;
    const std::string key = FormatMacKey(endpoint.mac);
    std::lock_guard<std::mutex> lock(g_memMu);
    auto it = MemCache().find(key);
    if (it == MemCache().end() || it->second.port == 0) return;
    if (it->second.suspect != suspect) {
        it->second.suspect = suspect;
        T2_LOG("discovery", L"cached port %u marked %s", static_cast<unsigned>(it->second.port),
               suspect ? L"Suspect (kept; replaced only by a confirmed scan result)" : L"Good");
    }
}

void SaveCachedPort(const NcmEndpoint& endpoint, uint16_t port, uint16_t rsdPort) {
    if (!endpoint.hasMac) return; // nothing stable to key this entry on
    if (port == 0) return;         // never persist an empty/zero port

    const std::string key = FormatMacKey(endpoint.mac);

    {
        // Always remember it for this process, even if the registry write
        // below fails (UMDF ACL edge cases).
        std::lock_guard<std::mutex> lock(g_memMu);
        MemPorts& m = MemCache()[key];
        m.port = port;
        m.rsd = rsdPort;
        m.suspect = false; // a confirmed port is Good
    }

    std::string value = std::to_string(port);
    if (rsdPort != 0) value += "," + std::to_string(rsdPort);
    const std::wstring wvalue = Widen(value);
    const std::wstring path = PortCacheRegPath();
    const std::wstring name = Widen(key);

    HKEY hKey = nullptr;
    LSTATUS rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr,
                                 REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr,
                                 &hKey, nullptr);
    if (rc != ERROR_SUCCESS) {
        ReportRegistryHealth(L"RegCreateKeyEx", path.c_str(), rc);
        return;
    }
    rc = RegSetValueExW(hKey, name.c_str(), 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(wvalue.c_str()),
                        static_cast<DWORD>((wvalue.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        ReportRegistryHealth(L"RegSetValueEx", path.c_str(), rc);
        return;
    }
    g_regFailureReported.store(false, std::memory_order_relaxed);
    T2_LOG("discovery", L"SaveCachedPort: wrote %s\\%s = %s",
           path.c_str(), name.c_str(), wvalue.c_str());
}

} // namespace t2::discovery
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
// Registry only - no in-process copy (see PortCache.h): one source of truth for
// the UMDF host, the CLI and the GUI, and for both transports.
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

namespace t2::discovery {
namespace {

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

// Strict decimal parse of a whole token: digits only, 1..65535.
bool ParsePortToken(const std::string& tok, int* out) {
    if (tok.empty() || tok.size() > 5) return false;
    int v = 0;
    for (char c : tok) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    if (v <= 0 || v > 65535) return false;
    *out = v;
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

// One health line per outage: a port cache that cannot be written (err 5 = the
// LocalService ACL is missing) is the reason EVERY boot pays a scan, so it must
// be visible once - but not repeated on every save.
std::atomic<bool> g_regFailureReported{false};
void ReportRegistryHealth(const wchar_t* api, const wchar_t* path, LSTATUS rc) {
    if (g_regFailureReported.exchange(true, std::memory_order_relaxed)) return;
    T2_LOG("health", L"PortCache registry write failed (%s on %s, err=%lu%s): the port is NOT "
           L"cached, so every connect re-scans. Re-run tools\\Set-T2NcmStaticIp.ps1 as "
           L"administrator to fix the key ACL.",
           api, path, static_cast<unsigned long>(rc),
           rc == ERROR_ACCESS_DENIED ? L" = access denied" : L"");
}

} // namespace

bool ParsePortCacheValue(const std::string& raw, uint16_t* outPort, uint16_t* outRsd) {
    std::string first = Trim(raw);
    std::string second;
    const size_t comma = first.find(',');
    if (comma != std::string::npos) {
        second = Trim(first.substr(comma + 1));
        first = Trim(first.substr(0, comma));
    }
    int value = 0;
    if (!ParsePortToken(first, &value)) return false;
    int rsd = 0;
    if (!second.empty() && !ParsePortToken(second, &rsd)) rsd = 0;
    if (outPort) *outPort = static_cast<uint16_t>(value);
    if (outRsd) *outRsd = static_cast<uint16_t>(rsd);
    return true;
}

bool LoadCachedPort(const NcmEndpoint& endpoint, uint16_t* outPort, uint16_t* outRsdPort) {
    if (!endpoint.hasMac) return false; // no stable key to look up
    std::string raw;
    uint16_t port = 0, rsd = 0;
    if (!ReadRegValue(FormatMacKey(endpoint.mac), &raw) || !ParsePortCacheValue(raw, &port, &rsd)) {
        return false; // miss => caller runs a full port scan
    }
    if (outPort) *outPort = port;
    if (outRsdPort) *outRsdPort = rsd;
    return true;
}

void SaveCachedPort(const NcmEndpoint& endpoint, uint16_t port, uint16_t rsdPort) {
    if (!endpoint.hasMac) return; // nothing stable to key this entry on
    if (port == 0) return;         // never persist an empty/zero port

    std::string value = std::to_string(port);
    if (rsdPort != 0) value += "," + std::to_string(rsdPort);
    const std::wstring wvalue = Widen(value);
    const std::wstring path = PortCacheRegPath();
    const std::wstring name = Widen(FormatMacKey(endpoint.mac));

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
    T2_LOG("discovery", L"SaveCachedPort: wrote %s\\%s = %s (%s)",
           path.c_str(), name.c_str(), wvalue.c_str(),
           t2::transport::IsTunnelModeActive() ? L"confirmed over IPv4 tunnel" : L"confirmed over native IPv6");
}

bool DeleteCachedPort(const NcmEndpoint& endpoint) {
    if (!endpoint.hasMac) return false;
    const std::wstring path = PortCacheRegPath();
    const std::wstring name = Widen(FormatMacKey(endpoint.mac));
    const LSTATUS rc = RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, path.c_str(), name.c_str());
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND;
}

} // namespace t2::discovery

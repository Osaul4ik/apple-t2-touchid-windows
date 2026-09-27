// SPDX-License-Identifier: GPL-2.0-only
// TransportMode — Native IPv6 (default) vs IPv4 tunnel for Cisco/WFP that
// drops all IPv6 before the packet reaches T2Ncm. When tunnel is on,
// userspace uses AF_INET to a link-local IPv4 mapped from the T2 fe80
// address; T2Ncm.sys rewrites IPv4↔IPv6 on the wire (T2 still speaks IPv6).
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "Iphlpapi.lib")

namespace t2::transport {

inline constexpr wchar_t kNetworkRegPath[] = L"SOFTWARE\\T2TouchId\\Network";
inline constexpr wchar_t kTransportModeValue[] = L"TransportMode";
inline constexpr wchar_t kPeerIpv6Value[] = L"PeerIpv6";
inline constexpr wchar_t kPeerMacValue[] = L"PeerMac";

enum class TransportMode : DWORD {
    NativeIpv6 = 0,
    Ipv4Tunnel = 1,
};

inline TransportMode ReadTransportMode() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kNetworkRegPath, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return TransportMode::NativeIpv6;
    }
    DWORD data = 0;
    DWORD type = 0;
    DWORD cb = sizeof(data);
    const LONG err = RegQueryValueExW(key, kTransportModeValue, nullptr, &type,
                                      reinterpret_cast<LPBYTE>(&data), &cb);
    RegCloseKey(key);
    if (err != ERROR_SUCCESS || (type != REG_DWORD && type != REG_BINARY)) {
        return TransportMode::NativeIpv6;
    }
    return (data == static_cast<DWORD>(TransportMode::Ipv4Tunnel))
               ? TransportMode::Ipv4Tunnel
               : TransportMode::NativeIpv6;
}

inline in_addr MapPeerToIpv4(const in6_addr& peer6) {
    unsigned a = peer6.s6_addr[14];
    unsigned b = peer6.s6_addr[15];
    if (a == 0) a = 1;
    if (a == 255) a = 254;
    if (b == 0) b = 1;
    if (b == 255) b = 254;
    a = (a + peer6.s6_addr[13]) % 254;
    if (a == 0) a = 1;
    in_addr out{};
    out.S_un.S_un_b.s_b1 = 169;
    out.S_un.S_un_b.s_b2 = 254;
    out.S_un.S_un_b.s_b3 = static_cast<UCHAR>(a);
    out.S_un.S_un_b.s_b4 = static_cast<UCHAR>(b);
    return out;
}

inline bool IsTunnelMappedIpv4(const in_addr& a) {
    return a.S_un.S_un_b.s_b1 == 169 && a.S_un.S_un_b.s_b2 == 254;
}

// Publish peer fe80 (+ optional MAC) for T2Ncm.sys (read at PASSIVE refresh).
inline void PublishTunnelPeer(const in6_addr& peer6, const UCHAR mac[6] /*nullable*/) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kNetworkRegPath, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }
    RegSetValueExW(key, kPeerIpv6Value, 0, REG_BINARY,
                   reinterpret_cast<const BYTE*>(&peer6), sizeof(peer6));
    if (mac) {
        RegSetValueExW(key, kPeerMacValue, 0, REG_BINARY, mac, 6);
    }
    RegCloseKey(key);
}

// Look up peer MAC from the IPv6 neighbor table (same entry as discovery).
inline bool LookupPeerMac(unsigned long ifIndex, const in6_addr& peer6, UCHAR outMac[6]) {
    PMIB_IPNET_TABLE2 table = nullptr;
    if (GetIpNetTable2(AF_INET6, &table) != NO_ERROR || !table) {
        return false;
    }
    bool found = false;
    UCHAR anyMac[6]{};
    bool any = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& e = table->Table[i];
        if (e.InterfaceIndex != ifIndex) continue;
        if (e.Address.si_family != AF_INET6) continue;
        if (e.PhysicalAddressLength < 6) continue;
        // Skip multicast/solicited-node style permanent junk: need a real MAC.
        if (e.PhysicalAddress[0] & 0x01) continue;
        if (!any) {
            std::memcpy(anyMac, e.PhysicalAddress, 6);
            any = true;
        }
        if (std::memcmp(&e.Address.Ipv6.sin6_addr, &peer6, sizeof(in6_addr)) == 0) {
            std::memcpy(outMac, e.PhysicalAddress, 6);
            found = true;
            break;
        }
    }
    FreeMibTable(table);
    if (!found && any) {
        std::memcpy(outMac, anyMac, 6);
        found = true;
    }
    return found;
}

// Static neighbor so TCP SYN is not stuck on ARP for 169.254.x.y.
inline void EnsureTunnelIpv4Neighbor(unsigned long ifIndex, const in_addr& peer4,
                                     const UCHAR mac[6]) {
    MIB_IPNET_ROW2 row{};
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr = peer4;
    row.InterfaceIndex = ifIndex;
    std::memcpy(row.PhysicalAddress, mac, 6);
    row.PhysicalAddressLength = 6;
    row.State = NlnsPermanent;
    // Create or set — ignore already-exists.
    const DWORD c = CreateIpNetEntry2(&row);
    if (c != NO_ERROR && c != ERROR_OBJECT_ALREADY_EXISTS) {
        SetIpNetEntry2(&row);
    }
}

// Call before AF_INET connect in tunnel mode.
inline void PrepareTunnelPeer(unsigned long ifIndex, const in6_addr& peer6) {
    UCHAR mac[6]{};
    const bool haveMac = LookupPeerMac(ifIndex, peer6, mac);
    PublishTunnelPeer(peer6, haveMac ? mac : nullptr);
    PushTunnelPeerToDriver(peer6);
    if (haveMac) {
        EnsureTunnelIpv4Neighbor(ifIndex, MapPeerToIpv4(peer6), mac);
    }
}

} // namespace t2::transport

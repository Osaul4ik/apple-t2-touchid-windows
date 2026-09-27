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
#include <cstdint>

namespace t2::transport {

// HKLM\SOFTWARE\T2TouchId\Network\TransportMode
//   0 = NativeIpv6 (default)
//   1 = Ipv4Tunnel
inline constexpr wchar_t kNetworkRegPath[] = L"SOFTWARE\\T2TouchId\\Network";
inline constexpr wchar_t kTransportModeValue[] = L"TransportMode";

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

// Map T2 fe80::… (or any in6) → unique 169.254.x.y in APIPA range.
// Avoids .0 / .255 in either octet. Stable across runs for the same peer.
inline in_addr MapPeerToIpv4(const in6_addr& peer6) {
    unsigned a = peer6.s6_addr[14];
    unsigned b = peer6.s6_addr[15];
    if (a == 0) a = 1;
    if (a == 255) a = 254;
    if (b == 0) b = 1;
    if (b == 255) b = 254;
    // Mix in a middle byte so different fe80 hosts rarely collide.
    a = (a + peer6.s6_addr[13]) % 254;
    if (a == 0) a = 1;
    in_addr out{};
    out.S_un.S_un_b.s_b1 = 169;
    out.S_un.S_un_b.s_b2 = 254;
    out.S_un.S_un_b.s_b3 = static_cast<UCHAR>(a);
    out.S_un.S_un_b.s_b4 = static_cast<UCHAR>(b);
    return out;
}

// Inverse is not unique; tunnel RX uses fixed rewrite of any IPv6 TCP from
// the T2 MAC toward a host 169.254 address derived the same way from the
// *source* IPv6 of the packet (peer). Host local IPv4 is not required to
// match a specific value when IP_UNICAST_IF binds the socket to ifIndex.

inline bool IsTunnelMappedIpv4(const in_addr& a) {
    return a.S_un.S_un_b.s_b1 == 169 && a.S_un.S_un_b.s_b2 == 254;
}

} // namespace t2::transport

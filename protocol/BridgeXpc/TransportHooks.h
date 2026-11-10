// SPDX-License-Identifier: GPL-2.0-only
// TransportHooks.h - the places where the transport / discovery code touches the
// machine, gathered behind ONE optional override so the whole connect flow can run
// against a simulated T2 (tests/FakeT2.*, tests/ScenarioTests.cpp).
//
// Production never installs hooks: every function below then does exactly what the
// code did before the seam existed (the real \\.\T2Ncm handle, the real fe80%if /
// 169.254.x.y address, the real ARP / registry / readiness checks).
//
// What is overridable, and why it is enough to drive BridgeDiscovery end to end:
//   * ncmIoctl          - every IOCTL to T2Ncm.sys (mode, sticky, peer, local, state)
//   * peerAddress       - where a TCP socket "to the T2" really connects, per transport
//   * connectVerdict    - a local verdict before connect() (WSAEACCES = WFP block)
//   * tunnelNeighborReady - PrepareTunnelPeer: no MAC lookup / static ARP / registry
//   * gateReady         - RunReadinessGate: adapter + link-local are taken as ready
//   * regRoot/regPath   - where the Network key (PortCache, AutoSwitch, ...) lives
//
// Install / clear only while no transport code is running (between scenarios); the
// pointer is read lock-free by many threads.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdint>
#include <functional>
#include <string>

namespace t2::transport {

// A socket address of the T2 on one transport, plus the family to create the
// socket with. Built by MakePeerAddress (TransportMode.h).
struct PeerAddress {
    sockaddr_storage addr{};
    int len = 0;
    int family = AF_UNSPEC;
    const sockaddr* sa() const { return reinterpret_cast<const sockaddr*>(&addr); }
};

namespace hooks {

struct Hooks {
    // \\.\T2Ncm control IOCTL. Return true when handled; then *ok / *returned / *err
    // are the answer (err = GetLastError of a failed call).
    std::function<bool(DWORD code, const void* in, DWORD inSize, void* out, DWORD outSize,
                       DWORD* returned, bool* ok, DWORD* err)> ncmIoctl;
    // Where a socket to the T2's `port` on `tunnel` (false = native IPv6) connects.
    // Return true and fill *out to redirect.
    std::function<bool(bool tunnel, uint16_t port, PeerAddress* out)> peerAddress;
    // Checked right before connect(): 0 = go ahead, anything else is returned as the
    // immediate WSA error of that connect() (WSAEACCES = local WFP block filter).
    std::function<int(bool tunnel, uint16_t port)> connectVerdict;
    bool tunnelNeighborReady = false;
    bool gateReady = false;
    HKEY regRoot = nullptr;     // nullptr = HKEY_LOCAL_MACHINE
    std::wstring regPath;       // empty   = SOFTWARE\T2TouchId\Network
};

// nullptr in production.
const Hooks* Active();
// Tests only. The object must outlive every use (until Clear()).
void Install(const Hooks* h);
void Clear();

} // namespace hooks
} // namespace t2::transport

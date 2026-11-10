// SPDX-License-Identifier: GPL-2.0-only
// FakeT2.h - a simulated T2 for the transport / discovery scenario tests.
//
// What it simulates, on 127.0.0.0/8:
//   * bkremoted's RemoteXPC (RSD) listener: HTTP/2 SETTINGS first, then a peer
//     record that advertises com.apple.eos.BiometricKit on the BridgeXPC port;
//   * the BiometricKit BridgeXPC listener: peer HELO, client HELO;
//   * optional decoy HTTP/2 listeners (other T2 services that never advertise it);
//   * T2Ncm.sys's control device (mode, sticky, peer, local, GET_TUNNEL_STATE) and
//     what its mode does to traffic: in native mode an IPv4-tunnel socket goes
//     nowhere, in tunnel mode every inbound IPv6 frame is rewritten, so a native
//     socket goes nowhere. "Nowhere" is a black-hole listener whose accept queue is
//     full: the SYN is never answered, exactly like a dead path.
//   * the host side of a VPN: native IPv6 blocked by a WFP filter (WSAEACCES at
//     connect) or silently dropped.
//
// Native IPv6 lands on 127.0.0.1, the tunnel on 127.0.0.2, so the fake can tell
// which transport a connection came over.
#pragma once
#include "../protocol/BridgeXpc/TransportHooks.h"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace t2::test {

enum class NativePath {
    Open,     // packets flow
    Blocked,  // WFP block filter: connect() fails with WSAEACCES at once
    Silent,   // dropped: no SYN-ACK, no RST
};

class FakeT2 {
public:
    FakeT2() = default;
    ~FakeT2() { Stop(); }
    FakeT2(const FakeT2&) = delete;
    FakeT2& operator=(const FakeT2&) = delete;

    // Picks free ports inside the discovery scan range and starts listening.
    bool Start();
    void Stop();

    uint16_t RsdPort() const { return rsdPort_; }
    uint16_t BridgePort() const { return bridgePort_.load(); }
    // A port that is free now (for "the cached port is stale").
    uint16_t SomeClosedPort() const { return closedPort_; }

    // BiometricKit moved to another port (T2 reboot): the old one closes.
    bool MoveBridgePort();
    // false: the RSD record does not list BiometricKit yet (service not up).
    void SetBiometricKitAdvertised(bool on) { advertised_ = on; }

    std::atomic<NativePath> nativePath{NativePath::Open};

    // ---- fake T2Ncm.sys ----
    std::atomic<int> driverMode{0};    // 0 native, 1 tunnel
    std::atomic<int> driverSticky{0};
    std::atomic<int> modeWrites{0};
    std::atomic<int> stickyWrites{0};
    std::atomic<bool> driverPresent{true};

    // ---- what reached the T2 ----
    std::atomic<int> rsdNative{0}, rsdTunnel{0};
    // BridgeXPC sessions per transport (peer HELO sent).
    std::atomic<int> heloNative{0}, heloTunnel{0};
    std::atomic<int> badClientHelo{0}; // the client answered with something else
    void ResetCounters();

    // Hooks wired to this instance (valid while it lives).
    const t2::transport::hooks::Hooks& Hooks() const { return hooks_; }

private:
    enum class Role { Rsd, Bridge, Decoy };
    struct Listener {
        SOCKET s = INVALID_SOCKET;
        uint16_t port = 0;
        Role role = Role::Rsd;
    };

    bool OpenListener(uint16_t port, Role role);
    bool OpenBlackHole();
    void AcceptLoop();
    void Serve(SOCKET c, Role role, bool tunnel);
    void ServeRsd(SOCKET c, bool tunnel);
    void ServeBridge(SOCKET c, bool tunnel);
    bool IoctlHook(DWORD code, const void* in, DWORD inSize, void* out, DWORD outSize,
                   DWORD* returned, bool* ok, DWORD* err);
    bool AddressHook(bool tunnel, uint16_t port, t2::transport::PeerAddress* out);
    int VerdictHook(bool tunnel, uint16_t port);
    static uint16_t PickFreePort(uint16_t from, uint16_t to, const std::set<uint16_t>& avoid);

    std::mutex mu_;
    std::vector<Listener> listeners_;
    std::vector<std::thread> workers_;
    std::vector<SOCKET> blackHoleFill_;
    SOCKET blackHole_ = INVALID_SOCKET;
    uint16_t blackHolePort_ = 0;
    std::thread acceptThread_;
    std::atomic<bool> stop_{false};

    uint16_t rsdPort_ = 0;
    std::atomic<uint16_t> bridgePort_{0};
    uint16_t closedPort_ = 0;
    std::atomic<bool> advertised_{true};

    t2::transport::hooks::Hooks hooks_;
};

} // namespace t2::test

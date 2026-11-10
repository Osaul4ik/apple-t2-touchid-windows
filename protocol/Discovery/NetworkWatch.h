// SPDX-License-Identifier: GPL-2.0-only
// NetworkWatch.h - "the host's network configuration changed" (a VPN came up or
// went down, an adapter appeared, routes were replaced), debounced, plus a cheap
// native-IPv6 path probe to judge whether that change broke the T2 link.
//
// Why: the transport (native IPv6 vs. the IPv4 tunnel, TransportMode.h) used to be
// re-decided only by a failed/successful connect and by a real unlock. A VPN that
// came up while a capture was armed over native IPv6 silently swallowed the T2's
// events (WFP drops them) until that capture's match window ran out; a VPN that went
// away left the tunnel committed until the next unlock. The watcher turns both into
// events the owner of the transport (the UMDF driver) can act on right away.
//
// Threading: the iphlpapi callbacks only signal an event; the debounce and the user
// callback run on one dedicated thread owned by the watcher, so the callback may
// block briefly (a probe) without stalling the system notification pool, and never
// runs concurrently with itself. Stop() unregisters the notifications (waiting for
// any callback in progress) and joins the thread; it must not be called from the
// callback.
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
#include <functional>

namespace t2::discovery {

class NetworkChangeWatcher {
public:
    using Callback = std::function<void()>;

    NetworkChangeWatcher() = default;
    ~NetworkChangeWatcher() { Stop(); }
    NetworkChangeWatcher(const NetworkChangeWatcher&) = delete;
    NetworkChangeWatcher& operator=(const NetworkChangeWatcher&) = delete;

    // Starts watching. `debounceMs`: quiet time after the LAST change before the
    // callback runs (a VPN connect produces a burst of interface + route events).
    // Returns false (and leaves nothing running) when the notifications cannot be
    // registered. Calling Start twice without Stop is a no-op returning true.
    bool Start(Callback onChange, DWORD debounceMs = 1500);
    void Stop();
    bool Running() const { return thread_ != nullptr; }

private:
    static VOID NETIOAPI_API_ OnIpInterfaceChange(PVOID ctx, PMIB_IPINTERFACE_ROW row,
                                                  MIB_NOTIFICATION_TYPE type);
    static VOID NETIOAPI_API_ OnRouteChange(PVOID ctx, PMIB_IPFORWARD_ROW2 row,
                                            MIB_NOTIFICATION_TYPE type);
    static DWORD WINAPI ThreadProc(LPVOID self);
    void Run();

    Callback onChange_;
    DWORD debounceMs_ = 1500;
    HANDLE changeEvent_ = nullptr; // auto-reset: "something changed"
    HANDLE stopEvent_ = nullptr;   // manual-reset
    HANDLE thread_ = nullptr;
    HANDLE ifNotify_ = nullptr;
    HANDLE routeNotify_ = nullptr;
};

// Is the native IPv6 path to the T2 usable right now? One TCP SYN to
// [peer%ifIndex]:port with a `timeoutMs` budget. Requires T2Ncm.sys to be in
// native mode (the caller only asks while the committed transport is native).
enum class NativePathProbe {
    Alive,      // SYN-ACK or RST came back: packets reach the T2 and back
    Blocked,    // WSAEACCES: a local WFP block filter (VPN kill-switch)
    Silent,     // nothing within the budget (filtered, or the T2 is gone)
    LocalError, // could not even try (no socket, no route) - says nothing
};
NativePathProbe ProbeNativePath(const in6_addr& peer, unsigned long ifIndex, uint16_t port,
                                DWORD timeoutMs);

const wchar_t* NativePathProbeName(NativePathProbe p);

} // namespace t2::discovery

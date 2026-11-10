// SPDX-License-Identifier: GPL-2.0-only
// NetworkWatch.cpp - see NetworkWatch.h.
#include "NetworkWatch.h"
#include "../BridgeXpc/Log.h"
#include "../BridgeXpc/Winsock.h"

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace t2::discovery {

bool NetworkChangeWatcher::Start(Callback onChange, DWORD debounceMs) {
    if (thread_ != nullptr) return true;
    onChange_ = std::move(onChange);
    debounceMs_ = debounceMs;
    changeEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!changeEvent_ || !stopEvent_) {
        T2_LOG("netwatch", L"CreateEvent failed (GetLastError=%lu)", GetLastError());
        Stop();
        return false;
    }
    // Notifications first, then the thread: a change that arrives in between only
    // leaves changeEvent_ signaled, which the thread picks up on its first wait.
    NETIO_STATUS st = NotifyIpInterfaceChange(AF_UNSPEC, &NetworkChangeWatcher::OnIpInterfaceChange,
                                              this, FALSE, &ifNotify_);
    if (st != NO_ERROR) {
        T2_LOG("netwatch", L"NotifyIpInterfaceChange failed (%lu)", static_cast<unsigned long>(st));
        ifNotify_ = nullptr;
        Stop();
        return false;
    }
    st = NotifyRouteChange2(AF_UNSPEC, &NetworkChangeWatcher::OnRouteChange, this, FALSE, &routeNotify_);
    if (st != NO_ERROR) {
        // Interface changes alone still cover a VPN adapter coming up / going down;
        // routes are the extra signal for a VPN that reuses an existing adapter.
        T2_LOG("netwatch", L"NotifyRouteChange2 failed (%lu) - interface changes only",
               static_cast<unsigned long>(st));
        routeNotify_ = nullptr;
    }
    thread_ = CreateThread(nullptr, 0, &NetworkChangeWatcher::ThreadProc, this, 0, nullptr);
    if (!thread_) {
        T2_LOG("netwatch", L"CreateThread failed (GetLastError=%lu)", GetLastError());
        Stop();
        return false;
    }
    T2_LOG("netwatch", L"watching host network changes (debounce %lu ms)", debounceMs_);
    return true;
}

void NetworkChangeWatcher::Stop() {
    // Unregister first: CancelMibChangeNotify2 waits for a callback in progress, so
    // after these two calls nothing can touch changeEvent_ any more.
    if (routeNotify_) {
        CancelMibChangeNotify2(routeNotify_);
        routeNotify_ = nullptr;
    }
    if (ifNotify_) {
        CancelMibChangeNotify2(ifNotify_);
        ifNotify_ = nullptr;
    }
    if (thread_) {
        SetEvent(stopEvent_);
        WaitForSingleObject(thread_, INFINITE);
        CloseHandle(thread_);
        thread_ = nullptr;
    }
    if (changeEvent_) {
        CloseHandle(changeEvent_);
        changeEvent_ = nullptr;
    }
    if (stopEvent_) {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
}

VOID NETIOAPI_API_ NetworkChangeWatcher::OnIpInterfaceChange(PVOID ctx, PMIB_IPINTERFACE_ROW,
                                                             MIB_NOTIFICATION_TYPE type) {
    // MibInitialNotification is only sent when InitialNotification=TRUE (not used).
    if (type == MibInitialNotification) return;
    auto* self = static_cast<NetworkChangeWatcher*>(ctx);
    if (self && self->changeEvent_) SetEvent(self->changeEvent_);
}

VOID NETIOAPI_API_ NetworkChangeWatcher::OnRouteChange(PVOID ctx, PMIB_IPFORWARD_ROW2,
                                                       MIB_NOTIFICATION_TYPE type) {
    if (type == MibInitialNotification) return;
    auto* self = static_cast<NetworkChangeWatcher*>(ctx);
    if (self && self->changeEvent_) SetEvent(self->changeEvent_);
}

DWORD WINAPI NetworkChangeWatcher::ThreadProc(LPVOID self) {
    static_cast<NetworkChangeWatcher*>(self)->Run();
    return 0;
}

void NetworkChangeWatcher::Run() {
    const HANDLE waitFirst[2] = {stopEvent_, changeEvent_};
    for (;;) {
        if (WaitForMultipleObjects(2, waitFirst, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) return;
        // Debounce: keep waiting while changes keep coming; fire after a quiet
        // debounceMs_. Bounded so a flapping adapter still gets evaluated.
        const ULONGLONG firstChange = GetTickCount64();
        for (;;) {
            const DWORD w = WaitForMultipleObjects(2, waitFirst, FALSE, debounceMs_);
            if (w == WAIT_OBJECT_0) return;                      // stop
            if (w == WAIT_TIMEOUT) break;                         // quiet: evaluate
            if (w != WAIT_OBJECT_0 + 1) return;                   // wait failed
            if (GetTickCount64() - firstChange > 10ull * debounceMs_) break;
        }
        T2_LOG("netwatch", L"host network configuration changed");
        if (onChange_) {
            try {
                onChange_();
            } catch (...) {
                T2_LOG("netwatch", L"change callback threw - ignored");
            }
        }
    }
}

const wchar_t* NativePathProbeName(NativePathProbe p) {
    switch (p) {
    case NativePathProbe::Alive:      return L"alive";
    case NativePathProbe::Blocked:    return L"blocked (WFP)";
    case NativePathProbe::Silent:     return L"silent";
    case NativePathProbe::LocalError: return L"local error";
    }
    return L"?";
}

NativePathProbe ProbeNativePath(const in6_addr& peer, unsigned long ifIndex, uint16_t port,
                                DWORD timeoutMs) {
    if (!t2::EnsureWinsock() || port == 0 || ifIndex == 0) return NativePathProbe::LocalError;
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return NativePathProbe::LocalError;
    u_long nonBlocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        closesocket(s);
        return NativePathProbe::LocalError;
    }
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = peer;
    addr.sin6_scope_id = ifIndex;

    NativePathProbe result = NativePathProbe::Silent;
    if (connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0) {
        result = NativePathProbe::Alive;
    } else {
        const int e = WSAGetLastError();
        if (e == WSAEACCES) {
            result = NativePathProbe::Blocked;
        } else if (e == WSAECONNREFUSED) {
            result = NativePathProbe::Alive;
        } else if (e != WSAEWOULDBLOCK) {
            result = (e == WSAENETUNREACH || e == WSAEADDRNOTAVAIL || e == WSAENETDOWN)
                         ? NativePathProbe::LocalError
                         : NativePathProbe::Silent;
        } else {
            fd_set wr, ex;
            FD_ZERO(&wr);
            FD_ZERO(&ex);
            FD_SET(s, &wr);
            FD_SET(s, &ex);
            timeval tv{};
            tv.tv_sec = static_cast<long>(timeoutMs / 1000);
            tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
            const int n = select(0, nullptr, &wr, &ex, &tv);
            if (n > 0) {
                int soErr = 0;
                int len = sizeof(soErr);
                getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &len);
                if (FD_ISSET(s, &wr) && soErr == 0) {
                    result = NativePathProbe::Alive;          // SYN-ACK
                } else if (soErr == WSAECONNREFUSED) {
                    result = NativePathProbe::Alive;          // RST: the path works
                } else if (soErr == WSAEACCES) {
                    result = NativePathProbe::Blocked;
                } else {
                    result = NativePathProbe::Silent;
                }
            }
            // n == 0: timeout -> Silent; n < 0: select failed -> Silent (no verdict wanted)
        }
    }
    // RST instead of a FIN dance: this was only a reachability probe.
    linger lg{1, 0};
    setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg));
    closesocket(s);
    return result;
}

} // namespace t2::discovery

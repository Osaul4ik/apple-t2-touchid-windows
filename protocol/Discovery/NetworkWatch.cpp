// SPDX-License-Identifier: GPL-2.0-only
// NetworkWatch.cpp - see NetworkWatch.h.
#include "NetworkWatch.h"
#include "../BridgeXpc/Log.h"

#pragma comment(lib, "Iphlpapi.lib")

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
    // WaitForMultipleObjects indices, spelled numerically: WAIT_OBJECT_0 expands to
    // (STATUS_WAIT_0 + 0), and STATUS_WAIT_0 is undeclared in the UMDF build
    // (UMDF_USING_NTSTATUS) - same convention as Connection.h / Log.h.
    constexpr DWORD kWaitStop = 0;   // == WAIT_OBJECT_0 + 0
    constexpr DWORD kWaitChange = 1; // == WAIT_OBJECT_0 + 1
    const HANDLE waitFirst[2] = {stopEvent_, changeEvent_};
    for (;;) {
        if (WaitForMultipleObjects(2, waitFirst, FALSE, INFINITE) != kWaitChange) return;
        // Debounce: keep waiting while changes keep coming; fire after a quiet
        // debounceMs_. Bounded so a flapping adapter still gets evaluated.
        const ULONGLONG firstChange = GetTickCount64();
        for (;;) {
            const DWORD w = WaitForMultipleObjects(2, waitFirst, FALSE, debounceMs_);
            if (w == kWaitStop) return;                           // stop
            if (w == WAIT_TIMEOUT) break;                         // quiet: evaluate
            if (w != kWaitChange) return;                         // wait failed
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

} // namespace t2::discovery

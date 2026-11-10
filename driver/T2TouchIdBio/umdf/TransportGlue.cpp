// SPDX-License-Identifier: GPL-2.0-only
// TransportGlue.cpp - the driver's side of the T2 transport that is not the capture
// itself: the host network-change watcher (VPN up/down) and the transport owner
// pipe (\\.\pipe\T2TouchIdTransport). Moved out of Queue.cpp; it reaches the
// capture engine only through CaptureState.h.
//
// No WDF here on purpose: this file builds with any Windows C++ compiler, so the
// host test build (tests/host) compiles it too.
#include "CaptureState.h"
#include "BridgeXpc/Log.h"
#include "BridgeXpc/TransportMode.h"
#include "Discovery/Adapter.h"
#include "Discovery/NetworkWatch.h"
#include "Discovery/PortCache.h"
#include "Discovery/TransportService.h"
#include "Ipc/TransportPipe.h"
#include <atomic>
#include <chrono>
#include <string>
#include <thread>

// ---- Host network changes (VPN up/down) -------------------------------------
// Until RC the transport was re-decided only by a connect (and one native re-check
// per real unlock). Two cases slipped through:
//  * a VPN came up while a capture was armed over native IPv6: its WFP filters drop
//    the T2's events, so the touch was ignored until that capture's match window
//    ended and the retry ladder reconnected (over the tunnel);
//  * the VPN that forced the sticky tunnel went away: the tunnel stayed until the
//    next unlock.
// The watcher (protocol/Discovery/NetworkWatch) calls this after a debounced burst
// of interface/route changes, on its own thread:
//  * sticky tunnel committed -> RequestNativeReprobe(): the next connect re-checks
//    native once (exactly what an unlock does). The armed tunnel session is left
//    alone - the tunnel keeps working without a VPN too;
//  * native committed and a capture armed -> one 250 ms SYN to the cached port. If
//    the native path no longer answers (WFP block / silence), the active match is
//    invalidated exactly like a screen lock does (the WBF CAPTURE_DATA stays pending,
//    the worker reconnects at once and the connect flow switches to the tunnel).
//    An alive path, or a probe that could not run, changes nothing.
namespace {

t2::discovery::NetworkChangeWatcher g_netWatch;

void OnHostNetworkChanged()
{
    if (t2::transport::IsTransportIoSuspended() || t2bio::SystemShuttingDown()) {
        T2BioLog("NetworkChange: ignored (system suspending / shutting down)");
        return;
    }
    t2::transport::DiagTransportSnapshot(L"host network change");
    if (!t2::transport::IsAutoSwitchEnabled()) {
        return; // native only: nothing to switch
    }
    t2::transport::RefreshStickyFromDriver();
    if (t2::transport::IsAutoTunnelCommitted()) {
        t2::transport::RequestNativeReprobe();
        T2BioLog("NetworkChange: IPv4 tunnel committed - the next connect re-checks native IPv6 once");
        return;
    }
    if (!t2bio::CaptureBusy()) {
        return; // nothing armed: the next connect decides on its own
    }
    if (t2::transport::HasTransportOverride()) {
        // A connect phase of this process is probing right now; the driver mode is
        // the probe's, so a native SYN would say nothing. That connect decides.
        T2BioLog("NetworkChange: a connect phase is running - leaving the decision to it");
        return;
    }
    t2::discovery::NcmEndpoint ep;
    if (!t2bio::GetStickyEndpoint(&ep, /*requirePeer=*/true)) {
        return;
    }
    uint16_t port = 0;
    uint16_t rsd = 0;
    if (!t2::discovery::LoadCachedPort(ep, &port, &rsd) || port == 0) {
        return;
    }
    using t2::transport::PathEvidence;
    const PathEvidence probe = t2::transport::ProbeNativePath(
        ep.peerLinkLocal, ep.ifIndex, port, std::chrono::milliseconds(250));
    T2_LOG("netwatch", L"armed capture over native IPv6: probe of port %u -> evidence %d "
           L"(0 positive, 1 silent, 2 local error, 3 refused, 4 blocked)",
           static_cast<unsigned>(port), static_cast<int>(probe));
    // SYN-ACK or RST: the path still reaches the T2. LocalError says nothing.
    if (probe == PathEvidence::Positive || probe == PathEvidence::Refused ||
        probe == PathEvidence::LocalError) {
        return;
    }
    t2bio::InvalidateCaptureForTransport("NetworkChange(native IPv6 path lost)");
}

}  // namespace

extern "C" VOID T2BioRegisterNetworkChangeNotification(VOID)
{
    if (!g_netWatch.Start(&OnHostNetworkChanged)) {
        T2BioLog("NetworkChange registration failed - VPN changes are picked up only by the "
                 "next connect / unlock");
    }
}

// Before unload: joins the watcher thread (it runs code from this DLL).
extern "C" VOID T2BioUnregisterNetworkChangeNotification(VOID)
{
    g_netWatch.Stop();
}

// ---- Transport owner: \\.\pipe\T2TouchIdTransport (protocol/Ipc/TransportPipe.h) ----
// This driver owns the T2 transport. The CLI (and through it the GUI's Rescan) asks
// here instead of scanning and flipping T2Ncm.sys from a second process. A rescan
// never runs under an armed capture (reply "busy"), and a capture that arrives while
// one runs cancels it: the relay below turns "capture armed" into the request's
// cancel event within 50 ms, so the capture's own connect gets the phase lock long
// before its 2 s wait runs out.
namespace {

t2::ipc::PipeServer g_transportPipe;

t2::discovery::TransportServiceContext OwnerContext()
{
    t2::discovery::TransportServiceContext ctx;
    ctx.ownerName = "T2TouchIdBio";
    ctx.captureBusy = [] { return t2bio::CaptureBusy(); };
    ctx.statusEndpoint = [](t2::discovery::NcmEndpoint* ep) {
        if (t2bio::GetStickyEndpoint(ep, /*requirePeer=*/false)) {
            return true;
        }
        auto eps = t2::discovery::FindT2NcmEndpoints(/*resolvePeer=*/false);
        if (eps.empty()) return false;
        *ep = eps.front();
        return true;
    };
    return ctx;
}

std::string OnTransportPipeRequest(const std::string& request, HANDLE clientGone)
{
    HANDLE cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!cancel) return "result=error\nerror=no event\n";
    std::atomic<bool> finished{false};
    std::thread relay;
    try {
        relay = std::thread([&] {
            while (!finished.load(std::memory_order_acquire)) {
                if (WaitForSingleObject(clientGone, 50) == 0 || t2bio::CaptureBusy()) {
                    SetEvent(cancel);
                    return;
                }
            }
        });
    } catch (...) {
        CloseHandle(cancel);
        return "result=error\nerror=no thread\n";
    }
    std::string reply;
    try {
        reply = t2::discovery::HandleTransportRequest(request, cancel, OwnerContext());
    } catch (...) {
        reply = "result=error\nerror=exception\n";
    }
    finished.store(true, std::memory_order_release);
    relay.join();
    CloseHandle(cancel);
    return reply;
}

}  // namespace

extern "C" VOID T2BioStartTransportOwner(VOID)
{
    if (!g_transportPipe.Start(t2::ipc::kTransportPipeName, &OnTransportPipeRequest)) {
        T2BioLog("transport owner pipe not started (GetLastError=%lu) - the CLI / GUI fall back to "
                 "running discovery themselves", GetLastError());
        return;
    }
    T2BioLog("transport owner: serving \\\\.\\pipe\\T2TouchIdTransport");
}

// Before unload: joins the pipe threads (they run code from this DLL).
extern "C" VOID T2BioStopTransportOwner(VOID)
{
    g_transportPipe.Stop();
}

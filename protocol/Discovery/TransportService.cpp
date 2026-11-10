// SPDX-License-Identifier: GPL-2.0-only
// TransportService.cpp - see TransportService.h.
#include "TransportService.h"
#include "BridgeDiscovery.h"
#include "PortCache.h"
#include "../BridgeXpc/Log.h"
#include "../BridgeXpc/TransportMode.h"
#include "../Ipc/TransportPipe.h"
#include <chrono>

namespace t2::discovery {

namespace tp = t2::transport;

const char* LadderResultName(LadderResult r) {
    switch (r) {
    case LadderResult::Ok:        return "ok";
    case LadderResult::NoAdapter: return "no_adapter";
    case LadderResult::NoPeer:    return "no_peer";
    case LadderResult::NotFound:  return "not_found";
    case LadderResult::TimedOut:  return "timed_out";
    case LadderResult::Cancelled: return "cancelled";
    }
    return "?";
}

static bool CancelledNow(void* cancelEvent) {
    return bridgexpc::Connection::IsEventSignaled(static_cast<HANDLE>(cancelEvent));
}

LadderOutcome ConnectWithLadder(const LadderOptions& options, bridgexpc::Connection* conn) {
    LadderOutcome out;
    const ULONGLONG deadline = GetTickCount64() + options.budgetMs;
    ConnectOptions opt;
    opt.forceRescan = options.forceRescan;
    DWORD backoffMs = 250;
    bool sawPeer = false;
    for (unsigned step = 1;; ++step) {
        out.steps = step;
        if (CancelledNow(options.cancelEvent)) {
            out.result = LadderResult::Cancelled;
            return out;
        }
        NcmEndpoint ep;
        const bool haveEp = options.resolveEndpoint ? options.resolveEndpoint(&ep, options.cancelEvent)
                                                    : PickDefaultT2Endpoint(&ep, options.cancelEvent);
        if (!haveEp) {
            out.result = CancelledNow(options.cancelEvent) ? LadderResult::Cancelled
                                                           : LadderResult::NoAdapter;
            return out;
        }
        if (ep.peerSource != PeerSource::None) sawPeer = true;
        out.endpoint = ep;

        bool exhausted = false;
        uint16_t port = 0, rsd = 0;
        if (ConnectToBiometricKitBridge(ep, conn, &port, &rsd, options.cancelEvent, &exhausted, opt)) {
            out.result = LadderResult::Ok;
            out.port = port;
            out.rsd = rsd;
            out.tunnel = tp::IsTunnelModeActive();
            T2_LOG("ladder", L"connected after %u step(s): port=%u rsd=%u (%s)", step,
                   static_cast<unsigned>(port), static_cast<unsigned>(rsd),
                   out.tunnel ? L"IPv4 tunnel" : L"native IPv6");
            return out;
        }
        if (CancelledNow(options.cancelEvent)) {
            out.result = LadderResult::Cancelled;
            return out;
        }
        if (exhausted) {
            T2_LOG("ladder", L"step %u: a full scan pass completed without BiometricKit - giving up", step);
            out.result = LadderResult::NotFound;
            return out;
        }
        const ULONGLONG now = GetTickCount64();
        if (now + backoffMs >= deadline) {
            T2_LOG("ladder", L"no BridgeXPC connection after %u step(s) - deadline reached", step);
            out.result = sawPeer ? LadderResult::TimedOut : LadderResult::NoPeer;
            return out;
        }
        T2_LOG("ladder", L"step %u: not connected yet - retrying in %lu ms", step, backoffMs);
        if (options.cancelEvent) {
            if (WaitForSingleObject(static_cast<HANDLE>(options.cancelEvent), backoffMs) == 0) {
                out.result = LadderResult::Cancelled;
                return out;
            }
        } else {
            Sleep(backoffMs);
        }
        backoffMs = backoffMs * 2 > 2000 ? 2000 : backoffMs * 2;
        opt.forceRescan = false; // only the first step of a rescan skips the cache
    }
}

namespace {

std::string Ipv6Text(const in6_addr& a) {
    char buf[64] = {};
    InetNtopA(AF_INET6, &a, buf, sizeof(buf));
    return buf;
}

std::string HandleStatus(const TransportServiceContext& ctx) {
    ipc::KvMessage r;
    r.Set("result", "ok");
    r.Set("owner", ctx.ownerName);
    r.Set("pid", static_cast<long long>(GetCurrentProcessId()));
    tp::RefreshStickyFromDriver();
    const bool sticky = tp::IsAutoTunnelCommitted();
    r.Set("transport", tp::IsTunnelModeActive() ? "tunnel" : "native");
    r.Set("sticky", sticky ? 1 : 0);
    r.Set("autoswitch", tp::IsAutoSwitchEnabled() ? 1 : 0);
    r.Set("v6unavailable", tp::IsV6Unavailable() ? 1 : 0);
    r.Set("generation", static_cast<long long>(tp::CurrentGeneration()));
    r.Set("capture_busy", (ctx.captureBusy && ctx.captureBusy()) ? 1 : 0);
    uint16_t port = 0, rsd = 0;
    NcmEndpoint ep;
    bool haveEp = false;
    if (ctx.statusEndpoint) {
        haveEp = ctx.statusEndpoint(&ep);
    } else {
        auto eps = FindT2NcmEndpoints(/*resolvePeer=*/false);
        if (!eps.empty()) {
            ep = eps.front();
            haveEp = true;
        }
    }
    if (haveEp) LoadCachedPort(ep, &port, &rsd);
    r.Set("port", port);
    r.Set("rsd", rsd);
    const tp::TransportStats st = tp::GetTransportStats();
    r.Set("connects_ok", static_cast<long long>(st.connectsOk));
    r.Set("connects_failed", static_cast<long long>(st.connectsFailed));
    r.Set("tunnel_commits", static_cast<long long>(st.tunnelCommits));
    r.Set("native_returns", static_cast<long long>(st.nativeReturns));
    r.Set("native_rechecks", static_cast<long long>(st.nativeRechecks));
    r.Set("last_connect_ok", st.lastConnectOk ? 1 : 0);
    r.Set("last_connect_tunnel", st.lastConnectTunnel ? 1 : 0);
    r.Set("last_connect_age_ms", st.lastConnectTick
                                     ? static_cast<long long>(GetTickCount64() - st.lastConnectTick)
                                     : -1);
    r.Set("last_port", st.lastPort);
    return r.Serialize();
}

std::string HandleConnect(const ipc::KvMessage& req, void* cancelEvent,
                          const TransportServiceContext& ctx) {
    ipc::KvMessage r;
    if (ctx.captureBusy && ctx.captureBusy()) {
        // The armed capture holds a live BridgeXPC session over the committed
        // transport; a scan / native probe would flip the global driver mode under it.
        r.Set("result", "busy");
        return r.Serialize();
    }
    LadderOptions lo;
    lo.forceRescan = req.GetInt("force", 0) != 0;
    long long timeout = req.GetInt("timeout", 60000);
    if (timeout < 1000) timeout = 1000;
    if (timeout > 300000) timeout = 300000;
    lo.budgetMs = static_cast<unsigned long long>(timeout);
    lo.cancelEvent = cancelEvent;
    lo.resolveEndpoint = ctx.resolveEndpoint;
    bridgexpc::Connection conn;
    const LadderOutcome o = ConnectWithLadder(lo, &conn);
    r.Set("result", LadderResultName(o.result));
    r.Set("steps", static_cast<long long>(o.steps));
    if (o.result == LadderResult::Ok) {
        r.Set("port", o.port);
        r.Set("rsd", o.rsd);
        r.Set("transport", o.tunnel ? "tunnel" : "native");
        if (o.endpoint.peerSource != PeerSource::None) r.Set("peer", Ipv6Text(o.endpoint.peerLinkLocal));
        int64_t version = 0;
        if (conn.GetBridgeVersion(&version, std::chrono::milliseconds(2000))) {
            r.Set("bridge_version", static_cast<long long>(version));
        }
    }
    conn.Close();
    return r.Serialize();
}

} // namespace

std::string HandleTransportRequest(const std::string& request, void* cancelEvent,
                                   const TransportServiceContext& ctx) {
    const ipc::KvMessage req = ipc::KvMessage::Parse(request);
    const std::string op = req.Get("op");
    T2_LOG("service", L"pipe request op=%S", op.c_str());
    if (op == "status") return HandleStatus(ctx);
    if (op == "connect") return HandleConnect(req, cancelEvent, ctx);
    ipc::KvMessage r;
    r.Set("result", "error");
    r.Set("error", "unknown op");
    return r.Serialize();
}

} // namespace t2::discovery

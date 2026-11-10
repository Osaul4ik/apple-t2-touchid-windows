// SPDX-License-Identifier: GPL-2.0-only
// TransportService.h - what the transport owner does for its clients, and the
// retry ladder every non-capture caller uses.
//
//   ConnectWithLadder  - repeat ConnectToBiometricKitBridge steps on a backoff until
//                        connected, a full pass found nothing, the budget ran out, or
//                        cancel. Used by the pipe's "connect" and by the CLI's local
//                        fallback (Queue.cpp's capture ladder has its own, tied to the
//                        capture state).
//   HandleTransportRequest - the pipe request handler (TransportPipe.h). Runs in the
//                        owner process (the UMDF driver); pure protocol code so it can
//                        be tested against the simulated T2.
//
// Requests and replies (KvMessage):
//   op=status
//     -> result=ok owner=<name> pid=<pid> transport=native|tunnel sticky=0|1
//        autoswitch=0|1 v6unavailable=0|1 generation=N capture_busy=0|1
//        port=<cached BridgeXPC port, 0 = none> rsd=<...>
//        connects_ok= connects_failed= tunnel_commits= native_returns= native_rechecks=
//        last_connect_ok=0|1 last_connect_age_ms=<ms, -1 = never> last_port=
//   op=connect force=0|1 timeout=<ms>
//     -> result=ok port= rsd= transport= bridge_version= peer=<fe80::...> steps=
//        result=busy      (a capture is armed: the sensor's own session decides)
//        result=no_adapter | no_peer | not_found | timed_out | cancelled
#pragma once
#include "Adapter.h"
#include "../BridgeXpc/Connection.h"
#include <cstdint>
#include <functional>
#include <string>

namespace t2::discovery {

enum class LadderResult { Ok, NoAdapter, NoPeer, NotFound, TimedOut, Cancelled };
const char* LadderResultName(LadderResult r); // "ok", "no_adapter", ...

struct LadderOptions {
    bool forceRescan = false;      // first step only (a port it confirms is cached)
    unsigned long long budgetMs = 60000;
    void* cancelEvent = nullptr;
    // Fills the endpoint for one step (adapter + readiness gate + peer). Default:
    // PickDefaultT2Endpoint. Return false = no adapter.
    std::function<bool(NcmEndpoint* ep, void* cancelEvent)> resolveEndpoint;
};

struct LadderOutcome {
    LadderResult result = LadderResult::TimedOut;
    uint16_t port = 0;
    uint16_t rsd = 0;
    bool tunnel = false;
    unsigned steps = 0;
    NcmEndpoint endpoint;
};

LadderOutcome ConnectWithLadder(const LadderOptions& options, bridgexpc::Connection* conn);

struct TransportServiceContext {
    std::string ownerName = "T2TouchIdBio";
    // True while a capture is armed: the owner must not move the transport under it.
    std::function<bool()> captureBusy;
    // Endpoint resolution (default PickDefaultT2Endpoint).
    std::function<bool(NcmEndpoint* ep, void* cancelEvent)> resolveEndpoint;
    // Endpoint whose cached port "status" reports (default: the first adapter, no I/O).
    std::function<bool(NcmEndpoint* ep)> statusEndpoint;
};

std::string HandleTransportRequest(const std::string& request, void* cancelEvent,
                                   const TransportServiceContext& ctx);

} // namespace t2::discovery

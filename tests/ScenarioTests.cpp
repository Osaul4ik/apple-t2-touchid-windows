// SPDX-License-Identifier: GPL-2.0-only
// ScenarioTests.cpp - the whole connect flow (BridgeDiscovery -> TransportMode ->
// PortScan / RemoteXPC / Connection) against a simulated T2 (FakeT2.h): the cases
// that used to be checked only on hardware - VPN on/off, stale port, service not
// up yet, sticky tunnel across processes, forced rescan.
//
// After EVERY connect the core invariant is checked: T2Ncm.sys's live mode equals
// the committed transport (sticky flag) - a phase never leaves the driver in its
// probe mode.
//
// Runs under wine (tests/host/run-tests-wine.sh) and on Windows. Uses
// HKCU\Software\T2TouchIdScenarioTests for its registry state.
#include "FakeT2.h"
#include "../protocol/Discovery/BridgeDiscovery.h"
#include "../protocol/Discovery/PortCache.h"
#include "../protocol/Discovery/TransportService.h"
#include "../protocol/Ipc/TransportPipe.h"
#include <atomic>
#include "../protocol/BridgeXpc/TransportMode.h"
#include <chrono>
#include <cstdio>
#include <functional>
#include <thread>
#include <string>
#include <vector>

using namespace t2;
using t2::test::FakeT2;
using t2::test::NativePath;
namespace tp = t2::transport;
namespace td = t2::discovery;

namespace {

int g_failures = 0;
const char* g_scenario = "";

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "FAIL [%s] %s:%d  %s\n", g_scenario, __FILE__, __LINE__, #cond); \
        ++g_failures; \
    } \
} while (0)

const wchar_t kTestRoot[] = L"Software\\T2TouchIdScenarioTests";
const wchar_t kTestNetwork[] = L"Software\\T2TouchIdScenarioTests\\Network";

void SetAutoSwitch(bool on) {
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kTestNetwork, 0, nullptr, 0, KEY_WRITE, nullptr, &k,
                        nullptr) == ERROR_SUCCESS) {
        DWORD v = on ? 1 : 0;
        RegSetValueExW(k, L"AutoSwitch", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        // Native "silent but answers ICMP" hold off: the fake T2 does not answer ICMP
        // anyway, and a 0 keeps a silent native path a definitive verdict.
        v = 0;
        RegSetValueExW(k, L"NativeSilenceGraceMs", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v),
                       sizeof(v));
        RegCloseKey(k);
    }
}

td::NcmEndpoint Endpoint() {
    td::NcmEndpoint ep;
    ep.ifIndex = 1;
    inet_pton(AF_INET6, "fe80::aede:48ff:fe00:1122", &ep.peerLinkLocal);
    ep.peerSource = td::PeerSource::NeighborTable;
    const unsigned char mac[6] = {0xAC, 0xDE, 0x48, 0x00, 0x11, 0x22};
    std::memcpy(ep.mac, mac, 6);
    ep.hasMac = true;
    return ep;
}

struct Result {
    bool ok = false;
    uint16_t port = 0;
    uint16_t rsd = 0;
    bool exhausted = false;
    long long ms = 0;
};

// One connect = one step of the caller's ladder, exactly as Queue.cpp / the CLI do.
Result Connect(FakeT2& fake, bool forceRescan = false, HANDLE cancelEvent = nullptr) {
    Result r;
    td::ConnectOptions opt;
    opt.forceRescan = forceRescan;
    bridgexpc::Connection conn;
    const auto t0 = std::chrono::steady_clock::now();
    r.ok = td::ConnectToBiometricKitBridge(Endpoint(), &conn, &r.port, &r.rsd, cancelEvent,
                                           &r.exhausted, opt);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
               .count();
    conn.Close();
    // Invariant 1 (docs/ARCHITECTURE.md): driver mode == committed mode once a phase ended.
    CHECK(fake.driverMode.load() == (tp::IsAutoTunnelCommitted() ? 1 : 0));
    // ...and the process's copy of the sticky flag is the driver's.
    CHECK(fake.driverSticky.load() == (tp::IsAutoTunnelCommitted() ? 1 : 0));
    return r;
}

// The transport owner as the UMDF driver runs it: HandleTransportRequest behind
// the pipe, endpoint = the simulated T2's.
const wchar_t kTestPipe[] = L"\\\\.\\pipe\\T2TouchIdTransport-scenario-test";
std::atomic<bool> g_captureBusy{false};

td::TransportServiceContext ServiceContext() {
    td::TransportServiceContext ctx;
    ctx.ownerName = "scenario-test";
    ctx.captureBusy = [] { return g_captureBusy.load(); };
    ctx.resolveEndpoint = [](td::NcmEndpoint* ep, void*) { *ep = Endpoint(); return true; };
    ctx.statusEndpoint = [](td::NcmEndpoint* ep) { *ep = Endpoint(); return true; };
    return ctx;
}

ipc::KvMessage Call(const std::string& request, DWORD timeoutMs, ipc::PipeCallResult* res = nullptr,
                    HANDLE cancel = nullptr) {
    std::string reply;
    const ipc::PipeCallResult r = ipc::CallPipe(kTestPipe, request, timeoutMs, &reply, cancel,
                                                /*requireServiceServer=*/false);
    if (res) *res = r;
    return ipc::KvMessage::Parse(reply);
}

bool RunningUnderWine() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll && GetProcAddress(ntdll, "wine_get_version") != nullptr;
}

uint16_t CachedPort() {
    uint16_t p = 0, rsd = 0;
    return td::LoadCachedPort(Endpoint(), &p, &rsd) ? p : 0;
}

// Fresh process: no transport / discovery state, empty registry, fresh driver.
void FreshProcess(FakeT2& fake, bool autoSwitch = true) {
    RegDeleteTreeW(HKEY_CURRENT_USER, kTestRoot);
    SetAutoSwitch(autoSwitch);
    tp::testing::ResetState();
    td::testing::ResetState();
    fake.driverMode = 0;
    fake.driverSticky = 0;
    fake.nativePath = NativePath::Open;
    fake.SetBiometricKitAdvertised(true);
    fake.ResetCounters();
}
// Same machine, the process restarted (WUDFHost restart / a new CLI): the driver and
// the registry keep their state.
void RestartProcess() {
    tp::testing::ResetState();
    td::testing::ResetState();
}

struct Scenario {
    const char* name;
    std::function<void(FakeT2&)> run;
};

// ---------------------------------------------------------------------------------
const Scenario kScenarios[] = {
    {"cold start, native IPv6: full scan finds BiometricKit, port is cached",
     [](FakeT2& f) {
         FreshProcess(f);
         const Result r = Connect(f);
         CHECK(r.ok);
         CHECK(r.port == f.BridgePort());
         CHECK(r.rsd == f.RsdPort());
         CHECK(f.heloNative == 1 && f.heloTunnel == 0);
         CHECK(f.driverMode == 0 && f.driverSticky == 0);
         CHECK(CachedPort() == f.BridgePort());
     }},

    {"warm start: cached port answers, no scan at all",
     [](FakeT2& f) {
         FreshProcess(f);
         CHECK(Connect(f).ok);
         RestartProcess();
         f.ResetCounters();
         const Result r = Connect(f);
         CHECK(r.ok && r.port == f.BridgePort());
         CHECK(f.rsdNative == 0 && f.rsdTunnel == 0); // no RemoteXPC = no scan
         CHECK(f.heloNative == 1);
     }},

    {"T2 rebooted, BiometricKit moved: stale cached port -> rescan -> cache updated",
     [](FakeT2& f) {
         FreshProcess(f);
         CHECK(Connect(f).ok);
         const uint16_t old = f.BridgePort();
         CHECK(f.MoveBridgePort());
         RestartProcess();
         const Result r = Connect(f);
         CHECK(r.ok);
         CHECK(r.port == f.BridgePort() && r.port != old);
         CHECK(CachedPort() == f.BridgePort());
         CHECK(f.driverSticky == 0); // an RST on the old port proves native works
     }},

    {"VPN kill-switch (WSAEACCES on IPv6): straight to the IPv4 tunnel, committed",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         const Result r = Connect(f);
         CHECK(r.ok && r.port == f.BridgePort());
         CHECK(f.heloTunnel == 1 && f.heloNative == 0);
         CHECK(f.driverSticky == 1 && f.driverMode == 1);
         CHECK(tp::IsAutoTunnelCommitted());
         CHECK(CachedPort() == f.BridgePort()); // the same port serves both transports
     }},

    {"VPN that silently drops IPv6: silent scan -> judged blocked -> tunnel",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Silent;
         const Result r = Connect(f);
         CHECK(r.ok && r.port == f.BridgePort());
         CHECK(f.heloTunnel == 1 && f.heloNative == 0);
         CHECK(f.driverSticky == 1);
     }},

    {"VPN comes up mid-session: next connect fails over to the tunnel",
     [](FakeT2& f) {
         FreshProcess(f);
         CHECK(Connect(f).ok);
         CHECK(f.driverSticky == 0);
         f.nativePath = NativePath::Blocked;
         f.ResetCounters();
         const Result r = Connect(f);
         CHECK(r.ok);
         CHECK(f.heloTunnel == 1);
         CHECK(f.driverSticky == 1);
     }},

    {"sticky tunnel survives a process restart (seeded from T2Ncm memory)",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         CHECK(Connect(f).ok);
         RestartProcess();
         f.ResetCounters();
         const Result r = Connect(f);
         CHECK(r.ok);
         CHECK(f.heloTunnel == 1 && f.heloNative == 0);
         CHECK(f.rsdNative == 0 && f.rsdTunnel == 0); // straight to the cached port on the tunnel
     }},

    {"VPN gone, no re-check requested: the tunnel stays committed",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         CHECK(Connect(f).ok);
         f.nativePath = NativePath::Open;
         f.ResetCounters();
         const Result r = Connect(f);
         CHECK(r.ok);
         CHECK(f.heloTunnel == 1 && f.heloNative == 0);
         CHECK(f.driverSticky == 1);
     }},

    {"VPN gone + network change / unlock re-check: back to native, sticky cleared",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         CHECK(Connect(f).ok);
         f.nativePath = NativePath::Open;
         tp::RequestNativeReprobe(); // what NetworkWatch / WTS_SESSION_UNLOCK do
         f.ResetCounters();
         const Result r = Connect(f);
         CHECK(r.ok);
         CHECK(f.heloNative == 1 && f.heloTunnel == 0);
         CHECK(f.driverSticky == 0 && f.driverMode == 0);
         CHECK(!tp::IsAutoTunnelCommitted());
     }},

    {"VPN still up + re-check: native fails once, the tunnel carries on",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         CHECK(Connect(f).ok);
         tp::RequestNativeReprobe();
         f.ResetCounters();
         const Result r = Connect(f);
         CHECK(r.ok);
         CHECK(f.heloTunnel == 1 && f.heloNative == 0);
         CHECK(f.driverSticky == 1);
     }},

    {"GUI Rescan (forceRescan) on a sticky tunnel after the VPN went away: native wins",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         CHECK(Connect(f).ok);
         f.nativePath = NativePath::Open;
         f.ResetCounters();
         const Result r = Connect(f, /*forceRescan=*/true);
         CHECK(r.ok && r.port == f.BridgePort());
         CHECK(f.rsdNative >= 1);   // a real scan ran
         CHECK(f.heloNative == 1);
         CHECK(f.driverSticky == 0);
     }},

    {"GUI Rescan with the VPN still up: native blocked -> tunnel, port re-confirmed",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         CHECK(Connect(f).ok);
         CHECK(f.MoveBridgePort());
         f.ResetCounters();
         const Result r = Connect(f, /*forceRescan=*/true);
         CHECK(r.ok && r.port == f.BridgePort());
         CHECK(f.rsdTunnel >= 1 && f.heloTunnel == 1);
         CHECK(CachedPort() == f.BridgePort());
         CHECK(f.driverSticky == 1);
     }},

    {"another process (CLI) cleared the sticky tunnel: this one follows the driver",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         CHECK(Connect(f).ok);
         CHECK(tp::IsAutoTunnelCommitted());
         // The CLI's rescan found native working and cleared it in T2Ncm memory.
         f.nativePath = NativePath::Open;
         f.driverSticky = 0;
         f.driverMode = 0;
         f.ResetCounters();
         const Result r = Connect(f);
         CHECK(r.ok);
         CHECK(f.heloNative == 1 && f.heloTunnel == 0);
     }},

    {"BiometricKit not advertised yet: not found, then found once it is up",
     [](FakeT2& f) {
         FreshProcess(f);
         f.SetBiometricKitAdvertised(false);
         Result r = Connect(f);
         CHECK(!r.ok);
         CHECK(r.exhausted);      // one complete pass without the service
         CHECK(CachedPort() == 0);
         CHECK(f.driverSticky == 0); // a working native path is not "blocked"
         f.SetBiometricKitAdvertised(true);
         Sleep(1100);             // the 1 s cool-down after an empty pass
         r = Connect(f);
         CHECK(r.ok && r.port == f.BridgePort());
     }},

    {"IPv6 blocked and BiometricKit down on the tunnel too: nothing committed, driver back on native",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         f.SetBiometricKitAdvertised(false);
         const Result r = Connect(f);
         CHECK(!r.ok);
         CHECK(f.rsdTunnel >= 1);      // the tunnel was really tried
         CHECK(!tp::IsAutoTunnelCommitted());
         CHECK(f.driverMode == 0);     // the probe's tunnel mode was rolled back
     }},

    {"cancel (CancelIoEx / lock) in the middle of a scan: mode rolled back, port kept",
     [](FakeT2& f) {
         FreshProcess(f);
         CHECK(Connect(f).ok);         // native works, port cached
         const uint16_t cached = CachedPort();
         f.nativePath = NativePath::Silent;
         CHECK(f.MoveBridgePort());    // cached port is stale: a scan is needed
         HANDLE cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
         std::thread canceller([cancel] { Sleep(300); SetEvent(cancel); });
         const Result r = Connect(f, false, cancel);
         canceller.join();
         CloseHandle(cancel);
         CHECK(!r.ok);
         CHECK(!r.exhausted);          // a cancelled pass is "not yet", never "failed"
         CHECK(f.driverMode == 0);
         CHECK(!tp::IsAutoTunnelCommitted());
         CHECK(CachedPort() == cached); // a failure never throws the saved port away
     }},

    {"pipe: owner rescans for the client, reply carries port / transport / bridge version",
     [](FakeT2& f) {
         FreshProcess(f);
         ipc::PipeServer server;
         const td::TransportServiceContext ctx = ServiceContext();
         CHECK(server.Start(kTestPipe, [&ctx](const std::string& req, HANDLE cancel) {
             return td::HandleTransportRequest(req, cancel, ctx);
         }));
         ipc::PipeCallResult pr;
         ipc::KvMessage r = Call("op=connect\nforce=1\ntimeout=20000\n", 30000, &pr);
         CHECK(pr == ipc::PipeCallResult::Ok);
         CHECK(r.Get("result") == "ok");
         CHECK(r.GetInt("port") == f.BridgePort());
         CHECK(r.GetInt("rsd") == f.RsdPort());
         CHECK(r.Get("transport") == "native");
         // FakeT2 answers HELO but not getBridgeVersion: the reply must then say nothing
         // about the version rather than invent one.
         CHECK(!r.Has("bridge_version"));
         CHECK(r.Get("peer") == "fe80::aede:48ff:fe00:1122");
         r = Call("op=status\n", 5000, &pr);
         CHECK(pr == ipc::PipeCallResult::Ok);
         CHECK(r.Get("owner") == "scenario-test");
         CHECK(r.GetInt("port") == f.BridgePort());
         CHECK(r.Get("transport") == "native" && r.GetInt("sticky") == 0);
         CHECK(r.GetInt("connects_ok") >= 1);
         CHECK(r.GetInt("last_connect_ok") == 1 && r.GetInt("last_port") == f.BridgePort());
         r = Call("op=bogus\n", 5000);
         CHECK(r.Get("result") == "error");
         server.Stop();
         CHECK(ipc::CallPipe(kTestPipe, "op=status\n", 500, nullptr, nullptr, false) ==
               ipc::PipeCallResult::NoServer);
     }},

    {"pipe: VPN blocks IPv6 -> the owner commits the tunnel, status shows it + counters",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Blocked;
         ipc::PipeServer server;
         const td::TransportServiceContext ctx = ServiceContext();
         CHECK(server.Start(kTestPipe, [&ctx](const std::string& req, HANDLE cancel) {
             return td::HandleTransportRequest(req, cancel, ctx);
         }));
         ipc::KvMessage r = Call("op=connect\nforce=1\ntimeout=20000\n", 30000);
         CHECK(r.Get("result") == "ok" && r.Get("transport") == "tunnel");
         r = Call("op=status\n", 5000);
         CHECK(r.Get("transport") == "tunnel" && r.GetInt("sticky") == 1);
         CHECK(r.GetInt("tunnel_commits") == 1);
         f.nativePath = NativePath::Open;
         r = Call("op=connect\nforce=1\ntimeout=20000\n", 30000);
         CHECK(r.Get("result") == "ok" && r.Get("transport") == "native");
         r = Call("op=status\n", 5000);
         CHECK(r.GetInt("sticky") == 0 && r.GetInt("native_returns") == 1);
         server.Stop();
     }},

    {"pipe: a capture is armed -> rescan refused (busy), transport untouched",
     [](FakeT2& f) {
         FreshProcess(f);
         ipc::PipeServer server;
         const td::TransportServiceContext ctx = ServiceContext();
         CHECK(server.Start(kTestPipe, [&ctx](const std::string& req, HANDLE cancel) {
             return td::HandleTransportRequest(req, cancel, ctx);
         }));
         g_captureBusy = true;
         const ipc::KvMessage r = Call("op=connect\nforce=1\ntimeout=20000\n", 30000);
         g_captureBusy = false;
         CHECK(r.Get("result") == "busy");
         CHECK(f.rsdNative == 0 && f.rsdTunnel == 0 && f.modeWrites == 0);
         server.Stop();
     }},

    {"pipe: client gives up mid-rescan -> the owner's scan is cancelled, mode rolled back",
     [](FakeT2& f) {
         FreshProcess(f);
         f.nativePath = NativePath::Silent;   // slow path: silent native, then tunnel...
         f.SetBiometricKitAdvertised(false); // ...that never finds the service
         ipc::PipeServer server;
         const td::TransportServiceContext ctx = ServiceContext();
         std::atomic<bool> handlerSawCancel{false};
         CHECK(server.Start(kTestPipe, [&](const std::string& req, HANDLE cancel) {
             std::string out = td::HandleTransportRequest(req, cancel, ctx);
             if (WaitForSingleObject(cancel, 0) == 0) handlerSawCancel = true;
             return out;
         }));
         ipc::PipeCallResult pr;
         const auto t0 = std::chrono::steady_clock::now();
         Call("op=connect\nforce=1\ntimeout=120000\n", 400, &pr); // the client times out
         CHECK(pr == ipc::PipeCallResult::TimedOut);
         server.Stop(); // joins the handler: it must end promptly once cancelled
         const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - t0).count();
         CHECK(handlerSawCancel.load());
         CHECK(ms < 10000);
         CHECK(f.driverMode == 0 && f.driverSticky == 0);
     }},

    {"pipe: name already taken (squatter) -> the owner refuses to serve on it",
     [](FakeT2&) {
         ipc::PipeServer squatter, owner;
         CHECK(squatter.Start(kTestPipe, [](const std::string&, HANDLE) { return std::string("result=ok\n"); }));
         // FILE_FLAG_FIRST_PIPE_INSTANCE: Windows refuses a second "first" instance.
         // wine does not implement the flag, so only the client-side check runs there.
         if (!RunningUnderWine()) {
             CHECK(!owner.Start(kTestPipe, [](const std::string&, HANDLE) { return std::string(); }));
         }
         // A real client (requireServiceServer=true) does not trust a non-service server.
         std::string reply;
         CHECK(ipc::CallPipe(kTestPipe, "op=status\n", 2000, &reply, nullptr, true) ==
               ipc::PipeCallResult::Untrusted);
         squatter.Stop();
     }},

    {"AutoSwitch off + IPv6 blocked: no tunnel, nothing committed",
     [](FakeT2& f) {
         FreshProcess(f, /*autoSwitch=*/false);
         f.nativePath = NativePath::Blocked;
         const Result r = Connect(f);
         CHECK(!r.ok);
         CHECK(f.heloTunnel == 0 && f.rsdTunnel == 0);
         CHECK(f.driverSticky == 0 && f.driverMode == 0);
     }},

    {"T2Ncm.sys missing: native still works, nothing breaks",
     [](FakeT2& f) {
         FreshProcess(f);
         f.driverPresent = false;
         const Result r = Connect(f);
         f.driverPresent = true;
         CHECK(r.ok && r.port == f.BridgePort());
         CHECK(f.heloNative == 1);
     }},
};

} // namespace

int wmain() {
    FakeT2 fake;
    if (!fake.Start()) {
        std::fprintf(stderr, "FakeT2: could not open the loopback listeners\n");
        return 2;
    }
    tp::hooks::Install(&fake.Hooks());
    std::printf("FakeT2: RemoteXPC %u, BridgeXPC %u (scan range 49000-65535)\n",
                static_cast<unsigned>(fake.RsdPort()), static_cast<unsigned>(fake.BridgePort()));

    int run = 0;
    for (const Scenario& s : kScenarios) {
        g_scenario = s.name;
        const int before = g_failures;
        const auto t0 = std::chrono::steady_clock::now();
        s.run(fake);
        const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - t0).count();
        std::printf("%s  %-82s %6lld ms\n", g_failures == before ? "ok  " : "FAIL", s.name, ms);
        ++run;
    }

    tp::hooks::Clear();
    fake.Stop();
    RegDeleteTreeW(HKEY_CURRENT_USER, kTestRoot);
    std::printf("%d scenarios, %d failed checks\n", run, g_failures);
    return g_failures == 0 ? 0 : 1;
}

// SPDX-License-Identifier: GPL-2.0-only
// FakeT2.cpp - see FakeT2.h.
#include "FakeT2.h"
#include "../protocol/Discovery/RemoteXpc.h"
#include "../protocol/BridgeXpc/Frame.h"
#include "../protocol/BridgeXpc/Winsock.h"
#include <chrono>
#include <cstring>

namespace t2::test {

namespace {

constexpr uint32_t kXpcMessageMagic = 0x29b00b92u;
constexpr uint32_t kFlagAlwaysSet = 0x00000001u;
constexpr uint32_t kFlagDataFlag = 0x00000100u;

constexpr uint32_t kNativeHost = 0x7F000001u; // 127.0.0.1 = "fe80::<T2>%if"
constexpr uint32_t kTunnelHost = 0x7F000002u; // 127.0.0.2 = "169.254.a.b"

void PutU32LE(std::vector<uint8_t>* v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v->push_back(static_cast<uint8_t>(x >> (8 * i)));
}
void PutU64LE(std::vector<uint8_t>* v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v->push_back(static_cast<uint8_t>(x >> (8 * i)));
}
std::vector<uint8_t> Http2Frame(uint8_t type, uint8_t flags, uint32_t stream,
                                const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> f;
    const uint32_t len = static_cast<uint32_t>(payload.size());
    f.push_back(static_cast<uint8_t>(len >> 16));
    f.push_back(static_cast<uint8_t>(len >> 8));
    f.push_back(static_cast<uint8_t>(len));
    f.push_back(type);
    f.push_back(flags);
    f.push_back(static_cast<uint8_t>(stream >> 24));
    f.push_back(static_cast<uint8_t>(stream >> 16));
    f.push_back(static_cast<uint8_t>(stream >> 8));
    f.push_back(static_cast<uint8_t>(stream));
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}
bool SendAll(SOCKET s, const std::vector<uint8_t>& b) {
    size_t off = 0;
    while (off < b.size()) {
        const int n = send(s, reinterpret_cast<const char*>(b.data() + off),
                           static_cast<int>(b.size() - off), 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}
// Reads and drops whatever the client sends until it closes or `ms` pass.
void Drain(SOCKET s, DWORD ms) {
    const ULONGLONG end = GetTickCount64() + ms;
    char buf[4096];
    for (;;) {
        const ULONGLONG now = GetTickCount64();
        if (now >= end) return;
        fd_set r;
        FD_ZERO(&r);
        FD_SET(s, &r);
        timeval tv{0, static_cast<long>((end - now > 100 ? 100 : end - now) * 1000)};
        const int sel = select(0, &r, nullptr, nullptr, &tv);
        if (sel < 0) return;
        if (sel == 0) continue;
        if (recv(s, buf, sizeof(buf), 0) <= 0) return;
    }
}
bool RecvExact(SOCKET s, uint8_t* p, size_t n, DWORD ms) {
    const ULONGLONG end = GetTickCount64() + ms;
    size_t got = 0;
    while (got < n) {
        const ULONGLONG now = GetTickCount64();
        if (now >= end) return false;
        fd_set r;
        FD_ZERO(&r);
        FD_SET(s, &r);
        timeval tv{0, static_cast<long>((end - now > 100 ? 100 : end - now) * 1000)};
        const int sel = select(0, &r, nullptr, nullptr, &tv);
        if (sel < 0) return false;
        if (sel == 0) continue;
        const int k = recv(s, reinterpret_cast<char*>(p + got), static_cast<int>(n - got), 0);
        if (k <= 0) return false;
        got += static_cast<size_t>(k);
    }
    return true;
}
std::vector<uint8_t> BridgeFrame(uint32_t type, const std::string& body) {
    std::vector<uint8_t> f;
    f.push_back(static_cast<uint8_t>(bridgexpc::kFrameMagic & 0xFF));
    f.push_back(static_cast<uint8_t>(bridgexpc::kFrameMagic >> 8));
    f.push_back(static_cast<uint8_t>(bridgexpc::kProtocolVersion & 0xFF));
    f.push_back(static_cast<uint8_t>(bridgexpc::kProtocolVersion >> 8));
    PutU32LE(&f, type);
    PutU64LE(&f, body.size());
    f.insert(f.end(), body.begin(), body.end());
    return f;
}

} // namespace

uint16_t FakeT2::PickFreePort(uint16_t from, uint16_t to, const std::set<uint16_t>& avoid) {
    for (uint32_t p = from; p <= to; ++p) {
        if (avoid.count(static_cast<uint16_t>(p))) continue;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return 0;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons(static_cast<uint16_t>(p));
        const bool ok = bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
        closesocket(s);
        if (ok) return static_cast<uint16_t>(p);
    }
    return 0;
}

bool FakeT2::OpenListener(uint16_t port, Role role) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY); // both 127.0.0.1 (native) and .2 (tunnel)
    a.sin_port = htons(port);
    if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || listen(s, 64) != 0) {
        closesocket(s);
        return false;
    }
    std::lock_guard<std::mutex> lock(mu_);
    listeners_.push_back({s, port, role});
    return true;
}

bool FakeT2::OpenBlackHole() {
    blackHole_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (blackHole_ == INVALID_SOCKET) return false;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(blackHole_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || listen(blackHole_, 0) != 0) {
        return false;
    }
    int n = sizeof(a);
    getsockname(blackHole_, reinterpret_cast<sockaddr*>(&a), &n);
    blackHolePort_ = ntohs(a.sin_port);
    // Fill the accept queue (never accepted): every later SYN is dropped.
    for (int i = 0; i < 4; ++i) {
        SOCKET f = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        u_long nb = 1;
        ioctlsocket(f, FIONBIO, &nb);
        connect(f, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        blackHoleFill_.push_back(f);
    }
    Sleep(100);
    return true;
}

bool FakeT2::Start() {
    t2::EnsureWinsock();
    stop_ = false;
    std::set<uint16_t> used;
    // RemoteXPC first band (59000-60000), BridgeXPC in the second (49000-49999),
    // like the hardware.
    rsdPort_ = PickFreePort(59200, 59900, used);
    used.insert(rsdPort_);
    const uint16_t bridge = PickFreePort(49300, 49900, used);
    used.insert(bridge);
    const uint16_t decoy = PickFreePort(59100, 59199, used);
    used.insert(decoy);
    closedPort_ = PickFreePort(49100, 49299, used);
    if (!rsdPort_ || !bridge || !decoy || !closedPort_) return false;
    bridgePort_ = bridge;
    if (!OpenListener(rsdPort_, Role::Rsd) || !OpenListener(bridge, Role::Bridge) ||
        !OpenListener(decoy, Role::Decoy) || !OpenBlackHole()) {
        return false;
    }

    hooks_ = {};
    hooks_.ncmIoctl = [this](DWORD code, const void* in, DWORD inSize, void* out, DWORD outSize,
                             DWORD* returned, bool* ok, DWORD* err) {
        return IoctlHook(code, in, inSize, out, outSize, returned, ok, err);
    };
    hooks_.peerAddress = [this](bool tunnel, uint16_t port, t2::transport::PeerAddress* out) {
        return AddressHook(tunnel, port, out);
    };
    hooks_.connectVerdict = [this](bool tunnel, uint16_t port) { return VerdictHook(tunnel, port); };
    hooks_.tunnelNeighborReady = true;
    hooks_.gateReady = true;
    hooks_.regRoot = HKEY_CURRENT_USER;
    hooks_.regPath = L"Software\\T2TouchIdScenarioTests\\Network";

    acceptThread_ = std::thread([this] { AcceptLoop(); });
    return true;
}

void FakeT2::Stop() {
    stop_ = true;
    if (acceptThread_.joinable()) acceptThread_.join();
    std::vector<std::thread> workers;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& l : listeners_) closesocket(l.s);
        listeners_.clear();
        workers.swap(workers_);
    }
    for (auto& w : workers) w.join();
    for (SOCKET f : blackHoleFill_) closesocket(f);
    blackHoleFill_.clear();
    if (blackHole_ != INVALID_SOCKET) closesocket(blackHole_);
    blackHole_ = INVALID_SOCKET;
}

bool FakeT2::MoveBridgePort() {
    const uint16_t old = bridgePort_;
    std::set<uint16_t> used{rsdPort_, old, closedPort_};
    const uint16_t fresh = PickFreePort(static_cast<uint16_t>(old + 1), 49999, used);
    if (!fresh || !OpenListener(fresh, Role::Bridge)) return false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
            if (it->port == old) {
                closesocket(it->s);
                listeners_.erase(it);
                break;
            }
        }
    }
    bridgePort_ = fresh;
    return true;
}

void FakeT2::ResetCounters() {
    rsdNative = rsdTunnel = heloNative = heloTunnel = 0;
    modeWrites = stickyWrites = 0;
}

void FakeT2::AcceptLoop() {
    while (!stop_) {
        fd_set r;
        FD_ZERO(&r);
        std::vector<Listener> ls;
        {
            std::lock_guard<std::mutex> lock(mu_);
            ls = listeners_;
        }
        for (const auto& l : ls) FD_SET(l.s, &r);
        timeval tv{0, 50 * 1000};
        if (select(0, &r, nullptr, nullptr, &tv) <= 0) continue;
        for (const auto& l : ls) {
            if (!FD_ISSET(l.s, &r)) continue;
            sockaddr_in local{};
            SOCKET c = accept(l.s, nullptr, nullptr);
            if (c == INVALID_SOCKET) continue;
            int n = sizeof(local);
            getsockname(c, reinterpret_cast<sockaddr*>(&local), &n);
            const bool tunnel = ntohl(local.sin_addr.s_addr) == kTunnelHost;
            std::lock_guard<std::mutex> lock(mu_);
            workers_.emplace_back([this, c, role = l.role, tunnel] { Serve(c, role, tunnel); });
        }
    }
}

void FakeT2::Serve(SOCKET c, Role role, bool tunnel) {
    BOOL nodelay = TRUE;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    switch (role) {
    case Role::Rsd:
        ServeRsd(c, tunnel);
        break;
    case Role::Bridge:
        ServeBridge(c, tunnel);
        break;
    case Role::Decoy:
        // Another T2 HTTP/2 service: speaks HTTP/2, never sends a RemoteXPC record.
        SendAll(c, Http2Frame(0x04, 0, 0, {}));
        Drain(c, 1500);
        break;
    }
    closesocket(c);
}

void FakeT2::ServeRsd(SOCKET c, bool tunnel) {
    ++(tunnel ? rsdTunnel : rsdNative);
    // Server speaks first: SETTINGS on stream 0 (what PortScan keys on).
    if (!SendAll(c, Http2Frame(0x04, 0, 0, {}))) return;
    // The peer record on the root channel (stream 1).
    discovery::XpcObject services = discovery::XpcObject::MakeDict();
    if (advertised_) {
        discovery::XpcObject bk = discovery::XpcObject::MakeDict();
        bk.SetField("Port", discovery::XpcObject::MakeString(std::to_string(bridgePort_.load())));
        services.SetField("com.apple.eos.BiometricKit", bk);
    }
    discovery::XpcObject other = discovery::XpcObject::MakeDict();
    other.SetField("Port", discovery::XpcObject::MakeString("49152"));
    services.SetField("com.apple.bridge.someotherservice", other);
    discovery::XpcObject record = discovery::XpcObject::MakeDict();
    record.SetField("MessageType", discovery::XpcObject::MakeString("Handshake"));
    record.SetField("Services", services);
    const std::vector<uint8_t> body = record.Encode();
    std::vector<uint8_t> wrapper;
    PutU32LE(&wrapper, kXpcMessageMagic);
    PutU32LE(&wrapper, kFlagAlwaysSet | kFlagDataFlag);
    PutU64LE(&wrapper, body.size());
    PutU64LE(&wrapper, 1);
    wrapper.insert(wrapper.end(), body.begin(), body.end());
    // Let the client's handshake frames arrive first (as the real peer does).
    Drain(c, 30);
    SendAll(c, Http2Frame(0x00, 0, 1, wrapper));
    Drain(c, 1500);
}

void FakeT2::ServeBridge(SOCKET c, bool tunnel) {
    const std::string helo =
        "{\"MaxSupportedProtocolVersion\":1,\"OSBuild\":\"22P1234\",\"BridgeXPCVersion\":39,"
        "\"ProcessName\":\"bkremoted\"}";
    // Counted BEFORE the peer HELO goes out: a client's connect only returns after it
    // has read that HELO, so the count is already visible when it does.
    ++(tunnel ? heloTunnel : heloNative);
    if (!SendAll(c, BridgeFrame(1, helo))) return;
    uint8_t hdr[16];
    if (!RecvExact(c, hdr, sizeof(hdr), 2000)) return;
    uint64_t len = 0;
    std::memcpy(&len, hdr + 8, 8);
    if (len > 4096) return;
    std::vector<uint8_t> clientHelo(static_cast<size_t>(len));
    if (len && !RecvExact(c, clientHelo.data(), clientHelo.size(), 2000)) return;
    uint32_t type = 0;
    std::memcpy(&type, hdr + 4, 4);
    if (type != 1) ++badClientHelo;
    Drain(c, 3000);
}

bool FakeT2::IoctlHook(DWORD code, const void* in, DWORD inSize, void* out, DWORD outSize,
                       DWORD* returned, bool* ok, DWORD* err) {
    *ok = false;
    *returned = 0;
    if (!driverPresent) {
        *err = ERROR_FILE_NOT_FOUND;
        return true;
    }
    const DWORD fn = (code >> 2) & 0xFFF;
    auto in32 = [&](ULONG* v) {
        if (!in || inSize < sizeof(ULONG)) return false;
        std::memcpy(v, in, sizeof(ULONG));
        return true;
    };
    ULONG v = 0;
    switch (fn) {
    case 0x902: // SET_TUNNEL_PEER
    case 0x904: // SET_TUNNEL_LOCAL
        *ok = in && inSize == 16;
        break;
    case 0x903: // SET_TRANSPORT_MODE
        if (in32(&v) && v <= 1) {
            driverMode = static_cast<int>(v);
            ++modeWrites;
            *ok = true;
        }
        break;
    case 0x905: // SET_TUNNEL_STICKY
        if (in32(&v) && v <= 1) {
            driverSticky = static_cast<int>(v);
            ++stickyWrites;
            *ok = true;
        }
        break;
    case 0x906: { // GET_TUNNEL_STATE
        const ULONG st[3] = {1, static_cast<ULONG>(driverSticky.load()), static_cast<ULONG>(driverMode.load())};
        if (out && outSize >= sizeof(st)) {
            std::memcpy(out, st, sizeof(st));
            *returned = sizeof(st);
            *ok = true;
        }
        break;
    }
    default:
        break;
    }
    if (!*ok) *err = ERROR_INVALID_PARAMETER;
    return true;
}

bool FakeT2::AddressHook(bool tunnel, uint16_t port, t2::transport::PeerAddress* out) {
    auto* a = reinterpret_cast<sockaddr_in*>(&out->addr);
    a->sin_family = AF_INET;
    out->family = AF_INET;
    out->len = sizeof(sockaddr_in);
    // What T2Ncm.sys's mode does to the traffic (Tunnel.c): a socket of the other
    // transport never gets an answer. So does a VPN that drops IPv6.
    const bool driverMatches = (driverMode.load() == 1) == tunnel;
    const bool dropped = !driverMatches || (!tunnel && nativePath.load() == NativePath::Silent);
    if (dropped) {
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a->sin_port = htons(blackHolePort_);
    } else {
        a->sin_addr.s_addr = htonl(tunnel ? kTunnelHost : kNativeHost);
        a->sin_port = htons(port);
    }
    return true;
}

int FakeT2::VerdictHook(bool tunnel, uint16_t /*port*/) {
    if (!tunnel && nativePath.load() == NativePath::Blocked) return WSAEACCES;
    return 0;
}

} // namespace t2::test

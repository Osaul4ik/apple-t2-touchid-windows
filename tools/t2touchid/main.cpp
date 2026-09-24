// SPDX-License-Identifier: GPL-2.0-only
// main.cpp — t2touchid.exe
//
// Milestone 2 §10, §27: commands are read-evidence tools, never a source
// of fabricated success. Every command either reports a real driver/IOCTL
// result or reports the specific failure — there is no "assume it worked"
// path anywhere in this file.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
// winsock2 MUST come before windows.h / Client.h, otherwise winsock.h is
// pulled first and winsock2.h redefinition errors kill the build (/WX).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "../../protocol/AppleKeyStore/Client.h"
#include "../../protocol/BridgeXpc/Connection.h"
#include "../../protocol/BiometricKit/Commands.h"
#include "../../protocol/BiometricKit/VerificationEngine.h"
#include "../../protocol/Discovery/Adapter.h"
#include "../../protocol/Discovery/PortCache.h"
#include "../../protocol/Discovery/PortScan.h"
#include "../../protocol/Discovery/RemoteXpc.h"
#include "../../protocol/BridgeXpc/Log.h"
#include <iostream>
#include <string>
#include <fstream>
#include <limits>
#include <conio.h>
#include <chrono>
#include <vector>
#include <optional>
#include <array>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <thread>
#include <mutex>

using namespace t2::applekeystore;

// Shared tail for terse failure lines throughout this file: every
// BridgeXPC-layer failure ("... command failed") now has a matching
// detailed reason logged from protocol/BridgeXpc/Connection.cpp — this
// just points the operator at where to look instead of leaving them with
// nothing but the one-line summary.
static const wchar_t* kSeeVerboseHint =
    L"(re-run with --verbose, or attach DebugView, for the detailed reason)\n";

// Matches the Linux reference's char secret[1024] + protect_secret_buffer()
// (mlock/RLIMIT_CORE=0/PR_SET_DUMPABLE=0 in t2-aks-tool.c): same 1024-byte
// capacity, reserved once up front so no push_back() here can ever trigger
// a reallocation.
static constexpr size_t kMaxSecretBytes = 1024;

// VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux, t2-aks-tool.c
// protect_secret_buffer / unlock_keybag): the Linux tool mlock()s a FIXED
// secret[1024] buffer before reading a single byte and keeps it locked
// until the wire exchange completes and it's explicit_bzero()'d.
//
// Two gaps existed here relative to that reference, both now fixed:
//   1. This used to build the password with std::vector::push_back with
//      no reserve() up front. Each capacity-doubling reallocation copies
//      the bytes typed so far into a new heap block and frees the old one
//      WITHOUT zeroing it first — every password longer than the current
//      capacity left a stale, plaintext prefix sitting in freed (and
//      reusable) heap memory. Reserving kMaxSecretBytes once, before any
//      character is read, makes reallocation impossible.
//   2. Nothing here paralleled mlock(): the buffer could be paged to
//      pagefile.sys, or captured whole by a crash dump, for as long as it
//      lived. VirtualLock() is the direct Windows analog; it's taken here
//      and held for the buffer's entire lifetime — including through the
//      caller's use of it in Client::Unlock — not just released the
//      instant this function returns. The caller (CmdUnlock) is
//      responsible for VirtualUnlock() once the secret has been consumed
//      and zeroed; see the comment there.
static std::vector<uint8_t> ReadPasswordInteractive() {
    std::wcout << L"Password: ";
    std::vector<uint8_t> secret;
    secret.reserve(kMaxSecretBytes);
    if (!VirtualLock(secret.data(), secret.capacity())) {
        // Same treatment as Linux: protect_secret_buffer() failing mlock()
        // is fatal ("protect password memory"), not a silent fallback to
        // an unlocked buffer.
        std::wcout << L"\nfailed to lock password memory (VirtualLock)\n";
        return {};
    }

    bool cancelled = false;
    bool overflowed = false;
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') break;
        if (ch == 3) { // Ctrl+C
            cancelled = true;
            break;
        }
        if (ch == '\b') {
            if (!secret.empty()) secret.pop_back();
            continue;
        }
        if (secret.size() == kMaxSecretBytes) {
            // Same shape as Linux's read_secret_line() filling its buffer
            // without a newline (EOVERFLOW): refuse outright rather than
            // silently truncate or grow past the locked/reserved region.
            overflowed = true;
            continue;
        }
        secret.push_back(static_cast<uint8_t>(ch));
        // No echo — password never appears on screen, in a log file, or in
        // command-line history (Milestone 2 §10).
    }
    std::wcout << L"\n";
    if (cancelled) std::wcout << L"cancelled\n";
    if (overflowed) std::wcout << L"password too long (max " << kMaxSecretBytes << L" bytes)\n";

    if (secret.empty() || cancelled || overflowed) {
        // Nothing usable is being returned — zero, unlock, and clear here
        // so no locked page is ever left behind on a path the caller
        // treats as "no password entered" and never touches again.
        SecureZeroMemory(secret.data(), secret.capacity());
        VirtualUnlock(secret.data(), secret.capacity());
        secret.clear();
        return secret;
    }
    // Still VirtualLock()'d on return (reserve() above means no
    // reallocation happens between here and the caller, so this is the
    // same physical pages) — see CmdUnlock for the matching VirtualUnlock.
    return secret;
}

static int CmdStatus(Client& client) {
    bool pci, bar4, ool, mailbox;
    AksResult r = client.GetStatus(&pci, &bar4, &ool, &mailbox);
    if (r != AksResult::Ok) {
        std::wcout << L"T2 PCI                  FAILED TO QUERY\n";
        return 1;
    }
    std::wcout << L"T2 PCI                  " << (pci ? L"OK" : L"NOT PRESENT") << L"\n";
    std::wcout << L"BAR4                    " << (bar4 ? L"mapped" : L"not mapped") << L"\n";
    std::wcout << L"SEP mailbox             " << (mailbox ? L"accessible" : L"unavailable") << L"\n";
    std::wcout << L"DMA / OOL               " << (ool ? L"registered" : L"not registered") << L"\n";
    // NOTE: network / RemoteXPC / BridgeXPC / BiometricKit / sensor /
    // identities rows from the ТЗ §27 example require the protocol layer
    // (network discovery + a live BridgeXpc connection), not just the
    // driver IOCTL surface this PoC's `status` currently queries. Wiring
    // those additional rows in is a follow-up, tracked explicitly in
    // docs/milestone-2-hardware-results.md rather than stubbed out here
    // with fake "OK" values.
    return 0;
}

static int CmdRegisterOol(Client& client) {
    // Gate 3 (docs/milestone-2-hardware-results.md): allocates the two
    // 16 KiB endpoint-7 common buffers and registers them with SEP via
    // SET_OOL_IN / SET_OOL_OUT (dma.c). This is a ONE-SHOT, irreversible
    // action for the lifetime of the boot: once OOL_IN registration
    // succeeds, SEP retains that physical address until reboot, so the
    // driver refuses to re-run it (idempotent success/failure replay
    // instead - see T2EvtIoDeviceControlRegisterOol).
    AksResult r = client.RegisterOol();
    if (r == AksResult::Ok) {
        std::wcout << L"DMA / OOL               registered\n";
        return 0;
    }
    if (r == AksResult::NotReady) {
        // Driver-side T2DmaAllocateOolBuffers/T2DmaRegisterOolBuffers
        // failed (e.g. SEP rejected SET_OOL_IN/SET_OOL_OUT, or a prior
        // attempt already failed this boot). Check DebugView/WinDbg
        // kernel prints from T2TouchIdTransport for the specific NTSTATUS
        // - this PoC deliberately does not guess a reason here.
        std::wcout << L"DMA / OOL               registration failed (not ready) - "
                      L"see kernel debug output for T2TouchIdTransport\n";
        return 1;
    }
    std::wcout << L"DMA / OOL               registration failed (I/O error) - "
                  L"is the driver loaded and are you Administrator?\n";
    return 1;
}

static int CmdCapabilities(Client& client) {
    uint64_t value = 0;
    AksResult r = client.GetCapabilities(1, &value);
    if (r != AksResult::Ok) {
        std::wcout << L"capabilities query failed\n";
        return 1;
    }
    std::wcout << L"capability[1] = 0x" << std::hex << value << std::dec << L"\n";
    // VERIFIED FROM SOURCE (t2-aks-tool.c capabilities): the Linux tool
    // treats this as a pass/fail self-test, not just a printout — it
    // returns exit code 1 unless the returned value is exactly 2
    // (`return value == 2 ? 0 : 1`). A successful mailbox round-trip with
    // any other value still means capability negotiation isn't behaving
    // as expected; this previously always returned 0 on any successful
    // exchange regardless of the value, which would mask that case in a
    // script checking the exit code.
    if (value != 2) {
        std::wcout << L"capabilities: unexpected value (expected 2)\n";
        return 1;
    }
    return 0;
}

static bool ReadBinaryFile(const std::wstring& path, std::vector<uint8_t>& bytes) {
    bytes.clear();

    std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
    if (!file) return false;

    const std::streampos end = file.tellg();
    if (end < 0) return false;

    const auto size = static_cast<unsigned long long>(end);
    // Keep one conservative limit at the CLI boundary. The Linux reference
    // uses 16000 bytes for the keybag payload, while the driver has a slightly
    // larger protocol maximum. Rejecting oversized files here avoids building
    // a request that can never be accepted and avoids accidental huge reads.
    constexpr unsigned long long kMaxKeybagBytes = 16000;
    if (size == 0 || size > kMaxKeybagBytes) return false;

    if (size > static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
        return false;
    }

    bytes.resize(static_cast<size_t>(size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        SecureZeroMemory(bytes.data(), bytes.size());
        bytes.clear();
        return false;
    }
    return true;
}

static int CmdLoadKeybag(Client& client, const std::wstring& path) {
    std::vector<uint8_t> bag;
    if (!ReadBinaryFile(path, bag)) {
        std::wcout << L"load-keybag: cannot read keybag file (must be 1..16000 bytes)\n";
        return 1;
    }

    int32_t handle = 0;
    int8_t sepStatus = 0;
    AksResult r = client.LoadKeybag(bag, &handle, 1, &sepStatus);
    SecureZeroMemory(bag.data(), bag.size());
    bag.clear();

    if (r == AksResult::NotReady) {
        std::wcout << L"load-keybag failed: DMA / OOL is not registered; run register-ool first\n";
        return 1;
    }
    if (r != AksResult::Ok) {
        std::wcout << L"load-keybag failed\n";
        return 1;
    }
    if (sepStatus != 0) {
        // AksResult::Ok here only means the mailbox round-trip completed —
        // Client::LoadKeybag returns Ok even when SEP itself rejected the
        // request (bad session, malformed bag, etc.), leaving outHandle
        // untouched (still 0 from the init above). Printing "OK,
        // handle=0" in that case would be a fabricated success, not a
        // real one — report the real SEP status instead.
        std::wcout << L"load-keybag: SEP rejected the request, sep_status="
                   << static_cast<int>(sepStatus) << L"\n";
        return 1;
    }

    std::wcout << L"load-keybag: OK, handle=" << handle << L"\n";
    return 0;
}

static int CmdSetSystemKeybag(Client& client, int32_t handle, int32_t specialUserBag) {
    int8_t sepStatus = 0;
    AksResult r = client.MakeSystemKeybag(handle, specialUserBag, 1, &sepStatus);
    if (r == AksResult::NotReady) {
        std::wcout << L"set-system-keybag failed: DMA / OOL is not registered; run register-ool first\n";
        return 1;
    }
    if (r != AksResult::Ok) {
        std::wcout << L"set-system-keybag failed\n";
        return 1;
    }
    if (sepStatus != 0) {
        // Same pattern as load-keybag: Ok only means the exchange
        // completed, not that SEP accepted the handle/session — check
        // the real status before declaring success.
        std::wcout << L"set-system-keybag: SEP rejected the request, sep_status="
                   << static_cast<int>(sepStatus) << L"\n";
        return 1;
    }

    std::wcout << L"set-system-keybag: OK\n";
    return 0;
}

static int CmdUnlock(Client& client, int32_t handle) {
    auto secret = ReadPasswordInteractive();
    if (secret.empty()) {
        std::wcout << L"no password entered\n";
        return 1;
    }
    // secret is VirtualLock()'d by ReadPasswordInteractive for its entire
    // lifetime, mirroring Linux's protect_secret_buffer()/mlock() scope,
    // which stays locked through the whole wire exchange in
    // unlock_keybag(). Client::Unlock zeroes the buffer's full capacity
    // internally before returning (see Client.cpp); capture the pointer
    // and capacity now so the matching VirtualUnlock still has a valid
    // range to release afterward, regardless of the outcome below.
    uint8_t* lockedPtr = secret.data();
    size_t lockedCapacity = secret.capacity();
    int8_t sepStatus = 0;
    AksResult r = client.Unlock(handle, secret, 1, &sepStatus); // zeroes `secret` internally
    VirtualUnlock(lockedPtr, lockedCapacity);
    if (r != AksResult::Ok) {
        std::wcout << L"unlock failed\n";
        return 1;
    }
    if (sepStatus != 0) {
        // Client::Unlock's own comment: SepStatus != 0 on this opcode IS
        // the wrong-password signal — it must never be reported as a
        // bare "unlock: OK". Without this check the CLI previously
        // printed success on a WRONG password.
        std::wcout << L"unlock: SEP rejected the request (wrong password or bad handle), "
                      L"sep_status=" << static_cast<int>(sepStatus) << L"\n";
        return 1;
    }
    std::wcout << L"unlock: OK\n";
    return 0;
}


static int CmdDeviceState(Client& client, int64_t handle, uint32_t selector) {
    std::vector<uint8_t> response;
    AksResult r = client.GetDeviceState(handle, selector, &response);
    if (r == AksResult::NotReady) {
        std::wcout << L"device-state failed: DMA / OOL is not registered; run register-ool first\n";
        return 1;
    }
    if (r != AksResult::Ok) {
        std::wcout << L"device-state failed (same timeout as capabilities implies EP7 dead)\n";
        return 1;
    }
    std::wcout << L"device-state: OK, response_length=" << response.size();
    if (response.size() >= 8) {
        uint32_t status = 0, blobLen = 0;
        std::memcpy(&status, response.data(), 4);
        std::memcpy(&blobLen, response.data() + 4, 4);
        std::wcout << L" status=0x" << std::hex << status
                   << L" blob_length=" << std::dec << blobLen;
    }
    std::wcout << L"\n";
    return 0;
}



// BiometricKit discovery constants (shared by the cache fast path, `network`
// and DiscoverBiometricKitBridge).
static constexpr const char* kBiometricKitService = "com.apple.eos.BiometricKit";
static constexpr std::chrono::milliseconds kRemoteXpcCheckTimeout{2000};

// Narrow an ASCII-only wide string (IPv6 literal from argv). Non-ASCII input
// yields an empty string, which the callers already report as "invalid
// --host", instead of silently truncating each char to its low byte.
static std::string NarrowAscii(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) {
        if (c > 0x7F) return {};
        out.push_back(static_cast<char>(c));
    }
    return out;
}

static bool IsDecimal(const std::wstring& a) {
    return !a.empty() && a.find_first_not_of(L"0123456789") == std::wstring::npos;
}

// Scan-then-verify in parallel (used by `network` and DiscoverBiometricKitBridge).
// Every HTTP/2 hit is handed to a RemoteXPC checker thread the moment
// PortScan.cpp finds it (onHit), running alongside the still-in-flight scan of
// the remaining ports. The instant a checker confirms the BiometricKit
// service, the scan's cancel flag stops the rest of the range. The caller
// fills in the ScanOptions knobs (concurrency, timeout, scanFromEnd, ...);
// onHit/cancel are owned by this function.
struct ScanProbeResult {
    uint16_t servicePort = 0;  // BridgeXPC port advertised by the verified candidate; 0 = none
    uint16_t rsdPort = 0;      // RemoteXPC (HTTP/2) port that advertised it
    std::vector<t2::discovery::PortCandidate> hits;
};

static ScanProbeResult ScanAndProbe(const t2::discovery::NcmEndpoint& ep,
                                    t2::discovery::ScanOptions opt) {
    using namespace t2::discovery;

    std::atomic<bool> stop{false};
    std::atomic<bool> serviceFound{false};
    std::mutex checkersMu;
    std::vector<std::thread> checkers;
    ScanProbeResult res;

    opt.cancel = &stop;
    opt.onHit = [&](const PortCandidate& c) {
        if (!c.http2PrefaceOk) return;      // TCP-only hits aren't real candidates
        if (serviceFound.load(std::memory_order_relaxed)) return; // already answered
        uint16_t port = c.port;
        std::lock_guard<std::mutex> lock(checkersMu);
        checkers.emplace_back([&, port]() {
            if (serviceFound.load(std::memory_order_relaxed)) return;
            uint16_t servicePort = 0;
            if (!ProbeServiceOnPort(ep, port, kBiometricKitService, kRemoteXpcCheckTimeout,
                                    &servicePort)) {
                return; // decoy or unreachable - not a discovery failure
            }
            bool expected = false;
            if (serviceFound.compare_exchange_strong(expected, true)) {
                res.servicePort = servicePort;
                res.rsdPort = port;
                stop.store(true, std::memory_order_relaxed); // abort rest of the scan
            }
        });
    };

    res.hits = ScanHttp2Preface(ep, opt);
    {
        // ScanHttp2Preface has already joined every scan worker, so onHit can
        // no longer fire and nothing else pushes into `checkers` concurrently.
        std::lock_guard<std::mutex> lock(checkersMu);
        for (auto& th : checkers) th.join();
    }
    return res;
}

// Cache fast-path shared by `network` and DiscoverBiometricKitBridge.
//
// The cache holds the BridgeXPC service port (raw TCP) and, when known, the
// RemoteXPC (HTTP/2) port whose peer record advertised it. Fast path, in
// order of cost:
//   A. direct BridgeXPC HELO on the cached service port (one TCP connect);
//   B. replay of the scan's own sequence against the cached RemoteXPC port:
//      RSD probe -> advertised port -> HELO (covers the case where the
//      service port only accepts clients after an RSD handshake, or moved);
// and only if both fail does the caller fall back to the 16384-port scan.
// Every path ends in a live BridgeXPC HELO, so a stale entry can never
// produce a false "found".
//
// NOTE: requires Winsock to be initialised. Previously WSAStartup was only
// called from inside ScanHttp2Preface, so on a cache hit (no scan) every
// socket() call failed and the cache always looked "stale". wmain now calls
// WSAStartup up front.
//
// On success `conn` is connected (HELO done) and *outPort is the BridgeXPC port.
static bool TryCachedBridgePort(const t2::discovery::NcmEndpoint& ep,
                                t2::bridgexpc::Connection* conn,
                                uint16_t* outPort) {
    using namespace t2::discovery;
    using namespace t2::bridgexpc;

    uint16_t svcPort = 0, rsdPort = 0;
    if (!LoadCachedPort(ep, &svcPort, &rsdPort)) return false;

    // A: direct.
    ConnectResult crA = conn->Connect(ep.peerLinkLocal, ep.ifIndex, svcPort,
                                       std::chrono::milliseconds(1500));
    if (crA == ConnectResult::Ok) {
        *outPort = svcPort;
        return true;
    }

    // B: RSD replay on the cached RemoteXPC port.
    if (rsdPort != 0) {
        uint16_t advertised = 0;
        if (ProbeServiceOnPort(ep, rsdPort, kBiometricKitService, kRemoteXpcCheckTimeout, &advertised)) {
            ConnectResult crB = conn->Connect(ep.peerLinkLocal, ep.ifIndex, advertised, kRemoteXpcCheckTimeout);
            if (crB == ConnectResult::Ok) {
                if (advertised != svcPort) SaveCachedPort(ep, advertised, rsdPort);
                *outPort = advertised;
                return true;
            }
            std::wcout << L"cached ports (RemoteXPC " << rsdPort << L", BridgeXPC " << advertised
                       << L"): HELO failed (direct result=" << static_cast<int>(crA)
                       << L", via RSD result=" << static_cast<int>(crB)
                       << L") - falling back to full scan.\n";
            return false;
        }
        std::wcout << L"cached ports (RemoteXPC " << rsdPort << L", BridgeXPC " << svcPort
                   << L"): direct HELO failed (result=" << static_cast<int>(crA)
                   << L") and RemoteXPC probe did not answer (T2 rebooted?) - falling back to full scan.\n";
        return false;
    }

    std::wcout << L"cached BridgeXPC port " << svcPort << L": direct HELO failed (result="
               << static_cast<int>(crA) << L") - falling back to full scan.\n";
    return false;
}

static int CmdNetwork(int argc, wchar_t* argv[]) {
    using namespace t2::discovery;

    unsigned long ifIndexOverride = 0;
    bool doScan = true;
    std::string hostOverride; // peer IPv6 without zone

    for (int i = 2; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--no-scan") {
            doScan = false;
        } else if (a == L"--ifindex" && i + 1 < argc) {
            ifIndexOverride = static_cast<unsigned long>(_wtoi(argv[++i]));
        } else if (a == L"--host" && i + 1 < argc) {
            hostOverride = NarrowAscii(argv[++i]);
            if (hostOverride.empty()) {
                std::wcout << L"invalid --host IPv6\n";
                return 1;
            }
        } else if (IsDecimal(a)) {
            ifIndexOverride = static_cast<unsigned long>(_wtoi(a.c_str()));
        }
    }

    std::vector<NcmEndpoint> endpoints;
    if (ifIndexOverride != 0) {
        NcmEndpoint ep;
        if (!GetEndpointByIfIndex(ifIndexOverride, &ep)) {
            std::wcout << L"no Preferred IPv6 link-local on ifIndex " << ifIndexOverride << L"\n";
            return 1;
        }
        endpoints.push_back(ep);
    } else {
        endpoints = FindT2NcmEndpoints();
        if (endpoints.empty()) {
            std::wcout << L"no T2 NCM adapter found.\n";
            std::wcout << L"hint: t2touchid.exe network <ifIndex> [--host fe80::...]\n";
            return 1;
        }
    }

    for (auto& ep : endpoints) {
        if (!hostOverride.empty()) {
            in6_addr parsed{};
            if (!ParseIpv6(hostOverride.c_str(), &parsed)) {
                std::wcout << L"invalid --host IPv6\n";
                return 1;
            }
            ep.peerLinkLocal = parsed;
            ep.peerSource = PeerSource::ManualOverride;
        }

        std::string local = FormatLinkLocal(ep.localLinkLocal, ep.ifIndex);
        std::string peer = FormatLinkLocal(ep.peerLinkLocal, ep.ifIndex);
        std::wcout << L"adapter:  " << ep.friendlyName << L"\n";
        std::wcout << L"desc:     " << ep.description << L"\n";
        std::wcout << L"ifIndex:  " << ep.ifIndex << L"\n";
        if (ep.hasMac) {
            std::wcout << L"mac:      ";
            for (int i = 0; i < 6; ++i) {
                wchar_t b[4];
                swprintf(b, 4, L"%02X%s", ep.mac[i], i < 5 ? L"-" : L"");
                std::wcout << b;
            }
            std::wcout << L"\n";
        }
        std::wcout << L"local:    ";
        std::wcout << std::wstring(local.begin(), local.end());
        std::wcout << L"  (Windows - do NOT scan this)\n";
        if (ep.peerSource == PeerSource::None) {
            std::wcout << L"peer:     (none found)\n";
            std::wcout << L"  no Reachable/Stale/Delay/Probe IPv6 neighbor "
                          L"on ifIndex " << ep.ifIndex << L" yet, even after "
                          L"an automatic ff02::1 prompt ping.\n";
            std::wcout << L"  try running the command again (the T2 may just "
                          L"need another moment), or pass --host fe80::...\n";
        } else {
            std::wcout << L"peer:     ";
            std::wcout << std::wstring(peer.begin(), peer.end());
            if (ep.peerSource == PeerSource::NeighborTable)
                std::wcout << L"  (IPv6 neighbor table - scan target)\n";
            else
                std::wcout << L"  (--host override - scan target)\n";
        }
    }

    if (!doScan) {
        std::wcout << L"scan skipped (--no-scan).\n";
        return 0;
    }

    const auto& ep = endpoints.front();
    if (ep.peerSource == PeerSource::None) {
        std::wcout << L"no peer to scan - see above.\n";
        return 1;
    }

    // Cache-first, same policy as DiscoverBiometricKitBridge (used by
    // identities/verify/warmup): the BridgeXPC port doesn't move within a
    // boot/session, so try the last known-good port for this adapter
    // before paying for a 16384-port scan. Verified by a live BridgeXPC
    // HELO (see TryCachedBridgePort) - a stale/wrong entry just falls
    // through to the full scan below, never a false "found".
    {
        using namespace t2::bridgexpc;
        Connection cachedBridge;
        uint16_t cachedPort = 0;
        if (TryCachedBridgePort(ep, &cachedBridge, &cachedPort)) {
            int64_t bridgeVersion = 0;
            if (cachedBridge.GetBridgeVersion(&bridgeVersion, std::chrono::milliseconds(2000))) {
                std::wcout << L"BiometricKit BridgeXPC port: " << cachedPort
                           << L"  (cached - skipped port scan)\n";
                std::wcout << L"BridgeXPC verified: HELO OK, bridge version="
                           << bridgeVersion << L"\n";
                return 0;
            }
            std::wcout << L"cached port " << cachedPort
                       << L" HELO OK but getBridgeVersion failed - falling back to full scan.\n";
            cachedBridge.Close();
        }
    }

    ScanOptions opt;
    opt.concurrency = 64;
    opt.connectTimeoutMs = 25;  // 10ms was flaky under concurrent scan load
    opt.includeTcpOnly = true;
    // Ascending (ScanOptions::scanFromEnd default) — the real BiometricKit
    // candidate has been observed near portBegin (~49000), not the high end.
    opt.onProgress = [](unsigned tried, unsigned total, unsigned tcp, unsigned http2) {
        std::wcout << L"  scanned " << tried << L"/" << total
                   << L"  tcp=" << tcp << L"  http2=" << http2 << L"\r" << std::flush;
    };

    std::wcout << L"scanning PEER ports " << opt.portBegin << L"-" << opt.portEnd
               << L" (concurrency " << opt.concurrency
               << L", timeout " << opt.connectTimeoutMs << L"ms)...\n";
    ScanProbeResult scan = ScanAndProbe(ep, opt);
    std::wcout << L"\n";
    std::vector<PortCandidate> hits = std::move(scan.hits);
    const uint16_t foundPort = scan.servicePort;
    const uint16_t foundRsdPort = scan.rsdPort;

    unsigned nTcp = 0, nHttp2 = 0;
    for (const auto& h : hits) {
        if (h.tcpOpen) ++nTcp;
        if (h.http2PrefaceOk) ++nHttp2;
    }

    if (hits.empty()) {
        std::wcout << L"no TCP listeners on peer in " << opt.portBegin << L"-"
                   << opt.portEnd << L".\n";
        std::wcout << L"try: --host fe80::... to override the discovered peer.\n";
        return 2;
    }

    // Sort ascending purely for a readable diagnostic table — with
    // scanFromEnd left at its default (ascending), hits already mostly
    // arrive in this order, but onHit/cancel can still leave it uneven;
    // this has no effect on scan or verification order above.
    std::sort(hits.begin(), hits.end(),
              [](const PortCandidate& a, const PortCandidate& b) { return a.port < b.port; });

    std::wcout << L"candidates: tcp_open=" << nTcp << L"  http2_settings=" << nHttp2;
    if (foundPort != 0) std::wcout << L"  (scan stopped early - BiometricKit already found)";
    std::wcout << L"\n";
    for (const auto& h : hits) {
        std::wcout << L"  port " << h.port;
        if (h.http2PrefaceOk) std::wcout << L"  [HTTP/2 SETTINGS]";
        else std::wcout << L"  [TCP only]";
        std::wcout << L"  recv=" << h.recvLen << L"B";
        if (h.recvLen > 0) {
            std::wcout << L"  hex=";
            int show = h.recvLen < 12 ? h.recvLen : 12;
            for (int i = 0; i < show; ++i) {
                wchar_t tmp[4];
                swprintf(tmp, 4, L"%02x", h.recvHead[i]);
                std::wcout << tmp;
            }
        } else {
            std::wcout << L"  (no data)";
        }
        std::wcout << L"\n";
    }

    if (foundPort == 0) {
        if (nHttp2 == 0) {
            std::wcout << L"note: no HTTP/2 SETTINGS yet. Confirm peer address matches Linux T2_TOUCHID_HOST.\n";
            return 0;
        }
        std::wcout << L"BiometricKit service not advertised by any candidate "
                      L"(all decoys, or T2 is not currently offering it).\n";
        return 0;
    }

    std::wcout << L"BiometricKit BridgeXPC port: " << foundPort << L"\n";

    // Gate 7 phase 1: prove the discovered port is a live BridgeXpc
    // endpoint, not just a plausible-looking number — open a real
    // connection (HELO handshake, Milestone 1 section 7) and read the
    // bridge's own version, rather than declaring victory on the port
    // number alone.
    using namespace t2::bridgexpc;
    Connection bridge;
    ConnectResult cr = bridge.Connect(ep.peerLinkLocal, ep.ifIndex, foundPort,
                                       std::chrono::milliseconds(2000));
    if (cr != ConnectResult::Ok) {
        std::wcout << L"BridgeXPC connect/HELO failed on port " << foundPort
                   << L" - discovered port did not answer as BridgeXpc.\n";
        return 1;
    }
    int64_t bridgeVersion = 0;
    if (!bridge.GetBridgeVersion(&bridgeVersion, std::chrono::milliseconds(2000))) {
        std::wcout << L"BridgeXPC HELO OK, but getBridgeVersion failed "
                      L"(unexpected reply shape).\n";
        return 1;
    }
    std::wcout << L"BridgeXPC verified: HELO OK, bridge version=" << bridgeVersion << L"\n";
    // Only cache after a live BridgeXPC connect actually succeeds — never
    // cache a port on RemoteXPC verification alone.
    SaveCachedPort(ep, foundPort, foundRsdPort);
    return 0;
}

// Shared discovery+connect step for `identities`, `warmup` and `verify`
// (cache fast path, then scan-and-probe; see TryCachedBridgePort and
// ScanAndProbe). Accepts the same trailing args as `network` (an ifIndex and/or
// --host fe80::...) starting at argv[firstArgIndex].
static bool DiscoverBiometricKitBridge(int argc, wchar_t* argv[], int firstArgIndex,
                                        t2::bridgexpc::Connection* outConn) {
    using namespace t2::discovery;
    using namespace t2::bridgexpc;

    unsigned long ifIndexOverride = 0;
    std::string hostOverride;
    // Flags whose *following* argv token is a value owned by CmdVerify /
    // CmdIdentities / etc. Must be skipped here or e.g. "--match-flags 1"
    // makes "1" look like a positional ifIndex and discovery dies with
    // "no Preferred IPv6 link-local on ifIndex 1".
    auto isValueFlag = [](const std::wstring& a) {
        return a == L"--uid" || a == L"--seconds" || a == L"--match-layout" ||
               a == L"--match-flags" || a == L"--host";
    };
    auto isBoolFlag = [](const std::wstring& a) {
        return a == L"--no-reset-sensor" || a == L"--no-load-calibration" ||
               a == L"--reset-sensor" || a == L"--load-calibration" ||
               a == L"--verbose" || a == L"-v";
    };
    for (int i = firstArgIndex; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--host" && i + 1 < argc) {
            hostOverride = NarrowAscii(argv[++i]);
            if (hostOverride.empty()) {
                std::wcout << L"invalid --host IPv6\n";
                return false;
            }
        } else if (isValueFlag(a) && i + 1 < argc) {
            ++i; // skip the value token
        } else if (isBoolFlag(a) || (!a.empty() && a[0] == L'-')) {
            // Boolean flag or unknown dashed option: ignore (do not treat as ifIndex).
        } else if (IsDecimal(a)) {
            // Pure decimal token only -> positional ifIndex override.
            ifIndexOverride = static_cast<unsigned long>(_wtoi(a.c_str()));
        }
    }

    NcmEndpoint ep;
    if (ifIndexOverride != 0) {
        if (!GetEndpointByIfIndex(ifIndexOverride, &ep)) {
            std::wcout << L"no Preferred IPv6 link-local on ifIndex " << ifIndexOverride << L"\n";
            return false;
        }
    } else {
        auto endpoints = FindT2NcmEndpoints();
        if (endpoints.empty()) {
            std::wcout << L"no T2 NCM adapter found - try 'network' first.\n";
            return false;
        }
        ep = endpoints.front();
    }
    if (!hostOverride.empty()) {
        in6_addr parsed{};
        if (!ParseIpv6(hostOverride.c_str(), &parsed)) {
            std::wcout << L"invalid --host IPv6\n";
            return false;
        }
        ep.peerLinkLocal = parsed;
        ep.peerSource = PeerSource::ManualOverride;
    }
    if (ep.peerSource == PeerSource::None) {
        std::wcout << L"no peer to scan (automatic ff02::1 prompt ping didn't "
                      L"turn one up) - run 'network' first or pass --host fe80::...\n";
        return false;
    }

    // Discovery race: a single scan is flaky under USB NCM jitter, so the scan
    // below is attempted twice (20ms, then 60ms per-port timeout). Hits are
    // verified over RemoteXPC while the scan is still running, and the scan
    // stops the moment BiometricKit is confirmed (see ScanAndProbe).
    // Cache first: the BridgeXPC port is ephemeral per T2 boot but stable within
    // a boot/session, so repeated identities/verify/warmup calls try the cached
    // port pair (see TryCachedBridgePort) before paying for a 16384-port scan.
    // A stale or wrong entry just fails the HELO and falls through to the scan.
    {
        uint16_t cachedPort = 0;
        if (TryCachedBridgePort(ep, outConn, &cachedPort)) {
            std::wcout << L"BiometricKit BridgeXPC port: " << cachedPort
                       << L"  (cached - skipped port scan)\n";
            return true;
        }
    }

    uint16_t foundPort = 0;
    uint16_t foundRsdPort = 0;
    unsigned lastHttp2Count = 0;
    const unsigned timeoutsMs[] = {20, 60};
    constexpr unsigned kAttempts = sizeof(timeoutsMs) / sizeof(timeoutsMs[0]);
    for (unsigned attempt = 0; attempt < kAttempts; ++attempt) {
        ScanOptions opt;
        opt.concurrency = 256;
        opt.includeTcpOnly = true;
        opt.connectTimeoutMs = timeoutsMs[attempt];
        // Ascending (ScanOptions::scanFromEnd default) — the real
        // candidate sits near portBegin (~49000), not the high end.

        ScanProbeResult scan = ScanAndProbe(ep, opt);
        if (scan.servicePort != 0) {
            foundPort = scan.servicePort;
            foundRsdPort = scan.rsdPort;
            if (attempt > 0) {
                std::wcout << L"BiometricKit found on retry " << (attempt + 1)
                           << L" (timeout " << opt.connectTimeoutMs << L"ms)\n";
            }
            break;
        }
        lastHttp2Count = 0;
        for (const auto& h : scan.hits) {
            if (h.http2PrefaceOk) ++lastHttp2Count;
        }
        const wchar_t* tail = (attempt + 1 < kAttempts) ? L" - retrying...\n" : L"\n";
        if (lastHttp2Count == 0) {
            std::wcout << L"no HTTP/2 candidates (attempt " << (attempt + 1)
                       << L", timeout " << opt.connectTimeoutMs << L"ms)" << tail;
        } else {
            std::wcout << L"BiometricKit service not advertised by any of " << lastHttp2Count
                       << L" HTTP/2 candidate(s) (attempt " << (attempt + 1) << L")" << tail;
        }
    }
    if (foundPort == 0) {
        if (lastHttp2Count == 0) {
            std::wcout << L"no HTTP/2 candidates on peer after retries - run 'network' for full diagnostics.\n";
        } else {
            std::wcout << L"BiometricKit is not being advertised right now (T2 still booting?) - "
                          L"run 'network' for full diagnostics.\n";
        }
        return false;
    }
    std::wcout << L"BiometricKit BridgeXPC port: " << foundPort << L"\n";

    ConnectResult cr = outConn->Connect(ep.peerLinkLocal, ep.ifIndex, foundPort,
                                         std::chrono::milliseconds(2000));
    if (cr != ConnectResult::Ok) {
        std::wcout << L"BridgeXPC connect/HELO failed on port " << foundPort << L"\n";
        return false;
    }
    // Only cache after a live BridgeXPC connect actually succeeds — never
    // cache a port on RemoteXPC verification alone, since that's exactly
    // the "verified but BridgeXPC HELO failed" case the cache-hit path
    // above already knows how to recover from.
    SaveCachedPort(ep, foundPort, foundRsdPort);
    return true;
}

// Gate 8 phase 1: read the enrolled identity list. Exact Linux ready
// sequence (t2-biometric-ready.sh): initialize, reset-sensor, cancel,
// load-calibration, identity-list. Does NOT start a match.
static int CmdIdentities(int argc, wchar_t* argv[]) {
    using namespace t2::bridgexpc;
    using namespace t2::biometrickit;

    uint32_t macosUserId = 501;
    for (int i = 2; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--uid" && i + 1 < argc) {
            macosUserId = static_cast<uint32_t>(_wtoi(argv[++i]));
        }
    }

    Connection bridge;
    if (!DiscoverBiometricKitBridge(argc, argv, 2, &bridge)) {
        return 1;
    }

    VerifyConfig cfg;
    cfg.macosUserId = macosUserId;
    VerificationEngine engine(cfg);
    std::vector<IdentityRecordV1> identities;
    if (!engine.WarmUp(&bridge, &identities)) {
        std::wcout << L"linux warm-up / identity-list failed. " << kSeeVerboseHint;
        return 1;
    }

    std::wcout << L"macOS user id: " << macosUserId << L"\n";
    std::wcout << L"enrolled identities: " << identities.size() << L"\n";
    for (size_t i = 0; i < identities.size(); ++i) {
        std::wcout << L"  [" << i << L"] user_id=" << identities[i].userId << L"\n";
    }
    return 0;
}

// Exact port of t2-biometric-ready.sh: non-matching initialize /
// reset-sensor / cancel / load-calibration / identity-list, then
// disconnect. No StartMatch, no cmd 0x53.
static int CmdWarmup(int argc, wchar_t* argv[]) {
    using namespace t2::bridgexpc;
    using namespace t2::biometrickit;

    uint32_t macosUserId = 501;
    for (int i = 2; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--uid" && i + 1 < argc) {
            macosUserId = static_cast<uint32_t>(_wtoi(argv[++i]));
        }
    }

    Connection bridge;
    if (!DiscoverBiometricKitBridge(argc, argv, 2, &bridge)) {
        return 1;
    }

    VerifyConfig cfg;
    cfg.macosUserId = macosUserId;
    VerificationEngine engine(cfg);
    std::vector<IdentityRecordV1> identities;
    if (!engine.WarmUp(&bridge, &identities)) {
        std::wcout << L"linux warm-up failed. " << kSeeVerboseHint;
        return 1;
    }
    std::wcout << L"linux warm-up OK, identities=" << identities.size() << L"\n";
    return 0;
}

// Gate 8 phase 2: single-session verification A/B.
//
// The production Linux fprintd path runs _run_probe() on one BridgeXPC
// connection: version negotiation, reset/cancel, FDR calibration, identity
// inventory, StartMatch, event loop, and cancel all share that connection.
// The separate t2-biometric-ready systemd warm-up is a boot/readiness step,
// not part of the verify transaction itself. This CLI intentionally removes
// its old warm-up/disconnect/reconnect pair so the hardware test isolates
// session lifecycle without changing the packet format or BM command order.
static int CmdVerify(int argc, wchar_t* argv[]) {
    using namespace t2::bridgexpc;
    using namespace t2::biometrickit;

    VerifyConfig cfg;
    for (int i = 2; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--uid" && i + 1 < argc) {
            cfg.macosUserId = static_cast<uint32_t>(_wtoi(argv[++i]));
        } else if (a == L"--seconds" && i + 1 < argc) {
            cfg.matchWindow = std::chrono::seconds(_wtoi(argv[++i]));
        } else if (a == L"--match-layout" && i + 1 < argc) {
            std::wstring layout = argv[++i];
            if (layout == L"inline") {
                cfg.matchLayout = MatchIdentityLayout::InlineIdentities;
            } else if (layout == L"padded") {
                cfg.matchLayout = MatchIdentityLayout::PaddedNoIdentities;
            } else if (layout == L"legacy") {
                cfg.matchLayout = MatchIdentityLayout::LegacyCounted;
            } else {
                std::wcout << L"unknown --match-layout '" << layout
                           << L"' (expected inline|padded|legacy)\n";
                return 1;
            }
        } else if (a == L"--match-flags" && i + 1 < argc) {
            // Linux: --match-processed-flags (default 0; "use 1 for an unlock match")
            cfg.matchFlags = static_cast<uint32_t>(_wtoi(argv[++i]));
        } else if (a == L"--no-reset-sensor") {
            // Redundant with the current default (VerifyConfig::
            // skipResetSensor = true, 24.09.2026) — kept as an explicit,
            // self-documenting no-op for scripts/muscle memory.
            cfg.skipResetSensor = true;
        } else if (a == L"--no-load-calibration") {
            // Same: redundant with the current default. bridgeOS
            // calibrates at its own boot; cmd 0x20 is not required per
            // verify attempt (real-hardware A/B, 24.09.2026).
            cfg.skipLoadCalibration = true;
        } else if (a == L"--reset-sensor") {
            // Explicit opt-OUT of the current default — forces ResetSensor
            // back on, e.g. for an A/B against Linux's always-resend warm_up.
            cfg.skipResetSensor = false;
        } else if (a == L"--load-calibration") {
            // Explicit opt-OUT of the current default — forces LoadCalibration
            // back on, same reason as --reset-sensor above.
            cfg.skipLoadCalibration = false;
        }
    }

    Connection bridge;
    if (!DiscoverBiometricKitBridge(argc, argv, 2, &bridge)) {
        return 1;
    }

    // 17.09.2026: the macOS reference sequence this project's own docs cite
    // (docs/milestone-2b-progress.md, "Reference order of a SUCCESSFUL
    // unlock") shows match_result arriving on the SECOND finger placement
    // of the session (finger on -> off -> on again -> match_result), not
    // the first. Both hardware captures analyzed so far only ever recorded
    // one touch cycle before the window ran out. Not confirmed as the
    // cause, but cheap to rule out, so the prompt now says so.
    std::wcout << L"place finger on sensor (lift and place again if prompted)...\n";
    VerificationEngine engine(cfg);
    std::optional<std::array<uint8_t, 16>> matchedUuid;
    VerifyOutcome outcome = engine.Verify(&bridge, &matchedUuid);

    switch (outcome) {
        case VerifyOutcome::Match:
            std::wcout << L"verify-match\n";
            return 0;
        case VerifyOutcome::NoMatch:
            std::wcout << L"verify-no-match\n";
            return 0;
        case VerifyOutcome::Timeout:
            // REMOVED (17.09.2026): this case used to split into Timeout vs.
            // NoImageCaptured depending on whether status codes 55/72/95
            // (ImageCaptured/ImageForProcessing/ImageWasAccepted) showed up.
            // VERIFIED FROM SOURCE (t2-fprintd.py verdict_from_result): the
            // reference's own verify verdict never inspects those codes at
            // all, only match_events' event_kind=="match_result" — so that
            // split was diagnosing a symptom the reference itself doesn't
            // treat as meaningful. finger_touch_cycles/image_pipeline_events
            // are still in the --verbose session-summary log if useful, just
            // not used to pick this message anymore.
            std::wcout << L"verify-timeout (no match_result event within window) " << kSeeVerboseHint;
            return 1;
        case VerifyOutcome::TransportError:
            std::wcout << L"verify-failed: transport error " << kSeeVerboseHint;
            return 1;
        case VerifyOutcome::RejectedByDevice:
            std::wcout << L"verify-failed: device rejected start-match\n";
            return 1;
        case VerifyOutcome::Malformed:
            std::wcout << L"verify-failed: malformed reply from device " << kSeeVerboseHint;
            return 1;
        case VerifyOutcome::UnstableIdentityInventory:
            std::wcout << L"verify-failed: identity inventory unstable between snapshots "
                          L"(fail-closed, StartMatch not sent) " << kSeeVerboseHint;
            return 1;
        case VerifyOutcome::Busy:
            std::wcout << L"verify-failed: engine busy (should not happen on a one-shot CLI call)\n";
            return 1;
    }
    return 1;
}


int wmain(int argc, wchar_t* argv[]) {
    // Pull --verbose/-v out of argv before any command sees it, so it
    // doesn't get misread as an ifIndex/host/uid value by commands that
    // scan their own argv slice positionally (CmdNetwork, CmdIdentities,
    // CmdVerify). T2TOUCHID_VERBOSE=1 works the same way without a flag,
    // for scripting or when you don't want to retype it every run.
    std::vector<wchar_t*> filtered;
    filtered.push_back(argv[0]);
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--verbose" || a == L"-v") {
            verbose = true;
            continue;
        }
        filtered.push_back(argv[i]);
    }
    argv = filtered.data();
    argc = static_cast<int>(filtered.size());

    t2::log::InitFromEnvironment(verbose);

    // Winsock must be up before ANY socket use. It used to be initialised
    // only inside ScanHttp2Preface (PortScan.cpp), so a cache hit - which
    // skips the scan - had every socket() fail with WSANOTINITIALISED.
    // (Ref-counted, so PortScan's own WSAStartup is harmless.)
    {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::wcout << L"WSAStartup failed\n";
            return 1;
        }
    }
    if (t2::log::ConsoleEnabled()) {
        std::wcout << L"[verbose logging on - also mirrored to DebugView]\n";
    }

    if (argc < 2) {
        std::wcout << L"usage: t2touchid.exe [--verbose|-v] <status|register-ool|capabilities|device-state|load-keybag|set-system-keybag|unlock|network|identities|warmup|verify>\n";
        std::wcout << L"  identities [ifIndex] [--host fe80::...] [--uid N]\n";
        std::wcout << L"  warmup     [ifIndex] [--host fe80::...] [--uid N]\n";
        std::wcout << L"  verify     [ifIndex] [--host fe80::...] [--uid N] [--seconds N]\n"
                      L"             [--match-layout inline|padded|legacy]  (default: legacy)\n"
                      L"             [--match-flags N]  (0=default, 1=unlock match per Linux)\n"
                      L"             [--no-reset-sensor] [--no-load-calibration]  (both ON by default, Linux parity)\n";
        std::wcout << L"  --verbose/-v (or env T2TOUCHID_VERBOSE=1): print step-by-step\n";
        std::wcout << L"    BridgeXPC diagnostics to the console. Always available in\n";
        std::wcout << L"    DebugView (run as Administrator, Capture Global Win32) even\n";
        std::wcout << L"    without this flag.\n";
        return 1;
    }

    std::wstring cmd = argv[1];

    // network / identities / warmup / verify are pure user-mode (IPv6 to the
    // T2), they never touch the transport driver - so dispatch them before
    // opening the device (which needs the driver loaded and Administrator, and
    // is opened with exclusive share mode).
    if (cmd == L"network") return CmdNetwork(argc, argv);
    if (cmd == L"identities") return CmdIdentities(argc, argv);
    if (cmd == L"warmup") return CmdWarmup(argc, argv);
    if (cmd == L"verify") return CmdVerify(argc, argv);

    Client client;
    AksResult openResult = client.Open();
    if (openResult != AksResult::Ok) {
        std::wcout << L"cannot open T2TouchIdTransport device - is the driver loaded and are you Administrator?\n";
        return 1;
    }

    if (cmd == L"status") return CmdStatus(client);
    if (cmd == L"register-ool") return CmdRegisterOol(client);
    if (cmd == L"capabilities") return CmdCapabilities(client);
    if (cmd == L"device-state") {
        // Default handle=0 selector=0 — pure EP7 liveness probe.
        int64_t handle = (argc >= 3) ? _wtoi64(argv[2]) : 0;
        uint32_t selector = (argc >= 4) ? static_cast<uint32_t>(_wtoi(argv[3])) : 0;
        return CmdDeviceState(client, handle, selector);
    }
    if (cmd == L"load-keybag") {
        if (argc < 3) {
            std::wcout << L"usage: load-keybag <keybag-file>\n";
            return 1;
        }
        return CmdLoadKeybag(client, argv[2]);
    }
    if (cmd == L"set-system-keybag") {
        if (argc < 4) {
            std::wcout << L"usage: set-system-keybag <handle> <special-user-bag>\n";
            return 1;
        }
        return CmdSetSystemKeybag(client, _wtoi(argv[2]), _wtoi(argv[3]));
    }
    if (cmd == L"unlock") {
        if (argc < 3) { std::wcout << L"usage: unlock <handle>\n"; return 1; }
        return CmdUnlock(client, _wtoi(argv[2]));
    }

    std::wcout << L"unknown command\n";
    return 1;
}
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

using namespace t2::applekeystore;

// Shared tail for terse failure lines throughout this file: every
// BridgeXPC-layer failure ("... command failed") now has a matching
// detailed reason logged from protocol/BridgeXpc/Connection.cpp — this
// just points the operator at where to look instead of leaving them with
// nothing but the one-line summary.
static const wchar_t* kSeeVerboseHint =
    L"(re-run with --verbose, or attach DebugView, for the detailed reason)\n";

static std::vector<uint8_t> ReadPasswordInteractive() {
    std::wcout << L"Password: ";
    std::vector<uint8_t> secret;
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') break;
        if (ch == 3) { // Ctrl+C
            SecureZeroMemory(secret.data(), secret.size());
            secret.clear();
            std::wcout << L"\ncancelled\n";
            return secret;
        }
        if (ch == '\b') {
            if (!secret.empty()) secret.pop_back();
            continue;
        }
        secret.push_back(static_cast<uint8_t>(ch));
        // No echo — password never appears on screen, in a log file, or in
        // command-line history (Milestone 2 §10).
    }
    std::wcout << L"\n";
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
    return 0;
}

static bool ReadBinaryFile(const std::wstring& path, std::vector<uint8_t>& bytes) {
    bytes.clear();

    std::ifstream file(path, std::ios::binary | std::ios::ate);
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
    int8_t sepStatus = 0;
    AksResult r = client.Unlock(handle, secret, 1, &sepStatus); // zeroes `secret` internally
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
            // Narrow wide arg to UTF-8-ish for InetPton
            std::wstring w = argv[++i];
            hostOverride.clear();
            for (wchar_t c : w) hostOverride.push_back(static_cast<char>(c & 0xFF));
        } else if (a[0] >= L'0' && a[0] <= L'9') {
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
        for (char c : local) std::wcout << static_cast<wchar_t>(c);
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
            for (char c : peer) std::wcout << static_cast<wchar_t>(c);
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
    ScanOptions opt;
    opt.concurrency = 64;
    opt.connectTimeoutMs = 10;  // ~1ms observed RTT; 150ms was overkill for this link
    opt.includeTcpOnly = true;
    opt.onProgress = [](unsigned tried, unsigned total, unsigned tcp, unsigned http2) {
        std::wcout << L"  scanned " << tried << L"/" << total
                   << L"  tcp=" << tcp << L"  http2=" << http2 << L"\r" << std::flush;
    };

    std::wcout << L"scanning PEER ports " << opt.portBegin << L"-" << opt.portEnd
               << L" (concurrency " << opt.concurrency
               << L", timeout " << opt.connectTimeoutMs << L"ms)...\n";
    auto hits = ScanHttp2Preface(ep, opt);
    std::wcout << L"\n";

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

    std::wcout << L"candidates: tcp_open=" << nTcp << L"  http2_settings=" << nHttp2 << L"\n";
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
    if (nHttp2 == 0) {
        std::wcout << L"note: no HTTP/2 SETTINGS yet. Confirm peer address matches Linux T2_TOUCHID_HOST.\n";
        return 0;
    }

    // Gate 6 Phase 2 (docs/gate6-discovery.md): run the RemoteXPC handshake
    // against each HTTP/2 candidate and look for
    // Services["com.apple.eos.BiometricKit"]["Port"]. A candidate that
    // completes RemoteXPC but doesn't advertise the service is a decoy,
    // not a failure — DiscoverServicePort already treats it that way and
    // moves on, matching discover-biometric-port.py's loop.
    std::vector<uint16_t> candidatePorts;
    for (const auto& h : hits) {
        if (h.http2PrefaceOk) candidatePorts.push_back(h.port);
    }
    std::wcout << L"probing " << candidatePorts.size()
               << L" RemoteXPC candidate(s) for com.apple.eos.BiometricKit...\n";
    auto discovered = t2::discovery::DiscoverServicePort(
        ep, candidatePorts, "com.apple.eos.BiometricKit",
        std::chrono::milliseconds(2000));
    if (discovered.found) {
        std::wcout << L"BiometricKit BridgeXPC port: " << discovered.port << L"\n";

        // Gate 7 phase 1: prove the discovered port is a live BridgeXpc
        // endpoint, not just a plausible-looking number — open a real
        // connection (HELO handshake, Milestone 1 section 7) and read the
        // bridge's own version, rather than declaring victory on the port
        // number alone.
        using namespace t2::bridgexpc;
        Connection bridge;
        ConnectResult cr = bridge.Connect(ep.peerLinkLocal, ep.ifIndex, discovered.port,
                                           std::chrono::milliseconds(2000));
        if (cr != ConnectResult::Ok) {
            std::wcout << L"BridgeXPC connect/HELO failed on port " << discovered.port
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
    } else {
        std::wcout << L"BiometricKit service not advertised by any candidate "
                      L"(all decoys, or T2 is not currently offering it).\n";
    }
    return 0;
}

// Shared discovery+connect step for `identities` and `verify` (Gate 6
// phase 2 / Gate 7, now confirmed live on real hardware via `network`:
// BridgeXPC HELO handshake + getBridgeVersion both verified). Deliberately
// NOT refactored out of CmdNetwork itself - CmdNetwork's scan+report path
// is already hardware-verified and is left untouched; this duplicates the
// minimal subset of it rather than risk that confirmed behavior.
// Accepts the same trailing args as `network` (an ifIndex and/or
// --host fe80::...) starting at argv[firstArgIndex].
static bool DiscoverBiometricKitBridge(int argc, wchar_t* argv[], int firstArgIndex,
                                        t2::bridgexpc::Connection* outConn) {
    using namespace t2::discovery;
    using namespace t2::bridgexpc;

    unsigned long ifIndexOverride = 0;
    std::string hostOverride;
    for (int i = firstArgIndex; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--host" && i + 1 < argc) {
            std::wstring w = argv[++i];
            hostOverride.clear();
            for (wchar_t c : w) hostOverride.push_back(static_cast<char>(c & 0xFF));
        } else if ((a == L"--uid" || a == L"--seconds") && i + 1 < argc) {
            // Not this function's flag - CmdVerify/CmdIdentities parse the
            // value themselves - but it still must be skipped here, or the
            // digit that follows (e.g. "20" in "--seconds 20") falls through
            // to the bare-digit branch below and gets misread as a
            // positional ifIndex override.
            ++i;
        } else if (!a.empty() && a[0] >= L'0' && a[0] <= L'9') {
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

    ScanOptions opt;
    opt.concurrency = 64;
    // BUG FIX: this was 4ms, well under the 10ms that `network`'s own
    // scan (CmdNetwork, same link, same probe) uses and has verified on
    // real hardware. On a USB NCM link ~1ms RTT is typical but not
    // guaranteed every probe — 4ms left too many of the 64 concurrent
    // connect()s timing out before SETTINGS arrived, which is why
    // `identities`/`verify` intermittently reported "no HTTP/2
    // candidates" right after `network` had just found 7. Match the
    // proven value instead of re-guessing a smaller one.
    opt.connectTimeoutMs = 10;
    opt.includeTcpOnly = true;
    auto hits = ScanHttp2Preface(ep, opt);

    std::vector<uint16_t> candidatePorts;
    for (const auto& h : hits) {
        if (h.http2PrefaceOk) candidatePorts.push_back(h.port);
    }
    if (candidatePorts.empty()) {
        std::wcout << L"no HTTP/2 candidates on peer - run 'network' for full diagnostics.\n";
        return false;
    }

    auto discovered = DiscoverServicePort(ep, candidatePorts, "com.apple.eos.BiometricKit",
                                           std::chrono::milliseconds(2000));
    if (!discovered.found) {
        std::wcout << L"BiometricKit service not advertised by any candidate.\n";
        return false;
    }
    std::wcout << L"BiometricKit BridgeXPC port: " << discovered.port << L"\n";

    ConnectResult cr = outConn->Connect(ep.peerLinkLocal, ep.ifIndex, discovered.port,
                                         std::chrono::milliseconds(2000));
    if (cr != ConnectResult::Ok) {
        std::wcout << L"BridgeXPC connect/HELO failed on port " << discovered.port << L"\n";
        return false;
    }
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
        } else if (a == L"--reset-sensor" || a == L"--load-calibration") {
            // Unconditional in the Linux ready sequence. Accepted so old
            // command lines keep parsing; they no longer gate anything.
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
        }
    }

    Connection bridge;
    if (!DiscoverBiometricKitBridge(argc, argv, 2, &bridge)) {
        return 1;
    }

    std::wcout << L"place finger on sensor...\n";
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
            std::wcout << L"verify-timeout (no match_result event within window)\n";
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
        case VerifyOutcome::Busy:
            std::wcout << L"verify-failed: engine busy (should not happen on a one-shot CLI call)\n";
            return 1;
        case VerifyOutcome::NoImageCaptured:
            std::wcout << L"verify-no-image: sensor reported the finger (FingerOn/FingerOff) but never\n"
                          L"                 reported ImageCaptured/ImageForProcessing/ImageWasAccepted.\n"
                          L"                 The match never got as far as comparing anything. "
                       << kSeeVerboseHint;
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
    if (t2::log::ConsoleEnabled()) {
        std::wcout << L"[verbose logging on - also mirrored to DebugView]\n";
    }

    if (argc < 2) {
        std::wcout << L"usage: t2touchid.exe [--verbose|-v] <status|register-ool|capabilities|device-state|load-keybag|set-system-keybag|unlock|network|identities|warmup|verify>\n";
        std::wcout << L"  identities [ifIndex] [--host fe80::...] [--uid N]\n";
        std::wcout << L"  warmup     [ifIndex] [--host fe80::...] [--uid N]\n";
        std::wcout << L"  verify     [ifIndex] [--host fe80::...] [--uid N] [--seconds N]\n"
                      L"             [--match-layout inline|padded|legacy]\n";
        std::wcout << L"  --verbose/-v (or env T2TOUCHID_VERBOSE=1): print step-by-step\n";
        std::wcout << L"    BridgeXPC diagnostics to the console. Always available in\n";
        std::wcout << L"    DebugView (run as Administrator, Capture Global Win32) even\n";
        std::wcout << L"    without this flag.\n";
        return 1;
    }

    Client client;
    AksResult openResult = client.Open();
    if (openResult != AksResult::Ok) {
        std::wcout << L"cannot open T2TouchIdTransport device - is the driver loaded and are you Administrator?\n";
        return 1;
    }

    std::wstring cmd = argv[1];
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
    if (cmd == L"network") {
        // Does not need the transport device handle — pure user-mode IPv6 scan.
        return CmdNetwork(argc, argv);
    }
    if (cmd == L"identities") {
        return CmdIdentities(argc, argv);
    }
    if (cmd == L"warmup") {
        return CmdWarmup(argc, argv);
    }
    if (cmd == L"verify") {
        return CmdVerify(argc, argv);
    }

    std::wcout << L"unknown command\n";
    return 1;
}
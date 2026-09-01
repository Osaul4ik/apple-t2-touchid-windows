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
#include "../../protocol/Discovery/Adapter.h"
#include "../../protocol/Discovery/PortScan.h"
#include <iostream>
#include <string>
#include <fstream>
#include <limits>
#include <conio.h>

using namespace t2::applekeystore;

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
    AksResult r = client.LoadKeybag(bag, &handle, /*session=*/1, &sepStatus);
    SecureZeroMemory(bag.data(), bag.size());
    bag.clear();

    if (r == AksResult::NotReady) {
        std::wcout << L"load-keybag failed: DMA / OOL is not registered; run register-ool first\n";
        return 1;
    }
    if (sepStatus != 0) {
        // Transport succeeded but SEP rejected the request (e.g. bad
        // session/handle or malformed keybag) - the Linux tool always
        // prints this status; surface it here too instead of the previous
        // generic "load-keybag failed" that hid it.
        std::wcout << L"load-keybag failed: SEP status=" << (int)sepStatus << L"\n";
        return 1;
    }
    if (r != AksResult::Ok) {
        std::wcout << L"load-keybag failed\n";
        return 1;
    }

    std::wcout << L"load-keybag: OK, handle=" << handle << L"\n";
    return 0;
}

static int CmdSetSystemKeybag(Client& client, int32_t handle, int32_t specialUserBag) {
    AksResult r = client.MakeSystemKeybag(handle, specialUserBag);
    if (r == AksResult::NotReady) {
        std::wcout << L"set-system-keybag failed: DMA / OOL is not registered; run register-ool first\n";
        return 1;
    }
    if (r != AksResult::Ok) {
        std::wcout << L"set-system-keybag failed\n";
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
    AksResult r = client.Unlock(handle, secret); // zeroes `secret` internally
    if (r != AksResult::Ok) {
        std::wcout << L"unlock failed\n";
        return 1;
    }
    std::wcout << L"unlock: OK\n";
    return 0;
}


static int CmdDeviceState(Client& client, int64_t handle, uint32_t selector) {
    std::vector<uint8_t> response;
    int8_t sepStatus = 0;
    AksResult r = client.GetDeviceState(handle, selector, &response, &sepStatus);
    if (r == AksResult::NotReady) {
        std::wcout << L"device-state failed: DMA / OOL is not registered; run register-ool first\n";
        return 1;
    }
    if (r != AksResult::Ok) {
        std::wcout << L"device-state failed (transport-level: timeout/IO error - EP7 not answering at all)\n";
        return 1;
    }
    if (sepStatus != 0) {
        // The exchange with SEP succeeded - this is AppleKeyStore itself
        // rejecting the request (e.g. `handle` isn't a currently-loaded
        // keybag handle), not an EP7/transport problem. handle=0 in
        // particular is not a valid "liveness probe" value for this op.
        std::wcout << L"device-state: SEP rejected the request, status=" << (int)sepStatus
                   << L" (handle=" << handle << L" selector=" << selector << L")\n";
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

    // Optional: network [ifIndex]
    // ifIndex override for the T2 NCM adapter (e.g. 27 from Get-NetIPAddress).
    unsigned long ifIndexOverride = 0;
    bool doScan = true;
    for (int i = 2; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--no-scan") {
            doScan = false;
        } else if (a == L"--ifindex" && i + 1 < argc) {
            ifIndexOverride = static_cast<unsigned long>(_wtoi(argv[++i]));
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
            std::wcout << L"no T2 NCM adapter found (description must contain T2+NCM or UsbNcm).\n";
            std::wcout << L"hint: t2touchid.exe network <ifIndex>   e.g. network 27\n";
            return 1;
        }
    }

    for (const auto& ep : endpoints) {
        std::string ll = FormatLinkLocal(ep.linkLocal, ep.ifIndex);
        std::wcout << L"adapter:  " << ep.friendlyName << L"\n";
        std::wcout << L"desc:     " << ep.description << L"\n";
        std::wcout << L"ifIndex:  " << ep.ifIndex << L"\n";
        std::wcout << L"link-local: ";
        for (char c : ll) std::wcout << static_cast<wchar_t>(c);
        std::wcout << L"\n";
    }

    if (!doScan) {
        std::wcout << L"scan skipped (--no-scan). RemoteXPC handshake not yet implemented.\n";
        return 0;
    }

    const auto& ep = endpoints.front();
    ScanOptions opt;
    opt.concurrency = 64;
    opt.connectTimeoutMs = 150; // Linux discover default --probe-timeout 0.15
    opt.includeTcpOnly = true; // diagnostic: show TCP-open even without SETTINGS
    opt.onProgress = [](unsigned tried, unsigned total, unsigned tcp, unsigned http2) {
        std::wcout << L"  scanned " << tried << L"/" << total
                   << L"  tcp=" << tcp << L"  http2=" << http2 << L"\r" << std::flush;
    };

    std::wcout << L"port scan " << opt.portBegin << L"-" << opt.portEnd
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
        std::wcout << L"no TCP listeners in " << opt.portBegin << L"-" << opt.portEnd << L".\n";
        std::wcout << L"possible causes:\n"
                   << L"  - bridgeOS services not exposing RemoteXPC on this boot\n"
                   << L"  - Windows Firewall blocking outbound link-local\n"
                   << L"  - T2 NCM data path up but no listeners yet\n";
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
            std::wcout << L"  (no data — peer silent)";
        }
        std::wcout << L"\n";
    }
    if (nHttp2 == 0) {
        std::wcout << L"note: no HTTP/2 SETTINGS frames seen; TCP-only ports may still be "
                      L"RemoteXPC decoys or other services. RSD handshake is Gate 6 phase 2.\n";
    } else {
        std::wcout << L"next: RemoteXPC handshake on HTTP/2 candidates for "
                      L"Services[com.apple.eos.BiometricKit].Port\n";
    }
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"usage: t2touchid.exe <status|register-ool|capabilities|device-state|load-keybag|set-system-keybag|unlock|network|identities|verify>\n";
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
    if (cmd == L"identities" || cmd == L"verify") {
        std::wcout << L"not yet wired — requires RemoteXPC BiometricKit port "
                      L"+ live BridgeXpc connection (Gate 6 phase 2 / Gate 7)\n";
        return 2;
    }

    std::wcout << L"unknown command\n";
    return 1;
}
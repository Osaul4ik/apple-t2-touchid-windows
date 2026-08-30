// main.cpp — t2touchid.exe
//
// Milestone 2 §10, §27: commands are read-evidence tools, never a source
// of fabricated success. Every command either reports a real driver/IOCTL
// result or reports the specific failure — there is no "assume it worked"
// path anywhere in this file.
#define NOMINMAX
#include "../../protocol/AppleKeyStore/Client.h"
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
    AksResult r = client.LoadKeybag(bag, &handle);
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

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"usage: t2touchid.exe <status|register-ool|capabilities|load-keybag|set-system-keybag|unlock|network|identities|verify>\n";
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
    if (cmd == L"network" || cmd == L"identities" || cmd == L"verify") {
        // These require the BridgeXpc/BiometricKit protocol layer wired
        // against a discovered port (see protocol/BridgeXpc,
        // protocol/BiometricKit). Left as an explicit next-step rather
        // than a fake "OK" — see docs/milestone-2-hardware-results.md.
        std::wcout << L"not yet wired in this PoC skeleton - requires RemoteXPC "
                      L"discovery + a live BridgeXpc connection on real hardware\n";
        return 2;
    }

    std::wcout << L"unknown command\n";
    return 1;
}
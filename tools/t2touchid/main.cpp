// main.cpp — t2touchid.exe
//
// Milestone 2 §10, §27: commands are read-evidence tools, never a source
// of fabricated success. Every command either reports a real driver/IOCTL
// result or reports the specific failure — there is no "assume it worked"
// path anywhere in this file.

#include "../../protocol/AppleKeyStore/Client.h"
#include <iostream>
#include <string>
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
        std::wcout << L"usage: t2touchid.exe <status|capabilities|load-keybag|set-system-keybag|unlock|network|identities|verify>\n";
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
    if (cmd == L"capabilities") return CmdCapabilities(client);
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

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
#include "../../protocol/BiometricKit/MacosUserId.h"
#include "../../protocol/Discovery/Adapter.h"
#include "../../protocol/Discovery/BridgeDiscovery.h"
#include "../../protocol/Discovery/PortCache.h"
#include "../../protocol/Discovery/PortScan.h"
#include "../../protocol/Discovery/RemoteXpc.h"
#include "../../protocol/Discovery/TransportService.h"
#include "../../protocol/Ipc/TransportPipe.h"
#include "../../protocol/BridgeXpc/Log.h"
#include "../../protocol/BridgeXpc/TransportMode.h"
#include "../../T2NCM/driver/Public.h"
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
    bool pci = false, bar4 = false, ool = false, mailbox = false, haveCounters = false;
    Client::ExchangeCounters counters;
    AksResult r = client.GetStatusEx(&pci, &bar4, &ool, &mailbox, &counters, &haveCounters);
    if (r != AksResult::Ok) {
        std::wcout << L"T2 PCI                  FAILED TO QUERY\n";
        return 1;
    }
    std::wcout << L"T2 PCI                  " << (pci ? L"OK" : L"NOT PRESENT") << L"\n";
    std::wcout << L"BAR4                    " << (bar4 ? L"mapped" : L"not mapped") << L"\n";
    std::wcout << L"SEP mailbox             " << (mailbox ? L"accessible" : L"unavailable") << L"\n";
    std::wcout << L"DMA / OOL               " << (ool ? L"registered" : L"not registered") << L"\n";
    if (haveCounters) {
        std::wcout << L"AKS exchanges           " << counters.ok << L" ok, " << counters.failed
                   << L" failed (" << counters.timeouts << L" SEP timeouts)\n";
        if (counters.lastFailureStatus != 0) {
            wchar_t st[16];
            swprintf_s(st, L"0x%08X", static_cast<unsigned>(counters.lastFailureStatus));
            FILETIME ft{static_cast<DWORD>(counters.lastFailureTimeUtc),
                        static_cast<DWORD>(counters.lastFailureTimeUtc >> 32)};
            FILETIME local{};
            SYSTEMTIME t{};
            FileTimeToLocalFileTime(&ft, &local);
            FileTimeToSystemTime(&local, &t);
            wchar_t when[32];
            swprintf_s(when, L"%04u-%02u-%02u %02u:%02u:%02u", t.wYear, t.wMonth, t.wDay, t.wHour,
                       t.wMinute, t.wSecond);
            std::wcout << L"last AKS failure        " << st << L" at " << when << L"\n";
        }
    } else {
        std::wcout << L"AKS exchanges           (counters need the updated T2TouchIdTransport.sys)\n";
    }
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

// The special user bag is the negated macOS uid (-502 <-> uid 502). Persist it
// so identities / warmup / verify and the UMDF driver stop using the old
// hardcoded 501 (HKLM\SOFTWARE\T2TouchIdBio\MacosUserId, needs Administrator).
static void ReportMacosUserIdFromSpecialBag(int32_t specialUserBag) {
    uint32_t uid = 0;
    if (!t2::biometrickit::MacosUserIdFromSpecialBag(specialUserBag, &uid)) return;
    if (t2::biometrickit::SaveConfiguredMacosUserId(uid)) {
        std::wcout << L"macOS user id set to " << uid << L" (from special bag " << specialUserBag << L")\n";
    } else {
        std::wcout << L"warning: could not save macOS user id " << uid
                   << L" to HKLM (run as Administrator); use --uid " << uid << L" explicitly\n";
    }
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
    ReportMacosUserIdFromSpecialBag(specialUserBag);
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
    ReportMacosUserIdFromSpecialBag(handle); // negative handle = special user bag (-502 -> uid 502)
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

// ---- Discovery + connect: the shared TransportManager ----------------------------
//
// Every BridgeXPC-facing command (`network`, `identities`, `warmup`, `verify`)
// connects through t2::discovery::ConnectToBiometricKitBridge - the SAME code the
// UMDF driver runs on the lock screen. That gives the CLI (and the GUI, which runs
// it for "Rescan" / "Test fingerprint") the cross-process TransportPhase lock, the
// native IPv6 -> IPv4 tunnel switch and the full scan policy. The CLI used to carry
// its own copy (cache fast path + ScanAndProbe): no phase lock, so it flipped the
// global T2Ncm transport mode underneath a driver connect, and no tunnel fallback,
// so a Rescan with a VPN on could never find the port.
//
// One call of ConnectToBiometricKitBridge is one STEP; like Queue.cpp, the CLI
// repeats steps on a short backoff until it connects, discovery reports that a full
// scan pass completed without BiometricKit, the deadline passes, or it is cancelled.

// Cancel for discovery / verify: Ctrl+C, Ctrl+Break, closing the console, or a named
// event the parent process signals (--cancel-event <name>, used by the GUI so a
// timed-out Rescan ends cleanly - TransportPhase scopes restore the driver mode -
// instead of being killed in the middle of a phase).
static HANDLE g_cliCancel = nullptr;

static BOOL WINAPI CliConsoleCtrl(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        if (g_cliCancel) SetEvent(g_cliCancel);
        return TRUE; // the running command sees the cancel and unwinds
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (g_cliCancel) SetEvent(g_cliCancel);
        Sleep(2000); // the process ends when this returns: give the scopes time
        return TRUE;
    default:
        return FALSE;
    }
}

// Pulls `--cancel-event <name>` out of argv (like --verbose) and sets up g_cliCancel.
// The named event must already exist (created by the parent); otherwise, and when no
// name is given, an anonymous manual-reset event is used (console Ctrl+C only).
static void InitCliCancel(int* argc, wchar_t** argv) {
    std::wstring name;
    int w = 1;
    for (int i = 1; i < *argc; ++i) {
        if (std::wstring(argv[i]) == L"--cancel-event" && i + 1 < *argc) {
            name = argv[++i];
            continue;
        }
        argv[w++] = argv[i];
    }
    *argc = w;
    if (!name.empty()) {
        g_cliCancel = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, name.c_str());
        if (!g_cliCancel) {
            std::wcout << L"warning: --cancel-event " << name << L" not found (GetLastError="
                       << GetLastError() << L") - Ctrl+C only\n";
        }
    }
    if (!g_cliCancel) g_cliCancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

// Ctrl+C -> cancel instead of process kill. Only for the BridgeXPC commands, which
// check g_cliCancel; `unlock` & co. read a password with _getch and must stay
// abortable with a plain Ctrl+C.
static void EnableCtrlCCancel() {
    SetConsoleCtrlHandler(CliConsoleCtrl, TRUE);
}

static bool CliCancelled() {
    return g_cliCancel && WaitForSingleObject(g_cliCancel, 0) == WAIT_OBJECT_0;
}

// Endpoint selection shared by every command: [ifIndex] and/or --host fe80::...
// starting at argv[firstArgIndex]. Flags owned by the individual commands are
// skipped so e.g. "--match-flags 1" never reads as ifIndex 1.
struct EndpointArgs {
    unsigned long ifIndex = 0;
    std::string host;      // peer IPv6 without zone
    bool ok = true;
};
static EndpointArgs ParseEndpointArgs(int argc, wchar_t* argv[], int firstArgIndex) {
    EndpointArgs r;
    auto isValueFlag = [](const std::wstring& a) {
        return a == L"--uid" || a == L"--seconds" || a == L"--match-layout" ||
               a == L"--match-flags" || a == L"--ifindex" || a == L"--timeout";
    };
    for (int i = firstArgIndex; i < argc; ++i) {
        const std::wstring a = argv[i];
        if (a == L"--host" && i + 1 < argc) {
            r.host = NarrowAscii(argv[++i]);
            if (r.host.empty()) {
                std::wcout << L"invalid --host IPv6\n";
                r.ok = false;
                return r;
            }
        } else if (a == L"--ifindex" && i + 1 < argc) {
            r.ifIndex = static_cast<unsigned long>(_wtoi(argv[++i]));
        } else if (isValueFlag(a) && i + 1 < argc) {
            ++i; // the value belongs to the command
        } else if (!a.empty() && a[0] == L'-') {
            // boolean flag of the command (or unknown): not an endpoint argument
        } else if (IsDecimal(a)) {
            r.ifIndex = static_cast<unsigned long>(_wtoi(a.c_str()));
        }
    }
    return r;
}

enum class CliConnect { Ok, NoAdapter, NoPeer, NotFound, TimedOut, Cancelled, BadArgs, Busy };

static CliConnect FromLadder(t2::discovery::LadderResult r) {
    using t2::discovery::LadderResult;
    switch (r) {
    case LadderResult::Ok:        return CliConnect::Ok;
    case LadderResult::NoAdapter: return CliConnect::NoAdapter;
    case LadderResult::NoPeer:    return CliConnect::NoPeer;
    case LadderResult::NotFound:  return CliConnect::NotFound;
    case LadderResult::TimedOut:  return CliConnect::TimedOut;
    case LadderResult::Cancelled: return CliConnect::Cancelled;
    }
    return CliConnect::TimedOut;
}

// Resolves the endpoint (adapter + readiness gate + peer) and connects through the
// shared ladder (TransportService.h ConnectWithLadder - the same one the transport
// owner runs for a pipe "connect"). *outPort / *outRsd: the BridgeXPC / RemoteXPC ports.
static CliConnect ConnectBridgeCli(const EndpointArgs& args, t2::bridgexpc::Connection* conn,
                                   bool forceRescan, ULONGLONG budgetMs,
                                   uint16_t* outPort, uint16_t* outRsd,
                                   t2::discovery::NcmEndpoint* outEndpoint = nullptr) {
    using namespace t2::discovery;
    if (!args.ok) return CliConnect::BadArgs;
    in6_addr manualPeer{};
    if (!args.host.empty() && !ParseIpv6(args.host.c_str(), &manualPeer)) {
        std::wcout << L"invalid --host IPv6\n";
        return CliConnect::BadArgs;
    }
    bool printedNoAdapter = false;
    LadderOptions lo;
    lo.forceRescan = forceRescan;
    lo.budgetMs = budgetMs;
    lo.cancelEvent = g_cliCancel;
    lo.resolveEndpoint = [&](NcmEndpoint* ep, void* cancel) {
        if (args.ifIndex != 0) {
            if (!GetEndpointByIfIndex(args.ifIndex, ep)) {
                if (!printedNoAdapter) std::wcout << L"no T2 NCM endpoint on ifIndex " << args.ifIndex << L"\n";
                printedNoAdapter = true;
                return false;
            }
        } else if (!PickDefaultT2Endpoint(ep, cancel)) {
            if (!CliCancelled() && !printedNoAdapter) std::wcout << L"no T2 NCM adapter found.\n";
            printedNoAdapter = true;
            return false;
        }
        if (!args.host.empty()) {
            ep->peerLinkLocal = manualPeer;
            ep->peerSource = PeerSource::ManualOverride;
        }
        return true;
    };
    const LadderOutcome o = ConnectWithLadder(lo, conn);
    if (outEndpoint) *outEndpoint = o.endpoint;
    if (o.result == LadderResult::Ok) {
        if (outPort) *outPort = o.port;
        if (outRsd) *outRsd = o.rsd;
    }
    return FromLadder(o.result);
}

// One-line reason for a failed connect, phrased for the GUI's FailureReason markers.
static void PrintConnectFailure(CliConnect r) {
    switch (r) {
    case CliConnect::NoAdapter: break; // already printed
    case CliConnect::BadArgs:   break; // already printed
    case CliConnect::NoPeer:
        std::wcout << L"no peer to scan: the T2 did not answer neighbor discovery / ping "
                      L"(try again, or pass --host fe80::...).\n";
        break;
    case CliConnect::NotFound:
        std::wcout << L"BiometricKit service not advertised: a full port scan found no "
                      L"BridgeXPC listener (T2 still booting?).\n";
        break;
    case CliConnect::TimedOut:
        std::wcout << L"BridgeXPC connect/HELO failed: no answer before the deadline "
                   << kSeeVerboseHint;
        break;
    case CliConnect::Cancelled:
        std::wcout << L"cancelled.\n";
        break;
    case CliConnect::Busy:
        std::wcout << L"sensor busy: a fingerprint capture is armed (lock screen / Windows Hello "
                      L"prompt) - the transport is not moved under it; try again when it is idle.\n";
        break;
    case CliConnect::Ok:
        break;
    }
}

// ---- the transport owner (T2TouchIdBio driver) over \\.\pipe\T2TouchIdTransport ----
// The UMDF driver owns the transport. When it is running, `network` / `--rescan`
// ask it to connect (it runs the scan in its own process, under its own phase
// lock, with its own sticky state) instead of doing all of that from here. When it
// is not (pipe missing), the CLI does the work locally as before.
enum class OwnerCall { Done, Fallback };

static std::wstring Widen(const std::string& s) { return std::wstring(s.begin(), s.end()); }

static OwnerCall ConnectViaOwner(bool forceRescan, ULONGLONG budgetMs, int* exitCode) {
    t2::ipc::KvMessage req;
    req.Set("op", "connect");
    req.Set("force", forceRescan ? 1 : 0);
    req.Set("timeout", static_cast<long long>(budgetMs));
    std::string reply;
    const t2::ipc::PipeCallResult pr =
        t2::ipc::CallPipe(t2::ipc::kTransportPipeName, req.Serialize(),
                          static_cast<DWORD>(budgetMs + 15000), &reply, g_cliCancel);
    if (pr == t2::ipc::PipeCallResult::NoServer || pr == t2::ipc::PipeCallResult::Untrusted) {
        T2_LOG("cli", L"transport owner pipe: %s - running discovery in this process",
               t2::ipc::PipeCallResultName(pr));
        return OwnerCall::Fallback;
    }
    if (pr == t2::ipc::PipeCallResult::Cancelled) {
        PrintConnectFailure(CliConnect::Cancelled);
        *exitCode = 1;
        return OwnerCall::Done;
    }
    if (pr != t2::ipc::PipeCallResult::Ok) {
        std::wcout << L"transport owner (T2TouchIdBio driver) did not answer: "
                   << t2::ipc::PipeCallResultName(pr) << L"\n";
        *exitCode = 1;
        return OwnerCall::Done;
    }
    const t2::ipc::KvMessage r = t2::ipc::KvMessage::Parse(reply);
    const std::string result = r.Get("result");
    std::wcout << L"owner:    T2TouchIdBio driver (WUDFHost pid " << r.GetInt("pid", 0)
               << L") - discovery ran in the driver\n";
    if (result != "ok") {
        CliConnect c = CliConnect::TimedOut;
        if (result == "busy") c = CliConnect::Busy;
        else if (result == "no_adapter") { std::wcout << L"no T2 NCM adapter found.\n"; c = CliConnect::NoAdapter; }
        else if (result == "no_peer") c = CliConnect::NoPeer;
        else if (result == "not_found") c = CliConnect::NotFound;
        else if (result == "cancelled") c = CliConnect::Cancelled;
        else if (result != "timed_out") std::wcout << L"owner error: " << Widen(r.Get("error", result)) << L"\n";
        PrintConnectFailure(c);
        *exitCode = c == CliConnect::NotFound ? 2 : 1;
        return OwnerCall::Done;
    }
    if (r.Has("peer")) std::wcout << L"peer:     " << Widen(r.Get("peer")) << L"\n";
    std::wcout << L"transport: " << (r.Get("transport") == "tunnel" ? L"IPv4 tunnel" : L"Native IPv6") << L"\n";
    std::wcout << L"BiometricKit BridgeXPC port: " << r.GetInt("port");
    if (r.GetInt("rsd") != 0) std::wcout << L"  (RemoteXPC " << r.GetInt("rsd") << L")";
    std::wcout << L"\n";
    if (!r.Has("bridge_version")) {
        std::wcout << L"BridgeXPC HELO OK, but getBridgeVersion failed (unexpected reply shape).\n";
        *exitCode = 1;
        return OwnerCall::Done;
    }
    std::wcout << L"BridgeXPC verified: HELO OK, bridge version=" << r.GetInt("bridge_version") << L"\n";
    *exitCode = 0;
    return OwnerCall::Done;
}

// `t2touchid transport-status`: what the owner knows - no network I/O at all.
static int CmdTransportStatus() {
    std::string reply;
    const t2::ipc::PipeCallResult pr =
        t2::ipc::CallPipe(t2::ipc::kTransportPipeName, "op=status\n", 5000, &reply, g_cliCancel);
    if (pr != t2::ipc::PipeCallResult::Ok) {
        std::wcout << L"transport owner not reachable (" << t2::ipc::PipeCallResultName(pr)
                   << L"): the T2TouchIdBio driver is not running.\n";
        return 1;
    }
    const t2::ipc::KvMessage r = t2::ipc::KvMessage::Parse(reply);
    for (const auto& kv : r.Items()) {
        std::wcout << Widen(kv.first) << L": " << Widen(kv.second) << L"\n";
    }
    return r.Get("result") == "ok" ? 0 : 1;
}

// Reads T2Ncm.sys's own RX/TX counters via IOCTL_T2NCM_GET_STATUS (0x900,
// Public.h). Regular NDIS-path sends never touch TxFramesSent/TxNtbsSent/
// TxFramesRejected - those three are diagnostic-only, populated solely by
// IOCTL_T2NCM_SEND_TEST_FRAME (see Public.h's own comment on that IOCTL) -
// so they are NOT printed here; printing them would just show permanent
// zeros for a normal session and could be misread as "nothing was ever
// sent". The RX counters, by contrast, DO reflect real bulk-IN traffic,
// which is exactly what's needed to tell apart the three ways a tunnel
// connect() can go silent: nothing arrives at all (RxNtbsReceived flat -
// T2 never replied, or the SYN never actually made it out), arrives and
// the driver's own filter drops it (RxFramesParsed up, RxFramesIndicated
// flat, RxFramesFiltered up), or arrives and is handed to NDIS fine
// (RxFramesIndicated up) - meaning the loss is above the driver, in the
// TCP/IP stack's handling of the rewritten frame. Run this once before a
// tunnel connect attempt and once right after; the deltas say which case
// this is.
static int CmdNcmStatus() {
    HANDLE h = CreateFileW(L"\\\\.\\T2Ncm", GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::wcout << L"cannot open \\\\.\\T2Ncm (GetLastError=" << GetLastError()
                   << L") - is the driver loaded and are you Administrator?\n";
        return 1;
    }
    T2NCM_STATUS status{};
    DWORD returned = 0;
    const DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS);
    BOOL ok = DeviceIoControl(h, code, nullptr, 0, &status, sizeof(status), &returned, nullptr);
    CloseHandle(h);
    if (!ok) {
        std::wcout << L"IOCTL_T2NCM_GET_STATUS failed, GetLastError=" << GetLastError() << L"\n";
        return 1;
    }
    auto printMac = [](const wchar_t* label, const UINT8 mac[6]) {
        wchar_t buf[32];
        swprintf_s(buf, L"%02X-%02X-%02X-%02X-%02X-%02X",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        std::wcout << label << buf << L"\n";
    };

    std::wcout << L"LifecycleState        " << status.LifecycleState << L"\n";
    std::wcout << L"NdisAdapterReady      " << (status.NdisAdapterReady ? L"yes" : L"no") << L"\n";
    std::wcout << L"DataPathRunning       " << (status.DataPathRunning ? L"yes" : L"no") << L"\n";
    std::wcout << L"PowerState            " << status.PowerState << L" (0=Unspecified,1=D0,2..5=D1..D3)\n";
    std::wcout << L"CdcPacketFilter       0x" << std::hex << status.CdcPacketFilter << std::dec
               << (status.CdcPacketFilterApplied ? L" (applied)" : L" (NOT applied)") << L"\n";
    std::wcout << L"MacAddressIsPermanent " << (status.MacAddressIsPermanent ? L"yes" : L"no (generated)") << L"\n";
    if (status.MacAddressValid) {
        printMac(L"MacAddress (ours)     ", status.MacAddress);
    } else {
        std::wcout << L"MacAddress (ours)     (not valid)\n";
    }
    std::wcout << L"OutstandingRxNbls     " << status.OutstandingRxNbls << L"\n";
    std::wcout << L"OutstandingTxRequests " << status.OutstandingTxRequests << L"\n";
    std::wcout << L"RxNtbsReceived        " << status.RxNtbsReceived << L"\n";
    std::wcout << L"RxFramesParsed        " << status.RxFramesParsed << L"\n";
    std::wcout << L"RxFramesFiltered      " << status.RxFramesFiltered << L"\n";
    std::wcout << L"RxFramesIndicated     " << status.RxFramesIndicated << L"\n";
    std::wcout << L"RxFramesRejected      " << status.RxFramesRejected << L"\n";
    std::wcout << L"RxLastFrameEtherType  0x" << std::hex << status.RxLastFrameEtherType << std::dec << L"\n";
    std::wcout << L"RxLastFrameLength     " << status.RxLastFrameLength << L"\n";
    printMac(L"RxLastFrameDest       ", status.RxLastFrameDest);
    printMac(L"RxLastFrameSrc        ", status.RxLastFrameSrc);
    std::wcout << L"DrainTimeoutCount     " << status.DrainTimeoutCount << L"\n";
    return 0;
}

static int CmdNetwork(int argc, wchar_t* argv[]) {
    using namespace t2::discovery;

    bool doScan = true;
    bool forceRescan = false; // --rescan: skip the cached port, always scan (GUI "Rescan")
    ULONGLONG budgetMs = 120000;
    for (int i = 2; i < argc; ++i) {
        const std::wstring a = argv[i];
        if (a == L"--no-scan") {
            doScan = false;
        } else if (a == L"--rescan") {
            forceRescan = true;
        } else if (a == L"--timeout" && i + 1 < argc) {
            const int sec = _wtoi(argv[++i]);
            if (sec > 0) budgetMs = static_cast<ULONGLONG>(sec) * 1000;
        }
    }
    const EndpointArgs args = ParseEndpointArgs(argc, argv, 2);
    if (!args.ok) return 1;

    // Adapter report (no network I/O beyond what enumeration itself does).
    std::vector<NcmEndpoint> endpoints;
    if (args.ifIndex != 0) {
        NcmEndpoint ep;
        if (!GetEndpointByIfIndex(args.ifIndex, &ep)) {
            std::wcout << L"no T2 NCM endpoint on ifIndex " << args.ifIndex << L"\n";
            return 1;
        }
        endpoints.push_back(ep);
    } else {
        endpoints = FindT2NcmEndpoints();
        if (endpoints.empty()) {
            std::wcout << L"no T2 NCM adapter found.\n";
            std::wcout << L"hint: t2touchid.exe network [ifIndex] [--host fe80::...] [--rescan]\n";
            return 1;
        }
    }
    for (const auto& ep : endpoints) {
        const std::string local = FormatLinkLocal(ep.localLinkLocal, ep.ifIndex);
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
        std::wcout << L"local:    " << std::wstring(local.begin(), local.end())
                   << L"  (Windows - do NOT scan this)\n";
    }
    if (!doScan) {
        std::wcout << L"scan skipped (--no-scan).\n";
        return 0;
    }

    std::wcout << (forceRescan ? L"rescanning" : L"connecting")
               << L" (shared TransportManager: native IPv6 first, IPv4 tunnel if IPv6 is "
                  L"blocked; up to " << (budgetMs / 1000) << L" s)...\n";
    // An explicit endpoint (ifIndex / --host) is a diagnostic request for THIS
    // process; otherwise the transport owner does it.
    if (args.ifIndex == 0 && args.host.empty()) {
        int code = 1;
        if (ConnectViaOwner(forceRescan, budgetMs, &code) == OwnerCall::Done) return code;
    }
    t2::bridgexpc::Connection bridge;
    uint16_t port = 0, rsd = 0;
    NcmEndpoint used;
    const CliConnect cr = ConnectBridgeCli(args, &bridge, forceRescan, budgetMs, &port, &rsd, &used);
    if (cr != CliConnect::Ok) {
        PrintConnectFailure(cr);
        return cr == CliConnect::NotFound ? 2 : 1;
    }
    if (used.peerSource != PeerSource::None) {
        const std::string peer = FormatLinkLocal(used.peerLinkLocal, used.ifIndex);
        std::wcout << L"peer:     " << std::wstring(peer.begin(), peer.end()) << L"\n";
    }
    const bool tunnel = t2::transport::IsTunnelModeActive();
    std::wcout << L"transport: " << (tunnel ? L"IPv4 tunnel" : L"Native IPv6") << L"\n";
    std::wcout << L"BiometricKit BridgeXPC port: " << port;
    if (rsd != 0) std::wcout << L"  (RemoteXPC " << rsd << L")";
    std::wcout << L"\n";

    // Prove the port is a live BridgeXPC endpoint beyond the HELO: read the
    // bridge's own version. (Discovery has already cached the port - it does so
    // the moment a scan confirms it, and only after a live HELO otherwise.)
    int64_t bridgeVersion = 0;
    if (!bridge.GetBridgeVersion(&bridgeVersion, std::chrono::milliseconds(2000))) {
        std::wcout << L"BridgeXPC HELO OK, but getBridgeVersion failed "
                      L"(unexpected reply shape).\n";
        return 1;
    }
    std::wcout << L"BridgeXPC verified: HELO OK, bridge version=" << bridgeVersion << L"\n";
    return 0;
}

// Shared discovery+connect step for `identities`, `warmup` and `verify`: the same
// TransportManager path as `network` (cache first, scan on a miss, tunnel when IPv6
// is blocked). Accepts the same trailing endpoint args as `network` (an ifIndex
// and/or --host fe80::...) starting at argv[firstArgIndex].
static bool DiscoverBiometricKitBridge(int argc, wchar_t* argv[], int firstArgIndex,
                                        t2::bridgexpc::Connection* outConn) {
    const EndpointArgs args = ParseEndpointArgs(argc, argv, firstArgIndex);
    uint16_t port = 0;
    const CliConnect cr = ConnectBridgeCli(args, outConn, /*forceRescan=*/false, 60000, &port, nullptr);
    if (cr != CliConnect::Ok) {
        PrintConnectFailure(cr);
        return false;
    }
    std::wcout << L"BiometricKit BridgeXPC port: " << port << L"  ("
               << (t2::transport::IsTunnelModeActive() ? L"IPv4 tunnel" : L"native IPv6") << L")\n";
    return true;
}

// Gate 8 phase 1: read the enrolled identity list. Exact Linux ready
// sequence (t2-biometric-ready.sh): initialize, reset-sensor, cancel,
// load-calibration, identity-list. Does NOT start a match.
static int CmdIdentities(int argc, wchar_t* argv[]) {
    using namespace t2::bridgexpc;
    using namespace t2::biometrickit;

    // Default = uid derived from the special bag last set via set-system-keybag /
    // unlock <-bag> / vault (HKLM\SOFTWARE\T2TouchIdBio\MacosUserId); --uid wins.
    uint32_t macosUserId = LoadConfiguredMacosUserId();
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

    // Default = uid derived from the special bag last set via set-system-keybag /
    // unlock <-bag> / vault (HKLM\SOFTWARE\T2TouchIdBio\MacosUserId); --uid wins.
    uint32_t macosUserId = LoadConfiguredMacosUserId();
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
    cfg.macosUserId = LoadConfiguredMacosUserId(); // --uid below overrides
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
            // Explicit opt-OUT of the current default (VerifyConfig::
            // skipResetSensor = false, 27.09.2026, matching t2-fprintd.py's
            // real _run_probe() which always sends --reset-sensor). Use
            // this to A/B against that default, e.g. re-running the
            // 24.09.2026 real-hardware skip test.
            cfg.skipResetSensor = true;
        } else if (a == L"--no-load-calibration") {
            // Same: explicit opt-OUT of the current default. bridgeOS
            // calibrates at its own boot, and a real-hardware A/B once
            // showed verify still matches without this — but
            // t2-fprintd.py's actual production probe always sends
            // --load-calibration, which is now this driver's default too.
            cfg.skipLoadCalibration = true;
        } else if (a == L"--reset-sensor") {
            // Redundant with the current default — kept as an explicit,
            // self-documenting no-op for scripts/muscle memory.
            cfg.skipResetSensor = false;
        } else if (a == L"--load-calibration") {
            // Same: redundant with the current default.
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
    VerifyOutcome outcome = engine.Verify(&bridge, &matchedUuid, g_cliCancel);

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
        case VerifyOutcome::Cancelled:
            std::wcout << L"verify-cancelled\n";
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
    // --cancel-event <name>: pulled out the same way (see InitCliCancel).
    InitCliCancel(&argc, argv);

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
        std::wcout << L"usage: t2touchid.exe [--verbose|-v] <status|register-ool|capabilities|device-state|load-keybag|set-system-keybag|unlock|network|transport-status|identities|warmup|verify>\n";
        std::wcout << L"  network    [ifIndex] [--host fe80::...] [--rescan] [--no-scan] [--timeout SEC]\n"
                      L"             (without ifIndex/--host the T2TouchIdBio driver does it, when running)\n";
        std::wcout << L"  transport-status  what the transport owner (driver) knows: transport, port, counters\n";
        std::wcout << L"  identities [ifIndex] [--host fe80::...] [--uid N]\n";
        std::wcout << L"  warmup     [ifIndex] [--host fe80::...] [--uid N]\n";
        std::wcout << L"  verify     [ifIndex] [--host fe80::...] [--uid N] [--seconds N]\n"
                      L"             [--match-layout inline|padded|legacy]  (default: legacy)\n"
                      L"             [--match-flags N]  (0=default, 1=unlock match per Linux)\n"
                      L"             [--no-reset-sensor] [--no-load-calibration]  (both ON by default, Linux parity)\n";
        std::wcout << L"  --cancel-event NAME: abort cleanly when the named event is signaled\n";
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
    if (cmd == L"network" || cmd == L"identities" || cmd == L"warmup" || cmd == L"verify") {
        EnableCtrlCCancel();
    }
    if (cmd == L"network") return CmdNetwork(argc, argv);
    if (cmd == L"identities") return CmdIdentities(argc, argv);
    if (cmd == L"warmup") return CmdWarmup(argc, argv);
    if (cmd == L"verify") return CmdVerify(argc, argv);
    if (cmd == L"ncmstatus") return CmdNcmStatus();
    if (cmd == L"transport-status") return CmdTransportStatus();

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
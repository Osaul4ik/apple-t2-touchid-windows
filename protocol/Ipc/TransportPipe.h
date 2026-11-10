// SPDX-License-Identifier: GPL-2.0-only
// TransportPipe.h - the transport owner's IPC.
//
// One process owns the T2 transport: the T2TouchIdBio UMDF driver (WUDFHost,
// LocalService). It serves \\.\pipe\T2TouchIdTransport; the CLI - and through it
// the GUI's Rescan / status - asks it instead of running discovery, flipping
// T2Ncm.sys and scanning from a second process. When the driver is not running
// (not installed, sensor disabled, early boot) the pipe does not exist and the
// CLI falls back to doing the work itself, exactly as before.
//
// Wire format: message-mode pipe, one request message, one reply message, both
// "key=value" lines (KvMessage). Requests: "op=status", "op=connect" (+ force=1,
// timeout=<ms>). See TransportService.h for the fields.
//
// Security:
//   * the pipe's DACL allows SYSTEM, Administrators and LocalService only (the CLI
//     runs elevated; standard users cannot drive the transport);
//   * the server creates it with FILE_FLAG_FIRST_PIPE_INSTANCE, so it never serves
//     on a name someone else squatted;
//   * the client checks that the server process runs as LocalService or SYSTEM
//     before trusting a reply (a squatter's answer is ignored -> local fallback).
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace t2::ipc {

inline constexpr wchar_t kTransportPipeName[] = L"\\\\.\\pipe\\T2TouchIdTransport";
inline constexpr DWORD kMaxPipeMessage = 64 * 1024;

// "key=value\n" lines. Keys are [a-zA-Z0-9_.-]; values may contain anything but a
// newline (newlines are replaced by spaces on Set).
class KvMessage {
public:
    void Set(const std::string& key, const std::string& value);
    void Set(const std::string& key, long long value) { Set(key, std::to_string(value)); }
    std::string Get(const std::string& key, const std::string& def = "") const;
    long long GetInt(const std::string& key, long long def = 0) const;
    bool Has(const std::string& key) const;
    std::string Serialize() const;
    static KvMessage Parse(const std::string& text);
    const std::vector<std::pair<std::string, std::string>>& Items() const { return items_; }
private:
    std::vector<std::pair<std::string, std::string>> items_;
};

// Serves one request at a time per client connection, several clients at once (a
// long "connect" does not block a "status"). The handler gets a cancel event that
// is signaled when the client goes away or the server stops.
class PipeServer {
public:
    using Handler = std::function<std::string(const std::string& request, HANDLE cancel)>;

    PipeServer() = default;
    ~PipeServer() { Stop(); }
    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;

    // `sddl` nullptr = SYSTEM + Administrators + LocalService.
    bool Start(const wchar_t* name, Handler handler, const wchar_t* sddl = nullptr);
    void Stop();
    bool Running() const { return listener_ != nullptr; }

private:
    struct Worker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    static DWORD WINAPI ListenerProc(LPVOID self);
    void Listen();
    void ReapFinishedWorkers(); // clientsMu_ held
    void ServeClient(HANDLE pipe);
    HANDLE CreateInstance(bool first);

    std::wstring name_;
    std::wstring sddl_;
    Handler handler_;
    HANDLE stopEvent_ = nullptr;
    HANDLE listener_ = nullptr;
    HANDLE pending_ = INVALID_HANDLE_VALUE; // first instance, handed to the listener
    std::mutex clientsMu_;
    std::vector<Worker> clients_;
    std::atomic<unsigned> active_{0};
};

enum class PipeCallResult {
    Ok,
    NoServer,      // the pipe does not exist: nobody owns the transport
    Untrusted,     // something else serves that name: ignored
    Failed,        // I/O error / malformed
    TimedOut,
    Cancelled,
};

// One request/reply. `requireServiceServer` (default) rejects a server that is not
// LocalService / SYSTEM; tests pass false.
PipeCallResult CallPipe(const wchar_t* name, const std::string& request, DWORD timeoutMs,
                        std::string* reply, HANDLE cancel = nullptr,
                        bool requireServiceServer = true);

const wchar_t* PipeCallResultName(PipeCallResult r);

} // namespace t2::ipc

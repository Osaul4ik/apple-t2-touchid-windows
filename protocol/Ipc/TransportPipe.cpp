// SPDX-License-Identifier: GPL-2.0-only
// TransportPipe.cpp - see TransportPipe.h.
#include "TransportPipe.h"
#include <sddl.h>

#pragma comment(lib, "Advapi32.lib")

namespace t2::ipc {

// ---- KvMessage -------------------------------------------------------------------
void KvMessage::Set(const std::string& key, const std::string& value) {
    std::string v = value;
    for (char& c : v) {
        if (c == '\n' || c == '\r') c = ' ';
    }
    for (auto& kv : items_) {
        if (kv.first == key) {
            kv.second = v;
            return;
        }
    }
    items_.emplace_back(key, v);
}

std::string KvMessage::Get(const std::string& key, const std::string& def) const {
    for (const auto& kv : items_) {
        if (kv.first == key) return kv.second;
    }
    return def;
}

long long KvMessage::GetInt(const std::string& key, long long def) const {
    const std::string v = Get(key);
    if (v.empty()) return def;
    try {
        size_t used = 0;
        const long long n = std::stoll(v, &used, 10);
        return used == v.size() ? n : def;
    } catch (...) {
        return def;
    }
}

bool KvMessage::Has(const std::string& key) const {
    for (const auto& kv : items_) {
        if (kv.first == key) return true;
    }
    return false;
}

std::string KvMessage::Serialize() const {
    std::string out;
    for (const auto& kv : items_) {
        out += kv.first;
        out += '=';
        out += kv.second;
        out += '\n';
    }
    return out;
}

KvMessage KvMessage::Parse(const std::string& text) {
    KvMessage m;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find('\n', pos);
        if (end == std::string::npos) end = text.size();
        std::string line = text.substr(pos, end - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const size_t eq = line.find('=');
        if (eq != std::string::npos && eq > 0) {
            m.items_.emplace_back(line.substr(0, eq), line.substr(eq + 1));
        }
        pos = end + 1;
    }
    return m;
}

// ---- helpers ---------------------------------------------------------------------
namespace {

constexpr DWORD kWaitStop = 0;  // WaitForMultipleObjects index 0 (WAIT_OBJECT_0 is not
constexpr DWORD kWaitIo = 1;    // usable under UMDF_USING_NTSTATUS, see Log.h)
constexpr DWORD kWaitTimeout = 0x102;
constexpr unsigned kMaxClients = 8;
constexpr DWORD kRequestReadMs = 5000;
constexpr DWORD kReplyWriteMs = 5000;

struct Overlapped {
    OVERLAPPED ov{};
    Overlapped() { ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr); }
    ~Overlapped() {
        if (ov.hEvent) CloseHandle(ov.hEvent);
    }
    Overlapped(const Overlapped&) = delete;
    Overlapped& operator=(const Overlapped&) = delete;
};

// Waits for an overlapped operation, the optional `abortEvent` or `timeoutMs`.
// Returns the transfer result; *aborted / *timedOut tell why it failed.
bool FinishIo(HANDLE h, Overlapped& o, HANDLE abortEvent, DWORD timeoutMs, DWORD* bytes,
              bool* aborted, bool* timedOut, DWORD* err) {
    *aborted = false;
    *timedOut = false;
    HANDLE waits[2] = {abortEvent, o.ov.hEvent};
    const DWORD r = abortEvent ? WaitForMultipleObjects(2, waits, FALSE, timeoutMs)
                               : (WaitForSingleObject(o.ov.hEvent, timeoutMs) == 0 ? kWaitIo : kWaitTimeout);
    if (r != kWaitIo) {
        CancelIoEx(h, &o.ov);
        DWORD ignored = 0;
        GetOverlappedResult(h, &o.ov, &ignored, TRUE);
        if (r == kWaitStop && abortEvent) *aborted = true;
        else *timedOut = true;
        *err = ERROR_OPERATION_ABORTED;
        return false;
    }
    if (!GetOverlappedResult(h, &o.ov, bytes, FALSE)) {
        *err = GetLastError();
        return false;
    }
    *err = 0;
    return true;
}

// Reads one whole message (ERROR_MORE_DATA -> keep reading).
bool ReadMessage(HANDLE h, HANDLE abortEvent, DWORD timeoutMs, std::string* out, bool* aborted,
                 bool* timedOut) {
    out->clear();
    char buf[4096];
    for (;;) {
        Overlapped o;
        if (!o.ov.hEvent) return false;
        DWORD got = 0;
        DWORD err = 0;
        BOOL ok = ReadFile(h, buf, sizeof(buf), &got, &o.ov);
        if (!ok) {
            err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                ok = FinishIo(h, o, abortEvent, timeoutMs, &got, aborted, timedOut, &err) ? TRUE : FALSE;
                if (!ok && (*aborted || *timedOut)) return false;
            }
        }
        if (ok || err == ERROR_MORE_DATA) {
            out->append(buf, got);
            if (out->size() > kMaxPipeMessage) return false;
            if (ok) return true;
            continue; // ERROR_MORE_DATA: rest of the message
        }
        return false;
    }
}

bool WriteMessage(HANDLE h, HANDLE abortEvent, DWORD timeoutMs, const std::string& msg,
                  bool* aborted, bool* timedOut) {
    Overlapped o;
    DWORD put = 0;
    DWORD err = 0;
    *aborted = false;
    *timedOut = false;
    if (!o.ov.hEvent) return false;
    if (!WriteFile(h, msg.data(), static_cast<DWORD>(msg.size()), &put, &o.ov)) {
        err = GetLastError();
        if (err != ERROR_IO_PENDING) return false;
        if (!FinishIo(h, o, abortEvent, timeoutMs, &put, aborted, timedOut, &err)) return false;
    }
    return put == msg.size();
}

bool ServerIsService(HANDLE pipe) {
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid) || pid == 0) return false;
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return false;
    HANDLE token = nullptr;
    bool ok = false;
    if (OpenProcessToken(proc, TOKEN_QUERY, &token)) {
        alignas(TOKEN_USER) unsigned char buf[256];
        DWORD len = 0;
        if (GetTokenInformation(token, TokenUser, buf, sizeof(buf), &len)) {
            PSID sid = reinterpret_cast<TOKEN_USER*>(buf)->User.Sid;
            ok = IsWellKnownSid(sid, WinLocalServiceSid) || IsWellKnownSid(sid, WinLocalSystemSid);
        }
        CloseHandle(token);
    }
    CloseHandle(proc);
    return ok;
}

} // namespace

// ---- PipeServer ------------------------------------------------------------------
HANDLE PipeServer::CreateInstance(bool first) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_.c_str(), SDDL_REVISION_1, &sd,
                                                              nullptr)) {
        return INVALID_HANDLE_VALUE;
    }
    sa.lpSecurityDescriptor = sd;
    const DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                           (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
    HANDLE h = CreateNamedPipeW(name_.c_str(), openMode,
                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
                                    PIPE_REJECT_REMOTE_CLIENTS,
                                PIPE_UNLIMITED_INSTANCES, kMaxPipeMessage, kMaxPipeMessage, 0, &sa);
    LocalFree(sd);
    return h;
}

bool PipeServer::Start(const wchar_t* name, Handler handler, const wchar_t* sddl) {
    if (listener_) return true;
    name_ = name;
    sddl_ = sddl ? sddl : L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)";
    handler_ = std::move(handler);
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) return false;
    // The first instance is created here, synchronously: if the name is already
    // taken (a squatter, or a second copy of us) Start fails instead of serving.
    HANDLE first = CreateInstance(true);
    if (first == INVALID_HANDLE_VALUE) {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
        return false;
    }
    pending_ = first;
    listener_ = CreateThread(nullptr, 0, &PipeServer::ListenerProc, this, 0, nullptr);
    if (!listener_) {
        CloseHandle(first);
        pending_ = INVALID_HANDLE_VALUE;
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
        return false;
    }
    return true;
}

void PipeServer::Stop() {
    if (!listener_) return;
    SetEvent(stopEvent_);
    WaitForSingleObject(listener_, INFINITE);
    CloseHandle(listener_);
    listener_ = nullptr;
    std::vector<Worker> clients;
    {
        std::lock_guard<std::mutex> lock(clientsMu_);
        clients.swap(clients_);
    }
    for (Worker& w : clients) {
        if (w.thread.joinable()) w.thread.join();
    }
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
}

DWORD WINAPI PipeServer::ListenerProc(LPVOID self) {
    static_cast<PipeServer*>(self)->Listen();
    return 0;
}

void PipeServer::Listen() {
    HANDLE inst = pending_;
    pending_ = INVALID_HANDLE_VALUE;
    while (inst != INVALID_HANDLE_VALUE) {
        Overlapped o;
        if (!o.ov.hEvent) {
            CloseHandle(inst);
            return;
        }
        bool connected = ConnectNamedPipe(inst, &o.ov) != FALSE;
        if (!connected) {
            const DWORD e = GetLastError();
            if (e == ERROR_PIPE_CONNECTED) {
                connected = true;
            } else if (e == ERROR_IO_PENDING) {
                HANDLE waits[2] = {stopEvent_, o.ov.hEvent};
                if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != kWaitIo) {
                    CancelIoEx(inst, &o.ov);
                    DWORD ignored = 0;
                    GetOverlappedResult(inst, &o.ov, &ignored, TRUE);
                    CloseHandle(inst);
                    return; // stopping
                }
                DWORD ignored = 0;
                connected = GetOverlappedResult(inst, &o.ov, &ignored, FALSE) != FALSE;
            }
        }
        if (WaitForSingleObject(stopEvent_, 0) == 0) {
            CloseHandle(inst);
            return;
        }
        // The next instance before serving this one, so a second client can connect
        // meanwhile. On failure (out of handles...) retry every second until stop.
        HANDLE next = CreateInstance(false);
        while (next == INVALID_HANDLE_VALUE && WaitForSingleObject(stopEvent_, 1000) != 0) {
            next = CreateInstance(false);
        }
        if (connected) {
            if (active_.load() >= kMaxClients) {
                bool a = false, t = false;
                WriteMessage(inst, stopEvent_, 1000, "error=busy\n", &a, &t);
                DisconnectNamedPipe(inst);
                CloseHandle(inst);
            } else {
                ++active_;
                auto done = std::make_shared<std::atomic<bool>>(false);
                try {
                    std::thread t([this, inst, done] {
                        ServeClient(inst);
                        --active_;
                        done->store(true, std::memory_order_release);
                    });
                    std::lock_guard<std::mutex> lock(clientsMu_);
                    ReapFinishedWorkers();
                    clients_.push_back({std::move(t), done});
                } catch (...) { // std::system_error: no thread
                    --active_;
                    DisconnectNamedPipe(inst);
                    CloseHandle(inst);
                }
            }
        } else {
            CloseHandle(inst);
        }
        inst = next;
    }
}

void PipeServer::ReapFinishedWorkers() {
    for (auto it = clients_.begin(); it != clients_.end();) {
        if (it->done->load(std::memory_order_acquire)) {
            if (it->thread.joinable()) it->thread.join();
            it = clients_.erase(it);
        } else {
            ++it;
        }
    }
}

void PipeServer::ServeClient(HANDLE pipe) {
    std::string request;
    bool aborted = false, timedOut = false;
    if (!ReadMessage(pipe, stopEvent_, kRequestReadMs, &request, &aborted, &timedOut)) {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return;
    }
    // Cancel for the handler: the client went away (its pending read below completes
    // with ERROR_BROKEN_PIPE) or the server is stopping.
    HANDLE cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Overlapped watch;
    if (!cancel || !done || !watch.ov.hEvent) {
        if (cancel) CloseHandle(cancel);
        if (done) CloseHandle(done);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return;
    }
    // Watch for the client going away: a 1-byte read that only completes when it
    // closes its end (it sends nothing after the request).
    char dummy = 0;
    DWORD got = 0;
    bool watching = false;
    if (!ReadFile(pipe, &dummy, 1, &got, &watch.ov)) {
        if (GetLastError() == ERROR_IO_PENDING) watching = true;
        else SetEvent(cancel); // already gone (ERROR_BROKEN_PIPE): do nothing expensive
    }
    std::string reply;
    auto run = [&] {
        try {
            reply = handler_ ? handler_(request, cancel) : std::string("result=error\nerror=no handler\n");
        } catch (...) {
            reply = "result=error\nerror=handler failed\n";
        }
        SetEvent(done);
    };
    std::thread worker;
    try {
        worker = std::thread(run);
    } catch (...) {
        run(); // no thread to spare: serve inline (no early cancel on client loss)
    }
    HANDLE waits[3] = {done, stopEvent_, watch.ov.hEvent};
    const DWORD n = watching ? 3 : 2;
    const DWORD r = WaitForMultipleObjects(n, waits, FALSE, INFINITE);
    if (r != 0) SetEvent(cancel); // stop or client gone
    if (worker.joinable()) worker.join();
    if (watching) {
        CancelIoEx(pipe, &watch.ov);
        DWORD ignored = 0;
        GetOverlappedResult(pipe, &watch.ov, &ignored, TRUE);
    }
    if (r == 0) {
        WriteMessage(pipe, stopEvent_, kReplyWriteMs, reply, &aborted, &timedOut);
        FlushFileBuffers(pipe);
    }
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    CloseHandle(cancel);
    CloseHandle(done);
}

// ---- client ----------------------------------------------------------------------
PipeCallResult CallPipe(const wchar_t* name, const std::string& request, DWORD timeoutMs,
                        std::string* reply, HANDLE cancel, bool requireServiceServer) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    HANDLE h = INVALID_HANDLE_VALUE;
    for (;;) {
        // SECURITY_IDENTIFICATION: the server may identify, never impersonate, us.
        h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                        nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        const DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return PipeCallResult::NoServer;
        if (e != ERROR_PIPE_BUSY) return PipeCallResult::Failed;
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return PipeCallResult::TimedOut;
        if (cancel && WaitForSingleObject(cancel, 0) == 0) return PipeCallResult::Cancelled;
        const DWORD slice = static_cast<DWORD>(deadline - now > 500 ? 500 : deadline - now);
        WaitNamedPipeW(name, slice);
    }
    if (requireServiceServer && !ServerIsService(h)) {
        CloseHandle(h);
        return PipeCallResult::Untrusted;
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);

    auto left = [&]() -> DWORD {
        const ULONGLONG now = GetTickCount64();
        return now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
    };
    bool aborted = false, timedOut = false;
    PipeCallResult result = PipeCallResult::Ok;
    if (!WriteMessage(h, cancel, left(), request, &aborted, &timedOut)) {
        result = aborted ? PipeCallResult::Cancelled
                         : timedOut ? PipeCallResult::TimedOut : PipeCallResult::Failed;
    } else if (!ReadMessage(h, cancel, left(), reply, &aborted, &timedOut)) {
        result = aborted ? PipeCallResult::Cancelled
                         : timedOut ? PipeCallResult::TimedOut : PipeCallResult::Failed;
    }
    // Closing the handle is what tells the server's handler to stop (cancel/timeout).
    CloseHandle(h);
    return result;
}

const wchar_t* PipeCallResultName(PipeCallResult r) {
    switch (r) {
    case PipeCallResult::Ok:        return L"ok";
    case PipeCallResult::NoServer:  return L"no server";
    case PipeCallResult::Untrusted: return L"untrusted server";
    case PipeCallResult::Failed:    return L"failed";
    case PipeCallResult::TimedOut:  return L"timed out";
    case PipeCallResult::Cancelled: return L"cancelled";
    }
    return L"?";
}

} // namespace t2::ipc

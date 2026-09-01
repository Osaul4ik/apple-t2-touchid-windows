// SPDX-License-Identifier: GPL-2.0-only
// Client.h — user-mode AppleKeyStore client
//
// Thin wrapper over IOCTL_T2_AKS_EXCHANGE. Password handling rules
// (Milestone 2 §10) are enforced structurally here: there is no API in
// this class that accepts a password via anything other than a caller-
// owned buffer that this class zeroes before returning, and no path here
// ever writes a password to argv/env/log/disk.

#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <optional>

namespace t2::applekeystore {

enum class AksResult {
    Ok,
    DeviceNotFound,
    NotReady,       // OOL not registered yet
    AccessDenied,   // driver rejected the opcode (should never happen for allow-listed ops)
    IoError,
};

class Client {
public:
    Client() = default;
    ~Client() { Close(); }

    // Milestone 2B §10: this class owns a raw HANDLE. The implicitly
    // generated copy constructor/assignment would copy that HANDLE value
    // into a second Client, and when either instance is destroyed (or
    // Close()d) it would CloseHandle() a handle the other instance still
    // believes is live - a double-close, and a potential handle-reuse bug
    // if a third, unrelated handle gets that same value in between. Delete
    // copying outright; there is no use case in this codebase for two
    // Client objects sharing one device handle.
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Moving is safe (and useful, e.g. returning a Client by value) as long
    // as the moved-from instance is left holding nothing to close.
    Client(Client&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }
    Client& operator=(Client&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    // Opens \\.\GLOBALROOT\Device\... via the registered device interface
    // (GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT). Requires admin (SDDL on the
    // device interface restricts to SYSTEM/Administrators).
    //
    // Safe to call again on an already-open Client (Milestone 2B §10
    // "check repeated Connect()"): any existing handle is closed first, so
    // a caller that calls Open() twice in a row gets a fresh handle instead
    // of leaking the first one.
    AksResult Open();
    void Close();

    AksResult GetStatus(bool* pciPresent, bool* bar4Mapped, bool* oolRegistered, bool* mailboxAccessible);
    AksResult RegisterOol();

    // secretUtf8 is zeroed by this call before returning, regardless of
    // outcome — caller must not reuse the buffer contents afterward.
    AksResult LoadKeybag(const std::vector<uint8_t>& bagBytes, int32_t* outHandle);
    AksResult MakeSystemKeybag(int32_t handle, int32_t specialUserBag);
    AksResult Unlock(int32_t handle, std::vector<uint8_t>& secretUtf8 /* zeroed on return */);
    AksResult GetCapabilities(uint64_t selector, uint64_t* outValue);
    // Differential test vs capabilities: same V2 transport, op 0x19.
    // body = [result:u32=0][handle:u64][selector:u32] (20 bytes).
    // outSepStatus (optional): the signed EP7 reply status. A nonzero value
    // here (with the call still returning AksResult::Ok — the IOCTL/transport
    // itself succeeded) means AppleKeyStore understood and rejected the
    // request, e.g. because `handle` isn't a currently-loaded keybag handle.
    // Do not mistake this for AksResult::IoError/NotReady: SEP replied fine.
    AksResult GetDeviceState(int64_t handle, uint32_t selector,
                            std::vector<uint8_t>* responseBody,
                            int8_t* outSepStatus = nullptr);

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;

    // outSepStatus (optional): see GetDeviceState's doc above — same
    // semantics for every AKS operation, not just device-state.
    AksResult Exchange(uint8_t operation,
                        const std::vector<uint8_t>& request,
                        std::vector<uint8_t>* response,
                        int8_t* outSepStatus = nullptr);
};

} // namespace t2::applekeystore
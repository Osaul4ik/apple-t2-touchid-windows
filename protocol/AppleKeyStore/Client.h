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
    // Opens \\.\GLOBALROOT\Device\... via the registered device interface
    // (GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT). Requires admin (SDDL on the
    // device interface restricts to SYSTEM/Administrators).
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
    AksResult GetDeviceState(int64_t handle, uint32_t selector,
                            std::vector<uint8_t>* responseBody);

    ~Client() { Close(); }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;

    AksResult Exchange(uint8_t operation,
                        const std::vector<uint8_t>& request,
                        std::vector<uint8_t>* response);
};

} // namespace t2::applekeystore

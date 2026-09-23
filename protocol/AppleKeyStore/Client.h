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
#include "../../driver/T2TouchIdTransport/public.h" // T2_BOOTSTRAP_STATUS, T2_SEP_BOOTSTRAP_REASON/STEP

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

    // Bootstrap status mailbox the driver holds in memory (public.h
    // T2_BOOTSTRAP_STATUS) — independent of the AppleKeyStore/SEP protocol
    // below. T2SepBootstrapService calls SetBootstrapStatus once after
    // each step of its sequence; SepVaultGui calls GetBootstrapStatus to
    // show the current state. Neither call touches the SEP.
    AksResult SetBootstrapStatus(T2_SEP_BOOTSTRAP_REASON reason, T2_SEP_BOOTSTRAP_STEP step,
                                int8_t sepStatus);
    AksResult GetBootstrapStatus(T2_BOOTSTRAP_STATUS* outStatus);

    // secretUtf8 is zeroed by this call before returning, regardless of
    // outcome — caller must not reuse the buffer contents afterward.
    //
    // session: VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux). The
    // t2-aks-tool.c CLI treats this as an untyped, unvalidated argument
    // for load_keybag (0x03) / set_system_keybag (0x0d) / unlock_keybag
    // (0x04) — no "must be 1" check exists in that file for these three
    // ops (that check is real, but scoped to the unrelated copy-keybag-uuid
    // opcode 0x06 and verify-password-acm opcode 0x21, both enforced
    // kernel-side in t2_aks_protocol.h). The project's own production
    // path — src/t2-keybag-load.sh, which is what actually runs on boot —
    // hardcodes SESSION=1 and passes it to BOTH load-keybag and
    // set-system-keybag; that same value is then written to the runtime
    // state file and read back by t2-keybag-unlock.sh for the unlock step,
    // so 1 is the value this reference project actually uses end-to-end on
    // real T2 hardware, even though the bare CLI tool would accept other
    // values without complaint. (Earlier revisions of this comment also
    // cited a literal `unlock-keybag 1 HANDLE` line in README.md as a
    // second source — no such line exists in the current README; the
    // documented manual path there is the `sudo t2-keybag-unlock` wrapper
    // described above, not a raw CLI invocation. Removed that claim rather
    // than leave an uncorroborated citation.) Default is 1 to match the
    // working boot-time path.
    //
    // outSepStatus (optional): see GetDeviceState's doc below — same
    // semantics here. A nonzero value means the mailbox exchange
    // succeeded but SEP rejected the request at the transport level (e.g.
    // bad session/handle). Separately from that, this call also checks
    // the body-level status:u32 the AKS operation itself returns
    // (VERIFIED FROM SOURCE, t2-aks-tool.c load_keybag) and returns
    // AksResult::IoError if it is nonzero even when outSepStatus is 0 —
    // that field is the actual load-keybag result and was previously
    // ignored here, which could report a rejected/malformed bag as a
    // fabricated success with a garbage handle.
    AksResult LoadKeybag(const std::vector<uint8_t>& bagBytes, int32_t* outHandle,
                        uint64_t session = 1, int8_t* outSepStatus = nullptr);
    AksResult MakeSystemKeybag(int32_t handle, int32_t specialUserBag,
                                uint64_t session = 1, int8_t* outSepStatus = nullptr);
    // outSepStatus (optional): same semantics as LoadKeybag/MakeSystemKeybag.
    // Previously missing on this call — AksResult::Ok only ever meant "the
    // mailbox round-trip completed", never "SEP accepted the password".
    // A wrong password still returns AksResult::Ok from Exchange(); the
    // rejection is opcode 0x04's SepStatus, which went undecoded and
    // silently dropped. Callers that skip this parameter get exactly the
    // old (misleading) behavior.
    //
    // Independently of outSepStatus, this call also checks the body-level
    // status:u32 the unlock operation itself returns (VERIFIED FROM
    // SOURCE, t2-aks-tool.c unlock_keybag_secret) and returns
    // AksResult::IoError when it is nonzero, even if outSepStatus is 0 —
    // that field is the real wrong-password/bad-handle signal for this
    // opcode and was previously never read here, so a wrong password could
    // come back as a false AksResult::Ok.
    AksResult Unlock(int32_t handle, std::vector<uint8_t>& secretUtf8 /* zeroed on return */,
                    uint64_t session = 1, int8_t* outSepStatus = nullptr);
    AksResult GetCapabilities(uint64_t selector, uint64_t* outValue);
    // Differential test vs capabilities: same V2 transport, op 0x19.
    // body = [result:u32=0][handle:u64][selector:u32] (20 bytes).
    // VERIFIED against jmurth1234/t2-touchid-linux's t2-aks-tool.c: this
    // matches its plain get_device_state() exactly (also opcode 0x19,
    // no session field). That source also has a get-device-state-v1
    // variant on the SAME opcode 0x19 with a different, 24-byte,
    // session-bearing body (codec_version, session, handle, selector) —
    // not implemented here; don't confuse the two if extending this call.
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
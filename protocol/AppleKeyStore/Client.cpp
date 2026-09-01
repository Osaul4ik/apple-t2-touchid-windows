// SPDX-License-Identifier: GPL-2.0-only
// Client.cpp
#include "Client.h"
#include "../../driver/T2TouchIdTransport/public.h"
#include <setupapi.h>
#include <string>
#pragma comment(lib, "setupapi.lib")

namespace t2::applekeystore {

static std::optional<std::wstring> FindDevicePath() {
    HDEVINFO devInfo = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devInfo == INVALID_HANDLE_VALUE) return std::nullopt;

    SP_DEVICE_INTERFACE_DATA ifData{};
    ifData.cbSize = sizeof(ifData);
    if (!SetupDiEnumDeviceInterfaces(devInfo, nullptr, &GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT, 0, &ifData)) {
        SetupDiDestroyDeviceInfoList(devInfo);
        return std::nullopt;
    }

    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, nullptr, 0, &requiredSize, nullptr);
    std::vector<uint8_t> buf(requiredSize);
    auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buf.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

    std::optional<std::wstring> result;
    if (SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, detail, requiredSize, nullptr, nullptr)) {
        result = std::wstring(detail->DevicePath);
    }
    SetupDiDestroyDeviceInfoList(devInfo);
    return result;
}

AksResult Client::Open() {
    // Milestone 2B §10: a repeated Open() call on an already-open Client
    // must not leak the previous handle - close it first so this is a
    // reconnect, not a leak.
    Close();

    auto path = FindDevicePath();
    if (!path) return AksResult::DeviceNotFound;

    handle_ = CreateFileW(path->c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, 0, nullptr);
    return (handle_ != INVALID_HANDLE_VALUE) ? AksResult::Ok : AksResult::DeviceNotFound;
}

void Client::Close() {
    if (handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
}

AksResult Client::GetStatus(bool* pciPresent, bool* bar4Mapped, bool* oolRegistered, bool* mailboxAccessible) {
    T2_TRANSPORT_STATUS status{};
    DWORD returned = 0;
    if (!DeviceIoControl(handle_, IOCTL_T2_GET_STATUS, nullptr, 0, &status, sizeof(status), &returned, nullptr)) {
        return AksResult::IoError;
    }
    *pciPresent = status.PciPresent;
    *bar4Mapped = status.Bar4Mapped;
    *oolRegistered = status.OolRegistered;
    *mailboxAccessible = status.MailboxAccessible;
    return AksResult::Ok;
}

AksResult Client::RegisterOol() {
    DWORD returned = 0;
    if (!DeviceIoControl(handle_, IOCTL_T2_REGISTER_OOL, nullptr, 0, nullptr, 0, &returned, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_NOT_READY) return AksResult::NotReady;
        return AksResult::IoError;
    }
    return AksResult::Ok;
}

AksResult Client::Exchange(uint8_t operation, const std::vector<uint8_t>& request,
                            std::vector<uint8_t>* response, int8_t* outSepStatus) {
    if (outSepStatus) {
        *outSepStatus = 0;
    }
    std::vector<uint8_t> in(sizeof(T2_AKS_EXCHANGE_IN) + request.size(), 0);
    auto* inHeader = reinterpret_cast<T2_AKS_EXCHANGE_IN*>(in.data());
    inHeader->Operation = operation;
    if (!request.empty()) {
        std::memcpy(in.data() + sizeof(T2_AKS_EXCHANGE_IN), request.data(), request.size());
    }

    constexpr size_t kResponseBodyCap = 4096; // local cap; response resized to actual length below
    std::vector<uint8_t> out(sizeof(T2_AKS_EXCHANGE_OUT) + kResponseBodyCap, 0);

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(handle_, IOCTL_T2_AKS_EXCHANGE,
        in.data(), static_cast<DWORD>(in.size()),
        out.data(), static_cast<DWORD>(out.size()), &returned, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) return AksResult::AccessDenied;
        if (err == ERROR_NOT_READY) return AksResult::NotReady;
        return AksResult::IoError;
    }

    auto* outHeader = reinterpret_cast<const T2_AKS_EXCHANGE_OUT*>(out.data());
    size_t responseLength = outHeader->ResponseLength;
    if (sizeof(T2_AKS_EXCHANGE_OUT) + responseLength > out.size()) {
        return AksResult::IoError; // defensive: driver must never claim more than our capacity
    }

    // SepStatus != 0 means SEP itself rejected the operation (e.g. invalid
    // handle) - the IOCTL still succeeded as a transport-level exchange, so
    // this is reported via outSepStatus, not as an AksResult error. The
    // driver guarantees ResponseLength==0 in that case (akstore.c).
    if (outSepStatus) {
        *outSepStatus = outHeader->SepStatus;
    }

    response->assign(out.begin() + sizeof(T2_AKS_EXCHANGE_OUT),
                      out.begin() + sizeof(T2_AKS_EXCHANGE_OUT) + responseLength);
    return AksResult::Ok;
}

AksResult Client::LoadKeybag(const std::vector<uint8_t>& bagBytes, int32_t* outHandle,
                            uint64_t session, int8_t* outSepStatus) {
    // VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux, t2-aks-tool.c
    // load_keybag): request body is [result:u32le=0][session:u64le]
    // [size:u32le=unpadded bag length] followed by the bag bytes
    // themselves padded to a 4-byte boundary (the padding bytes are NOT
    // reflected in the size field). session default (1) matches what the
    // project's actual production loader (src/t2-keybag-load.sh,
    // `SESSION=1`) passes to this exact call on real hardware — see the
    // "session" doc in Client.h.
    constexpr size_t kHeaderSize = 4 + 8 + 4;
    size_t paddedSize = (bagBytes.size() + 3) & ~size_t(3);

    std::vector<uint8_t> req(kHeaderSize + paddedSize, 0);
    uint32_t resultField = 0;
    uint32_t size = static_cast<uint32_t>(bagBytes.size());
    std::memcpy(req.data() + 0, &resultField, 4);
    std::memcpy(req.data() + 4, &session, 8);
    std::memcpy(req.data() + 12, &size, 4);
    if (!bagBytes.empty()) {
        std::memcpy(req.data() + kHeaderSize, bagBytes.data(), bagBytes.size());
    }

    std::vector<uint8_t> response;
    AksResult r = Exchange(static_cast<uint8_t>(T2AksOpLoadKeybag), req, &response, outSepStatus);
    if (r != AksResult::Ok) return r;
    if (outSepStatus && *outSepStatus != 0) return AksResult::Ok; // transport ok, SEP rejected — response body is empty
    if (response.size() < 8) return AksResult::IoError;
    std::memcpy(outHandle, response.data() + 4, 4); // status:u32 | handle:i32
    return AksResult::Ok;
}

AksResult Client::MakeSystemKeybag(int32_t handle, int32_t specialUserBag,
                                    uint64_t session, int8_t* outSepStatus) {
    // VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux, t2-aks-tool.c
    // set_system_keybag): exact 24-byte request body —
    // [result:u32le=0][session:u64le][handle:u32le][special:i32le]
    // [trailing empty blob length:u32le=0]. session default (1) matches
    // src/t2-keybag-load.sh, which passes the same SESSION=1 it used for
    // load-keybag into this call too — see Client.h. The Linux tool never
    // sends anything after byte 24 for this operation: "the final empty
    // blob is encoded as a zero length word at +20".
    std::vector<uint8_t> req(24, 0);
    uint32_t resultField = 0;
    uint32_t handleField = static_cast<uint32_t>(handle);
    uint32_t specialField = static_cast<uint32_t>(specialUserBag);
    uint32_t trailingBlobLength = 0;
    std::memcpy(req.data() + 0, &resultField, 4);
    std::memcpy(req.data() + 4, &session, 8);
    std::memcpy(req.data() + 12, &handleField, 4);
    std::memcpy(req.data() + 16, &specialField, 4);
    std::memcpy(req.data() + 20, &trailingBlobLength, 4);

    std::vector<uint8_t> response;
    AksResult r = Exchange(static_cast<uint8_t>(T2AksOpMakeSystemKeybag), req, &response, outSepStatus);
    if (r != AksResult::Ok) return r;
    if (outSepStatus && *outSepStatus != 0) return AksResult::Ok; // transport ok, SEP rejected — response body is empty
    if (response.size() < 4) return AksResult::IoError; // status:u32, VERIFIED FROM SOURCE
    uint32_t status = 0;
    std::memcpy(&status, response.data(), 4);
    return (status == 0) ? AksResult::Ok : AksResult::IoError;
}

AksResult Client::Unlock(int32_t handle, std::vector<uint8_t>& secretUtf8, uint64_t session) {
    // VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux, t2-aks-tool.c
    // unlock_keybag): the secret blob is padded to a 4-byte boundary on
    // the wire; secretLen still records the true, unpadded length, and
    // the pad bytes themselves are zero. session default (1) matches
    // README.md's documented manual unlock step (`unlock-keybag 1
    // HANDLE`) — see Client.h.
    size_t paddedSecretLen = (secretUtf8.size() + 3) & ~size_t(3);

    std::vector<uint8_t> req;
    req.reserve(4 + 8 + 4 + 4 + paddedSecretLen);
    uint32_t resultField = 0;
    uint32_t lockState = 0; // 0 = unlock
    uint32_t secretLen = static_cast<uint32_t>(secretUtf8.size());

    auto append = [&req](const void* p, size_t n) {
        auto* b = static_cast<const uint8_t*>(p);
        req.insert(req.end(), b, b + n);
    };
    append(&resultField, 4);
    append(&session, 8);
    append(&handle, 4);
    append(&lockState, 4);
    append(&secretLen, 4);
    append(secretUtf8.data(), secretUtf8.size());
    req.resize(req.size() + (paddedSecretLen - secretUtf8.size()), 0); // zero pad

    // Zero the caller's buffer and our local copy before returning,
    // regardless of success/failure (Milestone 2 §10, §24; Milestone 2B
    // §10 "zeroize the full actually-used sensitive buffer capacity, not
    // just size"). std::vector may have allocated more storage than
    // size() reports (e.g. the caller reserved/grew it before handing it
    // to us) - zeroing only up to size() would leave the secret bytes
    // sitting in that extra, still-allocated-but-"unused" capacity where
    // this function would never touch them again. uint8_t is trivial, so
    // writing zero bytes out to capacity() is well-defined even though
    // those bytes are past size().
    std::vector<uint8_t> response;
    AksResult r = Exchange(static_cast<uint8_t>(T2AksOpChangeLockState), req, &response);

    SecureZeroMemory(req.data(), req.capacity());
    SecureZeroMemory(secretUtf8.data(), secretUtf8.capacity());
    secretUtf8.clear();

    return r;
}

AksResult Client::GetCapabilities(uint64_t selector, uint64_t* outValue) {
    // VERIFIED FROM SOURCE (t2-aks-tool.c capabilities): 16-byte request —
    // [result:u32le=0][selector:u64le][reserved:u32le=0]. Response is
    // status:u32 at offset 0, value:u64 at offset 4; the tool additionally
    // requires >=16 response bytes even though only 12 are read, so this
    // client mirrors that same defensive minimum.
    std::vector<uint8_t> req(16, 0);
    uint32_t resultField = 0;
    std::memcpy(req.data() + 0, &resultField, 4);
    std::memcpy(req.data() + 4, &selector, 8);

    std::vector<uint8_t> response;
    AksResult r = Exchange(static_cast<uint8_t>(T2AksOpGetCapabilities), req, &response);
    if (r != AksResult::Ok) return r;
    if (response.size() < 16) return AksResult::IoError;
    uint32_t status = 0;
    std::memcpy(&status, response.data(), 4);
    if (status != 0) return AksResult::IoError;
    std::memcpy(outValue, response.data() + 4, 8); // status:u32 | value:u64
    return AksResult::Ok;
}


AksResult Client::GetDeviceState(int64_t handle, uint32_t selector,
                                 std::vector<uint8_t>* responseBody,
                                 int8_t* outSepStatus) {
    // VERIFIED FROM SOURCE (jmurth1234/t2-touchid-linux, t2-aks-tool.c
    // get_device_state — the plain variant, not get-device-state-v1):
    // 20-byte request [result:u32le=0][handle:u64le][selector:u32le], no
    // session field. Same V2 transport as every other allow-listed op —
    // useful differential vs 0x4d.
    std::vector<uint8_t> req(20, 0);
    uint32_t resultField = 0;
    uint64_t handleU = static_cast<uint64_t>(handle);
    std::memcpy(req.data() + 0, &resultField, 4);
    std::memcpy(req.data() + 4, &handleU, 8);
    std::memcpy(req.data() + 12, &selector, 4);

    std::vector<uint8_t> response;
    AksResult r = Exchange(static_cast<uint8_t>(T2AksOpGetDeviceState), req, &response, outSepStatus);
    if (r != AksResult::Ok) return r;
    // A nonzero SEP status (e.g. handle not found/loaded) means `response`
    // is empty by contract (akstore.c) - hand that back as-is rather than
    // treating it as a short/invalid response; the caller checks outSepStatus.
    if (responseBody) *responseBody = std::move(response);
    return AksResult::Ok;
}

} // namespace t2::applekeystore
// SPDX-License-Identifier: GPL-2.0-only
// SepVaultFormat.h
//
// On-disk layout written by SepVaultGui and read here. Deliberately NOT a
// project-wide "protocol" format (it never touches the SEP/BridgeXPC wire) —
// this is purely local secret storage, so it lives next to its only reader.
//
// Every multi-byte field is little-endian (native x64), which is also what
// System.IO.BinaryWriter produces on the .NET side — the two must agree on
// this without a shared header, so change both sides together if this ever
// changes.
//
//   offset  size  field
//   0       8     magic            "T2SEPV1\0"
//   8       4     version          uint32, currently 1
//   12      4     specialUserBag   int32 (e.g. -501)
//   16      4     keybagLen        uint32 — length of the DPAPI-protected
//                                  keybag blob that follows
//   20      4     passwordLen      uint32 — length of the DPAPI-protected
//                                  password blob that follows
//   24      *     keybagBlob       CRYPTPROTECT_LOCAL_MACHINE output over the
//                                  raw user.kb bytes
//   24+N    *     passwordBlob     CRYPTPROTECT_LOCAL_MACHINE output over the
//                                  UTF-8 password bytes
//
// Both blobs are opaque CryptProtectData() output — this file never sees
// plaintext key material, only what CryptUnprotectData() hands back after
// the service unwraps them at Start() time.

#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <fstream>

namespace t2::sepvault {

constexpr char kMagic[8] = {'T','2','S','E','P','V','1','\0'};
constexpr uint32_t kVersion = 1;

struct VaultReadResult {
    bool ok = false;
    int32_t specialUserBag = 0;
    std::vector<uint8_t> protectedKeybag;
    std::vector<uint8_t> protectedPassword;
};

// Reads and structurally validates the container. Does NOT call
// CryptUnprotectData — that happens in the service's Start(), inside the
// scope that will zero the result, so this function never holds plaintext.
inline VaultReadResult ReadVaultFile(const std::wstring& path) {
    VaultReadResult result;

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return result; // ok=false: missing/unreadable — caller logs, doesn't guess
    }

    char magic[8] = {};
    f.read(magic, sizeof(magic));
    if (!f || memcmp(magic, kMagic, sizeof(kMagic)) != 0) {
        return result; // wrong file or corrupted — fail closed, no partial parse
    }

    uint32_t version = 0;
    f.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (!f || version != kVersion) {
        return result;
    }

    int32_t specialUserBag = 0;
    uint32_t keybagLen = 0, passwordLen = 0;
    f.read(reinterpret_cast<char*>(&specialUserBag), sizeof(specialUserBag));
    f.read(reinterpret_cast<char*>(&keybagLen), sizeof(keybagLen));
    f.read(reinterpret_cast<char*>(&passwordLen), sizeof(passwordLen));
    if (!f) {
        return result;
    }

    // Sanity bounds — a corrupted/truncated length field must not turn into
    // a multi-gigabyte allocation attempt. user.kb is documented elsewhere
    // in this repo as 1..16000 bytes before DPAPI overhead; DPAPI's own
    // overhead is small (tens of bytes), so 64 KiB is generous headroom for
    // the keybag blob. The password blob has no legitimate reason to be
    // large either.
    constexpr uint32_t kMaxBlob = 64 * 1024;
    if (keybagLen == 0 || keybagLen > kMaxBlob ||
        passwordLen == 0 || passwordLen > kMaxBlob) {
        return result;
    }

    std::vector<uint8_t> keybagBlob(keybagLen);
    std::vector<uint8_t> passwordBlob(passwordLen);
    f.read(reinterpret_cast<char*>(keybagBlob.data()), keybagLen);
    f.read(reinterpret_cast<char*>(passwordBlob.data()), passwordLen);
    if (!f) {
        return result;
    }

    result.ok = true;
    result.specialUserBag = specialUserBag;
    result.protectedKeybag = std::move(keybagBlob);
    result.protectedPassword = std::move(passwordBlob);
    return result;
}

} // namespace t2::sepvault
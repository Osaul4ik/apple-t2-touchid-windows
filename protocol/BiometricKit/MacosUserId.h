// SPDX-License-Identifier: GPL-2.0-only
// MacosUserId.h
//
// Single source of truth for "which macOS user id's fingerprints do we match".
//
// Before this header the id was hardcoded to 501 in three places (UMDF driver
// kDefaultMacosUserId, CLI identities/warmup/verify defaults, VerifyConfig), so
// entering special bag -502 (GUI "Special bag ID", `set-system-keybag`,
// `unlock -502`, or the vault read by T2SepBootstrap) unlocked the SEP for user
// 502 but the identity list / match was still filtered for 501 -> "enrolled
// identities: 0" and no match.
//
// The special user bag of the SEP IS the negated macOS uid (bag -501 <-> uid
// 501, bag -502 <-> uid 502), so the uid is derived from the bag the user
// enters and persisted here:
//   HKLM\SOFTWARE\T2TouchIdBio\MacosUserId  (REG_DWORD, missing = 501)
// Writers: T2SepBootstrap service (from the vault, every start), SepVault GUI
// (on Save), t2touchid.exe set-system-keybag / unlock <-bag>.
// Readers: UMDF driver (Queue.cpp), t2touchid.exe identities/warmup/verify
// (an explicit --uid N still wins).

#pragma once
#include <windows.h>
#include <cstdint>

namespace t2::biometrickit {

inline constexpr uint32_t kDefaultMacosUserId = 501;
inline constexpr wchar_t kMacosUserIdRegKey[] = L"SOFTWARE\\T2TouchIdBio";
inline constexpr wchar_t kMacosUserIdRegValue[] = L"MacosUserId";

// Special user bag (negative AKS bag id) -> macOS uid. Returns false for a
// non-negative value (that is a keybag handle / not a special bag) so callers
// never persist a bogus uid.
inline bool MacosUserIdFromSpecialBag(int32_t specialUserBag, uint32_t* outUid) {
    if (specialUserBag >= 0 || specialUserBag == INT32_MIN) return false;
    *outUid = static_cast<uint32_t>(-static_cast<int64_t>(specialUserBag));
    return true;
}

// Raw (uncached) read; missing value / 0 -> kDefaultMacosUserId.
inline uint32_t LoadConfiguredMacosUserId() {
    DWORD v = 0;
    DWORD cb = sizeof(v);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kMacosUserIdRegKey, kMacosUserIdRegValue,
                     RRF_RT_REG_DWORD, nullptr, &v, &cb) != ERROR_SUCCESS || v == 0) {
        return kDefaultMacosUserId;
    }
    return static_cast<uint32_t>(v);
}

// Needs write access to HKLM (service = SYSTEM, CLI/GUI = Administrator).
inline bool SaveConfiguredMacosUserId(uint32_t uid) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kMacosUserIdRegKey, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const DWORD v = uid;
    const LSTATUS rc = RegSetValueExW(key, kMacosUserIdRegValue, 0, REG_DWORD,
                                      reinterpret_cast<const BYTE*>(&v), sizeof(v));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

// Convenience for writers: derive from the special bag and persist.
inline bool PersistMacosUserIdFromSpecialBag(int32_t specialUserBag, uint32_t* outUid = nullptr) {
    uint32_t uid = 0;
    if (!MacosUserIdFromSpecialBag(specialUserBag, &uid)) return false;
    if (outUid) *outUid = uid;
    return SaveConfiguredMacosUserId(uid);
}

}
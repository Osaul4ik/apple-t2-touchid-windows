// SPDX-License-Identifier: GPL-2.0-only
// NativeVerdict.h - when is a native-IPv6 attempt that got NO usable answer ("silent":
// no SYN-ACK and no RST from any probed port) allowed to be called "IPv6 blocked", i.e.
// to send discovery to the IPv4 tunnel?
//
// Pure logic, no Win32: unit-tested in tests/ProtocolTests.cpp.
//
// Why it exists: on a cold boot or right after a resume the T2's NCM link is up several
// seconds BEFORE its TCP service answers, and that looks exactly like a filtered path
// (a silent scan). Reading it as "blocked" sends the very next step to the IPv4 tunnel,
// which can commit the sticky tunnel until reboot although IPv6 would have worked a
// moment later. The two cases are told apart with an independent L3 proof of life:
//
//   - a local WFP block (WSAEACCES on connect) is a definitive verdict, never held back;
//   - silent, and the T2 does NOT answer an ICMPv6 echo either -> the IPv6 path really
//     looks dead (VPN filter dropping IPv6): Blocked, tunnel allowed - the old behavior;
//   - silent, but the T2 answers ICMPv6 echo -> the IPv6 path works and only the T2
//     service is not up yet: HoldNative (stay on native, retry), but only for a bounded
//     grace, so a filter that drops TCP and lets ICMPv6 through still reaches the tunnel;
//   - graceMs == 0 switches the hold off completely (exactly the old behavior).
#pragma once
#include <cstdint>

namespace t2::discovery {

enum class NativeSilenceVerdict {
    Blocked,    // treat IPv6 as unusable for this attempt: the tunnel may be tried
    HoldNative, // the T2 is alive over IPv6, its service is just not up: keep native
};

struct NativeSilenceEvidence {
    bool wfpBlocked = false;        // WSAEACCES seen on connect: local WFP block filter
    bool icmpAlive = false;         // the peer answered an ICMPv6 echo just now
    uint64_t silentForMs = 0;       // since the T2 first answered ICMPv6 while TCP stayed silent (0 = now)
    uint64_t graceMs = 0;           // 0 = never hold
};

inline NativeSilenceVerdict JudgeNativeSilence(const NativeSilenceEvidence& e) {
    if (e.wfpBlocked) return NativeSilenceVerdict::Blocked;
    if (!e.icmpAlive) return NativeSilenceVerdict::Blocked;
    if (e.graceMs == 0) return NativeSilenceVerdict::Blocked;
    return e.silentForMs < e.graceMs ? NativeSilenceVerdict::HoldNative
                                     : NativeSilenceVerdict::Blocked;
}

} // namespace t2::discovery
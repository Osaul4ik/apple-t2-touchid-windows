// SPDX-License-Identifier: GPL-2.0-only
// public.h
// Public IOCTL interface exposed by T2Ncm.sys — Task 25's diagnostic
// milestone. Mirrors T2TouchIdTransport's public.h (same GUID pattern,
// same METHOD_BUFFERED/inline-payload rationale). Deliberately read-only:
// this is a status query, not a control surface — negotiation is driven
// entirely by D0Entry (Device.c), never by a user-mode request, so there
// is no equivalent of T2TouchIdTransport's IOCTL_T2_REGISTER_OOL here.
//
// Purpose (per docs/T2Ncm-Architecture.md sequencing note): let Tasks
// 7-12 (NCM control-plane negotiation, MI_01 activation) be validated on
// real hardware — real negotiated sizes, a real decoded MAC, a real
// lifecycle state — before any RX/TX/NDIS wire code (Tasks 13+) is
// written against them.

#pragma once

#include <initguid.h>

// {32401F84-3D34-43AD-94B5-D0B8CF033DB0}
DEFINE_GUID(GUID_DEVINTERFACE_T2NCM,
    0x32401f84, 0x3d34, 0x43ad, 0x94, 0xb5, 0xd0, 0xb8, 0xcf, 0x03, 0x3d, 0xb0);

// Mirrors T2NCM_LIFECYCLE_STATE (Driver.h) numerically so a user-mode
// tool doesn't need the kernel header — but this enum is intentionally
// declared separately (not shared) so a Driver.h reorder can never
// silently change the wire values a released diagnostic tool depends on.
typedef enum _T2NCM_WIRE_STATE
{
    T2NcmWireStateCreated = 0,
    T2NcmWireStatePrepared,
    T2NcmWireStateUsbReady,
    T2NcmWireStateNcmReady,
    T2NcmWireStateNdisRegistered,
    T2NcmWireStateRunning,
    T2NcmWireStateStopping,
    T2NcmWireStateReleased,
} T2NCM_WIRE_STATE;

#pragma pack(push, 1)
typedef struct _T2NCM_STATUS
{
    UINT32  LifecycleState;        // one of T2NCM_WIRE_STATE

    // Tasks 7-11 (NcmProtocol.c) — all zero/FALSE until GET_NTB_PARAMETERS
    // + SET_NTB_FORMAT(NTB16) + SET_NTB_INPUT_SIZE have all succeeded at
    // least once. Never a guessed or default-filled value.
    BOOLEAN Ntb16Supported;
    UINT8   Reserved0[3];
    UINT32  NtbInMaxSize;
    UINT32  NtbOutMaxSize;

    // Task 8 — FALSE until a real 12-hex-char iMACAddress string was
    // decoded and passed the all-zero/all-FF sentinel check.
    BOOLEAN MacAddressValid;
    UINT8   MacAddress[6];         // meaningful only if MacAddressValid

    // Was Reserved1. MacAddressValid alone no longer means "hardware
    // address" — on units with no usable MAC string at all (confirmed
    // real on REV_0201), T2NcmEnsureMacAddress hands NDIS a generated
    // locally-administered address instead of none. This flag is TRUE
    // only for the former (real, device-reported) case; a user-mode
    // tool built against an older version of this header that still
    // treats this byte as reserved is unaffected — it was always
    // zero-filled, and MacAddressIsPermanent==FALSE there simply reads
    // as "not confirmed permanent", never as a fabricated positive.
    BOOLEAN MacAddressIsPermanent;

    // Task 12 — MI_01 switched to alt 1 and both bulk pipes discovered.
    BOOLEAN DataInterfaceActive;
    UINT8   Reserved2[3];

    // Task 14-15 (NcmRx.c) — diagnostic-only RX counters and a snapshot
    // of the most recently parsed frame. All zero until at least one
    // NTB has been received on the bulk-IN pipe. Frames are validated
    // and counted here but NOT yet indicated to NDIS (Tasks 18-20 don't
    // exist yet) — this field set exists purely to prove the NTB16/
    // NDP16 parser against real device traffic, same role
    // IOCTL_T2NCM_GET_STATUS already played for the control plane.
    UINT64  RxNtbsReceived;
    UINT64  RxFramesParsed;
    UINT64  RxFramesRejected;
    UINT8   RxLastFrameDest[6];
    UINT8   RxLastFrameSrc[6];
    UINT16  RxLastFrameEtherType;   // host byte order (already converted
                                      // from network byte order on read)
    UINT16  RxLastFrameLength;

    // Task 13/16 (NcmTx.c) — diagnostic-only TX counters, populated by
    // IOCTL_T2NCM_SEND_TEST_FRAME calls. All zero until at least one
    // test frame has been sent.
    UINT64  TxNtbsSent;
    UINT64  TxFramesSent;
    UINT64  TxFramesRejected;
} T2NCM_STATUS, *PT2NCM_STATUS;
#pragma pack(pop)

#define IOCTL_T2NCM_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS)

// Task 13/16 diagnostic milestone — same rationale as
// IOCTL_T2NCM_GET_STATUS existing for the control plane and RX: there
// is no NDIS miniport yet (Tasks 18-20) to originate outgoing frames,
// so this lets a user-mode tool hand the driver one raw Ethernet II
// frame (14-1514 bytes, no FCS) in the input buffer and have it
// wrapped in a single-datagram NTB16 and written to the bulk-OUT pipe.
// No output buffer — success/failure is the completion status alone;
// a user-mode tool wanting frame-level confirmation should capture on
// the receiving end (the Mac) rather than trust a driver-side
// "it left the pipe" signal, which IOCTL_T2NCM_GET_STATUS's
// RxFramesParsed/TxFramesSent counters already give without needing an
// output struct here.
#define IOCTL_T2NCM_SEND_TEST_FRAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)
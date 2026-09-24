// SPDX-License-Identifier: GPL-2.0-only
// public.h
// Public diagnostic interface exposed by T2Ncm.sys. Deliberately
// read-only apart from the test-frame injector: this is a status query,
// not a control surface — the control plane is brought up by
// MiniportInitializeEx and OID_PNP_SET_POWER (Power.c), never by a
// user-mode request.
//
// HOW THIS IS REACHED (changed with the NDIS revision): T2Ncm.sys is an
// NDIS miniport driver, so it has no WDF I/O queue and no
// WdfDeviceCreateDeviceInterface — a WdfDeviceMiniportCreate device
// never sees an IRP. The device object below is created with
// NdisMRegisterDeviceEx instead, which is the documented way for a
// miniport to expose an IOCTL surface, and reached through the symbolic
// link \\.\T2Ncm rather than through a device interface GUID.
// GUID_DEVINTERFACE_T2NCM is retained only so an existing tool built
// against the old header still compiles; it no longer resolves to
// anything.
//
// Purpose: let the NCM control plane, the NTB16 parser/builder and the
// inverted power model be checked against real hardware without
// attaching a kernel debugger — real negotiated sizes, a real decoded
// MAC, a real lifecycle state, and (new) the two halves of the power
// model side by side.

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

    // NcmRx.c — RX counters and a snapshot of the most recently parsed
    // frame. All zero until at least one NTB has been received on the
    // bulk-IN pipe. These count what the PARSER did; RxFramesIndicated
    // (below) counts what actually reached NDIS, and the difference
    // between the two is the useful signal.
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

    // ---- Added with the NDIS miniport / power-inversion revision ----
    // Appended at the END of the struct on purpose: a tool built against
    // the previous header asks for the previous (smaller) size, and the
    // driver copies min(requested, sizeof) bytes, so every field it does
    // know keeps its offset and meaning.

    // Frames that were parsed out of an NTB AND handed to NDIS. The gap
    // between RxFramesParsed and this is frames the parser accepted but
    // the driver dropped before indication — paused data path, packet
    // filter, or NBL allocation failure. That distinction is the first
    // thing worth knowing when "the NIC is up but nothing arrives".
    UINT64  RxFramesIndicated;

    // What NDIS last told the driver via OID_PNP_SET_POWER. Values match
    // NDIS_DEVICE_POWER_STATE: 0 = Unspecified, 1 = D0, 2..5 = D1..D3.
    // NDIS owns this; the driver only reacts to it.
    UINT32  PowerState;

    // What MiniportPause (FALSE) / MiniportRestart (TRUE) last set. The
    // driver never sets this itself — that is the whole point of the
    // inverted model, and these two fields disagreeing (a running data
    // path at a non-D0 power state, say) is how a regression in it would
    // show up from user mode.
    BOOLEAN DataPathRunning;

    // TRUE once NdisMSetMiniportAttributes has succeeded, i.e. an
    // adapter actually exists. FALSE during initialization and after
    // halt.
    BOOLEAN NdisAdapterReady;
    UINT8   Reserved3[2];

    // What MiniportPause has to wait for before it may report success:
    // NBLs indicated and not yet returned, and bulk-OUT writes submitted
    // and not yet completed. Both should be 0 whenever DataPathRunning
    // is FALSE; a non-zero value there means a drain did not complete.
    UINT32  OutstandingRxNbls;
    UINT32  OutstandingTxRequests;

    // ---- Added with the SET_ETHERNET_PACKET_FILTER fix ----
    // Appended, like the block above, so an older tool keeps every
    // offset it already knows.

    // The CDC-level filter (ECM 1.2 6.2.4 bitmap: 0x01 PROMISCUOUS,
    // 0x02 ALL_MULTICAST, 0x04 DIRECTED, 0x08 BROADCAST, 0x10
    // MULTICAST) last accepted by the device, and whether the device is
    // currently holding it. This is the one that decides whether the T2
    // sends anything to the host at all; a zero here with the adapter
    // otherwise healthy means RX will be exactly zero bytes.
    UINT16  CdcPacketFilter;
    BOOLEAN CdcPacketFilterApplied;
    UINT8   Reserved5;

    // Frames the NTB parser accepted and the driver's software filter
    // then discarded. Reading this next to RxFramesParsed and
    // RxFramesIndicated says which of the three possible silences you
    // have: nothing arriving (all three zero), arriving and dropped by
    // us (Parsed high, Filtered high), or arriving and delivered
    // (Indicated high).
    UINT64  RxFramesFiltered;

    // Times MiniportPause/Halt drain waited 5s and still had outstanding
    // RX NBLs or TX requests. Non-zero after sleep/resume cycles points
    // at a reference leak (pool free is then skipped to avoid bugcheck).
    UINT32  DrainTimeoutCount;
    UINT8   Reserved6[4];
} T2NCM_STATUS, *PT2NCM_STATUS;
#pragma pack(pop)

#define IOCTL_T2NCM_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS)

// Lets a user-mode tool hand the driver one raw Ethernet II frame
// (14-1514 bytes, no FCS) in the input buffer and have it wrapped in a
// single-datagram NTB16 and written to the bulk-OUT pipe, bypassing the
// TCP/IP stack entirely. Kept now that the miniport exists because
// putting a KNOWN frame on the wire is still the cleanest way to tell a
// TX-path problem apart from a binding/configuration one.
//
// Requires the adapter to be both armed AND restarted by NDIS: a frame
// injected at a paused adapter would be the driver using the hardware
// on its own schedule, which is exactly what the inverted power model
// exists to prevent.
// No output buffer — success/failure is the completion status alone;
// a user-mode tool wanting frame-level confirmation should capture on
// the receiving end (the Mac) rather than trust a driver-side
// "it left the pipe" signal, which IOCTL_T2NCM_GET_STATUS's
// RxFramesParsed/TxFramesSent counters already give without needing an
// output struct here.
#define IOCTL_T2NCM_SEND_TEST_FRAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// NT symbolic link the diagnostic device is reachable through. Created
// by NdisMRegisterDeviceEx in NdisMiniport.c; open it with
// CreateFile("\\\\.\\T2Ncm", ...).
#define T2NCM_DOS_DEVICE_NAME  L"\\DosDevices\\T2Ncm"
#define T2NCM_NT_DEVICE_NAME   L"\\Device\\T2Ncm"
#define T2NCM_USER_DEVICE_PATH L"\\\\.\\T2Ncm"
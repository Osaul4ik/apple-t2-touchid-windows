// SPDX-License-Identifier: GPL-2.0-only
// Driver.h
// T2Ncm.sys — NDIS 6.30 miniport driver for the Apple T2's USB CDC-NCM
// data interface (MI_01), with KMDF used *only* as a USB client library.
//
// ======================================================================
// POWER-MANAGEMENT INVERSION (this revision)
// ======================================================================
// Previously this driver was a KMDF function driver that owned the PnP/
// power policy for MI_01 and was going to bolt an NDIS miniport onto the
// side of it: EvtDevicePrepareHardware created the USB target,
// EvtDeviceD0Entry negotiated NCM and started the RX engine, and
// EvtDeviceD0Exit stopped it. NDIS would have been a passenger on a
// WDF-owned power state machine.
//
// That is backwards for a network adapter, and Microsoft's own guidance
// for NDIS miniports says so:
//
//   * NDIS — not the driver, and not KMDF — is the power policy owner of
//     a miniport adapter. It is NDIS that decides when the adapter goes
//     to a low-power state, and NDIS that owns the ordering around it.
//   * Before ANY low-power transition, NDIS *pauses* the miniport
//     (MiniportPause) and only then sends OID_PNP_SET_POWER. After
//     returning to D0, NDIS sends OID_PNP_SET_POWER(D0) and only then
//     *restarts* the miniport (MiniportRestart).
//   * Therefore the data path must be owned by Pause/Restart, and the
//     hardware D-state by OID_PNP_SET_POWER — never by a driver-private
//     D0Entry/D0Exit that runs on its own schedule underneath NDIS.
//
// So control is inverted: NDIS drives this driver, this driver drives
// KMDF. Concretely:
//
//   DriverEntry
//       WdfDriverCreate(WdfDriverInitNoDispatchOverride) — WDF does NOT
//         take over the driver object's dispatch table and does NOT get
//         an EvtDeviceAdd. It exists purely so we can use WDFUSBDEVICE /
//         WDFUSBPIPE below an NDIS miniport.
//       NdisMRegisterMiniportDriver — NDIS owns PnP and power from here.
//
//   MiniportInitializeEx   (was EvtDevicePrepareHardware + D0Entry)
//       WdfDeviceMiniportCreate over the FDO/next/PDO NDIS hands us,
//       create the USB target, negotiate the NCM control plane, switch
//       MI_01 to alt 1, then NdisMSetMiniportAttributes.
//       The adapter is left PAUSED — no RX, no TX. That is the NDIS
//       contract, and it is exactly the inversion: initialization no
//       longer starts the data path.
//
//   MiniportRestart        (new owner of "start the data path")
//   MiniportPause          (new owner of "stop the data path and drain")
//   OID_PNP_SET_POWER      (new owner of the D-state: quiesce to alt 0 on
//                           Dx, re-arm the control plane on D0)
//   MiniportHaltEx         (was EvtDeviceReleaseHardware)
//
// There are no EvtDeviceD0Entry/EvtDeviceD0Exit callbacks in this driver
// any more. A WDFDEVICE created with WdfDeviceMiniportCreate is not a
// power policy owner and receives no PnP/power callbacks at all — that
// is the mechanism that makes the inversion structural rather than a
// convention someone has to remember.
//
// ======================================================================
// ONE ROLE PER BINARY (changed)
// ======================================================================
// The previous revision shipped ONE .sys under two service names
// ("T2Ncm" on MI_01, "T2NcmCtrlStub" on MI_00) and branched in
// DriverEntry on a global read from RegistryPath. That cannot survive
// the inversion: the two roles now need *incompatible* DriverEntry
// bodies (NDIS registration + no dispatch override vs. a classic KMDF
// PnP driver that must own its dispatch table), and DriverEntry is
// reached at most once per loaded image — a single image cannot be both.
//
// The MI_00 claim is therefore a separate binary, T2NcmCtrl.sys, built
// from CtrlStub.c by T2NcmCtrl.vcxproj. g_T2NcmStubRole is gone.
//
// ======================================================================
// Module layout
// ======================================================================
//   Driver.c        DriverEntry, WDF-in-miniport-mode + NDIS registration
//   NdisMiniport.c  All NDIS entry points: Initialize/Halt/Pause/Restart,
//                    Send/Return, OID handling, PnP-event notify, and the
//                    NdisMRegisterDeviceEx diagnostic control device
//   Device.c        WDFDEVICE (miniport-mode) creation + the lifecycle
//                    state machine + diagnostic IOCTL handlers
//   Power.c         OID_PNP_SET_POWER / OID_PNP_QUERY_POWER handling —
//                    the D-state half of the inverted model
//   UsbTransport.c  USB target/pipe/descriptor discovery
//   NcmProtocol.c   CDC-NCM control plane (GET_NTB_PARAMETERS, format)
//   NcmRx.c         NTB16 RX parser + bulk-IN engine + NDIS indication
//   NcmTx.c         NTB16 TX builder + bulk-OUT engine + NBL send path
//   CtrlStub.c      SEPARATE BINARY (T2NcmCtrl.sys) — MI_00 claim only

#pragma once

// Pin the NDIS contract version before ndis.h is pulled in. 6.30 is the
// Windows 8 / Server 2012 level: it is the oldest version that has
// everything this driver needs (NDIS_PM_CAPABILITIES revision 1, the
// NDIS 6.20+ pause/restart semantics the inversion above relies on) and
// it keeps the same Windows 10 compatibility floor the rest of this
// project targets. Must match NDIS630_MINIPORT in T2Ncm.vcxproj.
#ifndef NDIS630_MINIPORT
#define NDIS630_MINIPORT 1
#endif

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>
#include <usb.h>
#include <usbdlib.h>
#include <wdfusb.h>

// ndis.h itself uses nameless struct/union extensions and trips C4201 at
// /W4; with /WX that becomes a hard error (C2220) even though we didn't
// write the offending code. This is Microsoft's own header, not ours —
// scope the suppression tightly to just this include rather than
// disabling C4201 project-wide.
#pragma warning(push)
#pragma warning(disable: 4201)
#include <ndis.h>
#pragma warning(pop)

// WdfDeviceMiniportCreate and WdfDriverMiniportUnload (used by Device.c,
// Driver.c and NdisMiniport.c) are declared here, not in wdf.h. This is
// the "KMDF-as-USB-client-library-under-an-NDIS-miniport" mode Driver.h
// describes above.
#include <wdfminiport.h>

#include "public.h"

// ---- Logging ----
// Reuses the T2TouchIdTransport convention (see driver/T2TouchIdTransport/driver.h):
// DbgPrintEx, not KdPrintEx, because KdPrintEx compiles to nothing when
// DBG=0 (Release), and this driver ships test-signed Release builds.
#define T2NCM_LOG(_x_) DbgPrintEx _x_
#define T2NCM_DPFLTR_ID DPFLTR_IHVDRIVER_ID

// ---- Device identity (VERIFIED FROM SOURCE: USBPcap descriptor dump) ----
#define T2NCM_VID           0x05ACu
#define T2NCM_PID           0x8233u
#define T2NCM_REV           0x0201u

// ---- Interface roles ----
// T2NCM_CONTROL_IFACE_NUM is only ever used as a wIndex value in
// NcmProtocol.c's SETUP packets — control transfers addressed by
// interface number go over the shared EP0 regardless of which PDO this
// driver instance is actually bound to, so it does NOT require owning
// MI_00's own WDFUSBINTERFACE object.
#define T2NCM_CONTROL_IFACE_NUM   0   // MI_00 — addressed by wIndex only
#define T2NCM_DATA_IFACE_NUM      1   // MI_01 — this driver's real bInterfaceNumber
#define T2NCM_DATA_ALT_IDLE       0   // Alt 0 — 0 endpoints
#define T2NCM_DATA_ALT_ACTIVE     1   // Alt 1 — bulk IN/OUT

// ---- Expected endpoint addresses (VERIFIED FROM SOURCE, discovered
// dynamically per Task 5 — these are cross-checks, not hard-coded truth) ----
#define T2NCM_EXPECTED_BULK_IN_EP   0x82u
#define T2NCM_EXPECTED_BULK_OUT_EP  0x01u

// ---- CDC/NCM class constants ----
#define T2NCM_CLASS_CDC_CONTROL     0x02u
#define T2NCM_SUBCLASS_NCM          0x0Du
#define T2NCM_CLASS_CDC_DATA        0x0Au

// ---- Pool tags ----
#define T2NCM_POOL_TAG              ((ULONG)'TNcm')
#define T2NCM_RX_POOL_TAG           ((ULONG)'RNcm')
#define T2NCM_TX_POOL_TAG           ((ULONG)'XNcm')

// ---- Ethernet / link constants ----
#define T2NCM_MAC_LENGTH            6u
#define T2NCM_ETHERNET_HEADER_SIZE  14u
#define T2NCM_MTU                   1500u
#define T2NCM_MAX_FRAME_SIZE        (T2NCM_ETHERNET_HEADER_SIZE + T2NCM_MTU)  // 1514
#define T2NCM_MAX_MULTICAST_LIST    32u

// The T2's NCM function sits on USB 2.0 high speed (480 Mbit/s) — this
// is the link speed reported to NDIS, not a measured throughput. There
// is no link-speed negotiation on this interface to read a real value
// from, and NDIS requires a non-zero value, so the bus rate is the only
// honest answer available.
#define T2NCM_LINK_SPEED_BPS        480000000ULL

// ---- Lifecycle states / device context ----
// Guard against accidental double inclusion of this block (e.g. a stale
// fat Device.h that still embeds the same typedefs while also #include'ing
// Driver.h — on Windows that yields C2011/C2374 because #pragma once is
// per-path and Device.h vs Driver.h are distinct files).
#ifndef T2NCM_DEVICE_CONTEXT_TYPES_DEFINED
#define T2NCM_DEVICE_CONTEXT_TYPES_DEFINED

// Unchanged names, but the owners have moved with the inversion:
//   Created        WDFDEVICE made (MiniportInitializeEx)
//   Prepared       USB target created + configuration selected
//   UsbReady       ditto, control plane not yet negotiated
//   NcmReady       NTB params negotiated, MI_01 on alt 1
//   NdisRegistered NdisMSetMiniportAttributes done — adapter exists, PAUSED
//   Running        MiniportRestart ran — data path live
//   Stopping       MiniportPause / MiniportHaltEx in progress
//   Released       MiniportHaltEx done, USB objects gone
// All transitions are explicit — see Device.c T2NcmTrySetState().
typedef enum _T2NCM_LIFECYCLE_STATE
{
    T2NcmStateCreated = 0,
    T2NcmStatePrepared,
    T2NcmStateUsbReady,
    T2NcmStateNcmReady,
    T2NcmStateNdisRegistered,
    T2NcmStateRunning,
    T2NcmStateStopping,
    T2NcmStateReleased,
} T2NCM_LIFECYCLE_STATE;

// ---- Device context ----
typedef struct _T2NCM_DEVICE_CONTEXT
{
    WDFDEVICE           WdfDevice;          // WdfDeviceMiniportCreate'd — NOT a PPO
    WDFUSBDEVICE        UsbDevice;
    WDFUSBINTERFACE     DataInterface;      // this PDO's own interface (MI_01)

    WDFUSBPIPE          BulkInPipe;         // 0x82 (alt 1)
    WDFUSBPIPE          BulkOutPipe;        // 0x01 (alt 1)

    // wMaxPacketSize of BulkOutPipe, captured when alt 1 is activated and
    // zeroed whenever the pipes are dropped. The TX builder needs it to
    // keep an NTB from ending exactly on a packet boundary (see
    // T2NcmTxComputeLayout). 0 = unknown, padding disabled.
    ULONG               BulkOutMaxPacketSize;

    T2NCM_LIFECYCLE_STATE State;
    WDFSPINLOCK          StateLock;

    // The single station address. The adapter has no user-settable
    // address (no NetworkAddress override), so the "current" and
    // "permanent" addresses NDIS asks for are always this same value.
    UCHAR                PermanentMacAddress[6];
    BOOLEAN              MacAddressValid;

    // TRUE only when PermanentMacAddress came from a real device string
    // (never today - the device has no hardware MAC). FALSE when T2NcmEnsureMacAddress
    // had to fall back to a generated locally-administered address —
    // MacAddressValid is still TRUE in that case (NDIS has *an*
    // address to use), this just tracks which kind it is so nothing
    // downstream mistakes a generated address for hardware truth.
    BOOLEAN              MacAddressIsPermanent;

    // ---- NDIS ----
    NDIS_HANDLE          MiniportAdapterHandle;   // from MiniportInitializeEx
    NDIS_HANDLE          RxNblPool;               // NET_BUFFER_LIST pool for indications
    NDIS_HANDLE          NdisDeviceHandle;        // NdisMRegisterDeviceEx (diagnostics)
    PDEVICE_OBJECT       ControlDeviceObject;

    // Written by OID_GEN_CURRENT_PACKET_FILTER on one CPU; read by the RX
    // indication path at DISPATCH_LEVEL on others. Access only via the
    // T2NcmRead/WritePacketFilter helpers below (Interlocked, LONG-typed
    // so /WX does not trip C4057 on ULONG* vs LONG*).
    volatile LONG        PacketFilter;

    // The CDC-side filter last successfully pushed to the device with
    // SET_ETHERNET_PACKET_FILTER, and whether that has ever succeeded
    // for the current alt-1 activation. The device forwards nothing
    // until this is set, and resets it on every SET_INTERFACE, so
    // CdcPacketFilterApplied is cleared whenever the data interface is
    // deactivated - see UsbTransport.c.
    USHORT               CdcPacketFilter;
    BOOLEAN              CdcPacketFilterApplied;

    // Applies a pending filter change when the OID path lands above
    // PASSIVE_LEVEL (control transfers are PASSIVE-only).
    WDFWORKITEM          PacketFilterWorkItem;
    ULONG                CurrentLookahead;

    // MulticastList/MulticastAddressCount are rewritten by
    // OID_802_3_MULTICAST_LIST (<= DISPATCH_LEVEL) while the RX path reads
    // them at DISPATCH_LEVEL on other CPUs. Every access goes through this
    // lock; without it a receive could see the list half zeroed and drop
    // multicast frames (IPv6 neighbour discovery) for no visible reason.
    KSPIN_LOCK           MulticastLock;
    ULONG                MulticastAddressCount;
    UCHAR                MulticastList[T2NCM_MAX_MULTICAST_LIST][T2NCM_MAC_LENGTH];

    // ---- Inverted power/data-path control ----
    // DataPathRunning is written ONLY by MiniportRestart (1) and
    // MiniportPause (0). Nothing else may start or stop the data path —
    // that is the whole point of the inversion. Read with a volatile
    // load from RX completions and the send path, both of which can run
    // at DISPATCH_LEVEL.
    volatile LONG        DataPathRunning;

    // Outstanding work NDIS must see drained before MiniportPause may
    // return NDIS_STATUS_SUCCESS: NBLs we have indicated up and not yet
    // had returned, and bulk-OUT writes we have submitted and not yet
    // completed. QuiesceEvent is signalled by whichever decrement takes
    // the counter to zero while a pause is in progress.
    volatile LONG        OutstandingRxNbls;
    volatile LONG        OutstandingTxRequests;
    volatile LONG        PauseInProgress;
    KEVENT               QuiesceEvent;

    // Current D-state as told to us by OID_PNP_SET_POWER. NDIS owns
    // this value; the driver only reacts to it (Power.c).
    NDIS_DEVICE_POWER_STATE PowerState;

    // Populated by NcmProtocol.c after GET_NTB_PARAMETERS
    BOOLEAN              Ntb16Supported;
    ULONG                NtbInMaxSize;
    ULONG                NtbOutMaxSize;

    // TRUE once GET_NTB_PARAMETERS/format-negotiation/SET_NTB_INPUT_SIZE
    // have succeeded at least once and the four fields above (plus
    // NdpOutDivisor/NdpOutPayloadRemainder/NdpOutAlignment/
    // NtbOutMaxDatagrams below) hold real, confirmed values. These are a
    // property of the physical device's firmware, not of the current
    // power cycle — same reasoning as the MAC-address comment in
    // T2NcmPowerArmHardware — so once confirmed they are trusted across
    // D0 re-entries instead of being re-queried every time. Cleared only
    // if a fast re-arm's alt-1 activation fails, forcing the next D0
    // entry back onto the full slow (re-query) path rather than trusting
    // possibly-stale values. See Power.c.
    BOOLEAN              NtbParametersCached;

    // RX diagnostics — retained from the pre-NDIS milestone because the
    // counters are still the fastest way to tell "the parser is fine but
    // NDIS isn't taking the frames" apart from "no frames are arriving".
    // The LastFrame* snapshot fields are best-effort, not lock-protected.
    LONG64               RxNtbsReceived;
    LONG64               RxFramesParsed;
    LONG64               RxFramesRejected;
    LONG64               RxFramesIndicated;

    // Frames the parser accepted but the software packet filter
    // discarded. Distinguishes "the device sends nothing" from "the
    // device sends frames we then throw away" - the two look identical
    // from Get-NetAdapterStatistics.
    LONG64               RxFramesFiltered;
    UCHAR                RxLastFrameDest[6];
    UCHAR                RxLastFrameSrc[6];
    USHORT               RxLastFrameEtherType;
    USHORT               RxLastFrameLength;

    // WDFUSBPIPE's own continuous-reader machinery owns the actual read
    // requests; nothing else to store here. Start/stop is idempotent —
    // see NcmRx.c.
    BOOLEAN              RxStarted;

    // Whether WdfUsbTargetPipeConfigContinuousReader has already been
    // called for the WDFUSBPIPE currently cached in BulkInPipe. WDF
    // allows that call exactly once per pipe object — a plain NDIS
    // Pause/Restart cycle reuses the SAME pipe object (no alt-setting
    // reselect happens), so Restart must only WdfIoTargetStart it again,
    // never reconfigure it. Cleared to FALSE only when BulkInPipe itself
    // is replaced with a new pipe object (T2NcmUsbActivateDataInterface),
    // which is the one event that actually invalidates this. See NcmRx.c.
    BOOLEAN              RxReaderConfigured;

    // OUT-direction NDP geometry from GET_NTB_PARAMETERS.
    // wNtbOutMaxDatagrams==0 is the spec's own "device imposes no limit"
    // value, not a missing/invalid one.
    USHORT               NdpOutDivisor;
    USHORT               NdpOutPayloadRemainder;
    USHORT               NdpOutAlignment;
    USHORT               NtbOutMaxDatagrams;

    // Running wSequence for outgoing NTBs — only needs to be
    // non-repeating within a reasonable window per the NCM spec, not
    // globally unique. NOW Interlocked: MiniportSendNetBufferLists can
    // run concurrently on several CPUs, which is exactly the "revisit
    // this once NDIS calls into TX" case the previous revision flagged.
    volatile LONG        TxSequence;

    LONG64               TxNtbsSent;
    LONG64               TxFramesSent;
    LONG64               TxFramesRejected;

    // ---- NDIS statistics (OID_GEN_STATISTICS / OID_GEN_XMIT_OK etc.) ----
    volatile LONG64      InUcastPkts;
    volatile LONG64      InBroadcastPkts;
    volatile LONG64      InMulticastPkts;
    volatile LONG64      InOctets;
    volatile LONG64      InErrors;
    volatile LONG64      InDiscards;
    volatile LONG64      OutUcastPkts;
    volatile LONG64      OutBroadcastPkts;
    volatile LONG64      OutMulticastPkts;
    volatile LONG64      OutOctets;
    volatile LONG64      OutErrors;
    volatile LONG64      OutDiscards;

} T2NCM_DEVICE_CONTEXT, *PT2NCM_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T2NCM_DEVICE_CONTEXT, T2NcmGetDeviceContext)

// Atomic accessors for PacketFilter (volatile LONG). Keep all call sites
// on these helpers so Interlocked always sees LONG volatile * — matching
// the WDK intrinsic prototypes and avoiding C4057 under /WX.
FORCEINLINE
ULONG
T2NcmReadPacketFilter(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    return (ULONG)InterlockedOr(
        (LONG volatile *)&DeviceContext->PacketFilter, 0);
}

FORCEINLINE
VOID
T2NcmWritePacketFilter(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ ULONG Filter
    )
{
    (VOID)InterlockedExchange(
        (LONG volatile *)&DeviceContext->PacketFilter, (LONG)Filter);
}

#endif // T2NCM_DEVICE_CONTEXT_TYPES_DEFINED

// Set once in DriverEntry. Needed by MiniportDriverUnload
// (NdisMDeregisterMiniportDriver) and nothing else.
extern NDIS_HANDLE g_T2NcmMiniportDriverHandle;

// The single adapter this driver services, published for the diagnostic
// control device only (NdisMRegisterDeviceEx creates ONE device object
// per driver, not per adapter, so its IRP dispatch has no adapter handle
// of its own to work from). NULL whenever no adapter is initialized.
// Never used by the data path — see NdisMiniport.c for why that
// restriction matters.
extern PT2NCM_DEVICE_CONTEXT volatile g_T2NcmDiagnosticAdapter;

// Guards g_T2NcmDiagnosticAdapter and the lifetime of what it points at.
// The diagnostic IOCTLs hold it shared for their whole duration; publishing
// or clearing the pointer (MiniportInitializeEx / MiniportHaltEx) takes it
// exclusive, so MiniportHaltEx cannot free the device context underneath
// an IOCTL that is still using it. ERESOURCE rather than a fast mutex:
// the IOCTL path does a PASSIVE_LEVEL-only synchronous USB write while
// holding it, and a fast mutex would raise IRQL to APC_LEVEL.
extern ERESOURCE g_T2NcmDiagnosticLock;

DRIVER_INITIALIZE DriverEntry;
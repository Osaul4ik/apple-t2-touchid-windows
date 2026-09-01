// SPDX-License-Identifier: GPL-2.0-only
// driver.h
// T2TouchIdTransport.sys — KMDF PCI driver for the Apple T2 SEP mailbox.
//
// Every numeric constant below is VERIFIED FROM SOURCE against the Linux
// reference implementation (jmurth1234/t2-touchid-linux, src/t2_sep_transport.c),
// as documented in docs/linux-reference-analysis.md (Milestone 1, section 3).
// Do not add or change a constant here without updating that provenance.

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>
#include "public.h"

// ---- Logging ----
// DELIBERATE: DbgPrintEx (the real kernel function), NOT KdPrintEx.
// KdPrintEx is a macro that expands to nothing when DBG is not defined -
// and the WDK driver build system defines DBG=0 for the Release
// configuration automatically. Since this driver is deployed/tested as a
// test-signed Release build (pnputil install path), every KdPrintEx call
// in this codebase was previously a silent no-op on the target machine,
// regardless of DebugView/WinDbg settings - there was nothing to filter,
// because nothing was ever emitted. DbgPrintEx is a real exported
// ntoskrnl function present and functional in both Debug and Release
// builds; it is still subject to the kernel debug-print component filter
// mask (see docs/milestone-2-hardware-results.md follow-up note on
// enabling the IHVDRIVER filter in DebugView / the registry), but at
// least the call itself always executes.
#define T2_LOG(_x_) DbgPrintEx _x_

// ---- PCI identity (VERIFIED FROM SOURCE) ----
#define T2_SEP_VENDOR_ID            0x106Bu
#define T2_SEP_DEVICE_ID            0x1802u
#define T2_SEP_MAILBOX_BAR_INDEX    4
#define T2_SEP_BAR_MIN_SIZE         0x10000u

// ---- Mailbox MMIO offsets (VERIFIED FROM SOURCE) ----
#define T2_SEP_INBOX_STATUS         0x0108u
#define T2_SEP_OUTBOX_STATUS        0x010Cu
#define T2_SEP_INBOX_DATA           0x0810u
#define T2_SEP_OUTBOX_DATA          0x0820u
#define T2_SEP_INBOX_EMPTY_BIT      (1u << 17)
#define T2_SEP_OUTBOX_FULL_BIT      (1u << 16)

// A read of all-ones off a PCI MMIO BAR is the standard "nothing answered"
// signal (link down / device surprise-removed / not yet powered) rather
// than a real register value - no legitimate T2_SEP_INBOX_STATUS value is
// 0xFFFFFFFF. Used by the D0Entry mailbox liveness check (device.c) to
// fail closed instead of trusting a bus read that never actually reached
// the SEP.
#define T2_SEP_MAILBOX_DEAD_READ    0xFFFFFFFFu

// ---- Endpoint / control-message layout (VERIFIED FROM SOURCE) ----
#define T2_SEP_CONTROL_ENDPOINT     0
#define T2_SEP_AKS_ENDPOINT         7
#define T2_SEP_CMSG_SET_OOL_IN      2
#define T2_SEP_CMSG_SET_OOL_OUT     3

// ---- DMA / OOL parameters (VERIFIED FROM SOURCE) ----
#define T2_SEP_OOL_SIZE             0x4000u   // 16 KiB per buffer, x2 (in/out)
#define T2_SEP_DMA_BITS             44
#define T2_SEP_DMA_ALIGNMENT        0x1000u   // 4 KiB

// ---- Timing (VERIFIED FROM SOURCE) ----
#define T2_SEP_TIMEOUT_US           (5 * 1000 * 1000)
#define T2_SEP_POLL_MIN_US          100
#define T2_SEP_POLL_MAX_US          200
#define T2_SEP_MAX_SKIPPED_REPLIES  32        // -> STATUS_DEVICE_PROTOCOL_ERROR beyond this

// Milestone 2B §9: bound the TOTAL time a single control/AKS transaction
// (T2SepControl / T2SepAksTransaction) may spend inside its receive loop,
// independent of how many unrelated/skipped mailbox messages show up along
// the way. Without this, T2_SEP_MAX_SKIPPED_REPLIES (32) skipped messages
// each re-arming a full T2_SEP_TIMEOUT_US (5s) wait could stretch a single
// logical transaction out to ~160s. This is NOT a protocol change - it only
// caps how long we keep polling for OUR reply; the wire messages and their
// semantics are untouched.
#define T2_SEP_TRANSACTION_DEADLINE_US (15ULL * 1000 * 1000)

// ---- AppleKeyStore header sizes (VERIFIED FROM SOURCE) ----
// NOTE: these are intentionally named T2_AKS_VERSION_Vn, not T2_AKS_HEADER_Vn:
// T2_AKS_HEADER_V1/V2 are the *struct* typedef names below. Reusing the same
// name for a #define and a typedef is a preprocessor collision — the macro
// expands first and silently corrupts the struct declaration (and every
// PT2_AKS_HEADER_Vn use downstream), producing a cascade of unrelated-looking
// C2059/C2118/C2148/C2369 errors. Do not rename these back.
#define T2_AKS_VERSION_V1           1
#define T2_AKS_VERSION_V2           2
#define T2_AKS_HEADER_V1_SIZE       0x48u
#define T2_AKS_HEADER_V2_SIZE       0x50u
#define T2_AKS_CAP_REQ_SIZE         0x5Cu

// VERIFIED FROM SOURCE (t2_sep_transport.c): every AKS wire message is
// prefixed by its own 4-byte little-endian header_size BEFORE the digest —
// i.e. wire = [u32 header_size][T2_AKS_HEADER_Vn]{...}[body]. This 4-byte
// prefix is NOT part of T2_AKS_HEADER_V1/V2 above; it is a separate field
// T2AksDigest/T2AksExchange must account for. t2_aks_exchange_locked() (the
// path reachable from the ioctl, i.e. every allow-listed operation this
// driver implements) always uses the V2 header; T2_SEP_AKS_HEADER_V1 is
// only used by the Linux driver's separate boot-time-only capability probe,
// which this driver does not implement as a distinct path.
#define T2_AKS_V1_WIRE_SIZE         (sizeof(UINT32) + T2_AKS_HEADER_V1_SIZE)
#define T2_AKS_V2_WIRE_SIZE         (sizeof(UINT32) + T2_AKS_HEADER_V2_SIZE)

// T2_AKS_MAX_BODY_SIZE is defined once, in public.h (it's part of the public
// IOCTL contract that user-mode callers also need). Do NOT redefine it here:
// public.h is already included above, and redefining it produces a
// macro-redefinition warning that is fatal under /WX and was cascading into
// unrelated parse errors later in this header (bogus C_ASSERT/negative-
// subscript/__C_ASSERT__-redefinition errors, and a missing PT2_AKS_HEADER_V2
// type in akstore.c). Assert the two derivations agree instead.
C_ASSERT(T2_AKS_MAX_BODY_SIZE == (T2_SEP_OOL_SIZE - T2_AKS_V2_WIRE_SIZE));

#pragma pack(push, 1)
typedef struct _T2_SEP_MESSAGE
{
    UINT32 Word[4];   // 16-byte mailbox message; Word[3] is always 0 on send
} T2_SEP_MESSAGE, *PT2_SEP_MESSAGE;

typedef struct _T2_AKS_HEADER_V1
{
    UINT8  Digest[16];
    UINT32 Version;
    UINT64 UsecTime;
    UINT32 Flags;
    UINT64 ClockId;
    UINT8  PlatformData[0x20];
} T2_AKS_HEADER_V1, *PT2_AKS_HEADER_V1;
C_ASSERT(sizeof(T2_AKS_HEADER_V1) == T2_AKS_HEADER_V1_SIZE);

typedef struct _T2_AKS_HEADER_V2
{
    T2_AKS_HEADER_V1 V1;
    UINT64 CalendarSeconds;
} T2_AKS_HEADER_V2, *PT2_AKS_HEADER_V2;
C_ASSERT(sizeof(T2_AKS_HEADER_V2) == T2_AKS_HEADER_V2_SIZE);
#pragma pack(pop)

// Milestone 2B §2: explicit transport lifecycle state, replacing a set of
// independent boolean flags. All transitions happen while holding
// ExchangeLock (the same lock that already serializes mailbox/AKS
// exchange) - see device.c T2SetTransportState and its callers.
//
//   NotInitialized -> HardwareReady            PrepareHardware succeeds
//   HardwareReady  -> RegisteringOol           IOCTL_T2_REGISTER_OOL starts
//   RegisteringOol -> Ready                    OOL_IN + OOL_OUT both registered
//   RegisteringOol -> HardwareReady            registration failed, fully
//                                               rolled back before SEP saw
//                                               anything - safe to retry
//   RegisteringOol -> Invalid                  OOL_IN reached SEP but OOL_OUT
//                                               failed - SEP may already be
//                                               holding the OOL_IN address,
//                                               so retrying with a fresh
//                                               allocation is not safe (§5/§7)
//   Ready          -> HardwareReady            D0Exit (leaving D0) - not
//                                               Ready again until D0Entry
//                                               revalidates
//   (Ready or HardwareReady) -> Ready          D0Entry, ordinary resume:
//                                               mailbox liveness check
//                                               succeeds (a real MMIO read,
//                                               not a bus-dead 0xFFFFFFFF -
//                                               see T2_SEP_MAILBOX_DEAD_READ)
//                                               AND OolInRegistered &&
//                                               OolOutRegistered are both
//                                               still TRUE from before the
//                                               sleep. Hardware testing
//                                               confirmed the same SEP OOL
//                                               registration keeps working
//                                               across an ordinary
//                                               D0->D3->D0 cycle, so this
//                                               path does NOT re-run
//                                               IOCTL_T2_REGISTER_OOL
//                                               (no SET_OOL_IN/SET_OOL_OUT)
//                                               - it only resumes the
//                                               TransportState to match the
//                                               OOL flags that never
//                                               changed, closing the
//                                               HardwareReady+OOL-registered
//                                               contradiction this used to
//                                               produce.
//   (Ready or HardwareReady) -> HardwareReady  D0Entry, otherwise: liveness
//                                               check failed (mailbox not
//                                               answering) OR OOL is not
//                                               *both* In+Out registered.
//                                               Fail closed - the next AKS
//                                               exchange gets an immediate
//                                               STATUS_DEVICE_NOT_READY
//                                               instead of a silent stale
//                                               mailbox timeout, and
//                                               IOCTL_T2_REGISTER_OOL must
//                                               be explicitly re-run to
//                                               reach Ready again.
//   (any)          -> Invalid                  ReleaseHardware ran while OOL
//                                               was registered - SEP-owned
//                                               memory is retained until
//                                               reboot (§7), so this
//                                               transport instance must never
//                                               look Ready again
//
// AKS exchange (T2EvtIoDeviceControlAksExchange) is only permitted in
// Ready. IOCTL_T2_REGISTER_OOL is only permitted in HardwareReady (or is a
// no-op success in Ready); every other state rejects both with
// STATUS_DEVICE_NOT_READY.
typedef enum _T2_TRANSPORT_STATE
{
    T2TransportNotInitialized = 0,
    T2TransportHardwareReady,
    T2TransportRegisteringOol,
    T2TransportReady,
    T2TransportStopping,
    T2TransportInvalid
} T2_TRANSPORT_STATE;

typedef struct _T2_DEVICE_CONTEXT
{
    WDFDEVICE           Device;
    PCI_COMMON_HEADER    PciConfig;      // vendor/device ID snapshot for status IOCTL

    PHYSICAL_ADDRESS     Bar4PhysicalAddress;
    ULONG                Bar4Length;
    PUCHAR               Bar4VirtualAddress;   // MmMapIoSpaceEx result
    BOOLEAN              Bar4Mapped;

    // Bus-mastering / DMA — only touched after IOCTL_T2_REGISTER_OOL.
    // WDF common buffers with AddressWidthOverride=32 give the device the
    // correct IOMMU/bus address; after writing OOL_IN we clflush so SEP
    // DMA sees the host stores (write-back cache).
    BOOLEAN              OolRegisterAttempted;  // diagnostic only - NOT used to gate retry, see State
    BOOLEAN              OolInRegistered;       // SET_OOL_IN *confirmed* (reply matched, result 0)
    BOOLEAN              OolOutRegistered;      // SET_OOL_OUT *confirmed* (reply matched, result 0)
    // Lifecycle hardening: a fact independent of OolInRegistered/
    // OolOutRegistered/State. Those three only become TRUE once we have a
    // *confirmed* reply from SEP - but T2MailboxSend can succeed (the
    // doorbell is rung, the message has physically left for SEP) and the
    // matching T2SepControl can still return failure afterward (its own
    // reply wait timed out, an unrelated message pushed it past
    // T2_SEP_MAX_SKIPPED_REPLIES, etc). In that case OolInRegistered/
    // OolOutRegistered stay FALSE - but SEP may already have received and
    // acted on the address, so it is NOT actually safe to free the buffer
    // and retry with a fresh allocation the way a "never sent" failure is.
    // OolSepMayKnowAddress is set TRUE the instant either SET_OOL_IN or
    // SET_OOL_OUT is successfully handed to the mailbox hardware (see
    // T2SepControl's SentToDevice out-param), and — like OolInRegistered —
    // is permanent for this device context: no deregistration opcode
    // exists, so once SEP might know an address, it might know it forever
    // (until reboot). T2DmaFreeOolBuffers refuses to run while this is
    // TRUE; PrepareHardware/ReleaseHardware/RegisterOol all treat it the
    // same way they already treat OolInRegistered/OolOutRegistered - fold
    // it into every "was OOL ever exposed to SEP" check alongside them.
    BOOLEAN              OolSepMayKnowAddress;
    WDFDMAENABLER        DmaEnabler;
    WDFCOMMONBUFFER      OolInBuffer;
    WDFCOMMONBUFFER      OolOutBuffer;
    PVOID                OolInVa;   // VA from common buffer
    PVOID                OolOutVa;
    PHYSICAL_ADDRESS     OolInPa;   // logical/bus address for SEP
    PHYSICAL_ADDRESS     OolOutPa;

    // Serializes mailbox + AKS exchange AND transport state transitions;
    // the mailbox is a single shared hardware resource, so only one
    // in-flight request at a time (matches Linux exchange_lock and
    // Milestone 2 section 23: one session at a time). Reusing this same
    // lock for state transitions (Milestone 2B §2) means an in-flight
    // exchange always completes (or times out) before D0Exit/ReleaseHardware
    // can move the state out from under it - no separate lock needed.
    WDFWAITLOCK          ExchangeLock;
    UINT8                NextTransaction;
    T2_TRANSPORT_STATE   State;   // guarded by ExchangeLock
} T2_DEVICE_CONTEXT, *PT2_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T2_DEVICE_CONTEXT, GetDeviceContext);

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD T2EvtDeviceAdd;
EVT_WDF_DEVICE_PREPARE_HARDWARE T2EvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE T2EvtDeviceReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY T2EvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT T2EvtDeviceD0Exit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL T2EvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_STOP T2EvtIoStop;

// device.c — transport lifecycle state (Milestone 2B §2). Caller must hold
// Ctx->ExchangeLock.
VOID T2SetTransportState(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ T2_TRANSPORT_STATE NewState);

// mailbox.c
NTSTATUS T2MailboxWaitOutbox(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ ULONG TimeoutUs);
NTSTATUS T2MailboxSend(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ const T2_SEP_MESSAGE *Message);
NTSTATUS T2MailboxReceive(_In_ PT2_DEVICE_CONTEXT Ctx, _Out_ T2_SEP_MESSAGE *Message, _In_ ULONG TimeoutUs);
// SentToDevice (optional): set to TRUE the moment T2MailboxSend for this
// control message succeeds - i.e. the message was physically handed to the
// mailbox hardware - regardless of what happens afterward (reply timeout,
// skipped-message overflow, SEP-reported error). Callers that must never
// treat a "not confirmed" failure as "never sent" (see OolSepMayKnowAddress
// in driver.h) check this instead of/in addition to the return status.
NTSTATUS T2SepControl(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Opcode, _In_ UINT8 Tag,
                       _In_ PHYSICAL_ADDRESS Dma, _In_ SIZE_T Size,
                       _Out_opt_ PBOOLEAN SentToDevice);

// EP7 (AppleKeyStore) transaction primitive. VERIFIED FROM SOURCE
// (t2_sep_transport.c, t2_aks_exchange_locked): this is a DIFFERENT wire
// message shape from T2SepControl/EP0 above — no DMA address is sent per
// call (the OOL_IN/OOL_OUT common buffers were already registered once via
// T2SepControl(SET_OOL_IN/OUT)); SEP reads/writes them directly by
// convention once endpoint 7 is addressed. Word[0] = endpoint(7) |
// operation<<8 | transaction<<16 ; Word[1] = requestWireLength<<16. The
// reply's Word[1] is NOT a result code here (unlike EP0) — success/failure
// is determined by the AKS response header + digest, checked by the caller.
//
// SepStatus (VERIFIED FROM SOURCE, t2_sep_transport.c t2_aks_exchange_locked):
// bits [31:24] of the matched reply's Word[0] are a SIGNED status byte the
// SEP fills in on every EP7 reply, independent of whether any OOL body
// follows. A nonzero value means the SEP understood and processed the
// request and is reporting a real result (e.g. invalid handle) — this is
// NOT a transport failure, and *ReplyWireLength/the OOL_OUT buffer must
// not be trusted when SepStatus != 0. *SepStatus is only meaningful when
// this function returns STATUS_SUCCESS (a reply was actually matched); on
// STATUS_IO_TIMEOUT/STATUS_DEVICE_PROTOCOL_ERROR it is left unwritten by
// the caller's zero-initialization, since no reply arrived to read it from.
NTSTATUS T2SepAksTransaction(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Operation,
                              _In_ UINT8 Transaction, _In_ SIZE_T RequestWireLength,
                              _Out_ UINT16 *ReplyWireLength, _Out_ INT8 *SepStatus);

// dma.c
NTSTATUS T2DmaAllocateOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx);
NTSTATUS T2DmaRegisterOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx);
VOID T2DmaFreeOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx);

// device.c — PCI config helpers (used by dma registration)
NTSTATUS T2EnablePciBusMaster(_In_ WDFDEVICE Device);

// akstore.c
BOOLEAN T2AksOperationAllowed(_In_ UINT8 Operation);
NTSTATUS T2AksDigest(_Inout_updates_bytes_(Length) PUCHAR Message, _In_ SIZE_T Length);
// SepStatus is always written (0 on entry-guaranteed success paths, the raw
// signed SEP status byte otherwise) whenever this function returns
// STATUS_SUCCESS. A STATUS_SUCCESS + nonzero *SepStatus means the exchange
// with SEP completed normally but the operation itself was rejected by
// AppleKeyStore (e.g. invalid handle) — *ResponseLength is 0 in that case.
// Callers that don't care can pass NULL.
NTSTATUS T2AksExchange(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Operation,
                        _In_reads_bytes_opt_(RequestLength) PUCHAR RequestBody, _In_ SIZE_T RequestLength,
                        _Out_writes_bytes_to_opt_(ResponseCapacity, *ResponseLength) PUCHAR ResponseBody,
                        _In_ SIZE_T ResponseCapacity, _Out_ SIZE_T *ResponseLength,
                        _Out_opt_ PINT8 SepStatus);
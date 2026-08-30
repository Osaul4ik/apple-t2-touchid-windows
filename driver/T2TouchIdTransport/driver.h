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

typedef struct _T2_DEVICE_CONTEXT
{
    WDFDEVICE           Device;
    PCI_COMMON_HEADER    PciConfig;      // vendor/device ID snapshot for status IOCTL

    PHYSICAL_ADDRESS     Bar4PhysicalAddress;
    ULONG                Bar4Length;
    PUCHAR               Bar4VirtualAddress;   // MmMapIoSpaceEx result
    BOOLEAN              Bar4Mapped;

    // Bus-mastering / DMA — only touched after IOCTL_T2_REGISTER_OOL.
    // Allocated via MmAllocateContiguousMemorySpecifyCache(MmNonCached) so
    // SEP DMA always sees host writes (write-back WDF common buffers were
    // the leading cause of silent EP7 timeouts after correct wire layout).
    BOOLEAN              OolRegisterAttempted;
    BOOLEAN              OolInRegistered;
    BOOLEAN              OolOutRegistered;
    PVOID                OolInVa;
    PVOID                OolOutVa;
    PHYSICAL_ADDRESS     OolInPa;
    PHYSICAL_ADDRESS     OolOutPa;

    // Serializes mailbox + AKS exchange; the mailbox is a single shared
    // hardware resource, so only one in-flight request at a time (matches
    // Linux exchange_lock and Milestone 2 section 23: one session at a time).
    WDFWAITLOCK          ExchangeLock;
    UINT8                NextTransaction;
} T2_DEVICE_CONTEXT, *PT2_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T2_DEVICE_CONTEXT, GetDeviceContext);

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD T2EvtDeviceAdd;
EVT_WDF_DEVICE_PREPARE_HARDWARE T2EvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE T2EvtDeviceReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY T2EvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT T2EvtDeviceD0Exit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL T2EvtIoDeviceControl;

// mailbox.c
NTSTATUS T2MailboxWaitOutbox(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ ULONG TimeoutUs);
NTSTATUS T2MailboxSend(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ const T2_SEP_MESSAGE *Message);
NTSTATUS T2MailboxReceive(_In_ PT2_DEVICE_CONTEXT Ctx, _Out_ T2_SEP_MESSAGE *Message, _In_ ULONG TimeoutUs);
NTSTATUS T2SepControl(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Opcode, _In_ UINT8 Tag,
                       _In_ PHYSICAL_ADDRESS Dma, _In_ SIZE_T Size);

// EP7 (AppleKeyStore) transaction primitive. VERIFIED FROM SOURCE
// (t2_sep_transport.c, t2_aks_exchange_locked): this is a DIFFERENT wire
// message shape from T2SepControl/EP0 above — no DMA address is sent per
// call (the OOL_IN/OOL_OUT common buffers were already registered once via
// T2SepControl(SET_OOL_IN/OUT)); SEP reads/writes them directly by
// convention once endpoint 7 is addressed. Word[0] = endpoint(7) |
// operation<<8 | transaction<<16 ; Word[1] = requestWireLength<<16. The
// reply's Word[1] is NOT a result code here (unlike EP0) — success/failure
// is determined by the AKS response header + digest, checked by the caller.
NTSTATUS T2SepAksTransaction(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Operation,
                              _In_ UINT8 Transaction, _In_ SIZE_T RequestWireLength,
                              _Out_ UINT16 *ReplyWireLength);

// dma.c
NTSTATUS T2DmaAllocateOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx);
NTSTATUS T2DmaRegisterOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx);
VOID T2DmaFreeOolBuffers(_In_ PT2_DEVICE_CONTEXT Ctx);

// device.c — PCI config helpers (used by dma registration)
NTSTATUS T2EnablePciBusMaster(_In_ WDFDEVICE Device);

// akstore.c
BOOLEAN T2AksOperationAllowed(_In_ UINT8 Operation);
NTSTATUS T2AksDigest(_Inout_updates_bytes_(Length) PUCHAR Message, _In_ SIZE_T Length);
NTSTATUS T2AksExchange(_In_ PT2_DEVICE_CONTEXT Ctx, _In_ UINT8 Operation,
                        _In_reads_bytes_opt_(RequestLength) PUCHAR RequestBody, _In_ SIZE_T RequestLength,
                        _Out_writes_bytes_to_(ResponseCapacity, *ResponseLength) PUCHAR ResponseBody,
                        _In_ SIZE_T ResponseCapacity, _Out_ SIZE_T *ResponseLength);
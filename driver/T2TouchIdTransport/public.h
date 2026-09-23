// SPDX-License-Identifier: GPL-2.0-only
// public.h
// Public IOCTL interface exposed by T2TouchIdTransport.sys.
// Mirrors the ioctl surface of the Linux reference (t2_sep_transport_uapi.h),
// adapted to Win32 DeviceIoControl conventions. Kept intentionally narrow:
// the driver enforces the AppleKeyStore allow-list internally (akstore.c) —
// this header does NOT expose a generic "send arbitrary SEP command" IOCTL.

#pragma once

#include <initguid.h>

// The IOCTL codes below use CTL_CODE / FILE_DEVICE_UNKNOWN / METHOD_BUFFERED /
// FILE_*_ACCESS. Kernel mode gets them from ntddk.h (always included before
// this header). In user mode they live in <winioctl.h>, which <windows.h>
// only pulls in when WIN32_LEAN_AND_MEAN is NOT defined - and the UMDF
// toolset defines it for every translation unit (T2TouchIdBio compiles
// protocol/AppleKeyStore/Client.cpp, which is where that surfaced). Include
// it here so the header does not depend on the includer's macros.
#if !defined(_NTDDK_) && !defined(_WDMDDK_)
#include <winioctl.h>
#endif

// {6E0F1A7C-6B7A-4E7A-9C6D-2C6B1E7F3A10}
DEFINE_GUID(GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT,
    0x6e0f1a7c, 0x6b7a, 0x4e7a, 0x9c, 0x6d, 0x2c, 0x6b, 0x1e, 0x7f, 0x3a, 0x10);

#define T2_AKS_MAX_BODY_SIZE   (0x4000 - 0x50 - sizeof(UINT32)) // OOL_SIZE - V2 wire header

// Allow-listed AppleKeyStore operations. Values match the Linux reference
// (VERIFIED FROM SOURCE, t2_sep_transport.c: t2_aks_operation_allowed()).
// This enum exists so callers cannot pass an arbitrary byte as "operation" —
// the driver still independently re-validates against this same set inside
// the kernel, this enum is a compile-time convenience for user-mode callers.
typedef enum _T2_AKS_OPERATION
{
    T2AksOpLoadKeybag        = 0x03,
    T2AksOpChangeLockState   = 0x04,
    T2AksOpMakeSystemKeybag  = 0x0d,
    T2AksOpGetDeviceState    = 0x19,
    T2AksOpGetCapabilities   = 0x4d,
} T2_AKS_OPERATION;

#pragma pack(push, 1)
// IOCTL_T2_AKS_EXCHANGE is METHOD_BUFFERED: the request body and response
// body travel INLINE, immediately after these fixed headers, inside the
// same buffer the I/O manager already validated and copied to/from
// user-mode. Earlier revisions carried RequestBuffer/ResponseBuffer as raw
// user-mode VAs inside the struct and had the driver ProbeForRead/
// ProbeForWrite + RtlCopyMemory them directly - that is only safe if the
// I/O request is serviced on the calling thread in the calling process's
// context, which KMDF does not guarantee (a request can be requeued and
// completed from a system worker thread, e.g. if the queue is briefly busy
// or the device is mid PnP/power transition). Doing so would probe/copy
// against the WRONG process's address space: an arbitrary kernel-mode
// read/write primitive driven by a user-supplied pointer. Passing the
// payload inline removes the raw pointers entirely - there is nothing left
// to mis-dereference.
typedef struct _T2_AKS_EXCHANGE_IN
{
    UINT8   Operation;          // one of T2_AKS_OPERATION; anything else -> STATUS_ACCESS_DENIED
    UINT8   Reserved0[7];       // must be zero
    // Request body follows immediately; its length is
    // (InputBufferLength - sizeof(T2_AKS_EXCHANGE_IN)), max T2_AKS_MAX_BODY_SIZE.
} T2_AKS_EXCHANGE_IN, *PT2_AKS_EXCHANGE_IN;

typedef struct _T2_AKS_EXCHANGE_OUT
{
    UINT32  ResponseLength;     // out: actual response body bytes written after this header
    // Signed status byte from the matched EP7 reply (VERIFIED FROM SOURCE,
    // t2_sep_transport.c: "EP7 reply: endpoint, operation|response,
    // transaction, signed status"). 0 = SEP accepted the operation.
    // Nonzero = SEP understood and rejected it (e.g. invalid handle) - this
    // is a real AppleKeyStore-level result, NOT a transport failure, and
    // ResponseLength is always 0 when this is nonzero. Only meaningful when
    // the IOCTL itself returned success; on a transport-level failure
    // (timeout etc.) this field is left as the driver wrote it (0).
    INT8    SepStatus;
    UINT8   Reserved1[3];       // must be zero; padding to keep the body offset stable
    // Response body follows immediately; caller must size OutputBufferLength
    // to sizeof(T2_AKS_EXCHANGE_OUT) + however many bytes it wants to receive
    // (max T2_AKS_MAX_BODY_SIZE).
} T2_AKS_EXCHANGE_OUT, *PT2_AKS_EXCHANGE_OUT;
#pragma pack(pop)

typedef struct _T2_TRANSPORT_STATUS
{
    BOOLEAN PciPresent;
    UINT16  VendorId;
    UINT16  DeviceId;
    BOOLEAN Bar4Mapped;
    UINT32  Bar4Size;
    BOOLEAN MailboxAccessible;
    BOOLEAN OolRegistered;      // both SET_OOL_IN and SET_OOL_OUT succeeded
} T2_TRANSPORT_STATUS, *PT2_TRANSPORT_STATUS;

#define IOCTL_T2_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS)

// Only issued once, opt-in, mirrors Linux register_ool=1: without this call
// the driver stays in observation-only mode (BAR4 mapped, mailbox status
// readable, no DMA allocated, no bus-mastering enabled).
#define IOCTL_T2_REGISTER_OOL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_T2_AKS_EXCHANGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// Bootstrap status: NOT part of the AppleKeyStore protocol. This is a
// small in-memory mailbox the driver holds purely so T2SepBootstrapService
// (which runs the actual load-keybag/unlock sequence in user mode, see
// T2SepBootstrapService.cpp) can record the outcome once per boot, and
// SepVaultGui can ask "what happened" without parsing C:\LogSEP.txt or
// racing a separate status file on disk. The driver does not interpret
// these values at all - it just stores whatever the service last wrote
// and hands it back, guarded by its own lock (BootstrapStatusLock) so a
// GUI query never blocks on an in-flight AKS exchange.
typedef enum _T2_SEP_BOOTSTRAP_REASON
{
    T2SepReasonUnknown          = 0, // service hasn't reported anything yet this boot
    T2SepReasonOk                = 1,
    T2SepReasonVaultMissing      = 2, // sep-vault.bin absent/malformed - run SepVaultGui
    T2SepReasonDpapi             = 3, // CryptUnprotectData failed
    T2SepReasonRegisterOolFailed = 4, // driver/transport-level failure, no SEP exchange attempted
    T2SepReasonSepHang           = 5, // AKS exchange never got a reply - SEP wedged, needs
                                       // a macOS boot to hardware-reset it, then reboot to Windows
    T2SepReasonSepRejected       = 6, // SEP replied and explicitly rejected (wrong password/keybag)
} T2_SEP_BOOTSTRAP_REASON;

typedef enum _T2_SEP_BOOTSTRAP_STEP
{
    T2SepStepNone              = 0,
    T2SepStepReadVault         = 1,
    T2SepStepUnprotectKeybag   = 2,
    T2SepStepUnprotectPassword = 3,
    T2SepStepRegisterOol       = 4,
    T2SepStepLoadKeybag        = 5,
    T2SepStepSetSystemKeybag   = 6,
    T2SepStepUnlockHandle      = 7,
    T2SepStepUnlockSpecialBag  = 8,
    T2SepStepReady             = 9,
} T2_SEP_BOOTSTRAP_STEP;

typedef struct _T2_BOOTSTRAP_STATUS
{
    T2_SEP_BOOTSTRAP_REASON Reason;
    T2_SEP_BOOTSTRAP_STEP   Step;
    INT8                    SepStatus;
    // Explicit padding to TimestampUtc's 8-byte natural alignment (x64):
    // 4 (Reason) + 4 (Step) + 1 (SepStatus) = 9, next 8-aligned offset is
    // 16, so 7 bytes here, not the 3 an offset-to-12 assumption would give
    // - written out so the layout is exact and self-documenting instead of
    // relying on the compiler's implicit tail padding, which SepStatusClient.cs
    // on the GUI side has to reproduce byte-for-byte via StructLayout.
    UINT8                   Reserved[7];
    LARGE_INTEGER           TimestampUtc; // KeQuerySystemTimePrecise, 0 if never set
} T2_BOOTSTRAP_STATUS, *PT2_BOOTSTRAP_STATUS;

// Written once by T2SepBootstrapService right after each step of the
// sequence (design doc §9.2); SYSTEM/Administrators-only, same as every
// other IOCTL on this device (device interface SDDL).
#define IOCTL_T2_SET_BOOTSTRAP_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Read by SepVaultGui (or any other diagnostic caller) to show the current
// SEP state without touching the SEP itself.
#define IOCTL_T2_GET_BOOTSTRAP_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_READ_ACCESS)
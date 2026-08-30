// public.h
// Public IOCTL interface exposed by T2TouchIdTransport.sys.
// Mirrors the ioctl surface of the Linux reference (t2_sep_transport_uapi.h),
// adapted to Win32 DeviceIoControl conventions. Kept intentionally narrow:
// the driver enforces the AppleKeyStore allow-list internally (akstore.c) —
// this header does NOT expose a generic "send arbitrary SEP command" IOCTL.

#pragma once

#include <initguid.h>

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
typedef struct _T2_AKS_EXCHANGE
{
    UINT8   Operation;          // one of T2_AKS_OPERATION; anything else -> STATUS_ACCESS_DENIED
    UINT8   Reserved0[7];       // must be zero
    UINT64  RequestBuffer;      // user VA, in
    UINT32  RequestLength;      // <= T2_AKS_MAX_BODY_SIZE
    UINT64  ResponseBuffer;     // user VA, out
    UINT32  ResponseCapacity;   // <= T2_AKS_MAX_BODY_SIZE
    UINT32  ResponseLength;     // out: actual bytes written
} T2_AKS_EXCHANGE, *PT2_AKS_EXCHANGE;
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

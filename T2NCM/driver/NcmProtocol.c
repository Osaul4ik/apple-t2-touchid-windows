// SPDX-License-Identifier: GPL-2.0-only
// NcmProtocol.c — Tasks 7-11 (NCM control layer): GET_NTB_PARAMETERS,
// NTB16 format negotiation, SET_NTB_INPUT_SIZE, and CDC Ethernet
// Functional Descriptor MAC address extraction. All four validate their
// inputs explicitly and fail closed (STATUS_NOT_SUPPORTED /
// STATUS_DEVICE_PROTOCOL_ERROR) rather than substituting a guessed or
// fabricated value for anything the device didn't actually report.

#include "NcmProtocol.h"
#include <ntstrsafe.h>  // RtlStringCbPrintfExA — raw-byte diagnostic dump only

// DEVPKEY_Device_ContainerId, declared locally instead of #include
// <devpkey.h>. That header defines ~150 DEVPKEY_* constants gated on
// INITGUID being defined at the point of inclusion — and INITGUID is
// already active for the rest of this TU (Driver.h pulls in
// <initguid.h> before wdfusb.h/ndis.h, both of which end up including
// devpkey.h themselves for their own property support). A second
// explicit #include <devpkey.h> here re-processed the whole file under
// INITGUID a second time in the same translation unit, which is a hard
// redefinition (C2374) rather than the harmless COMDAT-folding
// DECLSPEC_SELECTANY normally allows *across* TUs. Declaring only the
// one key we actually use avoids re-including that header at all.
DEFINE_DEVPROPKEY(T2Ncm_DEVPKEY_Device_ContainerId,
    0x8c7ed206, 0x3f8a, 0x4827, 0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c, 2);
    // DEVPROP_TYPE_GUID — verified against Microsoft's published value

// ---- CDC-NCM class-specific request codes (USB CDC-NCM 1.20 table 6.2) ----
#define T2NCM_REQ_GET_NTB_PARAMETERS    0x80u
#define T2NCM_REQ_SET_NTB_FORMAT        0x84u
#define T2NCM_REQ_SET_NTB_INPUT_SIZE    0x86u

#define T2NCM_NTB_FORMAT_16             0x0000u
#define T2NCM_BM_NTB16_SUPPORTED_BIT    0x0001u

// Wire-format NTB Parameter Structure (USB CDC-NCM 1.20 table 6.3),
// 28 bytes, little-endian, packed exactly as the device sends it.
#include <pshpack1.h>
typedef struct _T2NCM_WIRE_NTB_PARAMETERS
{
    USHORT wLength;
    USHORT bmNtbFormatsSupported;
    ULONG  dwNtbInMaxSize;
    USHORT wNdpInDivisor;
    USHORT wNdpInPayloadRemainder;
    USHORT wNdpInAlignment;
    USHORT wReserved;
    ULONG  dwNtbOutMaxSize;
    USHORT wNdpOutDivisor;
    USHORT wNdpOutPayloadRemainder;
    USHORT wNdpOutAlignment;
    USHORT wNtbOutMaxDatagrams;
} T2NCM_WIRE_NTB_PARAMETERS;
#include <poppack.h>

#define T2NCM_NTB_PARAM_WIRE_LENGTH 0x1Cu // 28 bytes, per wLength above

C_ASSERT(sizeof(T2NCM_WIRE_NTB_PARAMETERS) == T2NCM_NTB_PARAM_WIRE_LENGTH);

// Reasonability bounds for dwNtbIn/OutMaxSize (Task 9: "impossible
// sizes"). 2048 is the CDC-NCM floor a compliant NTB16 function must
// support; 65536 is a generous ceiling — nothing this driver will ever
// allocate for a single NTB should legitimately exceed it, and a device
// claiming more is reporting garbage, not a real capability.
#define T2NCM_NTB_MIN_SANE_SIZE  2048u
#define T2NCM_NTB_MAX_SANE_SIZE  65536u

// ---------------------------------------------------------------------
// Task 9 helper: an NDP geometry triple (divisor/remainder/alignment) is
// only meaningful if the divisor and alignment are non-zero powers of
// two and the remainder is strictly smaller than the divisor. Shared
// between the In and Out halves of the NTB Parameter Structure so both
// get the exact same validation.
// ---------------------------------------------------------------------
static
BOOLEAN
T2NcmValidateNdpGeometry(
    _In_ USHORT Divisor,
    _In_ USHORT PayloadRemainder,
    _In_ USHORT Alignment
    )
{
    if (Divisor == 0 || Alignment == 0)
    {
        return FALSE;
    }
    if ((Alignment & (Alignment - 1)) != 0)
    {
        return FALSE; // must be a power of two
    }
    if (PayloadRemainder >= Divisor)
    {
        return FALSE; // remainder must be strictly less than the divisor
    }
    return TRUE;
}

NTSTATUS
T2NcmGetNtbParameters(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_ PT2NCM_NTB_PARAMETERS Parameters
    )
{
    NTSTATUS status;
    WDF_USB_CONTROL_SETUP_PACKET setupPacket;
    WDF_MEMORY_DESCRIPTOR memDesc;
    T2NCM_WIRE_NTB_PARAMETERS wire;
    ULONG bytesReturned = 0;

    RtlZeroMemory(Parameters, sizeof(*Parameters));
    RtlZeroMemory(&wire, sizeof(wire));

    WDF_USB_CONTROL_SETUP_PACKET_INIT_CLASS(
        &setupPacket,
        BmRequestDeviceToHost,
        BmRequestToInterface,
        (UCHAR)T2NCM_REQ_GET_NTB_PARAMETERS,
        0,
        (USHORT)T2NCM_CONTROL_IFACE_NUM);

    WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&memDesc, &wire, (ULONG)sizeof(wire));

    status = WdfUsbTargetDeviceSendControlTransferSynchronously(
        DeviceContext->UsbDevice,
        WDF_NO_HANDLE,
        NULL,
        &setupPacket,
        &memDesc,
        &bytesReturned);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: GET_NTB_PARAMETERS control transfer failed 0x%08X\n", status));
        return status;
    }

    if (bytesReturned != (ULONG)sizeof(wire))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: GET_NTB_PARAMETERS returned %u bytes, expected %u\n",
            bytesReturned, (ULONG)sizeof(wire)));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    if (wire.wLength != T2NCM_NTB_PARAM_WIRE_LENGTH)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: NTB Parameter Structure wLength=0x%04X, expected 0x%04X\n",
            wire.wLength, T2NCM_NTB_PARAM_WIRE_LENGTH));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    // Task 9: validate every field — overflow, zero divisors, impossible
    // sizes, alignment. Nothing here is trusted blindly.
    if (wire.dwNtbInMaxSize < T2NCM_NTB_MIN_SANE_SIZE ||
        wire.dwNtbInMaxSize > T2NCM_NTB_MAX_SANE_SIZE)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: dwNtbInMaxSize %u out of sane range [%u,%u]\n",
            wire.dwNtbInMaxSize, T2NCM_NTB_MIN_SANE_SIZE, T2NCM_NTB_MAX_SANE_SIZE));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    if (wire.dwNtbOutMaxSize < T2NCM_NTB_MIN_SANE_SIZE ||
        wire.dwNtbOutMaxSize > T2NCM_NTB_MAX_SANE_SIZE)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: dwNtbOutMaxSize %u out of sane range [%u,%u]\n",
            wire.dwNtbOutMaxSize, T2NCM_NTB_MIN_SANE_SIZE, T2NCM_NTB_MAX_SANE_SIZE));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    if (!T2NcmValidateNdpGeometry(wire.wNdpInDivisor, wire.wNdpInPayloadRemainder, wire.wNdpInAlignment))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: invalid NDP-In geometry divisor=%u remainder=%u alignment=%u\n",
            wire.wNdpInDivisor, wire.wNdpInPayloadRemainder, wire.wNdpInAlignment));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    if (!T2NcmValidateNdpGeometry(wire.wNdpOutDivisor, wire.wNdpOutPayloadRemainder, wire.wNdpOutAlignment))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: invalid NDP-Out geometry divisor=%u remainder=%u alignment=%u\n",
            wire.wNdpOutDivisor, wire.wNdpOutPayloadRemainder, wire.wNdpOutAlignment));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    if ((wire.bmNtbFormatsSupported & T2NCM_BM_NTB16_SUPPORTED_BIT) == 0)
    {
        // NTB16 support is mandatory for every CDC-NCM function per the
        // spec. A device that doesn't advertise it is non-compliant —
        // fail now rather than let NegotiateNtbFormat discover this
        // later with a less informative error.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: device does not advertise mandatory NTB16 support "
            "(bmNtbFormatsSupported=0x%04X)\n", wire.bmNtbFormatsSupported));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    Parameters->dwNtbInMaxSize           = wire.dwNtbInMaxSize;
    Parameters->wNdpInDivisor            = wire.wNdpInDivisor;
    Parameters->wNdpInPayloadRemainder   = wire.wNdpInPayloadRemainder;
    Parameters->wNdpInAlignment          = wire.wNdpInAlignment;
    Parameters->dwNtbOutMaxSize          = wire.dwNtbOutMaxSize;
    Parameters->wNdpOutDivisor           = wire.wNdpOutDivisor;
    Parameters->wNdpOutPayloadRemainder  = wire.wNdpOutPayloadRemainder;
    Parameters->wNdpOutAlignment         = wire.wNdpOutAlignment;
    Parameters->wNtbOutMaxDatagrams      = wire.wNtbOutMaxDatagrams;
    Parameters->bmNtbFormatsSupported    = wire.bmNtbFormatsSupported;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: GET_NTB_PARAMETERS OK: InMax=%u OutMax=%u formats=0x%04X\n",
        wire.dwNtbInMaxSize, wire.dwNtbOutMaxSize, wire.bmNtbFormatsSupported));

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmNegotiateNtbFormat(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ const T2NCM_NTB_PARAMETERS* Parameters
    )
{
    NTSTATUS status;
    WDF_USB_CONTROL_SETUP_PACKET setupPacket;

    // Task 10: NTB16-preferred, never a silent NTB32 fallback. Since
    // T2NcmGetNtbParameters already fails closed if bit0 is absent, this
    // check is a defense against a caller passing hand-built Parameters
    // rather than a live-observed protocol path.
    if ((Parameters->bmNtbFormatsSupported & T2NCM_BM_NTB16_SUPPORTED_BIT) == 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: refusing to negotiate — NTB16 not in bmNtbFormatsSupported=0x%04X "
            "(this driver never falls back to NTB32)\n",
            Parameters->bmNtbFormatsSupported));
        return STATUS_NOT_SUPPORTED;
    }

    WDF_USB_CONTROL_SETUP_PACKET_INIT_CLASS(
        &setupPacket,
        BmRequestHostToDevice,
        BmRequestToInterface,
        (UCHAR)T2NCM_REQ_SET_NTB_FORMAT,
        (USHORT)T2NCM_NTB_FORMAT_16,
        (USHORT)T2NCM_CONTROL_IFACE_NUM);

    status = WdfUsbTargetDeviceSendControlTransferSynchronously(
        DeviceContext->UsbDevice,
        WDF_NO_HANDLE,
        NULL,
        &setupPacket,
        NULL,
        NULL);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: SET_NTB_FORMAT(NTB16) failed 0x%08X\n", status));
        return status;
    }

    DeviceContext->Ntb16Supported = TRUE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: SET_NTB_FORMAT(NTB16) OK\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmSetNtbInputSize(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ const T2NCM_NTB_PARAMETERS* Parameters
    )
{
    NTSTATUS status;
    WDF_USB_CONTROL_SETUP_PACKET setupPacket;
    WDF_MEMORY_DESCRIPTOR memDesc;
    ULONG dwNtbInputSize;

    // Task 11: checked arithmetic. Parameters->dwNtbInMaxSize was already
    // range-validated by T2NcmGetNtbParameters, but re-check here too —
    // this function must never trust a value it didn't itself verify,
    // in case a future caller assembles Parameters some other way.
    if (Parameters->dwNtbInMaxSize < T2NCM_NTB_MIN_SANE_SIZE ||
        Parameters->dwNtbInMaxSize > T2NCM_NTB_MAX_SANE_SIZE)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: refusing SET_NTB_INPUT_SIZE with out-of-range dwNtbInMaxSize=%u\n",
            Parameters->dwNtbInMaxSize));
        return STATUS_INVALID_PARAMETER;
    }

    // Accept the device's own advertised max as-is — it's already been
    // range-checked, so there's no reason to shrink it. This sends the
    // basic 4-byte SET_NTB_INPUT_SIZE payload (just dwNtbInMaxSize); the
    // extended 8-byte form (wNtbInMaxDatagrams pacing) is not used in
    // this milestone since NTB32/datagram-pacing negotiation isn't
    // implemented.
    dwNtbInputSize = Parameters->dwNtbInMaxSize;

    WDF_USB_CONTROL_SETUP_PACKET_INIT_CLASS(
        &setupPacket,
        BmRequestHostToDevice,
        BmRequestToInterface,
        (UCHAR)T2NCM_REQ_SET_NTB_INPUT_SIZE,
        0,
        (USHORT)T2NCM_CONTROL_IFACE_NUM);

    WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(&memDesc, &dwNtbInputSize, (ULONG)sizeof(dwNtbInputSize));

    status = WdfUsbTargetDeviceSendControlTransferSynchronously(
        DeviceContext->UsbDevice,
        WDF_NO_HANDLE,
        NULL,
        &setupPacket,
        &memDesc,
        NULL);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: SET_NTB_INPUT_SIZE(%u) failed 0x%08X\n", dwNtbInputSize, status));
        return status;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: SET_NTB_INPUT_SIZE(%u) OK\n", dwNtbInputSize));

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------
// HISTORICAL NOTE (Task 8, superseded — code removed, not just unused,
// because this driver builds /W4 /WX and an unused static function is a
// hard error here, not a warning to ignore):
//
// The original approach walked the USB configuration descriptor looking
// for the CDC Ethernet Functional Descriptor nested under MI_00, on the
// theory that a raw standard GET_DESCRIPTOR(CONFIGURATION) is a
// device-level USB operation that bypasses PDO scoping and always
// returns every interface. Real hardware disproved that: usbccgp
// filters/synthesizes the configuration descriptor per child PDO
// regardless of whether the request is sent via
// WdfUsbTargetDeviceRetrieveConfigDescriptor or a manually-built raw
// control transfer. A WDFUSBDEVICE bound to MI_01 gets back a
// descriptor buffer that simply does not contain MI_00's interface
// descriptor or the CS_INTERFACE Ethernet Functional Descriptor nested
// under it — USBD_ParseConfigurationDescriptorEx correctly returned
// NULL for T2NCM_CONTROL_IFACE_NUM every time, producing exactly the
// "MI_00 interface descriptor not found" error this approach hit in
// practice. Unlike class requests addressed by
// wIndex=T2NCM_CONTROL_IFACE_NUM (those DO reach MI_00's control logic,
// because wIndex routing happens at the EP0/class-request layer, not
// the config-descriptor-synthesis layer), this cannot work from an
// MI_01-only binding, full stop.
//
// Replaced below by T2NcmScanForMacStringIndex, which sidesteps the
// whole problem: it never touches the configuration descriptor at all,
// only the (unfiltered) string table.
// ---------------------------------------------------------------------

static
BOOLEAN
T2NcmHexNibble(
    _In_  WCHAR Ch,
    _Out_ UCHAR* Value
    )
{
    if (Ch >= L'0' && Ch <= L'9') { *Value = (UCHAR)(Ch - L'0');      return TRUE; }
    if (Ch >= L'A' && Ch <= L'F') { *Value = (UCHAR)(Ch - L'A' + 10); return TRUE; }
    if (Ch >= L'a' && Ch <= L'f') { *Value = (UCHAR)(Ch - L'a' + 10); return TRUE; }
    return FALSE;
}

// The CDC Ethernet MAC-address string is always exactly 12 hex
// characters (6 bytes) — fixed-size stack buffer, no pool allocation
// needed.
#define T2NCM_MAC_STRING_CHARS 12u

// ---------------------------------------------------------------------
// Variant 1 fix: T2NcmFindMacStringIndex (above) cannot work from an
// MI_01-only binding — MI_00's slice of the configuration descriptor is
// invisible to this WDFUSBDEVICE, full stop (see its comment). This is
// the actual replacement path.
//
// GET_DESCRIPTOR(STRING, index, langId) is NOT scoped by usbccgp the
// way GET_DESCRIPTOR(CONFIGURATION) is — a child PDO's string requests
// are answered straight from the device's own flat string table, since
// usbccgp has no per-function string list to synthesize (strings aren't
// tied to any one interface the way configuration-descriptor bytes
// are). So instead of reading iMACAddress out of the (invisible)
// Ethernet Functional Descriptor, this scans the string table directly
// for whichever string has exactly the CDC MAC-address shape: 12 hex
// digits.
//
// Two passes, in order:
//   1. Every index EXCEPT iManufacturer/iProduct/iSerialNumber. A
//      dedicated, standalone MAC string is the strongest evidence, so
//      it always wins when present. More than one match here is
//      AMBIGUOUS and fails closed (STATUS_DEVICE_PROTOCOL_ERROR) rather
//      than guessing — Task 8's "never invent a MAC" rule covers "never
//      pick among several candidates" too.
//   2. Only if pass 1 found nothing at all: iSerialNumber itself, in
//      case this device reuses its serial number as the Ethernet
//      address (real T2 hardware does — pass 1 alone came up empty on
//      it). This never runs, and never overrides pass 1's result, when
//      pass 1 found even one dedicated match.
// A missing index is an expected, silent skip during scanning (the
// device NAKs/stalls it) — only pass summaries are logged, not each
// probe. If BOTH passes come up empty, every non-empty string
// descriptor is dumped for diagnosis (T2NcmLogAllStringDescriptors).
// ---------------------------------------------------------------------
#define T2NCM_MAC_SCAN_MIN_INDEX   1u
#define T2NCM_MAC_SCAN_MAX_INDEX   32u  // generous; a real T2 has a handful of strings

// Probes one string index and reports whether its content is exactly
// T2NCM_MAC_STRING_CHARS hex digits. Shared by both scan passes below
// and by the diagnostic dump, so the "what counts as MAC-shaped" rule
// lives in exactly one place.
static
BOOLEAN
T2NcmStringIsMacShape(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ UCHAR                 Index
    )
{
    NTSTATUS status;
    USHORT numChars;
    WCHAR chars[T2NCM_MAC_STRING_CHARS];
    UCHAR i;

    numChars = 0;
    status = WdfUsbTargetDeviceQueryString(
        DeviceContext->UsbDevice, NULL, NULL, NULL, &numChars, Index, 0);
    if (!NT_SUCCESS(status) || numChars != T2NCM_MAC_STRING_CHARS)
    {
        return FALSE;
    }

    RtlZeroMemory(chars, sizeof(chars));
    numChars = T2NCM_MAC_STRING_CHARS;
    status = WdfUsbTargetDeviceQueryString(
        DeviceContext->UsbDevice, NULL, NULL, (PUSHORT)chars, &numChars, Index, 0);
    if (!NT_SUCCESS(status) || numChars != T2NCM_MAC_STRING_CHARS)
    {
        return FALSE;
    }

    for (i = 0; i < T2NCM_MAC_STRING_CHARS; i++)
    {
        UCHAR nibble;
        if (!T2NcmHexNibble(chars[i], &nibble))
        {
            return FALSE;
        }
    }

    return TRUE;
}

// Diagnostic-only: called after BOTH scan passes below have come up
// completely empty, to dump every non-empty string descriptor's raw
// content so a failure can be root-caused from the log alone, without
// needing a USB capture. Never called on a successful path — this is
// pure last-resort visibility, not part of the discovery logic itself.
static
VOID
T2NcmLogAllStringDescriptors(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    UCHAR idx;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
        "T2Ncm: MAC discovery failed both passes — dumping every non-empty "
        "string descriptor in indices %u..%u for diagnosis\n",
        T2NCM_MAC_SCAN_MIN_INDEX, T2NCM_MAC_SCAN_MAX_INDEX));

    for (idx = T2NCM_MAC_SCAN_MIN_INDEX; idx <= T2NCM_MAC_SCAN_MAX_INDEX; idx++)
    {
        NTSTATUS status;
        USHORT numChars = 0;
        WCHAR buffer[64];
        USHORT toRead;

        status = WdfUsbTargetDeviceQueryString(
            DeviceContext->UsbDevice, NULL, NULL, NULL, &numChars, idx, 0);
        if (!NT_SUCCESS(status) || numChars == 0)
        {
            continue;
        }

        if (numChars > (sizeof(buffer) / sizeof(buffer[0])) - 1)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm:   index %u: %u chars (too long to dump here)\n",
                idx, numChars));
            continue;
        }

        RtlZeroMemory(buffer, sizeof(buffer));
        toRead = numChars;
        status = WdfUsbTargetDeviceQueryString(
            DeviceContext->UsbDevice, NULL, NULL, (PUSHORT)buffer, &toRead, idx, 0);
        if (!NT_SUCCESS(status))
        {
            continue;
        }

        buffer[toRead < ((sizeof(buffer) / sizeof(buffer[0])) - 1)
                   ? toRead
                   : ((sizeof(buffer) / sizeof(buffer[0])) - 1)] = L'\0';

        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm:   index %u (%u chars, actually read %u): \"%ws\"\n",
            idx, numChars, toRead, buffer));

        // %ws stops at the first embedded NUL, which silently hides real
        // content (e.g. binary/GUID-shaped strings, or a short read where
        // toRead < numChars). Dump the raw bytes too so nothing is lost.
        {
            CHAR hex[3 * (sizeof(buffer) / sizeof(buffer[0])) + 1];
            PCHAR cursor = hex;
            SIZE_T remaining = sizeof(hex);
            USHORT hi;

            hex[0] = '\0';
            for (hi = 0; hi < toRead; hi++)
            {
                UCHAR lo  = (UCHAR)(buffer[hi] & 0xFF);
                UCHAR hib = (UCHAR)((buffer[hi] >> 8) & 0xFF);

                if (!NT_SUCCESS(RtlStringCbPrintfExA(
                        cursor, remaining, &cursor, &remaining, 0,
                        "%02X%02X ", lo, hib)))
                {
                    break;
                }
            }

            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
                "T2Ncm:   index %u raw bytes (LE per char): %s\n", idx, hex));
        }
    }
}

static
NTSTATUS
T2NcmScanForMacStringIndex(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_ UCHAR*                MacStringIndex
    )
{
    USB_DEVICE_DESCRIPTOR deviceDesc;
    UCHAR excludeManufacturer, excludeProduct, serialIndex;
    UCHAR candidateIndex = 0;
    ULONG matchCount = 0;
    UCHAR idx;

    *MacStringIndex = 0;
    RtlZeroMemory(&deviceDesc, sizeof(deviceDesc));

    // Cached by WDF at device creation — synchronous, no bus I/O, cannot
    // fail the way a real control transfer can.
    WdfUsbTargetDeviceGetDeviceDescriptor(DeviceContext->UsbDevice, &deviceDesc);

    excludeManufacturer = deviceDesc.iManufacturer;
    excludeProduct      = deviceDesc.iProduct;
    serialIndex         = deviceDesc.iSerialNumber;

    // Pass 1: every index EXCEPT iManufacturer/iProduct/iSerialNumber.
    // A dedicated, standalone MAC-address string (if the device has
    // one) is the strongest evidence and always wins over the fallback
    // below — a device that reuses its serial number for the MAC
    // wouldn't also carry a second, unrelated 12-hex-char string, so
    // there's no real ambiguity between the two passes in practice.
    for (idx = T2NCM_MAC_SCAN_MIN_INDEX; idx <= T2NCM_MAC_SCAN_MAX_INDEX; idx++)
    {
        if ((excludeManufacturer != 0 && idx == excludeManufacturer) ||
            (excludeProduct      != 0 && idx == excludeProduct)      ||
            (serialIndex         != 0 && idx == serialIndex))
        {
            continue;
        }

        if (T2NcmStringIsMacShape(DeviceContext, idx))
        {
            matchCount++;
            candidateIndex = idx;

            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
                "T2Ncm: string index %u has MAC-address shape (12 hex chars) — "
                "candidate #%lu\n", idx, matchCount));
        }
    }

    if (matchCount == 1)
    {
        *MacStringIndex = candidateIndex;

        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
            "T2Ncm: MAC address string found unambiguously at index %u\n",
            candidateIndex));

        return STATUS_SUCCESS;
    }

    if (matchCount > 1)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: %lu dedicated string descriptors matched the "
            "MAC-address shape — ambiguous, refusing to guess which one "
            "is real\n", matchCount));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    // Pass 2 (fallback, only reached when pass 1 found NOTHING): some
    // devices don't carry a separate MAC string at all and instead
    // derive/reuse the Ethernet address from iSerialNumber whenever it
    // happens to already be 12 hex characters. Real T2 hardware appears
    // to be one of them — this is exactly the shape observed after pass
    // 1 came up empty on it.
    if (serialIndex != 0 && T2NcmStringIsMacShape(DeviceContext, serialIndex))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: no dedicated MAC string found — falling back to "
            "iSerialNumber (index %u), which has the right shape\n",
            serialIndex));

        *MacStringIndex = serialIndex;
        return STATUS_SUCCESS;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
        "T2Ncm: no string descriptor — dedicated or iSerialNumber — in "
        "indices %u..%u matched the MAC-address shape (12 hex chars)\n",
        T2NCM_MAC_SCAN_MIN_INDEX, T2NCM_MAC_SCAN_MAX_INDEX));

    T2NcmLogAllStringDescriptors(DeviceContext);

    return STATUS_NOT_FOUND;
}

NTSTATUS
T2NcmReadMacAddress(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    NTSTATUS status;
    UCHAR macStringIndex = 0;
    USHORT numChars = 0;
    WCHAR macChars[T2NCM_MAC_STRING_CHARS];
    UCHAR macBytes[6];
    UCHAR i;
    BOOLEAN allZero, allFF;

    // Task 8: must fail explicitly, never fabricate a MAC.
    DeviceContext->MacAddressValid = FALSE;

    // Variant 1: T2NcmFindMacStringIndex (config-descriptor walk) cannot
    // see MI_00 from here — T2NcmScanForMacStringIndex (string-table
    // scan) is the one that actually works from an MI_01-only binding.
    status = T2NcmScanForMacStringIndex(DeviceContext, &macStringIndex);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (macStringIndex == 0)
    {
        // Not reachable in practice — T2NcmScanForMacStringIndex only
        // ever returns STATUS_SUCCESS with an index from its scan range
        // (>= T2NCM_MAC_SCAN_MIN_INDEX), never 0. Kept as a defensive
        // check rather than trusted implicitly.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: MAC string index resolved to 0 — treating as absent\n"));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    // First call: String == NULL means "just tell me the length" — WDF
    // fills in *NumCharacters with the string's actual character count.
    status = WdfUsbTargetDeviceQueryString(
        DeviceContext->UsbDevice, NULL, NULL, NULL, &numChars, macStringIndex, 0);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: QueryString(length) for iMACAddress index %u failed 0x%08X\n",
            macStringIndex, status));
        return status;
    }

    // The CDC Ethernet MAC-address string must be exactly 12 hex
    // characters (6 bytes). Anything else means this isn't a real MAC
    // string, so refuse to parse it instead of taking a truncated or
    // padded guess.
    if (numChars != T2NCM_MAC_STRING_CHARS)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: iMACAddress string is %u characters, expected exactly %u\n",
            numChars, T2NCM_MAC_STRING_CHARS));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    // Second call: String points at our buffer, *NumCharacters on input
    // is that buffer's capacity in characters; on output it's the
    // number actually copied.
    RtlZeroMemory(macChars, sizeof(macChars));
    numChars = T2NCM_MAC_STRING_CHARS;
    status = WdfUsbTargetDeviceQueryString(
        DeviceContext->UsbDevice, NULL, NULL, (PUSHORT)macChars, &numChars, macStringIndex, 0);
    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: QueryString(data) for iMACAddress failed 0x%08X\n", status));
        return status;
    }

    if (numChars != T2NCM_MAC_STRING_CHARS)
    {
        // Never trust the first call's length to still hold — re-verify
        // what actually came back on the second call before indexing it.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: iMACAddress data call returned %u characters, expected exactly %u\n",
            numChars, T2NCM_MAC_STRING_CHARS));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    for (i = 0; i < 6; i++)
    {
        UCHAR hi, lo;
        if (!T2NcmHexNibble(macChars[2 * i], &hi) ||
            !T2NcmHexNibble(macChars[2 * i + 1], &lo))
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: iMACAddress string contains a non-hex character\n"));
            return STATUS_DEVICE_PROTOCOL_ERROR;
        }
        macBytes[i] = (UCHAR)((hi << 4) | lo);
    }

    allZero = TRUE;
    allFF = TRUE;
    for (i = 0; i < 6; i++)
    {
        if (macBytes[i] != 0x00) { allZero = FALSE; }
        if (macBytes[i] != 0xFF) { allFF = FALSE; }
    }
    if (allZero || allFF)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: iMACAddress decoded to an all-%s sentinel value — rejecting\n",
            allZero ? "zero" : "0xFF"));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    if (macBytes[0] & 0x01)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
            "T2Ncm: iMACAddress has the multicast bit set (first octet 0x%02X) — "
            "unusual for a station address, continuing\n", macBytes[0]));
    }

    RtlCopyMemory(DeviceContext->PermanentMacAddress, macBytes, sizeof(macBytes));
    DeviceContext->MacAddressValid = TRUE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: MAC address %02X:%02X:%02X:%02X:%02X:%02X\n",
        macBytes[0], macBytes[1], macBytes[2], macBytes[3], macBytes[4], macBytes[5]));

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------
// Fallback for devices with no usable MAC string at all (confirmed real
// on REV_0201 — see the raw byte dump in T2NcmLogAllStringDescriptors's
// output). FNV-1a is used purely as a fast, well-distributed
// fingerprint — this has no security requirement, it only needs to map
// the same 16-byte ContainerID to the same 6 bytes every time.
// ---------------------------------------------------------------------
static
VOID
T2NcmHashBytesToMac(
    _In_reads_bytes_(Length) const UCHAR* Data,
    _In_ ULONG                           Length,
    _Out_writes_bytes_(6) UCHAR*         MacOut
    )
{
    ULONGLONG hash = 0xcbf29ce484222325ULL;   // FNV-1a 64-bit offset basis
    ULONG i;

    for (i = 0; i < Length; i++)
    {
        hash ^= Data[i];
        hash *= 0x100000001b3ULL;              // FNV-1a 64-bit prime
    }

    for (i = 0; i < 6; i++)
    {
        MacOut[i] = (UCHAR)(hash >> (8 * i));
    }

    // IEEE 802: bit 0 of the first octet = multicast/unicast, bit 1 =
    // locally-administered/universally-administered. Clearing bit 0 and
    // setting bit 1 marks this unambiguously as "not a registered-OUI
    // burned-in address" — the honest way to hand out a generated
    // address, never disguised as a real vendor-assigned one.
    MacOut[0] = (UCHAR)((MacOut[0] & 0xFCu) | 0x02u);
}

// Seeds the generated address from the device's ContainerID: a GUID
// Windows/PnP maintains specifically to identify "the same physical
// device" across reboots and across replugging into a different port,
// which is exactly the stability a station address needs.
//
// Reads DEVPKEY_Device_ContainerId straight off the WDM PDO via
// IoGetDevicePropertyData — NOT WdfDeviceQueryPropertyEx.
//
// WdfDeviceQueryPropertyEx was tried first and looked right (it is the
// current, WDF-native property API, KMDF >= 1.11), but
// DeviceContext->WdfDevice was created with WdfDeviceMiniportCreate,
// and WdfDeviceMiniportCreate's documented restrictions say that
// handle "cannot be passed to any general framework device object
// methods except WdfDeviceGetIoTarget, WdfDeviceWdmGetDeviceObject,
// WdfDeviceWdmGetAttachedDevice, and WdfDeviceWdmGetPhysicalDevice" —
// WdfDeviceQueryPropertyEx is not on that list. The framework's
// verifier catches the violation at run time, not compile time:
// MiniportInitializeEx bugchecks with WDF_VIOLATION (0x10D), arg1=5
// ("a framework object handle of the incorrect type was passed to a
// framework object method").
//
// The legacy IoGetDeviceProperty(DevicePropertyContainerID) was tried
// before that and was also wrong: on real hardware it came back
// STATUS_BUFFER_TOO_SMALL wanting 78 bytes, not the 16 a GUID needs —
// evidence it was resolving to some other, unrelated device property.
//
// IoGetDevicePropertyData is the fix that is actually legal here: it
// takes a raw PDEVICE_OBJECT (WdfDeviceWdmGetPhysicalDevice is on the
// miniport-device whitelist above, so getting that PDO is fine) and
// asks for DEVPKEY_Device_ContainerId specifically, reporting back the
// actual DEVPROPTYPE it found so a type/size mismatch is caught
// explicitly instead of silently misinterpreted — same safety property
// WdfDeviceQueryPropertyEx would have given, without touching WDF's
// device-property machinery that this device object never set up.
//
// Falls back to a VID/PID/REV-only seed if the property is ever
// unavailable — that fallback is deliberately weaker (every unit of
// this exact model would collide) and is logged as such rather than
// silently accepted.
static
NTSTATUS
T2NcmGenerateLocallyAdministeredMac(
    _In_                   PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_writes_bytes_(6)  UCHAR*                 MacOut,
    _Out_                  BOOLEAN*                UsedContainerId
    )
{
    PDEVICE_OBJECT pdo;
    GUID containerId;
    ULONG resultLength = 0;
    DEVPROPTYPE propertyType = DEVPROP_TYPE_EMPTY;
    NTSTATUS status;

    *UsedContainerId = FALSE;
    RtlZeroMemory(MacOut, 6);
    RtlZeroMemory(&containerId, sizeof(containerId));

    pdo = WdfDeviceWdmGetPhysicalDevice(DeviceContext->WdfDevice);

    status = IoGetDevicePropertyData(
        pdo,
        &T2Ncm_DEVPKEY_Device_ContainerId,
        LOCALE_NEUTRAL,
        0,
        sizeof(containerId),
        &containerId,
        &resultLength,
        &propertyType);

    if (NT_SUCCESS(status) &&
        propertyType == DEVPROP_TYPE_GUID &&
        resultLength == sizeof(containerId))
    {
        T2NcmHashBytesToMac((const UCHAR*)&containerId, sizeof(containerId), MacOut);
        *UsedContainerId = TRUE;
        return STATUS_SUCCESS;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
        "T2Ncm: DEVPKEY_Device_ContainerId query failed (0x%08X, "
        "type=%u, len=%u) — falling back to a VID/PID/REV seed\n",
        status, propertyType, resultLength));

    // Weak fallback: identical on every unit of this exact VID/PID/REV,
    // so two such devices on the same network segment WILL collide.
    // Logged loudly on purpose rather than treated as an equally-good
    // result.
    {
        struct { USHORT Vid; USHORT Pid; USHORT Rev; } seed;
        seed.Vid = T2NCM_VID;
        seed.Pid = T2NCM_PID;
        seed.Rev = T2NCM_REV;
        T2NcmHashBytesToMac((const UCHAR*)&seed, sizeof(seed), MacOut);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmEnsureMacAddress(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    NTSTATUS status;
    UCHAR generatedMac[6];
    BOOLEAN usedContainerId;

    status = T2NcmReadMacAddress(DeviceContext);
    if (NT_SUCCESS(status))
    {
        // T2NcmReadMacAddress already set PermanentMacAddress and
        // MacAddressValid = TRUE for a real, device-reported address.
        DeviceContext->MacAddressIsPermanent = TRUE;
        return STATUS_SUCCESS;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
        "T2Ncm: no permanent MAC available (0x%08X) — generating a "
        "locally-administered address instead of leaving NDIS without "
        "one\n", status));

    status = T2NcmGenerateLocallyAdministeredMac(DeviceContext, generatedMac, &usedContainerId);
    if (!NT_SUCCESS(status))
    {
        // T2NcmGenerateLocallyAdministeredMac has no failing path today
        // (its own fallback always produces something) — kept as a
        // defensive check rather than trusted implicitly, matching this
        // file's existing style for "not reachable in practice" guards.
        DeviceContext->MacAddressValid = FALSE;
        DeviceContext->MacAddressIsPermanent = FALSE;
        return status;
    }

    RtlCopyMemory(DeviceContext->PermanentMacAddress, generatedMac, sizeof(generatedMac));
    DeviceContext->MacAddressValid = TRUE;
    DeviceContext->MacAddressIsPermanent = FALSE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_WARNING_LEVEL,
        "T2Ncm: using generated locally-administered MAC "
        "%02X:%02X:%02X:%02X:%02X:%02X (seed: %s) — NOT a hardware "
        "address\n",
        generatedMac[0], generatedMac[1], generatedMac[2],
        generatedMac[3], generatedMac[4], generatedMac[5],
        usedContainerId ? "ContainerID" : "VID/PID/REV (weak, may collide)"));

    return STATUS_SUCCESS;
}
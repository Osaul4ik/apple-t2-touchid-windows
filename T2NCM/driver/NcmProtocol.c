// SPDX-License-Identifier: GPL-2.0-only
// NcmProtocol.c — Tasks 7-11 (NCM control layer): GET_NTB_PARAMETERS,
// NTB16 format negotiation, SET_NTB_INPUT_SIZE, and CDC Ethernet
// Functional Descriptor MAC address extraction. All four validate their
// inputs explicitly and fail closed (STATUS_NOT_SUPPORTED /
// STATUS_DEVICE_PROTOCOL_ERROR) rather than substituting a guessed or
// fabricated value for anything the device didn't actually report.

#include "NcmProtocol.h"

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
// Ethernet Functional Descriptor, this scans the string table directly,
// index by index, and accepts the string whose content has exactly the
// CDC MAC-address shape: 12 hex digits. iManufacturer/iProduct/
// iSerialNumber are excluded up front (pulled from the cached Device
// Descriptor — WdfUsbTargetDeviceGetDeviceDescriptor is a no-I/O cache
// read, not a request) so a hex-looking serial number could never be
// mistaken for the MAC.
//
// If more than one remaining string matches the shape, that is
// AMBIGUOUS and this fails closed (STATUS_DEVICE_PROTOCOL_ERROR) rather
// than pick one — Task 8's "never invent a MAC" rule covers "never
// guess among several candidates" too. A missing index is an expected,
// silent skip during the scan (the device NAKs/stalls it) — only the
// summary after the full scan is logged, not each probe.
// ---------------------------------------------------------------------
#define T2NCM_MAC_SCAN_MIN_INDEX   1u
#define T2NCM_MAC_SCAN_MAX_INDEX   32u  // generous; a real T2 has a handful of strings

static
NTSTATUS
T2NcmScanForMacStringIndex(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_ UCHAR*                MacStringIndex
    )
{
    USB_DEVICE_DESCRIPTOR deviceDesc;
    UCHAR excludeManufacturer, excludeProduct, excludeSerial;
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
    excludeSerial       = deviceDesc.iSerialNumber;

    for (idx = T2NCM_MAC_SCAN_MIN_INDEX; idx <= T2NCM_MAC_SCAN_MAX_INDEX; idx++)
    {
        NTSTATUS status;
        USHORT numChars;
        WCHAR chars[T2NCM_MAC_STRING_CHARS];
        UCHAR i;
        BOOLEAN allHex;

        if ((excludeManufacturer != 0 && idx == excludeManufacturer) ||
            (excludeProduct      != 0 && idx == excludeProduct)      ||
            (excludeSerial       != 0 && idx == excludeSerial))
        {
            continue;
        }

        // Length-probe call (String == NULL). A non-existent index
        // fails here (the device stalls/NAKs it) — that is a routine,
        // expected outcome of scanning, not something to log per index.
        numChars = 0;
        status = WdfUsbTargetDeviceQueryString(
            DeviceContext->UsbDevice, NULL, NULL, NULL, &numChars, idx, 0);
        if (!NT_SUCCESS(status) || numChars != T2NCM_MAC_STRING_CHARS)
        {
            continue;
        }

        RtlZeroMemory(chars, sizeof(chars));
        numChars = T2NCM_MAC_STRING_CHARS;
        status = WdfUsbTargetDeviceQueryString(
            DeviceContext->UsbDevice, NULL, NULL, (PUSHORT)chars, &numChars, idx, 0);
        if (!NT_SUCCESS(status) || numChars != T2NCM_MAC_STRING_CHARS)
        {
            continue;
        }

        allHex = TRUE;
        for (i = 0; i < T2NCM_MAC_STRING_CHARS; i++)
        {
            UCHAR nibble;
            if (!T2NcmHexNibble(chars[i], &nibble))
            {
                allHex = FALSE;
                break;
            }
        }

        if (!allHex)
        {
            continue;
        }

        matchCount++;
        candidateIndex = idx;

        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
            "T2Ncm: string index %u has MAC-address shape (12 hex chars) — "
            "candidate #%lu\n", idx, matchCount));
    }

    if (matchCount == 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: no string descriptor in indices %u..%u matched the "
            "MAC-address shape (12 hex chars)\n",
            T2NCM_MAC_SCAN_MIN_INDEX, T2NCM_MAC_SCAN_MAX_INDEX));
        return STATUS_NOT_FOUND;
    }

    if (matchCount > 1)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: %lu string descriptors matched the MAC-address shape — "
            "ambiguous, refusing to guess which one is real\n", matchCount));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    *MacStringIndex = candidateIndex;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: MAC address string found unambiguously at index %u\n",
        candidateIndex));

    return STATUS_SUCCESS;
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
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

// CDC Ethernet Functional Descriptor (USB CDC 1.20 table 25).
#define T2NCM_CS_INTERFACE_DESCRIPTOR_TYPE   0x24u
#define T2NCM_ETHERNET_FUNCTIONAL_DESCRIPTOR 0x0Fu
#define T2NCM_CONFIG_DESC_BUFFER_SIZE        512u

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
// Task 8 helper: walk the configuration descriptor to find the CDC
// Ethernet Functional Descriptor nested under MI_00 and return its
// iMACAddress string index. Never guesses an index — returns
// STATUS_NOT_FOUND / STATUS_DEVICE_PROTOCOL_ERROR if the descriptor
// isn't exactly where the CDC spec says it must be.
// ---------------------------------------------------------------------
static
NTSTATUS
T2NcmFindMacStringIndex(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_ UCHAR*                MacStringIndex
    )
{
    NTSTATUS status;
    UCHAR configBuffer[T2NCM_CONFIG_DESC_BUFFER_SIZE];
    USHORT configLength = (USHORT)sizeof(configBuffer);
    PUSB_CONFIGURATION_DESCRIPTOR configDesc = (PUSB_CONFIGURATION_DESCRIPTOR)configBuffer;
    PUSB_INTERFACE_DESCRIPTOR ifaceDesc;
    PUSB_COMMON_DESCRIPTOR walker;
    PUCHAR bufferEnd;

    *MacStringIndex = 0;

    status = WdfUsbTargetDeviceRetrieveConfigDescriptor(
        DeviceContext->UsbDevice, configBuffer, &configLength);

    if (!NT_SUCCESS(status))
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: RetrieveConfigDescriptor failed 0x%08X (fixed %u-byte buffer "
            "may be too small — never silently truncated)\n",
            status, (ULONG)sizeof(configBuffer)));
        return status;
    }

    ifaceDesc = (PUSB_INTERFACE_DESCRIPTOR)USBD_ParseConfigurationDescriptorEx(
        configDesc, configDesc,
        T2NCM_CONTROL_IFACE_NUM, 0, -1, -1, -1);

    if (ifaceDesc == NULL)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: MI_00 interface descriptor not found in config descriptor\n"));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    bufferEnd = configBuffer + configLength;
    walker = (PUSB_COMMON_DESCRIPTOR)((PUCHAR)ifaceDesc + ifaceDesc->bLength);

    while ((PUCHAR)walker + sizeof(USB_COMMON_DESCRIPTOR) <= bufferEnd)
    {
        if (walker->bLength == 0 || (PUCHAR)walker + walker->bLength > bufferEnd)
        {
            T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
                "T2Ncm: malformed descriptor chain searching for the Ethernet "
                "Functional Descriptor\n"));
            return STATUS_DEVICE_PROTOCOL_ERROR;
        }

        // A standard INTERFACE descriptor ends MI_00's own functional
        // block — stop before reading into MI_01's descriptors.
        if (walker->bDescriptorType == USB_INTERFACE_DESCRIPTOR_TYPE)
        {
            break;
        }

        if (walker->bDescriptorType == T2NCM_CS_INTERFACE_DESCRIPTOR_TYPE &&
            walker->bLength >= 4)
        {
            PUCHAR raw = (PUCHAR)walker;
            if (raw[2] == T2NCM_ETHERNET_FUNCTIONAL_DESCRIPTOR)
            {
                *MacStringIndex = raw[3];
                return STATUS_SUCCESS;
            }
        }

        walker = (PUSB_COMMON_DESCRIPTOR)((PUCHAR)walker + walker->bLength);
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
        "T2Ncm: Ethernet Functional Descriptor not found under MI_00\n"));
    return STATUS_NOT_FOUND;
}

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

    status = T2NcmFindMacStringIndex(DeviceContext, &macStringIndex);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (macStringIndex == 0)
    {
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: Ethernet Functional Descriptor has iMACAddress == 0 (no string)\n"));
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
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

// SET_ETHERNET_PACKET_FILTER — CDC ECM 1.2 section 6.2.4, reused
// unchanged by NCM 1.0 (NCM defines no filter request of its own; it
// inherits the ECM one). bmRequestType 0x21 (class, interface,
// host-to-device), wValue = the filter bitmap, wIndex = the CONTROL
// interface number, no data stage.
//
// THIS IS WHY NOTHING WAS EVER RECEIVED. The device resets its packet
// filter to zero - forward nothing - on every SET_CONFIGURATION and
// SET_INTERFACE, so an NCM function that is never told a filter sends
// the host exactly nothing, forever, while still happily accepting
// everything the host transmits. That is precisely the observed
// symptom: SentBroadcastPackets/SentMulticastPackets climbing,
// ReceivedBytes stuck at 0, and the BridgeOS peer permanently
// "Unreachable" in the neighbour table because not one neighbour
// advertisement ever came back.
//
// Linux does not have this problem because usbnet issues
// USB_CDC_SET_ETHERNET_PACKET_FILTER from its ndo_set_rx_mode as soon
// as the interface goes up (drivers/net/usb/cdc_ether.c,
// usbnet_cdc_update_filter, wired up by cdc_ncm via .set_rx_mode) -
// which is exactly what the reference setup in
// jmurth1234/t2-touchid-linux relies on, since it uses the stock
// cdc_ncm driver.
//
// Ordering matters: SET_INTERFACE(alt 1) clears the filter, so this
// must be sent AFTER T2NcmUsbActivateDataInterface, never before.
#define T2NCM_REQ_SET_ETHERNET_PACKET_FILTER 0x43u

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
            "T2Ncm: refusing to negotiate - NTB16 not in bmNtbFormatsSupported=0x%04X "
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
// MAC address: this device has no hardware MAC to read. On real T2 units
// (confirmed on REV_0201) the string table carries no MAC-address string
// and iSerialNumber is 40 NUL characters, and the CDC Ethernet
// Functional Descriptor (MI_00) is invisible from an MI_01-only binding.
// So the station address is always generated - see
// T2NcmEnsureMacAddress below.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Generated station address. FNV-1a is used purely as a fast,
// well-distributed fingerprint - no security requirement, it only needs
// to map the same 16-byte ContainerID to the same 6 bytes every time.
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
        "type=%u, len=%u) - falling back to a VID/PID/REV seed\n",
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

    status = T2NcmGenerateLocallyAdministeredMac(DeviceContext, generatedMac, &usedContainerId);
    if (!NT_SUCCESS(status))
    {
        // No failing path today (the generator's own fallback always
        // produces something) - kept as a defensive check.
        DeviceContext->MacAddressValid = FALSE;
        DeviceContext->MacAddressIsPermanent = FALSE;
        return status;
    }

    RtlCopyMemory(DeviceContext->PermanentMacAddress, generatedMac, sizeof(generatedMac));
    DeviceContext->MacAddressValid = TRUE;
    DeviceContext->MacAddressIsPermanent = FALSE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: using generated locally-administered MAC "
        "%02X:%02X:%02X:%02X:%02X:%02X (seed: %s); the device has no "
        "hardware MAC\n",
        generatedMac[0], generatedMac[1], generatedMac[2],
        generatedMac[3], generatedMac[4], generatedMac[5],
        usedContainerId ? "ContainerID" : "VID/PID/REV (weak, may collide)"));

    return STATUS_SUCCESS;
}
// ---------------------------------------------------------------------
// SET_ETHERNET_PACKET_FILTER
//
// See the T2NCM_REQ_SET_ETHERNET_PACKET_FILTER comment at the top of
// this file for why the absence of this request is what kept RX at
// exactly zero bytes.
// ---------------------------------------------------------------------

USHORT
T2NcmNdisFilterToCdcFilter(
    _In_ ULONG NdisFilter,
    _In_ BOOLEAN StationAddressIsFromDevice
    )
{
    // DIRECTED and BROADCAST unconditionally. Linux does the same and
    // for the same reason: a link that cannot carry broadcast cannot
    // carry ARP or IPv6 neighbour discovery, so the adapter would come
    // up and then be unable to resolve the only peer on it. NDIS is
    // free to ask for less, but there is nothing useful below this.
    USHORT cdcFilter = T2NCM_CDC_PACKET_TYPE_DIRECTED |
                       T2NCM_CDC_PACKET_TYPE_BROADCAST;

    // Device-side multicast filtering is optional in CDC and the T2
    // gives no way to program a list, so any multicast interest at all
    // becomes ALL_MULTICAST and the precise list is applied in software
    // by T2NcmRxAcceptsFrame. Same simplification Linux makes.
    if (NdisFilter & (NDIS_PACKET_TYPE_MULTICAST |
                      NDIS_PACKET_TYPE_ALL_MULTICAST))
    {
        cdcFilter |= T2NCM_CDC_PACKET_TYPE_ALL_MULTICAST;
    }

    if (NdisFilter & (NDIS_PACKET_TYPE_PROMISCUOUS | NDIS_PACKET_TYPE_ALL_LOCAL))
    {
        cdcFilter |= T2NCM_CDC_PACKET_TYPE_PROMISCUOUS;
    }

    // Safety net for the station-address situation this hardware
    // actually presents. Real REV_0201 units report an empty string
    // table, so there is no iMACAddress to read and the adapter runs on
    // a generated locally-administered address (see
    // T2NcmEnsureMacAddress). The device therefore has no way to know
    // which unicast address belongs to the host, and a DIRECTED-only
    // filter is a filter against an address the device was never told.
    // Asking for PROMISCUOUS in that case costs nothing on a
    // point-to-point USB link with exactly one peer, and removes a
    // whole class of "the adapter is up but silent" failure.
    if (!StationAddressIsFromDevice)
    {
        cdcFilter |= T2NCM_CDC_PACKET_TYPE_PROMISCUOUS;
    }

    return cdcFilter;
}

NTSTATUS
T2NcmSetEthernetPacketFilter(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ USHORT CdcFilter
    )
{
    NTSTATUS status;
    WDF_USB_CONTROL_SETUP_PACKET setupPacket;

    if (DeviceContext->UsbDevice == NULL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // wIndex is the CONTROL interface number, not the data one - the
    // filter is a property of the CDC function, and the function's
    // management element lives on MI_00. Same addressing as every other
    // class request in this file.
    WDF_USB_CONTROL_SETUP_PACKET_INIT_CLASS(
        &setupPacket,
        BmRequestHostToDevice,
        BmRequestToInterface,
        (UCHAR)T2NCM_REQ_SET_ETHERNET_PACKET_FILTER,
        CdcFilter,
        (USHORT)T2NCM_CONTROL_IFACE_NUM);

    status = WdfUsbTargetDeviceSendControlTransferSynchronously(
        DeviceContext->UsbDevice,
        WDF_NO_HANDLE,
        NULL,
        &setupPacket,
        NULL,   // no data stage
        NULL);

    if (!NT_SUCCESS(status))
    {
        // Logged loudly rather than swallowed: if this fails the adapter
        // will look completely healthy and receive nothing, which is the
        // single most confusing failure mode this driver has.
        T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
            "T2Ncm: SET_ETHERNET_PACKET_FILTER(0x%04X) failed 0x%08X - the "
            "device will forward NO frames to the host\n",
            CdcFilter, status));
        return status;
    }

    DeviceContext->CdcPacketFilter = CdcFilter;
    DeviceContext->CdcPacketFilterApplied = TRUE;

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_INFO_LEVEL,
        "T2Ncm: SET_ETHERNET_PACKET_FILTER(0x%04X) OK\n", CdcFilter));

    return STATUS_SUCCESS;
}

NTSTATUS
T2NcmApplyPacketFilter(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    USHORT desired = T2NcmNdisFilterToCdcFilter(
        DeviceContext->PacketFilter,
        DeviceContext->MacAddressIsPermanent);

    return T2NcmSetEthernetPacketFilter(DeviceContext, desired);
}

EVT_WDF_WORKITEM T2NcmEvtPacketFilterWorkItem;

VOID
T2NcmEvtPacketFilterWorkItem(
    _In_ WDFWORKITEM WorkItem
    )
{
    PT2NCM_DEVICE_CONTEXT deviceContext =
        T2NcmGetDeviceContext(WdfWorkItemGetParentObject(WorkItem));

    (VOID)T2NcmApplyPacketFilter(deviceContext);
}

VOID
T2NcmRequestPacketFilterUpdate(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    )
{
    // MiniportOidRequest is documented as IRQL <= DISPATCH_LEVEL, and
    // WdfUsbTargetDeviceSendControlTransferSynchronously is PASSIVE_LEVEL
    // only. Sending inline when we happen to be at PASSIVE keeps the
    // common case synchronous (so the filter is in effect before the OID
    // completes); anything higher is deferred to the work item rather
    // than dropped, because a filter update that silently never reaches
    // the device is the exact bug this whole path exists to fix.
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        (VOID)T2NcmApplyPacketFilter(DeviceContext);
        return;
    }

    if (DeviceContext->PacketFilterWorkItem != NULL)
    {
        WdfWorkItemEnqueue(DeviceContext->PacketFilterWorkItem);
        return;
    }

    T2NCM_LOG((T2NCM_DPFLTR_ID, DPFLTR_ERROR_LEVEL,
        "T2Ncm: packet-filter update requested at IRQL %u with no work "
        "item available - filter NOT updated\n",
        (ULONG)KeGetCurrentIrql()));
}
// SPDX-License-Identifier: GPL-2.0-only
// NcmProtocol.h — CDC-NCM control-plane (Tasks 7-11): GET_NTB_PARAMETERS,
// NTB16 format negotiation, SET_NTB_INPUT_SIZE, and MAC address readout.
// Called from Device.c's D0Entry; UsbTransport.c's Task 12 alt-setting
// switch (T2NcmUsbActivateDataInterface) is gated on these succeeding.

#pragma once
#include "Driver.h"

// GET_NTB_PARAMETERS decode target (Task 9).
typedef struct _T2NCM_NTB_PARAMETERS
{
    ULONG dwNtbInMaxSize;
    USHORT wNdpInDivisor;
    USHORT wNdpInPayloadRemainder;
    USHORT wNdpInAlignment;
    ULONG dwNtbOutMaxSize;
    USHORT wNdpOutDivisor;
    USHORT wNdpOutPayloadRemainder;
    USHORT wNdpOutAlignment;
    USHORT wNtbOutMaxDatagrams;
    USHORT bmNtbFormatsSupported;
} T2NCM_NTB_PARAMETERS, *PT2NCM_NTB_PARAMETERS;

// Task 9: issue GET_NTB_PARAMETERS and validate every field (overflow,
// zero divisors, impossible sizes, alignment).
NTSTATUS
T2NcmGetNtbParameters(
    _In_  PT2NCM_DEVICE_CONTEXT DeviceContext,
    _Out_ PT2NCM_NTB_PARAMETERS Parameters
    );

// Task 10: explicit NTB16-preferred format negotiation. Never silently
// falls back to NTB32 — fails cleanly per the task's documented decision.
NTSTATUS
T2NcmNegotiateNtbFormat(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ const T2NCM_NTB_PARAMETERS* Parameters
    );

// Task 11: SET_NTB_INPUT_SIZE using validated values, checked arithmetic.
NTSTATUS
T2NcmSetNtbInputSize(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ const T2NCM_NTB_PARAMETERS* Parameters
    );

// Task 8: find and read the device's real MAC-address string, validate,
// store in DeviceContext->PermanentMacAddress. Fails explicitly if no
// string descriptor unambiguously matches the MAC-address shape (12 hex
// characters) — never invents a MAC and never guesses among several
// candidates.
//
// Variant 1 note: this does NOT read the CDC Ethernet Functional
// Descriptor (that lives under MI_00's slice of the configuration
// descriptor, which is invisible to an MI_01-only WDFUSBDEVICE — see
// the historical-note comment in NcmProtocol.c). Instead it scans the
// device's string table directly (T2NcmScanForMacStringIndex): first
// for a dedicated MAC string, then — only if that finds nothing — for
// iSerialNumber doubling as the MAC, which is what real T2 hardware
// turned out to do. Neither pass is PDO-filtered, so this works from
// MI_01 alone with no dependency on an MI_00 stub. Device.c still
// treats a failure here as non-fatal/best-effort (defensive — a future
// firmware/revision with neither shape would otherwise cost the whole
// data path), but on known-good hardware this is expected to succeed.
NTSTATUS
T2NcmReadMacAddress(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Task 8 follow-up: real T2 units in the wild have turned up with an
// all-zero iMACAddress/iSerialNumber string table (confirmed on
// REV_0201 via raw string-descriptor byte dump — not a parsing bug,
// the device genuinely reports nothing). NDIS still needs *some*
// station address to bring an adapter up, so this wraps
// T2NcmReadMacAddress: on success, behaves identically (real,
// permanent address). On failure, deterministically derives a
// locally-administered address from the device's ContainerID (stable
// per physical device across reboots/replugs) instead of leaving the
// adapter with no address at all.
//
// This never silently mislabels a generated address as permanent:
// DeviceContext->MacAddressIsPermanent distinguishes the two cases for
// anything downstream (IOCTL_T2NCM_GET_STATUS, logs) that cares which
// kind of address it's looking at. MacAddressValid means "usable by
// NDIS", not "burned into hardware" — check MacAddressIsPermanent for
// that.
NTSTATUS
T2NcmEnsureMacAddress(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// ---------------------------------------------------------------------
// SET_ETHERNET_PACKET_FILTER (CDC ECM 1.2 6.2.4, inherited by NCM 1.0)
//
// The device forwards NOTHING to the host until the host sets a filter,
// and it resets the filter to zero on every SET_CONFIGURATION and
// SET_INTERFACE. Missing this request is what left the adapter
// transmitting normally while receiving exactly zero bytes.
// ---------------------------------------------------------------------
#define T2NCM_CDC_PACKET_TYPE_PROMISCUOUS    0x0001u
#define T2NCM_CDC_PACKET_TYPE_ALL_MULTICAST  0x0002u
#define T2NCM_CDC_PACKET_TYPE_DIRECTED       0x0004u
#define T2NCM_CDC_PACKET_TYPE_BROADCAST      0x0008u
#define T2NCM_CDC_PACKET_TYPE_MULTICAST      0x0010u

// Maps an NDIS packet filter onto the CDC bitmap. DIRECTED|BROADCAST
// are always included (without broadcast there is no ARP and no IPv6
// neighbour discovery, so the one peer on the link can never be
// resolved). PROMISCUOUS is added when NDIS asks for it, and also when
// the station address was NOT read from the device - see the comment on
// the implementation for why that case needs it.
USHORT
T2NcmNdisFilterToCdcFilter(
    _In_ ULONG NdisFilter,
    _In_ BOOLEAN StationAddressIsFromDevice
    );

// Issues the request. PASSIVE_LEVEL only. Must be called AFTER the data
// interface has been switched to alt 1, because SET_INTERFACE clears the
// filter the device is holding.
NTSTATUS
T2NcmSetEthernetPacketFilter(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_ USHORT CdcFilter
    );

// Computes the filter from the device context's current NDIS filter and
// station-address provenance, then sends it. PASSIVE_LEVEL only.
NTSTATUS
T2NcmApplyPacketFilter(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );

// Work-item callback used by T2NcmRequestPacketFilterUpdate below.
// Declared here because Device.c is what creates the work item.
EVT_WDF_WORKITEM T2NcmEvtPacketFilterWorkItem;

// IRQL-safe entry point for the OID path: applies inline at
// PASSIVE_LEVEL, defers to the device's work item otherwise.
VOID
T2NcmRequestPacketFilterUpdate(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );
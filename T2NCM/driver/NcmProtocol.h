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

// Task 8: the T2 has no hardware MAC (confirmed on REV_0201: no MAC string,
// iSerialNumber is all NULs). NDIS still needs a station address, so this
// deterministically derives a locally-administered one from the device's
// ContainerID (stable per physical device across reboots/replugs).
//
// DeviceContext->MacAddressIsPermanent is always FALSE (the address is
// generated, never a burned-in one). MacAddressValid means "usable by
// NDIS".
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
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
// device's string table directly (T2NcmScanForMacStringIndex), which is
// NOT PDO-filtered the way the configuration descriptor is, so it works
// from MI_01 alone with no dependency on an MI_00 stub. Device.c still
// treats a failure here as non-fatal/best-effort (defensive — a future
// firmware/revision without a clean 12-hex-char string would otherwise
// cost the whole data path), but on real T2 hardware this is expected
// to succeed every time.
NTSTATUS
T2NcmReadMacAddress(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );
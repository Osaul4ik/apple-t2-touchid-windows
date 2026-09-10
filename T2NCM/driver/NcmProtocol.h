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

// Task 8: read CDC Ethernet Functional Descriptor iMACAddress (string
// descriptor 6), validate, store in DeviceContext->PermanentMacAddress.
// Fails explicitly if the string descriptor is absent/invalid — never
// invents a MAC.
NTSTATUS
T2NcmReadMacAddress(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext
    );
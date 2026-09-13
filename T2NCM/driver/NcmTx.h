// SPDX-License-Identifier: GPL-2.0-only
// NcmTx.h — NTB16 TX builder + bulk-OUT engine (Tasks 13, 16).
//
// Same "prove the wire format on real hardware before anything is
// built on top of it" rationale as NcmRx.h. There is no NDIS layer yet
// (Tasks 18-20) to originate outgoing frames, so this milestone is
// exercised via IOCTL_T2NCM_SEND_TEST_FRAME (Device.c, public.h) —
// hand it one raw Ethernet frame, get back whether the NTB16-wrapped
// write actually reached the device.
#pragma once
#include "Driver.h"

// Wraps Frame in a single-datagram NTB16 (NTH16 + one NDP16 with one
// real entry and the required zero/zero terminator) and writes it to
// DeviceContext->BulkOutPipe synchronously. NDP16/datagram placement
// honors the device's negotiated NdpOutDivisor/PayloadRemainder/
// Alignment (driver.h) rather than assuming a fixed layout — those
// values came from GET_NTB_PARAMETERS specifically to tell the host
// where the device's OUT direction requires things to sit.
//
// Requires T2NcmUsbActivateDataInterface and a successful
// GET_NTB_PARAMETERS/SET_NTB_FORMAT/SET_NTB_INPUT_SIZE pass to have
// already populated BulkOutPipe/NtbOutMaxSize/NdpOut* — fails closed
// with STATUS_INVALID_DEVICE_STATE if they haven't.
//
// Frame must be a complete Ethernet II frame (dest+src+ethertype+
// payload, no FCS) between 14 and 1514 bytes — this milestone doesn't
// yet support jumbo frames; that needs MTU negotiation to land
// alongside Task 18-20's NDIS registration.
NTSTATUS
T2NcmTxSendFrame(
    _In_ PT2NCM_DEVICE_CONTEXT DeviceContext,
    _In_reads_bytes_(FrameLength) const UCHAR* Frame,
    _In_ ULONG FrameLength
    );
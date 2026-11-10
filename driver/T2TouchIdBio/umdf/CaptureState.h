// SPDX-License-Identifier: GPL-2.0-only
// CaptureState.h - the narrow view of the capture engine (Queue.cpp) that the rest
// of the driver may use. Plain C++, no WDF types, so TransportGlue.cpp stays
// buildable outside the WDK.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include "Discovery/Adapter.h"

// Driver.cpp. Debug-only trace (DebugView / the async log writer).
void T2BioLog(_In_z_ const char* fmt, ...);

// Registration entry points implemented in TransportGlue.cpp, C linkage like the
// rest of Internal.h's.
extern "C" {
VOID T2BioRegisterNetworkChangeNotification(VOID);
VOID T2BioUnregisterNetworkChangeNotification(VOID);
VOID T2BioStartTransportOwner(VOID);
VOID T2BioStopTransportOwner(VOID);
}

namespace t2bio {

// A CAPTURE_DATA holds the capture slot (a BridgeXPC session may be live).
bool CaptureBusy();
// System shutdown / restart in progress (no new work).
bool SystemShuttingDown();
// The endpoint the capture ladder last connected through. requirePeer: only when
// its T2 peer address is known.
bool GetStickyEndpoint(t2::discovery::NcmEndpoint* out, bool requirePeer);
// End the armed match so the worker reconnects at once (WBF's CAPTURE_DATA stays
// pending) - what a screen lock does, keeping the sticky endpoint.
void InvalidateCaptureForTransport(_In_z_ const char* why);

} // namespace t2bio

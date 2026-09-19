// SPDX-License-Identifier: GPL-2.0-only
// Internal.h - T2TouchIdBio (UMDF 2 WBDI driver)
//
// GET_ATTRIBUTES / GET_SENSOR_STATUS are the original skeleton gate (design
// doc section 8) and stay hardcoded/no-SEP-contact as documented in
// Queue.cpp. CAPTURE_DATA (design doc section 3) now links the same
// protocol/BridgeXpc + protocol/BiometricKit + protocol/Discovery code the
// t2touchid.exe CLI uses for `warmup`/`verify` — see Queue.cpp and
// protocol/Discovery/BridgeDiscovery.h for why that's a silent, argv-free
// copy of the CLI's discovery shape rather than a shared refactor of it.
//
#pragma once

// winsock2.h must be the very first Windows header pulled in by this TU
// chain (same reason as tools/t2touchid/main.cpp): protocol/Discovery and
// protocol/BridgeXpc headers include winsock2.h/ws2tcpip.h themselves, and
// if <windows.h> (below) is seen first, winsock.h wins the header-guard
// race and the later winsock2.h include becomes a redefinition-error mess.
// WIN32_LEAN_AND_MEAN keeps <windows.h> from re-pulling winsock.h on its own.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <wdf.h>
#include <strsafe.h>
#include <winbio_types.h>
#include <winbio_ioctl.h>

// Protocol libraries (protocol/T2TouchIdProtocol.vcxproj). Plain C++, no
// WDK-only headers - see BridgeDiscovery.h / VendorBir.h for why these are
// safe to reuse verbatim inside a UMDF host process instead of KMDF/WSK
// (design doc section 2's core argument).
#include "../../../protocol/Discovery/Adapter.h"
#include "../../../protocol/Discovery/BridgeDiscovery.h"
#include "../../../protocol/BiometricKit/VerificationEngine.h"
#include "../../../protocol/BiometricKit/VendorBir.h"

EXTERN_C_START
DRIVER_INITIALIZE                  DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD          T2BioEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL T2BioEvtIoDeviceControl;
EXTERN_C_END

// Debug-only trace; visible in DebugView (Capture Global Win32) because
// WUDFHost.exe is a normal user-mode process.
void T2BioLog(_In_z_ const char* fmt, ...);

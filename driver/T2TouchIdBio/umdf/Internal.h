// SPDX-License-Identifier: GPL-2.0-only
// Internal.h - T2TouchIdBio (UMDF 2 WBDI skeleton)
//
// Scope of this skeleton (design doc section 8, "next practical step"):
// answer IOCTL_BIOMETRIC_GET_ATTRIBUTES / _GET_SENSOR_STATUS only, so we can
// check that WinBio enumerates the device and lists it under
// Settings -> Sign-in options with test-signing on. NO protocol code is
// linked yet (BridgeXpc / BiometricKit / AppleKeyStore come after this gate).
#pragma once

#include <windows.h>
#include <wdf.h>
#include <strsafe.h>
#include <winbio_types.h>
#include <winbio_ioctl.h>

EXTERN_C_START
DRIVER_INITIALIZE                  DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD          T2BioEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL T2BioEvtIoDeviceControl;
EXTERN_C_END

// Debug-only trace; visible in DebugView (Capture Global Win32) because
// WUDFHost.exe is a normal user-mode process.
void T2BioLog(_In_z_ const char* fmt, ...);

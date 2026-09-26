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
// PowerRegisterSuspendResumeNotification (Queue.cpp, OnSuspendResume): a
// process-wide, OS-level suspend/resume notification - see that function's
// header comment for why this driver needs one instead of relying on
// EvtIoStop/EvtDeviceD0Exit alone. Link dependency: PowrProf.lib.
#include <powrprof.h>
// WTSRegisterSessionNotification (Queue.cpp, T2BioRegisterSessionLockNotification):
// the screen-lock invalidation boundary, in addition to the process-wide
// suspend/resume hook above - see that function's header comment for why a
// plain screen lock needs its own invalidation path. Link dependency:
// Wtsapi32.lib.
#include <wtsapi32.h>
#include <wdf.h>
#include <strsafe.h>
#include <winbio_types.h>
#include <winbio_err.h>   // WINBIO_E_* HRESULTs (not pulled in by winbio_types.h)

// INITGUID must be scoped tightly around winbio_ioctl.h ONLY (it is what
// DEFINE_GUIDs GUID_DEVINTERFACE_BIOMETRIC_READER; without INITGUID that
// header only *declares* it and the link fails with LNK2001). It must NOT
// stay defined across <windows.h>/<wdf.h> above: those pull in winioctl.h
// (directly and, separately, via WDF's own storage-GUID headers), and with
// INITGUID left on globally each DEFINE_GUID in winioctl.h gets fully
// instantiated on both paths, i.e. twice in this one TU -> C2374
// "redefinition; multiple initialization" on GUID_DEVINTERFACE_DISK and
// friends. Defining INITGUID only for this one header, then undefining it
// immediately, keeps windows.h/wdf.h on the normal extern-declaration path
// no matter how many times/routes they end up pulling winioctl.h in.
#include <initguid.h>
#include <winbio_ioctl.h>
#undef INITGUID

// Protocol libraries (protocol/T2TouchIdProtocol.vcxproj). Plain C++, no
// WDK-only headers - see BridgeDiscovery.h / VendorBir.h for why these are
// safe to reuse verbatim inside a UMDF host process instead of KMDF/WSK
// (design doc section 2's core argument).
#include "../../../protocol/Discovery/Adapter.h"
#include "../../../protocol/Discovery/BridgeDiscovery.h"
#include "../../../protocol/BiometricKit/VerificationEngine.h"
#include "../../../protocol/BiometricKit/VendorBir.h"

// SEP readiness gate (see CheckSepReady in Queue.cpp): reads the same
// in-memory bootstrap status T2SepBootstrapService reports via
// IOCTL_T2_SET_BOOTSTRAP_STATUS, so this driver never starts a capture (or
// claims WINBIO_SENSOR_READY) before the SEP has actually finished
// unlocking on this boot. Client.h/public.h only need <windows.h> and
// <setupapi.h> - no WDK-only types - so, like the protocol libraries
// above, safe to pull into this UMDF host process directly.
#include "../../../protocol/AppleKeyStore/Client.h"

EXTERN_C_START
DRIVER_INITIALIZE                  DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD          T2BioEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD               T2BioEvtDriverUnload;    // unregisters the suspend/resume hook below
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL T2BioEvtIoDeviceControl;
// Power-managed queue stop notification (device leaving D0, or queue/device
// removal). See the definition in Queue.cpp for why this driver needs one:
// without it, WDF's documented default is to block D0Exit until every
// outstanding request completes on its own, and CAPTURE_DATA(verify) is
// deliberately left pending with no deadline (design doc §9.4) until a
// touch or Windows' own CancelIoEx - neither of which a system sleep causes.
// 24.09.2026: proven on hardware to be dead code for THIS device (it is
// root-enumerated with no wake/idle policy - see Queue.cpp's OnSuspendResume
// comment) - kept anyway as the structurally-correct WDF-level handler for
// the (currently theoretical, for this device) cases where the framework
// does call it, e.g. a future non-root-enumerated build, or device removal.
EVT_WDF_IO_QUEUE_IO_STOP           T2BioEvtIoStop;
EXTERN_C_END

// Process-wide suspend/resume hook (Queue.cpp) - the fix that actually
// engages for this root-enumerated device, unlike EvtIoStop above. Called
// from DriverEntry / T2BioEvtDriverUnload (Driver.cpp).
EXTERN_C_START
VOID T2BioRegisterSuspendResumeNotification(VOID);
VOID T2BioUnregisterSuspendResumeNotification(VOID);
EXTERN_C_END

// Screen-lock invalidation boundary (WTS_SESSION_LOCK, Queue.cpp) - the
// second invalidation path, alongside the suspend/resume hook above, for a
// plain screen lock that happens without a suspend. Called from
// DriverEntry / T2BioEvtDriverUnload (Driver.cpp).
EXTERN_C_START
VOID T2BioRegisterSessionLockNotification(VOID);
VOID T2BioUnregisterSessionLockNotification(VOID);
EXTERN_C_END

// Debug-only trace; visible in DebugView (Capture Global Win32) because
// WUDFHost.exe is a normal user-mode process.
void T2BioLog(_In_z_ const char* fmt, ...);
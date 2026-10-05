// SPDX-License-Identifier: GPL-2.0-only
// BridgeDiscovery.h — silent (no stdout, no argv) BiometricKit BridgeXPC
// discovery+connect, for callers that are not the interactive CLI: right
// now that means the T2TouchIdBio UMDF WBDI driver (Windows-hello-design.MD
// section 3, IOCTL_BIOMETRIC_CAPTURE_DATA).
//
// This intentionally duplicates the SHAPE of tools/t2touchid/main.cpp's
// static ScanAndProbe/TryCachedBridgePort/DiscoverBiometricKitBridge (cache
// fast path -> scan-from-end with a RemoteXPC checker racing each HTTP/2
// hit -> live BridgeXPC HELO) rather than sharing code with them directly:
// those three are `static` to main.cpp and wired to argv/std::wcout, which
// a driver must never touch (no console, and DeviceIoControl callers should
// not pay for argv-shaped parsing). The underlying primitives this calls
// (ScanHttp2Preface, ProbeServiceOnPort, LoadCachedPort/SaveCachedPort,
// Connection::Connect/GetBridgeVersion) are the SAME already-hardware-
// verified library functions the CLI uses — no new wire-protocol code,
// exactly the "нуль нового протокольного коду" rule design doc 2 states.
//
// TODO(follow-up, low risk / not yet done): refactor main.cpp's
// DiscoverBiometricKitBridge to call ConnectToBiometricKitBridge for the
// no-ifIndex/no-host-override case, so the two callers share one
// implementation instead of two copies of the same shape. Left as a
// follow-up rather than done here to avoid touching a CLI path that is
// already confirmed working on real hardware, in the same change that
// introduces new, not-yet-hardware-tested driver code.
#pragma once
#include "Adapter.h"
#include "../BridgeXpc/Connection.h"
#include <cstdint>

namespace t2::discovery {

// Convenience: FindT2NcmEndpoints().front(), with the peer resolved AFTER the
// readiness gate (link-local no longer Tentative) rather than during enumeration.
// Returns false if no T2 NCM adapter is present at all, or when cancelled while
// the gate waited. The endpoint may have peerSource == None (nothing known yet);
// ConnectToBiometricKitBridge then returns false and the caller's ladder retries.
// cancelEvent (optional Win32 event HANDLE typed void*) interrupts the gate wait.
bool PickDefaultT2Endpoint(NcmEndpoint* outEndpoint, void* cancelEvent = nullptr);

// One STEP of "find the BiometricKit BridgeXPC port and connect". The caller
// (Queue.cpp) repeats it on a backoff ladder until it connects, Windows cancels,
// or this function reports *outScansExhausted. What survives between steps: the
// port (registry only, the same port for both transports), the sticky tunnel
// (T2Ncm.sys memory, cleared on reboot) and the scan resume cursor.
//
//   A. readiness gate   - adapter, non-Tentative link-local, peer; no conclusions.
//   B. native IPv6      - HELO on the registry port; no cache / no HELO => an
//                         immediate full-chain rescan (59000-60000, 49000-49999,
//                         rest of 49000-65535; 256 wide, 25 ms). The port is saved
//                         the moment it is confirmed, before the final connect and
//                         regardless of cancel.
//   C. IPv4 tunnel      - only when IPv6 is blocked (WSAEACCES, or no SYN-ACK and
//                         no RST at all) or the tunnel is already sticky: HELO on the
//                         same registry port, else a full-chain tunnel scan. A
//                         tunnel handshake commits the sticky tunnel until reboot.
//   D. nothing          - returns false.
//
// Every driver-mode flip happens inside a TransportPhase (cross-process mutex +
// RAII scope), so on return the driver mode equals the committed mode on every path.
//
// Peer: uses endpoint.peerLinkLocal when known; when endpoint.peerSource is None
// the gate resolves it (neighbor table -> persisted -> ping). Returns false if there
// is still no peer.
//
// On success: outConn is connected and HELO-verified; *outServicePort (if non-null)
// receives the BridgeXPC TCP port; *outRsdPort (if non-null) the RemoteXPC port that
// advertised it, or 0 when unknown (cache hit without RSD replay).
//
// cancelEvent (optional Win32 event HANDLE, typed void* like
// ScanOptions::cancelEvent): when signaled, the current probe/scan slice ends and no
// further one starts, so a cancelled CAPTURE_DATA does not keep the USB bulk pipe
// busy. Cancel neither removes the saved port nor rolls back committed state.
//
// outScansExhausted (optional): set to true on failure ONLY when 3 consecutive
// full-chain scan passes COMPLETED without finding BiometricKit on the transport that decides
// (the tunnel when IPv6 was blocked or the tunnel is sticky, otherwise native
// IPv6). Everything else - cancel, a silent path, a cool-down, no peer/MAC yet -
// leaves it false: "not yet", and the caller keeps retrying.
bool ConnectToBiometricKitBridge(const NcmEndpoint& endpoint,
                                  t2::bridgexpc::Connection* outConn,
                                  uint16_t* outServicePort = nullptr,
                                  uint16_t* outRsdPort = nullptr,
                                  void* cancelEvent = nullptr,
                                  bool* outScansExhausted = nullptr);

} // namespace t2::discovery
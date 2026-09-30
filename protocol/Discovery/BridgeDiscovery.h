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

// One bounded STEP of "find the BiometricKit BridgeXPC port and connect"
// (CONNECT_ARCHITECTURE_v2.md sections 5-13). The caller (Queue.cpp) repeats it
// on a backoff ladder for up to 30 s; what survives between steps and between
// cancelled CAPTURE_DATAs is in-process state keyed by the transport Generation
// (committed tunnel, scan progress) plus the registry port cache.
//
//   A. readiness gate   - adapter, non-Tentative link-local, peer; no conclusions.
//   B. "try v6"         - cached-port HELO on native, then <= 3 bounded probes.
//                         NOT a full scan. Only Positive evidence proves a path.
//   C. scan             - resumable, deadline-bounded, on the proven transport;
//                         the port is saved the moment it is confirmed, before the
//                         final connect and regardless of cancel.
//   D. tunnel attempt   - only when v6 produced no Positive evidence (auto-switch
//                         on) or the tunnel is forced. Nothing is committed until a
//                         tunnel handshake succeeded.
//   E. both empty       - returns false; nothing committed, cache and scan progress
//                         kept, the next step alternates/continues.
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
bool ConnectToBiometricKitBridge(const NcmEndpoint& endpoint,
                                  t2::bridgexpc::Connection* outConn,
                                  uint16_t* outServicePort = nullptr,
                                  uint16_t* outRsdPort = nullptr,
                                  void* cancelEvent = nullptr);

} // namespace t2::discovery
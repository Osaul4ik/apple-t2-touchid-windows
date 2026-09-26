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

// Convenience: FindT2NcmEndpoints().front(). Returns false if no T2 NCM
// adapter is present at all. Does not itself require a peer to already be
// known (see NcmEndpoint::peerSource) — that is ConnectToBiometricKitBridge's
// job below, same as the CLI's own flow (it only requires a peer once it is
// actually about to scan/connect).
bool PickDefaultT2Endpoint(NcmEndpoint* outEndpoint);

// Full discovery+connect pipeline: cache fast path (LoadCachedPort + a live
// HELO re-verify), then — on a miss — a two-attempt (20ms, 60ms) scan-from-
// end of the BridgeXPC port with a RemoteXPC "is this really BiometricKit"
// checker racing each HTTP/2 hit, matching ScanAndProbe's tuning in
// tools/t2touchid/main.cpp exactly (same constants, same rationale: the
// real candidate sits near the top of the ephemeral range and a single
// short-timeout pass is flaky under USB NCM jitter).
//
// 26.09.2026: the cache fast path is trusted (it is right almost every
// time) but is no longer allowed to block indefinitely on a dead cache
// entry — the whole cached-port attempt is capped at kCacheTrustBudgetMs
// (BridgeDiscovery.cpp), so a genuinely stale cache falls through to the
// full scan in well under a second instead of up to ~5.5s.
//
// Requires endpoint.peerSource != PeerSource::None (a real neighbor-table
// entry or a caller-supplied override) — unlike the CLI this never sends
// its own ff02::1 discovery ping; the driver is expected to be invoked only
// after `network`/an earlier successful connect has already populated the
// neighbor table, or after FindNeighborPeer() has been called separately.
// Returns false with *outConn left unconnected on any failure — no partial
// "maybe connected" state.
//
// On success: outConn is connected and HELO-verified; *outServicePort (if
// non-null) receives the BridgeXPC TCP port; *outRsdPort (if non-null,
// and only when found via a fresh scan rather than the "path A" direct
// cache re-verify) receives the RemoteXPC port that advertised it, 0
// otherwise. A successful connect is cached for next time exactly like the
// CLI does (SaveCachedPort), regardless of which path found it.
bool ConnectToBiometricKitBridge(const NcmEndpoint& endpoint,
                                  t2::bridgexpc::Connection* outConn,
                                  uint16_t* outServicePort = nullptr,
                                  uint16_t* outRsdPort = nullptr);

} // namespace t2::discovery
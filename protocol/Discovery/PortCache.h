// SPDX-License-Identifier: GPL-2.0-only
// PortCache.h — best-effort persistent cache of the last known-good
// BiometricKit BridgeXPC port for a given T2 NCM adapter.
//
// The port itself is ephemeral (the T2 appears to pick a fresh one each
// boot — see DiscoverBiometricKitBridge's scan-then-verify pipeline in
// t2touchid's main.cpp, which exists because of that), but it is stable
// across repeated tool invocations within the same boot/session. Callers
// use this to skip the ~16384-port scan on the common case (same boot,
// port hasn't changed) while still re-verifying the cached value over
// RemoteXPC (via ProbeServiceOnPort on the cached RemoteXPC port) and a live
// BridgeXPC HELO before trusting it - nothing here is used as a substitute
// for that verification, only as a shortcut to which port to verify first.
#pragma once
#include "Adapter.h"
#include <cstdint>

namespace t2::discovery {

// Reads the cached ports for `endpoint`, keyed by its MAC address (the one
// part of a T2 NCM adapter that is stable across reboots/replugs, unlike
// ifIndex). *outPort is the BridgeXPC service port (raw TCP). If
// outRsdPort is non-null it receives the RemoteXPC (HTTP/2) port whose peer
// record advertised that service, or 0 for legacy entries that only stored
// the service port. Returns false - leaving the outputs untouched - if there
// is no entry, the cache file doesn't exist or can't be read, or `endpoint`
// has no MAC to key on (NcmEndpoint::hasMac == false).
bool LoadCachedPort(const NcmEndpoint& endpoint, uint16_t* outPort,
                    uint16_t* outRsdPort = nullptr);

// Records `port` (BridgeXPC service port) and optionally `rsdPort` (the
// RemoteXPC HTTP/2 port that advertised it) as the last known-good pair for
// `endpoint`. Best-effort and silent on failure (no %LOCALAPPDATA%, can't
// create the directory or file, endpoint has no MAC, etc.) - caching is
// purely an optimization, never something correctness depends on, so a
// failed save just means the next run scans instead of short-circuiting.
void SaveCachedPort(const NcmEndpoint& endpoint, uint16_t port, uint16_t rsdPort = 0);

} // namespace t2::discovery
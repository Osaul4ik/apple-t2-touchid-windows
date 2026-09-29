// SPDX-License-Identifier: GPL-2.0-only
// PortCache.h — best-effort persistent cache of the last known-good
// BiometricKit BridgeXPC port for a given T2 NCM adapter.
//
// Storage: %ProgramData%\t2touchid\portcache.ini (machine-wide, shared by
// the UMDF driver host and the CLI). Process-lifetime map is consulted
// first so a failed/delayed first write does not force every CAPTURE in
// the same WUDFHost process to re-scan.
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
//
// Missing file, empty file, or entry with no/invalid port ⇒ Load returns
// false ⇒ caller MUST run a full scan (never hang waiting on a dead cache).
#pragma once
#include "Adapter.h"
#include <cstdint>

namespace t2::discovery {

// Reads the cached ports for `endpoint`, keyed by its MAC address (the one
// part of a T2 NCM adapter that is stable across reboots/replugs, unlike
// ifIndex). *outPort is the BridgeXPC service port (raw TCP). If
// outRsdPort is non-null it receives the RemoteXPC (HTTP/2) port whose peer
// record advertised that service, or 0 for legacy entries that only stored
// the service port.
//
// Returns false (outputs untouched) when:
//   - the cache file does not exist or is unreadable,
//   - there is no entry for this MAC,
//   - the entry exists but the port is empty / non-numeric / out of range,
//   - or `endpoint` has no MAC to key on (NcmEndpoint::hasMac == false).
// Any of those is a cache miss: the caller must fall through to a full
// port scan and, on success, call SaveCachedPort so the file is created.
bool LoadCachedPort(const NcmEndpoint& endpoint, uint16_t* outPort,
                    uint16_t* outRsdPort = nullptr);

// Records `port` (BridgeXPC service port) and optionally `rsdPort` (the
// RemoteXPC HTTP/2 port that advertised it) as the last known-good pair for
// `endpoint`. Always updates the process-lifetime map. File write is
// best-effort (creates %ProgramData%\t2touchid if needed, atomic replace
// via .tmp); failure is logged but does not affect the in-process cache.
// port == 0 is rejected so an empty value can never be persisted.
void SaveCachedPort(const NcmEndpoint& endpoint, uint16_t port, uint16_t rsdPort = 0);

} // namespace t2::discovery

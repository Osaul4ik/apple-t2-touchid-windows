// SPDX-License-Identifier: GPL-2.0-only
// PortCache.h — best-effort persistent cache of the last known-good
// BiometricKit BridgeXPC port for a given T2 NCM adapter.
//
// Storage: HKLM\SOFTWARE\T2TouchId\Network\PortCache, one REG_SZ value per
// adapter MAC (machine-wide, shared by the UMDF driver host and the CLI; the
// same key tree PeerIpv6/AutoSwitch live in, so the LocalService ACL granted by
// Set-T2NcmStaticIp.ps1 covers it). Process-lifetime map is consulted first so a
// failed/delayed first write does not force every CAPTURE in the same
// WUDFHost process to re-scan.
//
// The port is not guaranteed to survive a T2 reboot, but in practice a port
// from an earlier boot is often still valid - so it is always tried first
// (a dead one costs one refused connect, see Connection::ConnectOnce), and it
// is stable across repeated tool invocations within the same boot/session. Callers
// use this to skip the ~16384-port scan on the common case (same boot,
// port hasn't changed) while still re-verifying the cached value over
// RemoteXPC (via ProbeServiceOnPort on the cached RemoteXPC port) and a live
// BridgeXPC HELO before trusting it - nothing here is used as a substitute
// for that verification, only as a shortcut to which port to verify first.
//
// Missing value, or a value with no/invalid port ⇒ Load returns
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
//   - the PortCache key does not exist or is unreadable,
//   - there is no value for this MAC,
//   - the entry exists but the port is empty / non-numeric / out of range,
//   - or `endpoint` has no MAC to key on (NcmEndpoint::hasMac == false).
// Any of those is a cache miss: the caller must fall through to a full
// port scan and, on success, call SaveCachedPort so the value is created.
bool LoadCachedPort(const NcmEndpoint& endpoint, uint16_t* outPort,
                    uint16_t* outRsdPort = nullptr);

// Records `port` (BridgeXPC service port) and optionally `rsdPort` (the
// RemoteXPC HTTP/2 port that advertised it) as the last known-good pair for
// `endpoint`. Always updates the process-lifetime map. The registry write is
// best-effort (creates the PortCache key if needed); failure is logged with the
// Win32 error but does not affect the in-process cache.
// port == 0 is rejected so an empty value can never be persisted.
void SaveCachedPort(const NcmEndpoint& endpoint, uint16_t port, uint16_t rsdPort = 0);

} // namespace t2::discovery
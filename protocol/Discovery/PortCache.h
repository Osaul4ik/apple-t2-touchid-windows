// SPDX-License-Identifier: GPL-2.0-only
// PortCache.h — persistent cache of the last known-good BiometricKit BridgeXPC
// port for a given T2 NCM adapter.
//
// Storage: HKLM\SOFTWARE\T2TouchId\Network\PortCache, one REG_SZ value per
// adapter MAC (machine-wide, shared by the UMDF driver host, the CLI and the GUI;
// the same key tree PeerIpv6/AutoSwitch live in, so the LocalService ACL granted
// by Set-T2NcmStaticIp.ps1 covers it).
//
// THE REGISTRY IS THE ONLY SOURCE OF TRUTH. There is no in-process copy: every
// Load reads the value (microseconds), so a port written by the CLI/GUI or by
// another WUDFHost instance is seen immediately, and nothing in memory can
// shadow a newer value.
//
// ONE CACHE FOR BOTH TRANSPORTS. On hardware the BiometricKit service port is
// the same whether it is reached over native IPv6 or the IPv4 tunnel (T2Ncm only
// rewrites the IP header, the T2 service is the same socket), so whichever
// transport confirms a port writes the same entry.
//
// The port is not guaranteed to survive a T2 reboot, but in practice a port
// from an earlier boot is often still valid - so it is always tried first with a
// live BridgeXPC HELO. Nothing here is used as a substitute for that
// verification, only as a shortcut to which port to verify first.
//
// Missing value, unreadable key, or a value with no/invalid port => Load returns
// false => caller MUST run a full scan (never hang waiting on a dead cache).
// A failed HELO never deletes the entry; only a port CONFIRMED by a scan
// overwrites it.
#pragma once
#include "Adapter.h"
#include <cstdint>
#include <string>

namespace t2::discovery {

// Parses a cache value "port" or "port,rsdPort". Returns false when the service
// port is missing, non-numeric or outside 1..65535 (cache miss => full scan).
// An invalid rsdPort part is not an error: *outRsd is then 0.
bool ParsePortCacheValue(const std::string& raw, uint16_t* outPort, uint16_t* outRsd);

// Reads the cached ports for `endpoint`, keyed by its MAC address (the one
// part of a T2 NCM adapter that is stable across reboots/replugs, unlike
// ifIndex). *outPort is the BridgeXPC service port (raw TCP). If
// outRsdPort is non-null it receives the RemoteXPC (HTTP/2) port whose peer
// record advertised that service, or 0 for entries that only stored the
// service port.
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
// `endpoint`, in the registry only (creates the PortCache key if needed).
// A write failure is logged once as a health line; there is no fallback copy,
// so the next process simply rescans.
// port == 0 is rejected so an empty value can never be persisted.
// Call it the moment a port is CONFIRMED (scan + RemoteXPC), before the final
// connect and regardless of cancel, so a cancelled CAPTURE_DATA never throws the
// finding away.
void SaveCachedPort(const NcmEndpoint& endpoint, uint16_t port, uint16_t rsdPort = 0);

// Removes this adapter's entry (tests / tooling). Returns true when the value is
// gone afterwards (deleted, or it did not exist).
bool DeleteCachedPort(const NcmEndpoint& endpoint);

} // namespace t2::discovery

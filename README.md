# apple-t2-touchid-windows

Experimental Windows 11 driver/protocol stack that exposes the built-in
Touch ID sensor on Intel MacBooks with an Apple T2 chip as a Windows Hello
biometric device.

**Status: proof-of-concept, not hardware-validated.** The code builds and
passes hardware-free unit tests, but no run has yet happened on real T2
hardware — see [Status](#status) below.

## What this is

macOS Touch ID verification runs through several layers on top of the T2's
Secure Enclave Processor (SEP): a PCI mailbox transport, AppleKeyStore
(keybag/lock-state operations), BridgeXPC (a session protocol carried over
a virtual USB Ethernet interface), and BiometricKit (fingerprint match
requests/results). This project reimplements that stack for Windows so the
same hardware sensor can back a Windows Hello credential — **verification
only**. It does not implement its own fingerprint matching, does not store
raw fingerprint images, and does not do enrollment (enrollment stays on
macOS).

## Scope

- **Target platform (phase 1):** MacBook Pro 2019 (Intel CPU, Apple T2,
  built-in Touch ID), Windows 11 x64, running alongside macOS via Boot Camp.
- **In scope:** PCI SEP mailbox transport, AppleKeyStore client, BridgeXPC
  session handling, BiometricKit match verification, a WBDI biometric
  driver for Windows Hello.
- **Out of scope:** enrollment, raw fingerprint storage/matching on
  Windows, non-T2 Touch Bar/Touch ID variants.

## Layout

```
driver/T2TouchIdTransport/   KMDF PCI driver — SEP mailbox, DMA/OOL buffers,
                              AppleKeyStore opcode allow-list (T2TouchIdTransport.sys)
protocol/AppleKeyStore/      User-mode client wrapping the transport's AKS IOCTL
protocol/BridgeXpc/          BridgeXPC session/frame/plist handling
protocol/BiometricKit/       Match-result parsing and verification engine
tools/t2touchid/             Diagnostic CLI (t2touchid.exe)
tests/                       Hardware-free unit tests
docs/                        Design docs, protocol analysis, milestone reports
```

## Status

All Milestone 1 (Linux reference source audit) protocol gates are
confirmed from source — the SEP mailbox, AppleKeyStore, BridgeXPC, and
BiometricKit protocols are documented, not guessed. Milestone 2 (Windows
implementation) exists as working source but every hardware-facing gate is
still `UNKNOWN` pending a real run:

| Gate | Status |
|---|---|
| SEP PCI transport / mailbox | Implemented, not run on hardware |
| AppleKeyStore exchange | Implemented, not run on hardware |
| CDC-NCM / IPv6 discovery | Not implemented |
| RemoteXPC discovery | Not implemented |
| BridgeXPC | `Connection.cpp` has TODOs; needs `PlistPayload.cpp` completion |
| BiometricKit / real MATCH-NO_MATCH | Blocked on BridgeXPC |

See `docs/milestone-2-hardware-results.md` for the full gate list and
`docs/Windows pnp power lifecycle design.md` for sleep/wake behavior
(D0Entry/D0Exit fail-closed re-arm logic, added after a reported
sleep-related battery-drain investigation).

## Building

Open `T2TouchId.sln` in Visual Studio with the WDK installed. The driver
project targets KMDF; protocol libraries and the CLI tool are ordinary C++
projects.

## Installing the driver (test hardware only)

`T2TouchIdTransport.inf` targets `PCI\VEN_106B&DEV_1802` — the same T2 SEP
PCI function Apple's own Boot Camp support software binds to a no-op null
driver (`AppleNull64.inf`). This project's driver is **not WHQL-signed**:
installing it requires Windows test-signing mode (or Secure Boot disabled),
via Device Manager → the device → *Update driver* → *Have Disk*. Do this
only on a machine you're prepared to debug; the SEP is the same coprocessor
macOS relies on for FileVault key material, and this driver enables PCI bus
mastering and DMA against it.

## Acknowledgments

This project would not exist without [jmurth1234](https://github.com/jmurth1234)'s
[t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux). Every
protocol detail this Windows port relies on — the SEP PCI mailbox layout,
AppleKeyStore opcodes, BridgeXPC framing, BiometricKit match handling —
comes from that project's source. This repository is a Windows port built
directly on top of that work: thank you for doing the hard reverse-engineering
first and publishing it under a free license.

## License

GPL-2.0-only. See `LICENSE`. Protocol facts (not code) were derived from
analysis of [jmurth1234/t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux)
— see `NOTICE.md` and `docs/linux-reference-analysis.md`.
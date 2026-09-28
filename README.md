# apple-t2-touchid-windows

<img width="1286" height="533" alt="Screenshot_3" src="https://github.com/user-attachments/assets/e8078b76-2424-421c-aaaa-5d41a15570d4" />

Experimental Windows 10/11 driver/protocol stack that exposes the built-in
Touch ID sensor on Intel MacBooks with an Apple T2 chip as a Windows Hello
biometric device.

**Status: proof-of-concept.** Match/No-Match against real hardware works.
Windows Hello sign-in is work in progress (see the [Gate status table](#status)).

> **Read this before you do anything else.** The T2's Secure Enclave
> Processor (SEP) is the same coprocessor macOS uses for FileVault key
> material. This project unlocks it from an unsigned, PoC-quality driver
> stack. Only do this on a machine you are prepared to debug, and only
> after you understand [Safety notes](#safety-notes) below.

## Disclaimer

This is an **experimental, proof-of-concept test project**, built and
published for research purposes. It is **not** production software, has
**no** warranty of any kind, and is provided **as is**.

**The author(s) take no responsibility for any consequences of using this
project** — including but not limited to data loss, a bricked SEP/keybag,
broken FileVault/Data Protection, driver instability or crashes, security
issues, or any other direct or indirect damage to your hardware, data, or
system. You install unsigned kernel/UMDF drivers and let them talk
directly (PCI DMA) to the same Secure Enclave your FileVault keys live in,
entirely **at your own risk**, on your own hardware, and you are expected
to understand what each step in this README does before running it.
See also `LICENSE` (GPL-2.0-only, §11–12 — no warranty, no liability) and
[Safety notes](#safety-notes) below.

## Table of contents

- [Disclaimer](#disclaimer)
- [What this is](#what-this-is)
- [Scope](#scope)
- [Status](#status)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Building](#building)
- [Installing the drivers](#installing-the-drivers)
- [Getting `user.kb` from macOS](#getting-userkb-from-macos)
- [Importing the vault (SEP setup, one-time)](#importing-the-vault-sep-setup-one-time)
- [What happens on every boot](#what-happens-on-every-boot)
- [Network transport: native IPv6 vs. IPv4 tunnel](#network-transport-native-ipv6-vs-ipv4-tunnel)
- [Using the CLI (`t2touchid.exe`)](#using-the-cli-t2touchidexe)
- [Windows Hello enrollment](#windows-hello-enrollment)
- [Troubleshooting](#troubleshooting)
- [Safety notes](#safety-notes)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## What this is

macOS Touch ID verification runs through several layers on top of the T2's
Secure Enclave Processor (SEP): a PCI mailbox transport, AppleKeyStore
(keybag/lock-state operations), BridgeXPC (a session protocol carried over
a virtual USB Ethernet interface), and BiometricKit (fingerprint match
requests/results). This project reimplements that stack for Windows so the
same hardware sensor can back a Windows Hello credential — **verification
only**. It does not implement its own fingerprint matching, does not store
raw fingerprint images, and does not do enrollment (enrollment stays on
macOS: you enroll fingers in macOS System Settings, and this project just
asks the SEP "does the finger touching it right now match one of the
identities already enrolled there").

## Scope

- **Target platform (phase 1):** MacBook Pro 2019 (Intel CPU, Apple T2,
  built-in Touch ID), Windows 11 x64, running alongside macOS via Boot Camp
  (dual-boot — the SEP and its enrolled fingerprints live on the Mac side,
  Windows only talks to them).
- **In scope:** PCI SEP mailbox transport, AppleKeyStore client, the CDC-NCM
  virtual network link, RemoteXPC/BridgeXPC session handling, BiometricKit
  match verification, a WBDI biometric driver for Windows Hello.
- **Out of scope:** enrollment, raw fingerprint storage/matching on
  Windows, non-T2 Touch Bar/Touch ID variants, Apple Silicon Macs.

## Status

Milestone 1 (Linux reference source audit) protocol facts are confirmed
from source — the SEP mailbox, AppleKeyStore, BridgeXPC, and BiometricKit
protocols are documented, not guessed (see [Acknowledgments](#acknowledgments)).
Milestone 2 (Windows implementation) has real hardware results:

| Gate | Status |
|---|---|
| SEP PCI transport / mailbox | **Confirmed on hardware** |
| DMA / OOL registration | **Confirmed on hardware** |
| AppleKeyStore exchange (register-ool / load-keybag / unlock) | **Confirmed on hardware** |
| CDC-NCM / IPv6 link to the T2 | **Confirmed on hardware** — inbox `UsbNcm` bound via `T2NCM/apple-t2-ncm.inf` |
| RemoteXPC / BridgeXPC discovery | **Confirmed on hardware** |
| BiometricKit real MATCH/NO_MATCH | **Confirmed on hardware** |
| Windows Hello sign-in (WBDI/UMDF biometric driver) | **Work in progress** |

## Repository layout

```
T2NCM/                        apple-t2-ncm.inf + apple-t2-composite.inf — inbox UsbNcm
                               binding for the T2's USB CDC-NCM (virtual Ethernet) interface,
                               plus the T2Ncm.sys NDIS miniport (IPv4-tunnel rewrite support)
driver/T2TouchIdTransport/    KMDF PCI driver — SEP mailbox, DMA/OOL buffers,
                               AppleKeyStore opcode allow-list (T2TouchIdTransport.sys)
driver/T2TouchIdBio/          UMDF WBDI biometric driver + SepVaultGui (WPF) +
                               T2SepBootstrap (boot-time SEP unlock service)
protocol/AppleKeyStore/       User-mode client wrapping the transport's AKS IOCTL
protocol/BridgeXpc/           BridgeXPC session/frame/plist handling, transport-mode
                               (native IPv6 / IPv4 tunnel) selection
protocol/Discovery/           RemoteXPC/BridgeXPC port discovery over the T2 NCM link
protocol/BiometricKit/        Match-result parsing and verification engine
tools/t2touchid/              Diagnostic/bootstrap CLI (t2touchid.exe)
tools/                        Install-T2TouchIdBio.ps1, InstallDriver.bat, InstallCert.bat,
                               Set-T2NcmStaticIp.ps1 — packaging/install helpers
tests/                        Hardware-free unit tests
```

Design docs worth reading before touching a given area:
`T2NCM/docs/T2Ncm-Architecture.md` (NCM/tunnel driver internals),
`driver/T2TouchIdBio/docs/Windows-hello-design.MD` (SEP bootstrap, vault
format, WBDI plan), `driver/T2TouchIdBio/umdf/Readme.md` (Bio driver build
skeleton).

## Requirements

- A MacBook Pro with an Apple T2 chip, Boot Camp-installed Windows 11 x64.
- macOS still installed and bootable on the same machine (you need it once,
  to export `user.kb` — see below).
- Visual Studio 2022 with the **Windows Driver Kit (WDK)** workload, to
  build the KMDF/UMDF drivers.
- Administrator access on the Windows side. Every step below (driver
  install, vault import, service start) requires it.
- Windows **test-signing mode enabled**, or Secure Boot disabled. None of
  the drivers here are WHQL-signed (see [Safety notes](#safety-notes)).

## Building

Open `T2TouchId.sln` in Visual Studio with the WDK installed and build
`Release|x64`. The solution covers `driver/T2TouchIdTransport`
(KMDF PCI driver), `protocol/*` (static libs), `tools/t2touchid`
(the CLI), and `tests/`.

`driver/T2TouchIdBio` (the WBDI biometric driver + SepVaultGui) and
`T2NCM` (the NDIS/NCM driver + INFs) are **not** part of `T2TouchId.sln` —
build them separately, per their own project files / `Readme.md`s, so an
in-progress change there can't break the main solution's CI. GitHub
Actions workflows under `.github/workflows/` build each piece
independently (`BuildT2TouchId.yml`, `BuildNCM_Inf.yml`,
`Cit2touchidbio.yml`) and are the reference for the exact `msbuild`/WDK
tooling invocations if you'd rather not chase them down by hand.

## Installing the drivers

Assemble the built output (or a CI artifact) into a folder with this
layout, then run `InstallDriver.bat` **as Administrator**:

```
<install folder>\
  InstallDriver.bat
  Inst\
    InstallCert.bat
    Install-T2TouchIdBio.ps1
    Set-T2NcmStaticIp.ps1
  SEP\
    T2TouchIdTransport.inf / .sys / .cat / .cer
  NCM\
    apple-t2-composite.inf
    apple-t2-ncm.inf
    apple-t2-ncm-ctrl-stub.inf
  Bio\
    T2TouchIdBio.inf / .dll / .cat
```

`InstallDriver.bat` does, in order:

1. Imports the test-signing certificate into `Cert:\LocalMachine\Root` and
   `Cert:\LocalMachine\TrustedPublisher` (`Inst\InstallCert.bat`).
2. Installs `T2TouchIdTransport.inf` — this is what binds to the T2's SEP
   PCI function (`PCI\VEN_106B&DEV_1802`), the same device Apple's own Boot
   Camp support software normally binds to a no-op null driver
   (`AppleNull64.inf`). Update-driver over that binding.
3. Installs `apple-t2-composite.inf`, then rescans devices.
4. Installs `apple-t2-ncm.inf` and `apple-t2-ncm-ctrl-stub.inf` — this is
   what turns the T2's USB CDC-NCM interface into a normal Windows network
   adapter ("Apple T2 USB NCM Network Adapter"), the link everything below
   (BridgeXPC, RemoteXPC discovery) actually talks over.
5. Runs `Set-T2NcmStaticIp.ps1`, which assigns `169.254.84.1/16` to that
   adapter — needed for [IPv4 tunnel mode](#network-transport-native-ipv6-vs-ipv4-tunnel),
   not for normal (native IPv6) operation. Best-effort: it just logs a
   warning and continues if the adapter hasn't enumerated yet (Mac not
   plugged in, T2 still asleep).
6. Runs `Inst\Install-T2TouchIdBio.ps1`, which installs the WBDI biometric
   driver (`Bio\T2TouchIdBio.inf`, root-enumerated — see that script for
   why `pnputil /add-driver` alone isn't enough for a root-enumerated INF).
7. Rescans devices and restarts the `WbioSrvc` (Windows Biometric Service).

If you'd rather do it by hand (or a step above fails and you want to retry
just that one), each is a plain `pnputil /add-driver <inf> /install` —
read `InstallDriver.bat` itself, it's short and linear.

After this step: Device Manager should show
`T2TouchIdTransport` (System devices, no Code 43), the **Apple T2 USB NCM
Network Adapter** (Network adapters), and a **Biometric devices** node with
no Code 31/39/43. None of this unlocks the SEP yet — that's the vault
import below.

## Getting `user.kb` from macOS

`user.kb` is your macOS user's **AppleKeyStore keybag** — the file that
holds your wrapped Data Protection class keys, not your fingerprints
(fingerprint identity UUIDs live inside the SEP itself and are handed out
by BiometricKit at runtime; see `driver/T2TouchIdBio/docs/Windows-hello-design.MD`
§11.1 if you want the byte-level detail). This project needs it purely to
unlock the SEP on the Windows side, the same way logging into your macOS
account does.

Per Apple's own documentation, on a Mac it lives at:

```
~/Library/Keychains/<hardware-UUID>/user.kb
```

To get it onto the Windows/Boot Camp partition:

1. Boot into **macOS**, log in as the account whose Touch ID you want to
   use from Windows.
2. Open Terminal and find your Keychains folder:
   ```
   ls ~/Library/Keychains/
   ```
   You'll see one folder named as a hardware UUID (and possibly a
   `metadata.keychain-db` etc. next to it) — `user.kb` is inside that
   folder.
3. Copy `user.kb` somewhere the Windows side can read it. The simplest
   option on a Boot Camp machine is the Boot Camp (Windows) partition
   itself, which macOS can normally see and write to directly — e.g.
   `/Volumes/BOOTCAMP/user.kb`. A USB drive works too if Boot Camp isn't
   mounted for write.
4. Reboot into **Windows**. You should now have `user.kb` somewhere on
   disk, e.g. `C:\Macos\user.kb`.

You'll also need the **special bag id** for your account — the convention
this project follows (per the Linux reference project) is `-501`, Apple's
usual id for the first non-root macOS user. If you have more than one
macOS user account you care about, or a non-default UID, check
`driver/T2TouchIdBio/docs/Windows-hello-design.MD` for how that id is used
(`AppleKeyStore::Client::MakeSystemKeybag`/`Unlock`).

`user.kb` itself never needs to touch the network or leave the machine —
the import step below reads it once, encrypts it into the vault, and from
that point on you can (and should) delete the plaintext copy.

## Importing the vault (SEP setup, one-time)

This is a one-time, manual, Administrator step — not something that runs
on every boot.

1. Run the T2TouchIdBio GUI (`T2TouchIdBio.exe`, "SepVaultGui" in the
   source) **as Administrator**.
2. In the "Разовий імпорт keybag" / one-time keybag import card:
   - **Browse** to the `user.kb` file you copied over from macOS.
   - Enter the **special bag id** (`-501` for the default first macOS
     user — see above).
   - Enter your macOS **account password**. This is the same password
     used for both `unlock <handle>` and `unlock <special bag>` inside
     AppleKeyStore — one password, used twice.
   - Click **Save**.
3. This writes `%ProgramData%\T2TouchId\sep-vault.bin`: the keybag bytes
   and the password, each `CryptProtectData`-encrypted at **machine**
   scope (not user scope — the boot-time service below runs before any
   user profile exists, so user-scope DPAPI isn't available to it).
   Nothing is ever written to disk in plaintext by this step.
4. Delete the original `user.kb` copy (e.g. `C:\Macos\user.kb`) — the
   vault doesn't need it in plaintext on disk anymore, and there's no
   reason to leave a second copy of your Data Protection keybag lying
   around.
5. **Reboot Windows** to apply — see the next section for what happens
   next.

## What happens on every boot

`T2SepBootstrap` is a Windows service (`Automatic`, `LocalSystem`) that
starts once per cold boot (not on resume-from-sleep) and runs the exact
sequence you'd otherwise have to do by hand with the CLI:

```
1. Read sep-vault.bin, CryptUnprotectData -> keybag bytes + password
2. AppleKeyStore::Client::RegisterOol()
3. AppleKeyStore::Client::LoadKeybag(keybagBytes, &handle)
4. AppleKeyStore::Client::MakeSystemKeybag(handle, specialUserBag)
5. AppleKeyStore::Client::Unlock(handle, password)
6. AppleKeyStore::Client::Unlock(specialUserBag, password)   // same password
7. zero the decrypted keybag/password buffers
8. signal readiness (read by the WBDI driver's GET_SENSOR_STATUS handler)
```

The password never goes through a command line or an environment
variable — the service links the same `protocol/AppleKeyStore::Client`
library the CLI uses and calls it in-process.

The T2TouchIdBio GUI's main window shows the current outcome of this
sequence (green "SEP готовий" banner on success; specific banners for a
missing/corrupt vault, a DPAPI failure, a wrong password, or a hung SEP).
Free-text detail beyond that summary is logged to `C:\LogSEP.txt`.

## Network transport: native IPv6 vs. IPv4 tunnel

Everything above (RemoteXPC discovery, BridgeXPC, verify) talks to the T2
over its CDC-NCM adapter's IPv6 link-local address by default. Some
corporate VPN/firewall software (Cisco AnyConnect + a restrictive WFP
filter is the case this was written against) blocks **all** IPv6 traffic
system-wide, which would otherwise make the T2 completely unreachable
while that VPN is active.

To work around that, the stack can fall back to an **IPv4 tunnel**:
userspace talks AF_INET to a synthetic `169.254.x.y` address, and
`T2Ncm.sys` (the NDIS miniport in `T2NCM/`) rewrites those frames to IPv6
on the wire — the T2 itself only ever sees IPv6, nothing changes on its
side.

This is fully automatic and needs no configuration in the normal case:

- Every cold boot always tries native IPv6 first.
- After the first (and every) real unlock, the stack **prepares the IPv4
  tunnel path in the background** (ARP neighbor + peer push into
  `T2Ncm.sys` — same work the `network` / static-IP path needs) while
  staying on native IPv6. That way a later VPN that blocks IPv6 can fall
  back without a cold ARP miss.
- If a connect attempt (e.g. finger unlock while VPN is up) doesn't get an
  IPv6 handshake within **~400 ms**, that one call falls back to the IPv4
  tunnel and the verify continues over the tunnel; every subsequent call
  **for the rest of that lock cycle** skips straight to the tunnel too —
  no repeated 400 ms timeouts while the screen stays locked.
- Every real unlock runs a throwaway native-IPv6 reachability probe
  (~100 ms). If the VPN dropped it succeeds and the next Connect uses
  IPv6 again; if not, the tunnel stays selected until a later unlock
  succeeds.
- Once every **4 unlocks** the background path also forces a full tunnel
  re-arm before the probe, then switches back to native IPv6 only if the
  probe succeeds.
- This state resets on every reboot (it's a volatile registry cache) —
  Windows always starts a fresh boot by trying IPv6.

There's also a manual override in the T2TouchIdBio GUI ("IPv4 tunnel цього
сеансу" checkbox): checking it forces the tunnel immediately, exactly as
if a real probe had just failed; unchecking it clears that and the next
connect tries native IPv6 again. It's session-scoped on purpose (same
volatile flag as the automatic fallback, not a separate persistent
setting) so a forgotten checked box can't silently pin every future boot
to the tunnel.

If you ever do need tunnel mode, make sure `169.254.84.1/16` is assigned
to the "Apple T2 USB NCM Network Adapter" — `Set-T2NcmStaticIp.ps1`
(step 5 of `InstallDriver.bat`) does this automatically at install time;
see that script if you need to re-run it by hand.

## Using the CLI (`t2touchid.exe`)

`t2touchid.exe` is both the diagnostic tool used to develop this project
and, at a low level, the exact sequence `T2SepBootstrap` automates. Run it
**as Administrator** from an elevated console (driver access + AKS IOCTLs
require it).

```
t2touchid.exe [--verbose|-v] <command> [args]

  status                                current SEP/transport status
  register-ool                          register out-of-line buffers with AKS
  capabilities                          query AKS capabilities
  device-state [handle] [selector]      raw EP7 liveness probe
  load-keybag <keybag-file>             load a keybag (e.g. user.kb), prints a handle
  set-system-keybag <handle> <bag>      MakeSystemKeybag(handle, specialUserBag)
  unlock <handle>                       unlock a loaded keybag/bag handle (prompts for password)
  network                               discover/scan the T2's RemoteXPC/BridgeXPC port
  ncmstatus                             report on the T2Ncm.sys tunnel driver state
  identities [ifIndex] [--host ...] [--uid N]   list SEP-enrolled fingerprint identities
  warmup     [ifIndex] [--host ...] [--uid N]   warm up BiometricKit before a real verify
  verify     [ifIndex] [--host ...] [--uid N] [--seconds N]
             [--match-layout inline|padded|legacy] [--match-flags N]
             [--no-reset-sensor] [--no-load-calibration]
```

`--verbose`/`-v` (or `T2TOUCHID_VERBOSE=1`) prints step-by-step BridgeXPC
diagnostics to the console; the same trace is always available in
[DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview)
(run as Administrator, *Capture Global Win32*) whether or not you pass it.

A typical manual bring-up sequence, before the GUI/service existed to do
it for you, looked like:

```
t2touchid.exe network                              # confirm the T2 answers over RemoteXPC
t2touchid.exe load-keybag C:\Macos\user.kb          # -> prints a handle
t2touchid.exe set-system-keybag <handle> -501
t2touchid.exe unlock <handle>                       # prompts for your macOS password
t2touchid.exe unlock -501                           # same password again
t2touchid.exe identities                            # list what the SEP has enrolled
t2touchid.exe verify --seconds 20                   # touch the sensor, watch MATCH/NO_MATCH
```

In normal use you shouldn't need any of this — the GUI + `T2SepBootstrap`
do steps 2–5 automatically on every boot once the vault is imported. It's
useful for diagnosing a specific step when something in the boot sequence
fails.

## Windows Hello enrollment

Not implemented yet. The WBDI/UMDF biometric driver
(`driver/T2TouchIdBio`) currently answers sensor-attribute/status queries
and can run a real `CAPTURE_DATA`/`Verify()` against the SEP; wiring that
up to Windows' own Storage/Engine adapters so `Settings → Accounts →
Sign-in options → Fingerprint recognition` works end-to-end is tracked in
`driver/T2TouchIdBio/docs/Windows-hello-design.MD` (sections 7–9, 11).
Enrollment itself will always stay on macOS — Windows only ever asks "does
this touch match an identity the SEP already knows about".

## Troubleshooting

- **Driver won't load / Code 52 or "driver can't be verified"** — test
  signing isn't enabled. `bcdedit /set testsigning on` and reboot, or
  disable Secure Boot. See [Safety notes](#safety-notes) for why this is
  required instead of WHQL signing.
- **`cannot open T2TouchIdTransport device`** from the CLI — the driver
  isn't loaded, or you're not running as Administrator. Check Device
  Manager for the SEP PCI device.
- **`t2touchid.exe network` finds nothing** — confirm the "Apple T2 USB
  NCM Network Adapter" exists and is up in Network Connections; if a VPN
  is active, see [Network transport](#network-transport-native-ipv6-vs-ipv4-tunnel)
  above — it should fall back automatically, but `ncmstatus` will tell you
  which mode is actually active.
- **SEP status banner shows "Не вдалось розшифрувати vault"** — usually
  means `sep-vault.bin` was copied from a different machine (DPAPI machine
  keys don't transfer). Re-run the vault import on this machine.
- **SEP status banner shows "SEP відхилив запит"** — wrong password or a
  stale/mismatched keybag for the special bag id you entered. Re-import
  with the correct password and bag id.
- **Detailed logs:** `C:\LogSEP.txt` (SEP bootstrap), DebugView with
  `--verbose`/`T2TOUCHID_VERBOSE=1` (protocol-level trace), Event Viewer →
  Applications and Services Logs → Microsoft → Windows → Biometrics →
  Operational (WBDI-level events once the Bio driver loads).

## Safety notes

- None of the drivers in this repository are WHQL-signed. Installing them
  requires Windows test-signing mode or Secure Boot disabled — do this
  only on a machine you're prepared to debug and re-image if something
  goes wrong.
- `T2TouchIdTransport.sys` enables PCI bus mastering and DMA against the
  same SEP coprocessor macOS uses for FileVault key material. This project
  does not touch FileVault or any Data Protection class key beyond what's
  needed to unlock the keybag for identity/match operations, but you are
  running unsigned, early-stage code with direct DMA access to that
  coprocessor — treat it accordingly.
- `sep-vault.bin` contains your macOS account password (DPAPI-encrypted,
  machine-scope) and your Data Protection keybag. Its ACL is restricted to
  `SYSTEM` + `Administrators`; don't relax that, and don't copy the file
  to another machine (it won't decrypt there anyway — see Troubleshooting).
- Delete the plaintext `user.kb` copy from the Windows side once the vault
  import succeeds — there's no reason for a second on-disk copy of your
  keybag once it's inside the vault.

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
— see `NOTICE.md` for the full attribution statement.
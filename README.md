# T2 TouchID for Windows

<img width="1400" height="420" alt="fDhvq" src="https://github.com/user-attachments/assets/ae5efc29-7ed3-4b4b-96b0-0978328ae352" />

**Touch ID on Windows** for Intel MacBooks with an Apple T2 chip.

This project talks to the same Secure Enclave and fingerprint sensor that macOS uses, and exposes them to Windows as a Windows Hello biometric device.

> **Proof of concept.** Matching fingerprints on real hardware works. Full Windows Hello sign-in is still evolving. Read the safety notes before installing anything.

---

## ✨ What you get

| Piece | Role |
|--------|------|
| **T2TouchIdTransport** | Kernel driver for the T2 SEP (PCI) |
| **T2 NCM** | Network adapter over the T2 USB NCM link (BridgeXPC) |
| **T2TouchIdBio** | Windows Biometric driver + engine adapter |
| **SepVault GUI** | One-time macOS keybag setup, options, status |
| **T2SepBootstrap** | Service that unlocks the SEP on every cold boot |
| **t2touchid.exe** | Optional CLI for diagnostics |

After setup: power button can turn the display off and lock the PC; Touch ID can unlock it again (when Hello is configured).

---

## ⚠️ Disclaimer

Experimental research software. **No warranty.**

You install **unsigned** drivers that talk to the same Secure Enclave that holds FileVault / Data Protection keys. That can mean data loss, an unusable keybag, crashes, or worse.

Use only on a machine you can afford to break, and only if you understand the steps below. See `LICENSE` (GPL-2.0-only).

---

## 📋 Requirements

- Intel MacBook **with T2**, Windows 10 x64 via Boot Camp  
- macOS still bootable (needed once to copy `user.kb`)  
- Administrator rights  
- **Test signing** enabled, or Secure Boot off (drivers are not WHQL-signed)

```
bcdedit /set testsigning on
:: reboot
```

---

## 🚀 Quick start

### 1. Install drivers

As Administrator, run `InstallDriver.bat` from a folder that contains the built packages (`SEP\`, `NCM\`, `Bio\`, `Inst\`).

That will:

1. Install the test certificate  
2. Install **T2TouchIdTransport** (SEP PCI device)  
3. Install **Apple T2 NCM** network adapter  
4. Install the **biometric** driver  
5. Restart the Windows Biometric Service  

In Device Manager you should see healthy nodes for transport, NCM adapter, and a biometric device (no Code 43).

### 1.1 REBOOT!

### 2. Copy `user.kb` from macOS

Boot into **macOS**, log in as the account whose Touch ID you want on Windows.

```bash
Open UserFolder and Press ⌘ Command + ⇧ Shift + .
then open /Library/Keychains/ UUID-named folder → copy user.kb to the Boot Camp volume or a USB stick
```

Special bag ID is usually **`-501`** (first normal macOS user).

### 3. Import the keybag (once)

Run **SepVault GUI** as Administrator:

1. Open the **macOS Keybag** card  
2. Browse to `user.kb`  
3. Set special bag ID (`-501`) and the **macOS login password**  
4. Save  

The file is stored as DPAPI-protected `%ProgramData%\T2TouchId\sep-vault.bin`.  
On every cold boot, **T2SepBootstrap** unlocks the SEP with that vault.

If the keybag is already configured, the GUI shows status and a **Clear keybag** button.

### 4. Windows Hello

Settings → Accounts → Sign-in options → Fingerprint → set up.

Enrollment still relies on identities already present in the SEP from macOS; this is not a full enrollment pipeline yet.

---

## ⚙️ T2TouchID_GUI options

| Option | Default | Meaning |
|--------|---------|---------|
| **Fast verification** | On | Skips sensor reset + calibration reload; still runs cancel, identity list, and stability checks |
| **Lock on power-button display off** | Off | Sets power button to “Turn off the display” on all plans and locks the PC when the screen goes off (bootstrap service performs the lock) |
| **Logging** | Off | DebugView categories under Developer tools |

Developer tools (logging, transport override) stay hidden until you enable **Developer mode** in the footer.

---

## 🌐 Network transport

BridgeXPC needs a working path to the T2:

- **Native IPv6** (preferred) when the adapter has a link-local address  
- **IPv4 tunnel** (`169.254.84.1/16`) as fallback — `Set-T2NcmStaticIp.ps1` runs during install  

The GUI can force a mode under Developer tools if needed.

---

## 💻 CLI (`t2touchid.exe`)

Optional diagnostics: connect, identities, verify, bootstrap-related commands. Prefer the GUI for day-to-day setup. See `tools/t2touchid/` and design docs for command details.

---

## 🛠️ Troubleshooting

| Symptom | What to check |
|---------|----------------|
| Code 43 on transport / NCM | Test signing, correct INF, reboot; try disable/enable the device |
| SEP never “ready” | `C:\LogSEP.txt` from T2SepBootstrap; vault present; password/bag ID correct |
| No biometric device | Bio INF installed; `WbioSrvc` running; engine adapter DLL in `WinBioPlugIns` |
| Lock on display-off does nothing | Toggle on in GUI (admin); service **T2SepBootstrap** running; look for `lock:` lines in `C:\LogSEP.txt` |
| Fingerprint works in macOS only | Expected until Hello enrollment on Windows succeeds |

More detail: `driver/T2TouchIdBio/docs/`, `T2NCM/docs/`.

---

## 🔐 Safety notes

- **Unsigned drivers** — test signing only; do not use on a production-only machine.  
- **SEP is shared with FileVault** — a bad unlock sequence is not “just another driver bug.”  
- Keep a **macOS recovery path** and backups.  
- This is not an Apple-supported configuration.

---

## 📁 Repository layout
```
driver/T2TouchIdTransport/   KMDF SEP PCI driver
driver/T2TouchIdBio/         WBDI biometric stack, GUI, bootstrap service
T2NCM/                       NDIS NCM miniport + INFs
protocol/                    BridgeXPC, BiometricKit, AppleKeyStore clients
tools/                       Install scripts, t2touchid CLI
tests/                       Unit tests (no hardware)
```


## ☕ Support

If you find this project useful, consider buying me a coffee!

[![Ko-fi](https://img.shields.io/badge/Support%20me%20on-Ko--fi-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/osaul4ik)



## 🙏 Acknowledgements

This project was developed with reference to the excellent research and implementation work in [t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux) by **jmurth1234**.

The project was used as a technical reference to understand the T2 Touch ID communication flow and Apple-specific behavior.



## License

GPL-2.0-only — see `LICENSE` and `NOTICE.md`.

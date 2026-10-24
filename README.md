# T2 Touch ID for Windows

<img width="1400" height="420" alt="T2 Touch ID for Windows" src="https://github.com/user-attachments/assets/ae5efc29-7ed3-4b4b-96b0-0978328ae352" />

**Windows Hello fingerprint sign-in for Intel Macs with the Apple T2 Security Chip.**

**Status: Release Candidate (RC1)** — fingerprint verification, Windows lock-screen unlock, and repeated lock/unlock and sleep/resume scenarios have been tested on real hardware. This is an independent project, not an Apple or Microsoft driver.

> **Important:** This is a release candidate, not a production-certified driver. It uses test-signed drivers and communicates with the T2 Secure Enclave. Back up your data and keep macOS recovery available before installing.

## ✨ Features

- **Windows Hello unlock:** use fingerprints already enrolled in macOS to unlock Windows.
- **T2 Secure Enclave integration:** native communication with the T2 SEP and BiometricKit via BridgeXPC.
- **Fast verification:** optional short verification path without unnecessary sensor reset/calibration reload.
- **Responsive event handling:** event-driven BridgeXPC receive path with cancellation-aware waits instead of continuous polling.
- **Sleep/resume support:** power-state handling and recovery of the T2/NCM communication path.
- **Network fallback:** native IPv6 over T2 NCM, with an IPv4 tunnel fallback.
- **Cold-boot bootstrap:** `T2SepBootstrap` initializes the SEP using an encrypted macOS keybag vault.
- **SepVault GUI:** keybag setup, verification settings, status, logging, and advanced transport controls.
- **Diagnostics:** selectable log categories and optional `t2touchid.exe` CLI.

## 🧩 Components

| Component | Purpose |
| --- | --- |
| `T2TouchIdTransport` | PCI/SEP transport driver |
| `T2NCM` | T2 USB NCM network interface and control channel |
| `T2TouchIdBio` | UMDF 2 biometric sensor driver for Windows Biometric Framework |
| `T2TouchIdEngineAdapter` | Windows Hello biometric engine adapter |
| `T2SepBootstrap` | SEP/keybag initialization during Windows startup |
| `SepVault GUI` | Configuration and diagnostics |
| `t2touchid.exe` | Optional command-line diagnostics |

## 📋 Requirements

- An **Intel Mac equipped with an Apple T2 Security Chip**, with Windows 10/11 x64 via Boot Camp. Not every model/Windows build has been individually verified.
- A working macOS installation with Touch ID fingerprints already enrolled.
- Administrator access to Windows and access to the macOS account's `user.kb` keybag.
- A recovery path and recent backups.
- Driver test-signing enabled; the supplied drivers are **not WHQL-certified**. If Secure Boot prevents `testsigning`, do not attempt to bypass platform security without understanding the implications.

**Not supported:** Apple silicon Macs, non-T2 Macs, and native fingerprint enrollment entirely within Windows.

## 🚀 Installation

**Upgrading from an earlier experimental build?** Uninstall the old T2 driver packages using `remove-t2-drivers.bat` as Administrator, then run the new `InstallDriver.bat` **without rebooting between removal and installation**. Restart Windows after installation. The removal script preserves `%ProgramData%\T2TouchId\sep-vault.bin`, but resets driver and GUI registry settings; back up your settings first if needed. It also offers to disable Test Mode — **leave Test Mode enabled** when reinstalling a test-signed build.

### 1. Install the drivers

Download the appropriate release package from GitHub Releases and **extract it first**. From the extracted release package, run `InstallDriver.bat` as Administrator. Its expected layout includes `SEP/`, `NCM/`, `Bio/`, and `Inst/` directories.

The installer configures test signing (when needed), installs the certificate and T2 drivers, configures the IPv4 fallback address, and sets the Windows Biometric Service startup ordering. **Reboot Windows when installation is complete.**

Check Device Manager for the T2 transport, T2 NCM network adapter, and biometric device without device errors.

### 2. Obtain your macOS keybag

Boot macOS and sign in to the account that has your fingerprints enrolled. In Finder, press **Command + Shift + .** to show hidden files. Find `user.kb` in the appropriate UUID-named directory under `/Library/Keychains/` and copy it to a location accessible from Windows.

The first ordinary macOS user commonly has special bag ID `-501`, but verify the value for your account rather than assuming it.

**Treat `user.kb` and the macOS account password as sensitive credentials.** Do not attach them to bug reports or publish them.

### 3. Set up SepVault

Launch **SepVault GUI** as Administrator:

1. Open **macOS Keybag**.
2. Select the copied `user.kb`.
3. Enter the correct special bag ID and macOS account password.
4. Save the encrypted vault.

The vault is saved as a DPAPI-protected `%ProgramData%\T2TouchId\sep-vault.bin`. The bootstrap service uses it at startup to unlock the required SEP state.

### 4. Configure Windows Hello

Open **Settings → Accounts → Sign-in options → Fingerprint recognition (Windows Hello)** and complete setup.

**Enrollment note:** Matching depends on identities already enrolled in macOS; this project does not yet implement an independent Windows fingerprint enrollment pipeline.

## ⚙️ SepVault GUI

| Feature | Description |
| --- | --- |
| **Fast verification** | Uses a short verification sequence to reduce unlock latency |
| **Lock on display off** | Optional integration with the Mac power button/display state |
| **Developer mode** | Shows logging and advanced transport controls |
| **Logging** | Select Bio, BridgeXPC, and Power/diagnostic categories |
| **Transport selection** | Auto selection, with native IPv6 preferred and IPv4 fallback |

Use **Developer mode** for verbose logging. Disable verbose tracing during everyday use when it is no longer needed.

## 🌐 Communication

Windows reaches BridgeXPC through the Apple T2 NCM adapter:

1. **Native IPv6**, preferred when reachable.
2. **IPv4 tunnel**, as a fallback; the installer attempts to configure `169.254.84.1` on the NCM interface.

BridgeXPC processes asynchronous biometric events and acknowledges them. Verification requests support cancellation when Windows locks, changes sessions, or transitions power states.

## 🛠️ Troubleshooting

| Issue | Check |
| --- | --- |
| Device Manager error / missing biometric device | Test signing, driver installation, and reboot; verify `WbioSrvc` |
| SEP not initialized after cold boot | Vault configuration and `T2SepBootstrap`; review `C:\LogSEP.txt` if present |
| Touch ID does not respond at the lock screen | Verify Bio/BridgeXPC logging; look for `CAPTURE_DATA`, `StartMatch`, and `FingerOn` |
| Unlock stops working after cancellation | Collect logs with `CancelGuard`, `CAPTURE_DATA`, and `DATA_COLLECTION_IN_PROGRESS` |
| Unlock fails after sleep | Collect Power/T2NCM events alongside biometric logs |
| Connection cannot be established | Check NCM adapter and native IPv6 / IPv4 fallback path |

When reporting a regression, include: Mac model, Windows version, release/build, whether cold boot or sleep/resume was involved, and a **redacted** debug log. Never share `user.kb`, vault files, account passwords, or SEP secrets.

Diagnostic details: `driver/T2TouchIdBio/docs/`, `T2NCM/docs/`, and `tools/t2touchid/`.

## 🔐 Security and limitations

- These are **test-signed, non-WHQL drivers**. Use at your own risk.
- The SEP is also used by macOS security features. Keep verified backups and macOS recovery options.
- Fingerprints must be enrolled in macOS; independent Windows enrollment is not implemented.
- RC status does not imply independent security audit, broad device compatibility, or guaranteed support.

## 📁 Repository structure

```text
driver/T2TouchIdTransport/   SEP PCI transport
driver/T2TouchIdBio/         UMDF biometrics, GUI, and bootstrap service
T2NCM/                       USB NCM network drivers
protocol/                    BridgeXPC, BiometricKit, and AppleKeyStore
tools/                       Install/removal scripts and CLI
tests/                       Protocol tests
```

## ☕ Support

If this project is useful, you can support the development here:

[![Ko-fi](https://img.shields.io/badge/Support%20me%20on-Ko--fi-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/osaul4ik)

## 🙏 Acknowledgements

Thanks to **jmurth1234** and the research behind [t2-touchid-linux](https://github.com/jmurth1234/t2-touchid-linux), which provided valuable reference material for the Apple T2 biometric communication flow.

## License

GPL-2.0-only. See [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md).

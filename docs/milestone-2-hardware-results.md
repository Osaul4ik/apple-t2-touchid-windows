# milestone-2-hardware-results.md

## Статус: НЕ ВИКОНАНО

Це формальна вимога розділу 31 ТЗ ("Milestone 2 is NOT complete based on
compilation") і критичного правила №8 ("No mocked hardware"). Я (модель,
що генерувала цей код) працюю в Linux-контейнері без Windows 11, без WDK/
Visual Studio, без фізичного MacBook Pro 2019 і без можливості
скомпілювати чи прошити цей код на реальний T2. Тому:

- Жодного рядка нижче не буде заповнено вигаданими значеннями.
- Усі Gate-статуси розділу 32 — `UNKNOWN`, доки ти особисто не запустиш
  `t2touchid.exe` на цільовій машині.

## Gate results (заповнити після реального запуску)

| Gate | Статус | Нотатки |
|---|---|---|
| 1 — T2 PCI access | T2 PCI OK | | BAR4 mapped 
| 2 — SEP mailbox | SEP mailbox accessible  | |
| 3 — DMA / OOL | **DMA / OOL registered** | Закрито 30.08.2026 на реальному залізі. BAR4 base `0xc1620000` (64-bit), resource index 4, `len=0x10000`, підтверджено через PCI config space offset 0x20 (`GetBusData`), а не через вгадування першого memory-ресурсу — попередня версія коду мапила НЕ той BAR (SEP-функція має 3 memory BAR на цій машині), що й спричиняло "queued unrelated mailbox message from endpoint 0" ×32 → `STATUS_DEVICE_PROTOCOL_ERROR` при спробі `SET_OOL_IN`. Після виправлення BAR4-selection логіки в `device.c` (`T2QueryBar4ViaPciConfig`): `mailbox inbox=0x20001 empty=1 outbox=0x20001 full=0`, потім `registered 16 KiB endpoint-7 OOL input/output buffers`. |
| 4 — AppleKeyStore | OK | t2touchid.exe capabilities - > capability[1] = 0x2. sleep/wake lifecycle in testing
| 5 — CDC-NCM / IPv6 | **Confirmed on hardware** | inbox `UsbNcm.sys` via `apple-t2-ncm.inf`; adapter Up/Connected; IPv6 `fe80::…%27` Preferred (01.09.2026). See `docs/apple-t2-ncm-binding.md`. |
| 6 — RemoteXPC discovery | **In progress** | Phase 1: `protocol/Discovery` HTTP/2 port scan + `t2touchid network`. Phase 2 (RSD handshake → BiometricKit port) not yet implemented. |
| 7 — BridgeXPC | UNKNOWN | Connection.cpp має TODO-заглушки, потребує PlistPayload.cpp |
| 8 — BiometricKit | UNKNOWN | залежить від Gate 7 |
| 9 — Real NO_MATCH | UNKNOWN | залежить від Gate 8 |
| 10 — Real MATCH | UNKNOWN | залежить від Gate 8 |

## Відкриті пункти перед тим, як Gates 5–10 взагалі можна перевірити

1. Дописати `PlistPayload.cpp` (обрати й підключити `libplist` або інший
   maintained bplist parser — Milestone 2 §15).
2. Дописати RemoteXPC discovery (Milestone 2 §12–13) — наразі відсутнє.
3. Дописати FDR-calibration крок у `VerificationEngine::Verify` (позначено
   TODO) — без нього перше match-звернення, найімовірніше, не спрацює.
4. Підтвердити BAR4-selection логіку (`windows-transport-design.md`,
   "Відкрите питання") на реальному PCI config space цільової машини.
5. Отримати точний offset UUID у match_result event на реальному трафіку
   (`windows-security-model.md`) — поточна реалізація сканує весь буфер
   як безпечний, але тимчасовий fallback.

**Milestone 2 не може бути закритий (Definition of DONE, §33) без
виконання пунктів 1–5 і реального запуску на MacBook Pro 2019 з Windows
10 (цільова аудиторія проєкту — Windows 10; драйвер зібраний з
KmdfLibraryVersion 1.15 саме для цього).** Цей документ навмисно залишається "чесно неповним" замість того,
щоб симулювати результат.
## 2026-08-30 follow-up: Gate 4 timeout fix

**Symptom:** `capabilities` / any AKS (EP7) exchange timed out with
`final inbox=... empty=1` after successful OOL registration.

**Root cause 1 — missing PCI bus-master:**
Linux `t2_sep_transport.c` calls `pci_set_master(pdev)` before SET_OOL / AKS.
Windows driver never set `PCI_COMMAND` bits 1+2. SEP therefore could not
DMA the registered OOL buffers and never posted an EP7 reply.

**Root cause 2 — wrong AKS timestamps:**
`T2AksBuildHeaderV2` used FILETIME (since 1601) for both `usec_time` and
`calendar_seconds`. Linux uses monotonic µs + Unix epoch seconds.

**Changes (this patch):**
- `device.c`: new `T2EnablePciBusMaster()` via BUS_INTERFACE_STANDARD
  SetBusData on offset 0x04.
- `dma.c`: call it at the start of `T2DmaRegisterOolBuffers`.
- `akstore.c`: `usec_time` ← `KeQueryUnbiasedInterruptTime()/10`,
  `calendar_seconds` ← FILETIME-to-Unix conversion.
- `driver.h`: prototype for the new helper.


## 2026-09-01 follow-up: Gate 5 CDC-NCM (hardware)

**Result:** inbox `UsbNcm.sys` bound to parent `USB\VID_05AC&PID_8233`
via project package `T2NCM/apple-t2-ncm.inf`.

| Check | Value |
|-------|-------|
| Problem | `CM_PROB_NONE` |
| Service | `UsbNcm` Running |
| Adapter | `Apple T2 USB NCM Network Adapter` — Up / Connected |
| MAC | `AC-DE-48-00-11-22` |
| MTU | 9000 |
| Selected INF | published as `oem181.inf` from `apple-t2-ncm.inf` |

**Design notes that mattered on hardware:**

1. Match the **parent** HWID, not `&MI_00`/`&MI_01`. Apple `oem15.inf`
   Null on the parent suppresses child PDOs; NCM on the parent is what
   makes the function usable.
2. Do not edit `oem15.inf`. PnP rank selects our package when installed.
3. `Include/Needs` alone left the device in `CM_PROB_NEED_CLASS_CONFIG`
   (Code 56) with `UsbNcm` Stopped. Explicit `Characteristics` / `*IfType`
   / `Ndi` AddReg (mirroring public `usbncm.inf`) cleared Code 56 after
   reinstall + reboot.

Full write-up: `docs/apple-t2-ncm-binding.md`.

**Still open for BridgeXPC path:** IPv6 link-local on the new adapter,
RemoteXPC discovery (Gate 6), BridgeXPC session (Gate 7).

## 2026-09-01 follow-up: Gate 6 Discovery (phase 1)

IPv6 on T2 NCM adapter confirmed:

```text
fe80::dcc9:6760:e950:2ecd%27   AddressState=Preferred   ifIndex=27
```

Code added:

- `protocol/Discovery/Adapter.{h,cpp}` — find T2 NCM endpoints / by ifIndex
- `protocol/Discovery/PortScan.{h,cpp}` — concurrent HTTP/2 preface scan
  (dynamic ports 49152–65535), Linux `discover-biometric-port.py` phase 1
- `t2touchid.exe network [ifIndex] [--no-scan]`

Still required for Gate 6 DONE: RemoteXPC/RSD handshake on HTTP/2
candidates to read `Services[com.apple.eos.BiometricKit].Port`.

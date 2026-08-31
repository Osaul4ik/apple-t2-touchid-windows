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
| 4 — AppleKeyStore | OK | t2touchid.exe capabilities - > capability[1] = 0x2. Lifecycle (SleepWake) OK
| 5 — CDC-NCM / IPv6 | UNKNOWN | не реалізовано в цьому Milestone (див. protocol-architecture.md) |
| 6 — RemoteXPC discovery | UNKNOWN | не реалізовано в цьому Milestone |
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

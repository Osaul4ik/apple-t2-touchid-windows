# milestone-2-hardware-results.md

## Статус: НЕ ВИКОНАНО — немає доступу до фізичного заліза в цьому середовищі

Це формальна вимога розділу 31 ТЗ ("Milestone 2 is NOT complete based on
compilation") і критичного правила №8 ("No mocked hardware"). Я (модель,
що генерувала цей код) працюю в Linux-контейнері без Windows 11, без WDK/
Visual Studio, без фізичного MacBook Pro 2019 і без можливості
скомпілювати чи прошити цей код на реальний T2. Тому:

- Жодного рядка нижче не буде заповнено вигаданими значеннями.
- Усі Gate-статуси розділу 32 — `UNKNOWN`, доки ти особисто не запустиш
  `t2touchid.exe` на цільовій машині.

## Що потрібно від тебе, щоб закрити цей документ

1. Встановити WDK + Visual Studio (Driver Development workload).
2. Увімкнути test signing (`bcdedit /set testsigning on`) або підписати
   драйвер тестовим сертифікатом — Secure Boot майже напевно доведеться
   тимчасово вимкнути для першого PoC.
3. Скомпілювати `driver/T2TouchIdTransport`, встановити через
   `pnputil /add-driver T2TouchIdTransport.inf /install` (або Device
   Manager → Update driver → Have Disk).
4. Скомпілювати `tools/t2touchid` (потребує `protocol/*` і `libplist` —
   див. `docs/windows-protocol-architecture.md` щодо відсутньої
   `PlistPayload.cpp` реалізації, яку треба дописати першою).
5. Запустити послідовно:
   ```
   t2touchid.exe status
   ```
   і заповнити нижче реальний вивід.

## Gate results (заповнити після реального запуску)

| Gate | Статус | Нотатки |
|---|---|---|
| 1 — T2 PCI access | UNKNOWN | |
| 2 — SEP mailbox | UNKNOWN | |
| 3 — DMA / OOL | UNKNOWN | |
| 4 — AppleKeyStore | UNKNOWN | |
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
11.** Цей документ навмисно залишається "чесно неповним" замість того,
щоб симулювати результат.

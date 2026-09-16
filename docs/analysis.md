# Чому скан не відбувається — розбір по логах

## Коротка відповідь

Сенсор **бачить палець, але жодного разу не робить знімок**. Порівняння твого
Windows-логу з macOS-логом того самого ноутбука (та сама прошивка `23P5067`,
той самий uid 501, ті самі 3 identity) показує, що на Windows у потоці подій
немає жодного статусу з image-конвеєра.

macOS при вдалому розблокуванні:

```
90 SensorOperationModeCapture
63 FingerOn
55 ImageCaptured          <-- ось сам скан
72 ImageForProcessing
95 ImageWasAccepted  (238 B)
91 SensorOperationModePause
64 FingerOff
...
>>> 0xE3FF8002 match_result, 3228 B <<<
73 TemplateListUpdated (3202 B)
```

Твій Windows:

```
90 SensorOperationModeCapture
statistics type 4, 35, 25
81   <-- такого коду немає в жодному вдалому циклі на macOS
63 FingerOn
91 SensorOperationModePause
78   <-- такого коду теж немає
64 FingerOff
statistics type 30
90 SensorOperationModeCapture
```

`55 / 72 / 95` не з'являються ніколи. Тобто це не «матчер сказав ні» — матчер
взагалі не отримав картинки. Через 20 с вікно збігає, клієнт шле Cancel.

Додаткове незалежне підтвердження з статистики: на macOS під час обробки
зображення прилітають statistics типів **0, 1, 2** — це `double` у діапазоні
0.02–0.14, метрики якості знімка. У твоєму логу є лише типи 4, 25, 30, 35.
Жодного 0/1/2 → зображення не оброблялось.

## Що точно НЕ зламано

- Транспорт, BridgeXPC, HELO, версії — ок.
- Парсинг подій — ок. Я перевірив зміщення по macOS-логу: `embedded_type` на
  офсеті 8, ordinal на 24, довжина на 32, дані з 40. Твій декодер дає рівно ті
  ж числа, що й Apple-івський демон (90/36/12 тощо).
- Identity list — ок. 3 записи по 20 байт, і UUID, який macOS повертає при
  вдалому матчі (`D6AE7EAA-…`), — це другий запис з твого ж списку. Шаблони на
  місці й доступні.
- `kMinMatchResultEventBytes = 0xC70` — коректний поріг (реальна подія 3228 B).

## Три знайдені розбіжності з macOS

### 1. Розмір payload команди StartMatch: 132 B замість 68 B ← головне

macOS на цій самій машині з цими самими 3 identity:

```
performCommand:version:inValue:inData:inSize:outData:outSize: 4 1 0 <ptr> 68
```

Увесь внутрішній payload команди 4 — **68 байт**. А `68 == 8 + 3*20`.

`EncodeMatchInitData` збирав `MatchInitDataV1 (68) + uint32 count (4) + 3*20` =
**132 байти** — рівно те, що видно в твоєму логу (`inner=140B` = 8 заголовка +
132).

Схоже, «68-байтова структура опцій з 60 reserved» у Linux-референсі — це
неправильно прочитаний дамп із машини, де теж було рівно три пальці: ці
60 «reserved» байт і є масивом identity. SEP отримує сміття там, де чекає
масив identity — і сесія матчу озброює сенсор, але не доходить до
image-стадії.

### 2. `LoadCalibration` (cmd 0x20) — macOS її не шле взагалі

За 4 хвилини живої активності (з двома вдалими розблокуваннями) macOS
використовує команди `4, 12, 39, 40, 44, 46, 48, 56, 61, 62, 63, 74, 80, 84`.
Команди `0x20` там немає жодного разу. bridgeOS калібрує сенсор на своєму
власному завантаженні.

А в твоєму логу прямо під час завантаження 61407-байтового FDR-блоба SEP
відповідає статусом `94` (сусідній до `95 ImageWasAccepted`, тобто дуже схоже
на «image rejected»), після чого всі подальші кадри відхиляються. Тобто є
серйозна підозра, що ми перетираємо робочу калібрувальну конфігурацію сенсора
сирим FDR-блобом.

### 3. `ResetSensor` (cmd 2, value 2) — macOS її теж не шле

Ресет сенсора безпосередньо перед озброєнням матчу — правдоподібний спосіб
втратити стан, який bridgeOS виставив на буті.

## Що саме змінено

| Файл | Зміна |
|---|---|
| `protocol/BiometricKit/Commands.h/.cpp` | Новий `MatchIdentityLayout`: `inline` (8-байтовий заголовок + записи identity → 68 B, **новий дефолт**), `padded` (лише 68-байтова структура, без identity — друге можливе прочитання 68 B), `legacy` (стара поведінка 132 B). `EncodeMatchInitData` приймає layout. |
| `protocol/BiometricKit/MatchResult.h/.cpp` | `StatusCodeName()` — справжні імена Apple зі свіжого macOS-логу (ImageCaptured, FingerOn, ImageWasAccepted…). `StatusCodeIsImagePipeline()`. `ParseStatisticsEventBody()` — статистика тепер декодується (`uint32 type` + `uint64/double value`), а не дампиться сирою. Виправлено застарілий коментар про «no-op діапазон 81..84» — залізо його спростовує. |
| `protocol/BiometricKit/VerificationEngine.h/.cpp` | `ResetSensor` і `LoadCalibration` стали opt-in (`resetSensor`, `loadCalibration`, обидва `false`). Новий `matchLayout`. Новий результат **`NoImageCaptured`** — сесія, де був FingerOn, але жодного image-статусу, більше не звітується як безликий `Timeout`. Логи статусів тепер містять `status_name=`, у кінці — `session summary`. |
| `tools/t2touchid/main.cpp` | Прапорці `--match-layout inline\|padded\|legacy`, `--reset-sensor`, `--load-calibration`; вивід для `verify-no-image`. |
| `tests/ProtocolTests.cpp` | Регресійні тести: inline == 68 B, padded == 68 B, legacy == 132 B; імена статусів; 78/81 лишаються без імені; декодер статистики на реальних байтах із твого логу. |
| `docs/macos-verified-status-map.md` | Уся провенанс-документація: як знято лог, таблиця статусів, еталонна послідовність вдалого анлоку, карта команд macOS, формат statistics. |
| `tools/analyze-verify-log.py` | Розбирає `t2touchid` verify-лог у читабельний таймлайн — сам перекодовує hex подій, тому старі логи теж читаються. |

Кодування payload перевірено збіркою на g++: `68 / 68 / 132` для трьох
identity, заголовок `flags|uid`, далі записи як є.

## Порядок перевірки на залізі

1. **Дефолт (новий):** `t2touchid.exe verify -v`
   → inline-68, без calibration, без reset. Це найближче до того, що робить
   macOS.
2. Якщо знову `verify-no-image` — `--match-layout padded`
   (друге прочитання 68 байт: тільки опції, без identity).
3. Якщо й це ні — `--match-layout inline --load-calibration`, щоб відділити
   вплив калібрування від вплив layout-у.
4. `--match-layout legacy` відтворює стару поведінку для контролю.

Після кожного прогону:
`python3 tools/analyze-verify-log.py t2touchid-verify.log` — він одразу скаже,
чи з'явились `55 ImageCaptured` / `95 ImageWasAccepted` і статистика типів
0/1/2. Поява будь-чого з цього означає, що конвеєр зображення нарешті
запустився.

## Чесна межа впевненості

Розмір 68 vs 132 — це факт із логу, тут сумнівів немає. Чим саме заповнені ці
68 байт (identity inline чи опції з padding) — лог за розміром не розрізняє,
тому обидва варіанти зроблені перемикачами, а не здогадкою в коді. Те, що
`LoadCalibration`/`ResetSensor` шкодять, — обґрунтована гіпотеза (macOS їх не
шле + статус 94 під час завантаження блоба), а не доведений факт; тому вони
вимкнені, але не видалені.

Коди `78` і `81` лишаються без імені навмисно: у жодному вдалому циклі macOS
вони не зустрічаються, тож придумувати їм значення не було на чому.
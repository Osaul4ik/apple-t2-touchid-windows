# Milestone 1 — Source-Level Audit of t2-touchid-linux

Джерело: повний clone `github.com/jmurth1234/t2-touchid-linux` (перевірено 2026-08-30), файли прочитані напряму — `src/t2_sep_transport.c`, `src/t2-aks-tool.c`, `src/discover-biometric-port.py`, `src/bridge-xpc-probe.py`, `src/t2-fprintd.py`, `tests/test_t2_fprintd.py`.

**Примітка щодо формату:** ТЗ вимагає окремі файли (`docs/linux-reference-analysis.md`, `docs/apple-keystore.md`, `docs/bridgexpc-protocol.md` тощо). Для практичності все зведено в один документ з чіткими секціями — кожну секцію можна винести окремим файлом без змін змісту. Кожне важливе твердження позначено тегом:

`VERIFIED FROM SOURCE` | `VERIFIED FROM MS DOCS` | `INFERRED` | `UNKNOWN`

---

## 1. Executive summary

Головний висновок Milestone 0 ("SEP-транспорт pinned після DMA registration") **підтверджено джерелом, і причина точно встановлена**: це поведінка самого Linux-модуля (навмисне рішення розробника, а не апаратне обмеження), яке спрацьовує лише в `register_ool=1` режимі. Це суттєво змінює Windows transport design (розділ 5) — Windows-драйвер **не зобов'язаний** копіювати "no unload" поведінку буквально, якщо коректно реалізує deregistration SEP endpoint 0 перед unload. Причина, чому Linux цього не робить: репозиторій просто ще не реалізував deregistration control message — це прагматичне рішення research-проєкту, не hardware-факт.

Байтовий рівень BridgeXPC-протоколу і AppleKeyStore opcode-простір тепер **VERIFIED FROM SOURCE** — розділи 6 і 8 нижче дають точні структури.

---

## 2. Complete execution path (verification request → MATCH/NO_MATCH)

```
PAM/D-Bus caller
 ↓
FprintDevice.VerifyStart()                    [t2-fprintd.py:287]  sync, validates claim+finger
 ↓
FprintDevice._run_verification() (asyncio.Task) [t2-fprintd.py:307]  async
 ↓
T2Backend.verify()                              [t2-fprintd.py:154]
 ↓
T2Backend.discover() → cached port or subprocess discover-biometric-port.py
 ↓
T2Backend._run_probe() → subprocess: bridge-xpc-probe.py --initialize --reset-sensor
                          --cancel-operation --load-calibration --identity-list
                          --match-seconds N --stop-on-match-result
 ↓ (new TCP/IPv6 connection per probe invocation — NOT a persistent session)
socket.connect(host, port)                      [bridge-xpc-probe.py:449]  sync connect over link-local IPv6
 ↓
receive_frame() → HELO (frame type 1)            [bridge-xpc-probe.py:450-454]
 ↓
send_helo()                                      responds with own HELO JSON body
 ↓
request(sock,[0]) → getBridgeVersion              [bridge-xpc-probe.py:459-475]  reply=[0, api_version]
 ↓
request(sock,[10, client_version]) → setClientVersion (min(api_version,2))
 ↓
biometric_command(sock, 2, value=2) → reset sensor  [Apple cmd 2]
 ↓
biometric_command(sock, 12) → cancel outstanding op [Apple cmd 12]
 ↓
request_with_events(sock,[11]) → read FDR calibration blob (bridge-level method 11)
 ↓
biometric_command(sock, 0x20, value=3, data=FDR) → load calibration into sensor
 ↓
biometric_command(sock, 0x42, data=uid) → identity-list (returns N × 20-byte identity_record_v1_t)
 ↓
biometric_command(sock, 4, data=match_init_data_v1) → START MATCH   [bridge-xpc-probe.py:774]
 ↓ (async event loop, up to --match-seconds)
receive_envelope() loop → bridge-side status callbacks (envelope[1]==False)
   ↓ each ack'd with [1, True, envelope[2], [0]]
   ↓ summarize_event() classifies embedded_type:
       0xE3FF8001 → "status"
       0xE3FF8002 → "match_result"   ← THE decision point
       0xE3FF8004 → "statistics"
 ↓ on match_result event (or timeout) → biometric_command(sock, 12) cancel
 ↓
verdict_from_result()                             [t2-fprintd.py:53]  sync, pure function
 ↓
"verify-match" | "verify-no-match" | RuntimeError("rejected")
 ↓
FprintDevice.VerifyStatus signal → D-Bus caller
```

Синхронність: усе спілкування з T2 у `bridge-xpc-probe.py` є **синхронним блокуючим socket I/O** всередині одного subprocess-виклику; `t2-fprintd.py` огортає це в asyncio subprocess, тобто кожен verify-цикл — це окремий короткоживучий TCP-з'єднання, а не довгоживуча сесія. Це важлива відмінність від того, що можна було б припустити з Milestone-0 моделі.

---

## 3. T2 SEP transport analysis (`t2_sep_transport.c`) — VERIFIED FROM SOURCE

### PCI
| Поле | Значення |
|---|---|
| Vendor ID | `0x106b` (Apple) |
| Device ID | `0x1802` |
| BAR | BAR4, min size `0x10000` |
| Init | `pcim_enable_device` → `pcim_iomap_regions(BIT(4))` |
| Reset поведінка | не реалізована окремо; модуль лише читає inbox/outbox status на probe |
| Переривання | **не використовуються** — мейлбокс опитується через `readl`/`usleep_range` полінг (100–200 мкс), timeout 5 секунд (`T2_SEP_TIMEOUT_US`) |

### Реєстри мейлбоксу
| Offset | Призначення |
|---|---|
| `0x0108` | INBOX_STATUS, біт 17 = INBOX_EMPTY |
| `0x010c` | OUTBOX_STATUS, біт 16 = OUTBOX_FULL |
| `0x0810` | INBOX_DATA (4×32-біт слова, читання останнього просуває FIFO) |
| `0x0820` | OUTBOX_DATA (4×32-біт слова, останнє слово завжди 0) |

Повідомлення — рівно 16 байт (4×u32), endpoint/tag/opcode закодовані в слові 0 (endpoint control: `endpoint | tag<<8 | opcode<<16 | target_endpoint<<24`; endpoint 7 AKS: `endpoint | operation<<8 | transaction<<16`).

### DMA
| Параметр | Значення |
|---|---|
| DMA mask | 44-бітний (`DMA_BIT_MASK(44)`) |
| Буфери | 2× 16 KiB (`T2_SEP_OOL_SIZE = 0x4000`) coherent, `dma_alloc_coherent` |
| Реєстрація | control-повідомлення `SET_OOL_IN` (opcode 2) і `SET_OOL_OUT` (opcode 3) на endpoint 0, кожне з `dma_addr >> PAGE_SHIFT` і розміром |
| Alignment | адреса має бути вирівняна на 4 KiB (`IS_ALIGNED(dma, SZ_4K)`) |

### AppleKeyStore endpoint (7) — wire format
Кожен обмін — заголовок (16 або 24 байти + опційний тіло) з SHA-256 digest у перших 16 байтах заголовка (обчислюється над рештою заголовка + тілом, digest-поле обнулене під час хешування):

```
V1 header (0x48 bytes): digest[16] | version:u32le | usec_time:u64le | flags:u32le | clock_id:u64le | platform_data[0x20]
V2 header (0x50 bytes): V1 header | calendar_seconds:u64le
```
Ціла EP7-транзакція на дроті: `length_prefix:u32le | header | body`.

### Пінінг — ТОЧНА ПРИЧИНА (закриває питання з Milestone 0, п.4)
**VERIFIED FROM SOURCE, рядки 588-599 та 637-652:**
- Пінінг **не є hardware-обмеженням SEP**. Це явне рішення модуля: після успішної реєстрації `SET_OOL_IN`/`SET_OOL_OUT` драйвер викликає `__module_get(THIS_MODULE)`, що інкрементує refcount модуля і **робить `rmmod` неможливим** (`t2_sep_remove` також рано виходить з `dev_warn`, якщо буфери зареєстровані).
- Причина в коментарі: "SEP retains both DMA addresses" — тобто SEP-хардвер дійсно продовжує вважати ці фізичні адреси валідними для DMA, і драйвер **свідомо не реалізує** control-повідомлення для деreation (SEP endpoint 0 не має задокументованого в цьому коді "unregister OOL" opcode — можливо, він існує в SEP, але цей модуль його не викликає).
- Отже: `Windows driver cannot unload` — це **INFERRED, не факт**. Точніше: без реалізації deregistration-опкоду Windows-драйвер має ту саму проблему, але це відкриває шлях: якщо такий opcode існує (потрібне окреме дослідження SEP command set поза межами verification-only функціоналу), "чистий" unload стає можливим. Для V1 PoC безпечніше і чесніше **явно копіювати обережну поведінку** (не намагатися unload), а не одразу вважати проблему нерозв'язною назавжди.

---

## 4. Windows transport design implications

Перед тим, як писати новий PCI transport, перевірено наявні Windows-проєкти для T2-заліза (пошук GitHub, розділ 12).

**Знайдено:** `imbushuo/mac-precision-touchpad` (AmtPtpDevice-родина — до речі, це та сама кодова лінія, з якої походить власний `AmtPtpDeviceUsbKm` проєкт Владислава) та `imbushuo/DFRDisplayKm` — обидва працюють з T2-під'єднаними USB-composite пристроями (трекпад через SPI/T2-USB, Touch Bar через USB). **Жоден з них не реалізує PCI-мейлбокс до SEP** — вони працюють на рівні USB/SPI HID, не на рівні endpoint 0/7 мейлбоксу, який потрібен саме для Touch ID. Це підтверджує: **готового Windows PCI-transport для SEP endpoint 7 не існує**, T2TouchIdTransport.sys буде першою реалізацією цього рівня на Windows.

Мінімальні вимоги, що випливають із джерела (не з припущень):
- Потрібен **KMDF, не UMDF**, для transport-шару: пряма робота з PCI BAR4 MMIO (`readl`/`writel`-еквіваленти через `READ_REGISTER_ULONG`/`WRITE_REGISTER_ULONG`) і DMA common buffer з 44-бітним адресним простором — це класичний kernel-mode PCI driver, UMDF WinUsb-модель тут не підходить, бо T2 SEP — не USB-пристрій, а окрема PCI-функція.
- Полінг замість переривань спрощує Windows-порт (не потрібен ISR/DPC для мейлбоксу), але додає бюджет latency (5-секундний timeout копіюється напряму).
- SHA-256 digest-обчислення (endpoint-7 AKS wire format) переноситься напряму через CNG (`BCryptHashData`) — алгоритм і структура повністю відомі, це не потребує reverse engineering.

---

## 5. AppleKeyStore audit (`t2-aks-tool.c`) — VERIFIED FROM SOURCE

Allow-listed operations (з `t2_aks_operation_allowed()` у транспортному модулі — **це enforced в kernel, не лише в userspace tool**):

| Opcode | Назва (з коду) | Request body | Response | Потрібен для verification | Потрібен для boot/unlock |
|---|---|---|---|---|---|
| `0x03` | load_keybag | session:u64le, size:u32le, bag_bytes | status:u32le, handle:i32le | НІ (setup-крок) | ТАК |
| `0x04` | change_lock_state (unlock) | result:u32(0), session:u64le, handle:i32le, lock_state:u32le(0=unlock), secret_len:u32le, secret_bytes | status:u32le | НІ напряму, але verification неможлива без розблокованого keybag | ТАК |
| `0x0d` | make_system_keybag (set-system-keybag) | session:u64le, handle:u32le, special:i32le, empty-blob-len:u32le(0) | status:u32le | НІ (setup) | ТАК |
| `0x19` | get_device_state | handle:i64le, selector:u32le | status:u32le, blob_len:u32le, blob | Опційно (діагностика) | Опційно |
| `0x4d` (`T2_SEP_AKS_GET_CAPABILITIES`) | capabilities | selector qword=1 | status:u32le, capability_value:u64le | НІ (read-only самоперевірка) | НІ |

**UID-припущення:** UID 501 **не є вимогою протоколу AppleKeyStore** — це конфігурований параметр (`T2_TOUCHID_MACOS_USER_ID`, дефолт `501` в `t2-fprintd.py` і `bridge-xpc-probe.py`). Це підтверджує явно те, що Milestone 0 позначив як PARTIALLY KNOWN: **UID 501 — конвенція проєкту (типовий перший non-root macOS user), не hardware/протокольне обмеження.** Windows-реалізація не зобов'язана хардкодити 501.

Будь-яка інша операція на endpoint 7 **відхиляється самим kernel-модулем** (`-EACCES`), незалежно від того, що просить userspace — це сильна властивість безпеки, яку варто зберегти 1:1 у Windows-драйвері (allow-list у kernel-mode компоненті, не лише в user-mode протокольному шарі).

---

## 6. Keybag lifecycle — VERIFIED FROM SOURCE

1. **Cold boot:** keybag не завантажений; `/dev/t2-aks` доступний лише root (mode 0600) одразу після успішної DMA-реєстрації.
2. **Unlock:** `load_keybag` (0x03) завантажує збережені bag-байти (макс. 16000 байт) із файлу, повертає `handle`. Потім `set-system-keybag` (0x0d) приймає `session`, `handle`, `special` bag ID. Далі `unlock-keybag` (0x04) з `handle` і паролем (session=0 у типовому виклику з README) розблоковує.
3. **Пароль:** вводиться інтерактивно через `/dev/tty` з вимкненим echo, або через stdin (`unlock-keybag-stdin`) — **ніколи не передається через argv чи env**; тримається лише в стековому буфері `secret[1024]`, обнуляється (`memset`) перед виходом з функції в усіх шляхах, включно з error path.
4. **Скільки тримається:** лише на час одного ioctl-виклику; не кешується між викликами `t2-aks-tool`.
5. **Handles:** normal handle (з `load_keybag`) + special user bag (передається окремим `-501`-подібним аргументом у `set-system-keybag`/`unlock-keybag` викликах — від'ємне значення позначає "special").
6. **Verification без розблокованого keybag:** явно не протестовано в цьому коді (verification йде через окремий BridgeXPC/BiometricKit шлях, не через `/dev/t2-aks`); але README стверджує пряму залежність — SEP не видасть matching identity, якщо catacomb/keybag недоступні.
7. **Verification сама щось розблоковує?** Ні — `bridge-xpc-probe.py` ніде не викликає AppleKeyStore ioctl; keybag-unlock і BiometricKit verification — **два незалежні протокольні шляхи** (AKS endpoint 7 vs. BridgeXPC over IP), об'єднані лише спільним станом SEP.
8-10. Logout/reboot/sleep: код не містить logout-хука; reboot скидає SEP-реєстрацію (volatile); sleep/resume — окремо, розділ 9.

**Висновок для Windows V1:** ручний diagnostic-unlock (аналог виклику `t2-aks-tool load-keybag` + `set-system-keybag` + `unlock-keybag`) **достатній і не потребує Credential Provider** — підтверджує рекомендацію Milestone 0, п.7 ТЗ.

---

## 7. BridgeXPC protocol — byte-level (`bridge-xpc-probe.py`) — VERIFIED FROM SOURCE

### Транспорт
IPv6 link-local, TCP, scoped за `interface` (`socket.if_nametoindex`), порт — динамічний (розділ 8).

### Frame header (кожен фрейм)
```
offset  size  field
0x00    2     magic          = 0xB892 (little-endian u16)
0x02    2     version        = 1 (PROTOCOL_VERSION)
0x04    4     frame_type     1=HELO, 2=MESSAGE  (u32le)
0x08    8     body_length    u64le
0x10    N     body
```
(`struct.Struct("<HHIQ")` — увага: третє поле u32 не u16, четверте u64; сумарний header = 16 байт)

### HELO frame (type 1)
Тіло — JSON: `{"MaxSupportedProtocolVersion": 1, "OSBuild": "...", "BridgeXPCVersion": N, "ProcessName": "..."}`. T2 надсилає HELO першим при з'єднанні; клієнт відповідає своїм HELO з тим самим `BridgeXPCVersion`, який прийшов від peer.

### MESSAGE frame (type 2)
Тіло — binary property list (`plistlib.FMT_BINARY`). Верхній рівень — **завжди 4-елементний список**: `[version, is_reply(bool), request_id(UUID string), payload]`.
- Запит: `[1, False, "<UUID4>", payload]`
- Відповідь: `[1, True, "<same UUID>", reply_payload]`
- Асинхронні bridge-side status callbacks приходять як `is_reply=False` events з новим `request_id`, які клієнт **зобов'язаний** підтвердити тим самим request_id: `[1, True, callback_id, [0]]` — інакше з'єднання застрягне (це задокументовано в коментарі як імітація поведінки `BiometricKitBridgeConnection`).

### Внутрішній BiometricKit command wrapper ("BM" header)
Команди рівня BiometricKit (не bridge-рівня) обгортаються ще одним 8-байтним заголовком і надсилаються як bridge-payload `[3, 0, inner_bytes, output_capacity]`:
```
offset  size  field
0x00    2     magic     = 0x4D42 ("BM" little-endian)
0x02    2     command   (BiometricKit command ID)
0x04    2     version
0x06    2     value
0x08    N     data (command-specific payload)
```

### Відомі bridge-level методи (payload[0] верхнього рівня)
| ID | Назва | Дія |
|---|---|---|
| 0 | getBridgeVersion | повертає `[0, api_version]` |
| 1 | getServiceOpened | read-only статус сервісу |
| 3 | (обгортка команди) | `[3, 0, inner_BM_bytes, output_capacity]` — весь BiometricKit command layer йде через це |
| 5 | read EEPROM calibration | повертає `[blob or None]` |
| 10 | setClientVersion | `[10, client_version]` |
| 11 | read FDR calibration | те саме, джерело — bridgeOS FDR, не локальний macOS файл |

### Відомі BiometricKit command ID (усередині "BM"-обгортки)
| Command | Назва | Дані запиту | Відповідь |
|---|---|---|---|
| 1 | biometric protocol version | — | 4 байти u32 |
| 2 | reset sensor | value=2 | status |
| 4 | start match | `match_init_data_v1`: flags:u32le, macos_user_id:u32le, 60 reserved bytes, [count:u32le] + N×20-byte identity records | status + async match events |
| 0x0c (12) | cancel operation | — | status |
| 0x20 | load calibration | value=3(bridgeOS FDR)/5(local), data=blob | status |
| 0x27 | SKS lock state | data=macos_user_id:u32le | 4-byte lock state |
| 0x35 | sensor info | — | 12 bytes (3×u32) |
| 0x3c | catacomb state | — | 8 or 16 bytes |
| 0x40 | load catacomb archive component | data=LTFC-wrapped secure blob | status |
| 0x42 | identity list | data=macos_user_id:u32le | N × 20-byte `identity_record_v1_t` |
| 0x4b | load bio-lockout record | data=HRLB-wrapped blob | status |
| 0x53 | sensor readiness | — | 1 byte bool |

### `identity_record_v1_t` (20 bytes) — VERIFIED FROM SOURCE
```
offset  size  field
0x00    4     user_id (u32le) — matches configured macOS user ID
0x04    16    identity UUID (opaque, never logged)
```

### Match-result event (embedded_type `0xE3FF8002`)
Мінімум `0xC70` байт валідується перед парсингом. **Критично**: перше signed-слово в event_data **не є надійним індикатором успіху** — контрольовані тести показали, що воно лишається `-1` для обох результатів (MATCH і NO_MATCH). Єдиний надійний сигнал: **чи міститься в event_data 16-байтний UUID однієї із заенролених identity-записів**, отриманих раніше через command `0x42`. Це підтверджує ключове припущення Milestone 0 (розділ 10) буквально, без жодних припущень.

Інші типи подій: `0xE3FF8001` = "status" (4-байт status_code + 8-байт status_data_length за офсетом 8), `0xE3FF8004` = "statistics" (вміст не парситься детально в цьому коді).

---

## 8. Dynamic port discovery (`discover-biometric-port.py`) — VERIFIED FROM SOURCE

- Механізм — **не RemoteXPC-style service-list request per se**, а брутфорс TCP-connect по всьому динамічному діапазону портів (49152–65535) з concurrency-limited (default 512) HTTP/2 preface probe (`greeting[3]==4` тобто HTTP/2 SETTINGS frame type, порожній payload) — це фільтрує кандидатів, а не одразу дає відповідь.
- Для кожного кандидата-порту виконується RemoteXPC handshake (`RemoteXPCConnection` з `pymobiledevice3`, стороння бібліотека): `connect()` → `send_device_handshake()` → `receive_response()` дає peer record з полем `Services`, де ключ `com.apple.eos.BiometricKit` містить `{"Port": N}` — **саме цей порт — реальний порт BiometricKit**, окремий від порту, на якому відбувався сам RemoteXPC handshake.
- Кілька інших сервісів на T2 відповідають на той самий HTTP/2-preface, але відхиляють RSD peer-record запит — вони явно трактуються як очікувані "decoys", не помилки.

**Питання зі стабільності порту (Milestone 0 unknown, розділ D):**
- Код **не кешує порт на диску сам** — кешування на рівні `/var/lib/t2-touchid/biometric-port` реалізовано окремо в `t2-fprintd.py` (`T2Backend.__init__`, читає файл; `t2-biometric-ready.service` з Milestone-0 репорту його заповнює).
- `t2-fprintd.py` явно реалізує **retry-once-on-failure** логіку (`test_failed_cached_endpoint_is_rediscovered_once`): якщо кешований порт більше не працює — один раз перевідкрити, потім здатися. Це підтверджує: **порт може змінюватися** (інакше цей retry-код не мав би сенсу), але код не документує точну умову зміни (reboot vs T2 reset vs bridgeOS restart) — це залишається **UNKNOWN**, як і в Milestone 0.

Windows discovery design: прямий порт RemoteXPC-протоколу на Windows вимагає або (а) переносу еквівалентної RSD-handshake логіки з нуля (специфікація `pymobiledevice3.remote.remotexpc` — стороння залежність, ліцензію і код якої треба перевірити окремо, не входить в аналізований репозиторій), або (б) port-scan-only підходу без справжнього RSD handshake, що менш надійно відрізняє BiometricKit від "decoy" сервісів. Це відкрите архітектурне рішення для Milestone 4.

---

## 9. BiometricKit verification lifecycle — MATCH/NO_MATCH state diagram

```
CONNECT (TCP/IPv6 to discovered port)
   │
   ▼
HELO exchange (peer HELO → own HELO)                    malformed magic/version → ERROR
   │
   ▼
getBridgeVersion → setClientVersion(min(api,2))          version_reply[0]!=0 → ERROR
   │
   ▼
reset sensor (cmd 2) → cancel (cmd 12) → load calibration (cmd 0x20)
   │
   ▼
identity-list (cmd 0x42) → enrolled_identity_records      empty → match still attempted, but
   │                                                        cannot ever produce MATCH (no UUID to compare)
   ▼
start match (cmd 4, match_init_data_v1)
   │
   ├── match_reply[0] != 0 → match_rejected=True → ERROR (never a silent success)
   │
   ▼ match_started
VERIFYING (event loop, up to --match-seconds)
   │
   ├── recv timeout (deadline reached, no match_result event)  → loop exits →
   │       cancel (cmd 12) sent regardless → NO_MATCH-equivalent (verdict_from_result
   │       falls through to "verify-no-match" when match_events is empty)
   │
   ├── match_result event (embedded_type 0xE3FF8002) received:
   │       UUID found among enrolled_identity_records → matched=True,
   │           matches_enrolled_identity=True → MATCH
   │       UUID not found → matched=True, matches_enrolled_identity=False →
   │           NO_MATCH (fails closed even though a "match" bit may be set —
   │           only an ENROLLED-identity match counts)
   │
   └── malformed/short event (<0xC70 bytes) → summary lacks "matched" key →
           verdict_from_result treats it as non-match_result event → falls through
           to NO_MATCH (never raises an exception, never treated as MATCH)
   │
   ▼
cancel (cmd 12) sent unconditionally after loop exit
   │
   ▼
verdict_from_result(): only "verify-match" if BOTH matched==True AND
    matches_enrolled_identity==True; RuntimeError only for match_rejected
    or structurally malformed probe JSON (transport/subprocess failure) —
    everything else is NO_MATCH by default (VERIFIED by
    test_missing_or_explicit_no_match_fails_closed,
    test_unenrolled_identity_fails_closed)
```

**Транспортний успіх ≠ біометричний успіх:** `match_reply[0]==0` (SEP accepted the *start match* command) is only a "match session began" signal — не результат. Єдиний шлях до `verify-match` — конкретний `match_result` event із збігом UUID. Це відповідає на пряме питання Milestone 0/1: **fail-closed модель формально безумовна** — жодного коду, який трактує "command succeeded" як autoматичний match, не знайдено.

---

## 10. fprintd layer → WBDI feasibility (GATE 6 preliminary)

`t2-fprintd.py` реалізує рівно: `Claim` / `Release` / `ListEnrolledFingers` (повертає статичний список з одним записом з env var) / `VerifyStart` / `VerifyStop` / сигнали `VerifyFingerSelected`, `VerifyStatus`. `EnrollStart`/`EnrollStop`/`DeleteEnrolledFinger*` **явно повертають D-Bus помилку** ("enroll in macOS" / "delete in macOS") — enrollment не просто "не реалізований", а **активно заблокований** на рівні API.

**Питання "чи може verification-only backend без raw image бути WBDI unit" залишається UNKNOWN до окремого дослідження офіційної WBDI-документації Microsoft** (Milestone 0 вже послався на неї, але не заглиблювався в деталі capture-model). Це прямо вимагає окремого кроку, тому що WBDI історично моделює capture-then-match конвеєр (сенсор повертає image/template captured дані, Windows Biometric Service керує matching), тоді як тут SEP сам виконує matching і повертає лише boolean-подібний результат — модель ближча до "match-on-card"/"system-owned-template" пристроїв (аналог smartcard-based biometric match), яка в WBF документації описана окремо. **Не позначаю це ні SUPPORTED, ні UNSUPPORTED — це прямо GATE 6, UNKNOWN, потребує читання `getting-started-with-biometric-drivers` і `roadmap-for-developing-biometric-drivers` на рівні деталей WBDI IOCTL semantics, а не заголовків**, що є окремим кроком (рекомендація в розділі 13).

---

## 11. Existing Windows T2/Apple research — VERIFIED FROM SOURCE (GitHub search)

| Repository | Призначення | Архітектура | Ліцензія | Придатність |
|---|---|---|---|---|
| `imbushuo/mac-precision-touchpad` | Precision Touchpad для Apple трекпадів, включно з T2-USB варіантом | KMDF (SPI/T2 kernel-mode), UMDF (traditional USB) | перевірити окремо перед копіюванням коду | Немає прямого коду для SEP endpoint 7/PCI мейлбоксу; релевантно як приклад KMDF-структури для T2-звʼязаного заліза, і як та сама лінія, з якої походить власний AmtPtpDeviceUsbKm |
| `imbushuo/DFRDisplayKm` | Touch Bar (DFR) дисплей на Windows | KMDF + UMDF, USB composite device | перевірити окремо | Показує підхід до нестандартних T2-периферій на Windows, але знову рівень USB, не PCI SEP |
| `t2linux/apple-bce-drv` | Linux BCE/VHCI/audio для T2 | Linux kernel module | GPL (типово для t2linux) | Reference лише для розуміння BCE-шару T2 (не той самий канал, що SEP endpoint 7 мейлбокс — BCE це окремий PCI-функція від SEP) |

**Висновок:** жодного існуючого Windows-драйвера, що реалізує PCI SEP mailbox / endpoint 7 AppleKeyStore обмін, не знайдено. `T2TouchIdTransport.sys` буде першою публічно відомою реалізацією цього шару на Windows — це підвищує обсяг роботи в Milestone 2 порівняно з оптимістичним сценарієм "переносимо існуючий Windows-транспорт", але **не змінює feasibility-висновок**: сам PCI-протокол повністю задокументований вище (розділ 3) і не потребує подальшого reverse engineering, лише порту.

---

## 12. Hardware compatibility — VERIFIED FROM SOURCE + INFERRED

| Mac model | T2 generation | Touch ID | bridgeOS build | Статус |
|---|---|---|---|---|
| MacBookPro16,2 | T2 (`0x106b:0x1802`) | так | 23P1072 | CONFIRMED (єдина протестована конфігурація) |
| MacBookPro15,x / інші 16,x | T2 (той самий Device ID, INFERRED — усі T2 Mac використовують один SEP PCI ID за загальновідомою архітектурою, але **не підтверджено цим репозиторієм**) | так (де є Touch ID) | невідомо | UNTESTED |
| MacBook Pro 2019 (ціль ТЗ Milestone 0) | ймовірно той самий `0x1802`, INFERRED | так | невідомо, PROBABLY needs own verification | UNTESTED — саме ця модель НЕ є тією, що протестована в Linux-репозиторії |

**Важливо:** цільова машина ТЗ (MacBook Pro 2019) **не тотожна** протестованій Linux-машині (MacBookPro16,2 з конкретним bridgeOS build). PCI Vendor/Device ID (`0x106b:0x1802`) із дуже високою ймовірністю співпадає (T2 — один чіп у всіх цих моделях), але це не підтверджено на цільовому залізі. Потрібна власна перевірка на реальній машині перед Milestone 2.

---

## 13. Power management — VERIFIED FROM SOURCE (repo also ships `docs/SUSPEND_REPORT.md`, not yet read in full — flagged for Milestone 8) + confirms Milestone 0

Milestone-0 висновок підтверджується README дослівно (перефразовано): збій — `NETDEV WATCHDOG` timeout на CDC-NCM інтерфейсі T2 після глибокого S3, BridgeXPC стає недосяжним, rebind інтерфейсу відновлює link-рівень, але не RemoteXPC. Причина позначена в README як **T2 BCE resume-шлях**, не Linux CDC-NCM driver bug конкретно — тобто це **INFERRED як firmware/BCE-рівнева проблема**, що підвищує (не знижує) ризик відтворення того самого на Windows, оскільки Windows так само залежить від того ж T2 BCE resume-поведінки нижче будь-якого OS-специфічного мережевого стека. Залишається `UNKNOWN` до тестування на Windows.

---

## 14. Security audit — VERIFIED FROM SOURCE

- **Arbitrary AppleKeyStore commands:** заблоковано на рівні kernel-модуля (`t2_aks_operation_allowed`), не лише userspace — сильна властивість.
- **Buffer/length validation:** усі ioctl-шляхи перевіряють `request_length`/`response_capacity` проти `T2_SEP_AKS_MAX_BODY_SIZE`, DMA-адреси перевіряються на alignment і 44-бітну межу (`-ERANGE` при порушенні).
- **Integrity:** кожен AKS-обмін має SHA-256 digest, перерахований і звірений (`memcmp`) на відповіді в **окремому scratch-буфері**, щоб malformed відповідь ніколи "не виглядала валідною" навіть частково.
- **Replay/sequence:** транзакційний ID (`next_transaction`, інкрементується, уникає 0) захищає від змішування відповідей на різні запити в межах одного мейлбоксу.
- **Password lifetime:** пароль ніколи не потрапляє в argv/env/логи; explicit `memset`/`memzero_explicit` на всіх шляхах виходу, включно з error paths.
- **Privilege:** `/dev/t2-aks` mode 0600, лише root.
- **UUID/logging:** `summarize_event` явно НІКОЛИ не серіалізує сам UUID чи fingerprint payload — лише boolean `matches_enrolled_identity`.
- **Timeout:** усі мейлбокс-операції мають 5-секундний timeout (`-ETIMEDOUT`), skip-loop для "чужих" endpoint-повідомлень обмежений 32 ітераціями (`-EOVERFLOW`), що запобігає нескінченному очікуванню при shuffled/spoofed трафіку на тому самому мейлбоксі.

Усі ці властивості мають бути перенесені 1:1 у Windows-реалізацію — жодних послаблень немає підстав вносити.

---

## 15. Linux → Windows implementation map

| Linux | Точна роль | Протокол | Windows equivalent | Kernel/user | Впевненість |
|---|---|---|---|---|---|
| `t2_sep_transport.c` probe/DMA/mailbox | PCI BAR4 полінг, DMA alloc, EP0 control messages | 16-byte mailbox messages | `T2TouchIdTransport.sys`, KMDF PCI driver, common-buffer DMA | kernel | HIGH — протокол повністю відомий з коду |
| `t2_aks_exchange_locked` + allow-list | EP7 AppleKeyStore обмін, SHA-256 digest wrapper | V1/V2 header wire format вище | `T2TouchIdTransport.sys` (IOCTL exposed to user-mode protocol layer) або окремий `applekeystore.sys` шар | kernel (allow-list enforced тут) | HIGH |
| `t2-aks-tool.c` CLI | user-mode виклики unlock/load/state | ioctl `T2_AKS_IOC_EXCHANGE` | diagnostic utility (Milestone 5), пряма 1:1 логіка | user-mode | HIGH |
| `discover-biometric-port.py` | TCP port-scan + RemoteXPC RSD handshake | HTTP/2 preface фільтр + RSD peer record | `T2TouchIdProtocol/bridgexpc/discovery` | user-mode | MEDIUM — RSD handshake сам залежить від сторонньої `pymobiledevice3`, потребує окремого протокол-аналізу поза цим репозиторієм |
| `bridge-xpc-probe.py` frame/HELO/message layer | BridgeXPC envelope | Header вище, повністю задокументований | `T2TouchIdProtocol/bridgexpc/` parser + `biometrickit/` command layer | user-mode | HIGH |
| `bridge-xpc-probe.py` match logic | identity-list + start match + event parsing | команди 0x42/4/12 вище | `T2TouchIdProtocol/biometrickit/verify.cpp` | user-mode | HIGH |
| `t2-fprintd.py` | verification-only lifecycle, fail-closed verdict | D-Bus (Linux-специфічний) | **не переноситься 1:1** — замінюється WBDI unit lifecycle (Claim≈device open, VerifyStart≈WBDI capture/verify IOCTL) | — | MEDIUM — залежить від GATE 6 |
| PAM templates + `t2-pam-unlock.sh` | password passthrough для keybag unlock | — | поза scope V1; майбутній Credential Provider hook | user-mode | LOW (за межами V1) |

---

## 16. Revised architecture (v2)

Архітектура з Milestone 0 (розділ E) **підтверджена без структурних змін** — джерело не виявило причин для іншої моделі. Уточнення:
1. Transport-шар (`T2TouchIdTransport.sys`) явно містить AppleKeyStore allow-list enforcement у kernel-mode (не лише документує його) — це прямий перенос властивості безпеки з Linux.
2. `T2TouchIdProtocol/bridgexpc/` реалізує повний frame parser (header + HELO JSON + MESSAGE plist) з unit-тестами на malformed/truncated/wrong-version/wrong-magic, включно з wrong-UUID-у-reply-envelope перевіркою.
3. WBDI unit (`T2TouchIdWbdi`) залишається позначеним UNKNOWN щодо точної відповідності WBF capture-model, поки не пройдено Milestone-1.5 (розділ 10) окремо, до Milestone 2 коду.

---

## 17. GO / NO-GO gates

| Gate | Статус | Обґрунтування |
|---|---|---|
| 1 — T2 transport | **GO** | PCI ID, BAR, DMA, мейлбокс-протокол повністю відомі з коду; немає невідомих байтів |
| 2 — SEP communication | **GO** | Control-messages (EP0) і EP7 AKS wire format повністю задокументовані |
| 3 — AppleKeyStore | **GO** | 5 allow-listed opcode повністю задокументовані з request/response структурами |
| 4 — BridgeXPC | **GO** | Frame header, HELO, MESSAGE envelope, BM-command wrapper — усе byte-level відомо |
| 5 — BiometricKit verification | **GO** | Command IDs, identity_record формат, match_result semantics — усе відоме; discovery-механізм MEDIUM confidence через залежність від сторонньої RSD-бібліотеки |
| 6 — WBDI verification-only | **UNKNOWN** | Потребує окремого читання WBDI/WBF документації на рівні деталей capture-model, а не заголовків — не встановлено в цьому Milestone |
| 7 — Windows Hello | **UNKNOWN** | Прямо залежить від Gate 6; не можна оцінювати окремо |

**Жоден gate не NO-GO.** Transport/protocol рівень (Gates 1-5) технічно розв'язаний повністю на основі джерела, без вигаданих значень. Реальна невизначеність проєкту зосереджена **виключно** в Gate 6/7 — це узгоджується з п.12-13 ТЗ, які прямо називають це "GO/NO-GO gate" і найважливішим питанням.

---

## 18. Remaining unknowns

- **RSD/RemoteXPC handshake byte-level деталі** — код покладається на стороннню бібліотеку `pymobiledevice3`, чий власний протокол-код не входить у проаналізований репозиторій. Потрібен окремий аналіз (або цієї бібліотеки, або незалежна byte-level специфікація RSD handshake) перед Milestone 4.
- **WBDI capture-model сумісність з verification-only backend без raw image** (Gate 6) — не встановлено.
- **Точний PCI Device ID цільового MacBook Pro 2019** (ймовірно `0x106b:0x1802`, INFERRED, не VERIFIED на цільовому залізі).
- **Чи існує SEP control-opcode для "unregister OOL buffers"**, який дозволив би чистий unload — не досліджено, бо Linux-модуль його не використовує.
- **Умова зміни dynamic BridgeXPC порту** (reboot vs T2 reset vs bridgeOS update) — код лише реагує на це (retry-once), не документує причину.
- **Windows-специфічна поведінка S3/Modern Standby з CDC-NCM T2 інтерфейсом** — не тестовано, лише за аналогією з Linux-збоєм.

---

## 19. Recommended Milestone 2

Перед будь-яким кодом драйвера: **вузьке, сфокусоване дослідження WBDI/WBF документації** для закриття Gate 6/7 (не весь Milestone 2 транспорту, а саме capture-model питання) — це найдешевший спосіб уникнути написання transport+protocol шарів для архітектури, яку WBDI/Windows Hello згодом відхилить. Лише після GO на Gate 6/7 переходити до `T2TouchIdTransport.sys` PoC (detect T2, map BAR4, читати inbox/outbox status без DMA — фаза "observation-only", що прямо відповідає `register_ool=false` режиму цього ж Linux-модуля, тобто перший безпечний крок навіть без DMA).

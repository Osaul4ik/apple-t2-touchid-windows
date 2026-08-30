# Milestone 2A — прогрес (код-рівень), сесія Claude

Формат наслідує `milestone-2-hardware-results.md`: чесно розділяю "код
виправлено і звірено з реальним джерелом" від "перевірено на залізі" —
друге я фізично зробити не можу (немає доступу до T2 MacBook), перше
можу і зробив нижче.

## Що я реально зробив цього разу

Прочитав напряму (не з пам'яті) три референсні файли з
`jmurth1234/t2-touchid-linux`, на які посилається ТЗ:
`src/bridge-xpc-probe.py`, `src/t2-aks-tool.c`, `src/t2_sep_transport.c`.
Кожна правка нижче позначена "VERIFIED FROM SOURCE" в коді й посилається
на конкретну функцію в цих файлах — я нічого не вигадував там, де раніше
стояв TODO/placeholder.

### §2–§4 BridgeXpc/Connection.cpp
- Реальні `UUIDv4` (через `UuidCreate`/`UuidToStringA`, uppercase — точно
  як `str(uuid.uuid4()).upper()` в probe.py) замість трьох фіксованих
  `00000000-...-00000N` request-ID.
- `GetBridgeVersion` тепер реально парсить `[0, api_version]` замість
  повернення `negotiatedVersion_` як placeholder.
- `outputCapacity` в `SendBiometricCommand` більше не відкидається —
  payload зібраний як точний `[3, 0, inner, outputCapacity]`.
- Додано `Connection::GetFdrCalibration()` (bridge-level метод `11`).

### §3 PlistPayload
- `PlistPayload.cpp` дописаний на libplist: `ParseMessageBody`,
  `EncodeRequestEnvelope`, `EncodeAckEnvelope`, плюс нові
  `DecodeIntArrayPayload`, `DecodeSingleBlobPayload`,
  `DecodeStatusEventData` — потрібні для §2 і §5 нижче.

### §5 MatchResult.cpp
- Провенанс-нотатку переписано: суцільне сканування буфера на 16-байтний
  UUID — це НЕ здогадка, а точна поведінка `bridge-xpc-probe.py`
  (`identity_uuid in event_data`, Python `bytes`-membership).
- Додано `ParseStatusEventHeader` — реальний парсинг 24-байтного
  заголовка (`sequence:u64, embedded_type:u32, version:u32, ordinal:u64`)
  перед event-специфічним тілом.
- `VerificationEngine.cpp` більше не хардкодить
  `embeddedType = kEmbeddedTypeMatchResult` на кожній події — тепер реально
  дістає його з payload.

### §6 FDR calibration
- `VerificationEngine::Verify` тепер реально викликає
  `GetFdrCalibration()` → `LoadCalibration` (cmd `0x20`, value=3,
  "source 3 = remote/bridgeOS FDR") перед identity list, а не пропускає
  крок.

### §8 akstore.c — найбільша знахідка
- Виявлено і виправлено принципову розбіжність з `t2_sep_transport.c`:
  wire-формат AKS-повідомлення має **4-байтний little-endian
  `header_size` перед digest**, якого в коді не було взагалі (digest
  стояв на самому початку буфера). Виправлено в `T2AksDigest`/
  `T2AksExchange`.
- Всі реальні AKS-обміни (через ioctl) в Linux завжди йдуть із
  **V2**-заголовком (`t2_aks_exchange_locked`), не V1 — V1 в референсі
  використовується лише окремою boot-time-only capability-probe-функцією.
  Виправлено: тепер завжди V2.
- Головний баг §8 ("довжина відповіді визначається з `ResponseCapacity`
  замість реальної довжини") виправлено: тепер довжина тіла відповіді
  береться з `replyWireLength`, яку SEP реально повернув у mailbox-
  повідомленні, ПІСЛЯ валідації заголовка й digest; `ResponseCapacity`
  лишається лише верхньою межею (перевищення → `STATUS_BUFFER_TOO_SMALL`,
  а не мовчазне обрізання).
- Виявлено, що AKS-обмін (endpoint 7) використовує ІНШИЙ формат
  mailbox-повідомлення, ніж EP0 control (`T2SepControl`, який лишився
  правильним — він відповідає `t2_sep_control` майже 1:1). Додано окрему
  `T2SepAksTransaction` (mailbox.c) замість помилкового повторного
  використання `T2SepControl` для AKS-операцій.

### §9 MakeSystemKeybag
- Замінено "спрощений на 12 байт, не фінальний" запит на точний 24-байтний
  wire-формат з `t2-aks-tool.c set_system_keybag`
  (`result:4 | session:8 | handle:4 | special:4 | trailing-blob-len:4=0`).
- Заразом виправлено ті самі проблеми в `LoadKeybag` (бракував весь
  16-байтний заголовок — тіло bag просто йшло сирим) і `GetCapabilities`
  (бракував leading `result` та trailing padding до 16 байт), бо обидва
  використовують той самий header+session wire-конвент, який видно лише
  з `t2-aks-tool.c`.

### Тести
- Додано модульні тести на `ParseStatusEventHeader` і на round-trip
  `PlistPayload` (encode → parse → decode), включно з негативним тестом
  на мальформований top-level.

## Що НЕ зроблено (і чому саме зараз)

- §10/§11 (PCI BAR4-selection assumption, реальний DMA/OOL handshake) —
  логіка вже написана раніше і структурно відповідає
  `t2_sep_transport.c`; але "чи `first memory resource == BAR4`
  на КОНКРЕТНІЙ машині" і "чи SEP реально приймає SET_OOL_IN/OUT" —
  це факти про залізо, які можна встановити тільки запуском на реальному
  MacBook Pro 2019, а не читанням джерела.
- §12 CLI: команди вже є (`status/capabilities/unlock/network/identities/
  verify`), але `status` явно не показує network/BridgeXPC/BiometricKit-
  рядки — це задокументовано в коді як окремий follow-up, не
  замасковано під готове.
- §13 debug logging: вже й так є ОДИН механізм (`KdPrintEx` з одним
  `DPFLTR_IHVDRIVER_ID` фільтром) — немає окремих
  bridgeDebug/aksDebug/etc. Але тегів `[T2]/[SEP]/[DMA]/...` перед
  повідомленнями поки немає — це косметичне доопрацювання, не змінює
  логіку.
- §14/§15/§17/§18 (реальні PASS/FAIL на залізі, hardware verification,
  Definition of Done) — можеш зробити тільки ти на своєму MacBook Pro
  2019. Я не можу компілювати/прошивати/тестувати цей код на T2.

## Провенанс

Усі три файли (`bridge-xpc-probe.py`, `t2-aks-tool.c`,
`t2_sep_transport.c`) прочитані напряму з
`github.com/jmurth1234/t2-touchid-linux` (гілка `main`) цього сеансу —
не з тренувальних даних. Якщо після цього в апстрімі щось зміниться,
ці правки потрібно звірити заново.

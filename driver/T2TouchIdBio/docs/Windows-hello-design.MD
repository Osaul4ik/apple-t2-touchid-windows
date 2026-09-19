# Windows Hello integration — дизайн

Базується на стані `Win_Hello` (README: Gate 1–7 confirmed on hardware,
`WindowsHello: work in progress`). Мета документа — зафіксувати архітектурне
рішення до того, як почнеться код, і явно назвати місця, де воно спирається
на припущення, які треба перевірити на залізі.

## 1. Що вже є і чого бракує

Є повний verify-стек до рівня "SEP сказав Match/NoMatch":
`T2TouchIdTransport.sys` (PCI/SEP/AKS) → `AppleKeyStore` → `BridgeXpc::Connection`
→ `BiometricKit::VerificationEngine::Verify()` → `VerifyOutcome`.//Все це — user-mode
C++ (STL, `std::chrono`, сокет BridgeXPC через CDC-NCM) плюс окремий KMDF-драйвер
для PCI/DMA.

Бракує рівня, який Windows взагалі розуміє як "біометричний пристрій":
Windows Biometric Framework (WBF) не знає нічого про SEP, AKS чи BridgeXPC —
вона говорить лише мовою **WBDI** (IOCTL-інтерфейс: `IOCTL_BIOMETRIC_GET_ATTRIBUTES`,
`_GET_SENSOR_STATUS`, `_CALIBRATE`, `_CAPTURE_DATA`, `_RESET` тощо) і трьох
плагінів — **Sensor / Engine / Storage adapter**, які реєструються під Windows
Biometric Service (`wbiosrvc`, службовий процес) і теж MS-владні по інтерфейсу.

## 2. Ключове архітектурне рішення: WBDI-драйвер — UMDF, не KMDF

Мій перший інстинкт був "новий KMDF-драйвер типу Biometric", по аналогії з
`T2TouchIdTransport.sys`. Це неправильно, і ось чому.

`VerificationEngine`/`BridgeXpc`/`BiometricKit` — це готовий, вже перевірений
на залізі user-mode код на сокетах і STL. Перенести цю логіку в kernel mode
означало б переписувати BridgeXPC-сесію на WSK (Winsock Kernel), тягнути
`std::vector`/`std::chrono` в kernel (заборонено/дуже болісно), і тестувати
заново весь Gate 5–7 стек у контексті, де помилка = BSOD, а не виняток.
Це symptomatic-складність, не необхідна.

Microsoft прямо документує, що WBDI-драйвер **може бути UMDF**
(офіційний приклад — `WudfBioUsbSample`, Device.cpp якого MS сама наводить
як референс для IOCTL-послідовності). Тобто:

- Новий компонент — `T2TouchIdBio.dll`, UMDF 2 driver, Setup Class = Biometric,
  реалізує IOCTL з п.3.
- Він лінкується напряму проти `protocol/BridgeXpc` і `protocol/BiometricKit`
  (той самий код, той самий сокет, той самий `VerificationEngine::Verify()`) —
  **нуль нового протокольного коду**, тільки обгортка.
- `T2TouchIdTransport.sys` (KMDF, PCI/SEP) лишається як є — UMDF-драйвер ходить
  до нього так само, як зараз ходить `t2touchid.exe`, через
  `GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT` + `IOCTL_T2_AKS_EXCHANGE`.

Це і є "root cause, не патч": замість боротьби з тим, що WBDI хоче kernel-driver
семантику, а наш стек — user-mode сокети, обираємо той з двох офіційно
підтримуваних варіантів WBDI, який не змушує це протиріччя вирішувати.

**Ризик, який я не можу закрити без заліза:** чи приймає WinBio на Windows 11
UMDF-based третьосторонній Biometric-драйвер без WHQL для *SystemSensor*
(логін-сценарію), чи є прихована вимога на full KMDF/сертифікацію саме для
логіну (а не просто для app-level `WinBioVerify`). README вже фіксує, що
`T2TouchIdTransport.sys` не WHQL-signed і вимагає test-signing — той самий
режим має покривати й UMDF-хост, але це варто перевірити окремо, бо
Windows Hello логін іде через LogonUI/Credential Provider, а не звичайний
процес користувача, і там історично трапляються додаткові обмеження
(secure desktop). Перший практичний крок реалізації — не писати весь driver,
а підняти мінімальний UMDF-скелет, що тільки відповідає на
`IOCTL_BIOMETRIC_GET_ATTRIBUTES`, і перевірити, що WinBio взагалі бачить
пристрій і пропонує його в `Settings → Sign-in options` під test-signing.
Якщо ні — усе нижче зсувається назад до KMDF+WSK.

## 3. Мапінг WBDI IOCTL → існуючий код

| WBDI IOCTL | Що робить UMDF-хендлер |
|---|---|
| `IOCTL_BIOMETRIC_GET_ATTRIBUTES` | Статичні дані (vendor id, sensor mode = поки лише **verify**, не identify — див. §4). Хардкод, SEP не питаємо. |
| `IOCTL_BIOMETRIC_GET_SENSOR_STATUS` | `SensorAccessDenied`, якщо `T2TouchIdTransport.sys` не з'явився / `IOCTL_T2_GET_STATUS` каже `MailboxAccessible=false`; інакше `SensorNotBusy`. Калібрування не потрібне — `NoCalibrationRequired` (WarmUp сам робить load-calibration всередині сесії). |
| `IOCTL_BIOMETRIC_CAPTURE_DATA` | Тут відбувається все: `Connection::Connect()` → `VerificationEngine::Verify()`. **Без внутрішнього `matchWindow`-обмеження** (див. §9.4) — чекає, скільки чекає сам Windows на екрані блокування, і завершується лише зовнішнім cancel. Результат пакується у vendor-specific `WINBIO_BIR` (див. §5) — не сирий відбиток, лише `VerifyOutcome` + `matchedUuid`. |
| `IOCTL_BIOMETRIC_RESET` / cancel (`IWDFIoRequest::MarkCancelable`) | Мапиться на існуючий `Connection`/session cancel шлях — той самий, що вже є для timeout у `VerificationEngine`. |
| `IOCTL_BIOMETRIC_CALIBRATE` | Опційний; можна не реалізовувати, якщо `GET_SENSOR_STATUS` завжди повертає "не потрібно". |

## 4. Enrollment: чому це не "фейк", а звужений сценарій

Enrollment на macOS лишається поза скоупом (як і зараз написано в README) —
але Windows Hello **вимагає** локально збереженого template, прив'язаного до
SID, інакше `WinBioEnroll`/NGC просто не матимуть на що посилатись при логіні.
Рішення: **1 Windows-акаунт = 1 `macosUserId`**, той самий параметр, що вже є
в `VerifyConfig::macosUserId` (зараз 501, "configurable, NOT hardcoded").

Enroll-флоу (через `Settings → Sign-in options`) не збирає новий biometric
sample — він **запускає ту саму `WarmUp()`/identity-list послідовність**, що
вже є в `VerificationEngine`, підтверджує, що SEP видає непорожній
identity-list для вибраного `macosUserId`, і Storage adapter зберігає лише
`{ macosUserId, matchedUuid при першому успішному WarmUp }` як template —
без жодних сирих даних відбитка (те саме обмеження, що вже задеклароване в
README: "does not store raw fingerprint images").

Це узгоджено з тим, що `Verify()` вже повертає `matchedUuid` — Engine adapter
на верифікації просто звіряє його зі збереженим (1:1, WinBio "verify", не
"identify" — не намагаємось розрізняти кількох користувачів на одному
Windows-акаунті).

**Наслідок, який варто проговорити з самого початку:** якщо на T2 enrolled
кілька macOS-пальців під різними `macosUserId`, кожен потребує окремого
Windows-акаунту або окремого enroll-проходу з explicit вибором id — автоматичного
"дізнайся, який палець торкнувся" з UI Windows Hello наразі немає (`VerifyOutcome`
не робить N-way identify, лише verify проти вже заданого `macosUserId`).

## 5. VerifyOutcome → WinBio статус

| `VerifyOutcome` | WBDI/Engine-adapter відповідь |
|---|---|
| `Match` | Capture BIR з `matchedUuid`; Engine adapter → `WINBIO_E_SUCCESS`, ідентичність == enrolled |
| `NoMatch` | `WINBIO_E_NO_MATCH` |
| `Timeout` | `WINBIO_E_BAD_CAPTURE` (палець не прикладено вчасно — той самий сенс, що й зараз у CLI) |
| `TransportError` | `WINBIO_E_DEVICE_FAILURE` |
| `RejectedByDevice` | `WINBIO_E_DEVICE_FAILURE` (fail-closed, як і в описі коду — ніколи не мапиться на silent success) |
| `Busy` | `WINBIO_E_DATA_COLLECTION_IN_PROGRESS` — вже готовий сенс з Milestone 2 §23, WBDI саме цього й очікує від паралельного `CAPTURE_DATA` |
| `UnstableIdentityInventory` | `WINBIO_E_DEVICE_FAILURE` + лог; не `NO_MATCH`, бо це не заперечення identity, а fail-closed відмова |
| `Malformed` | `WINBIO_E_UNKNOWN_ERROR` |

Ключове: жоден шлях не перетворює transport-невдачу на `Match` — той самий
fail-closed принцип, що вже explicitly задокументований у
`VerificationEngine.h`, просто продовжується на рівень WinBio.

## 6. Concurrency

`VerificationEngine::IsBusy()`/"one active session" вже існує. WBDI-хендлер
`CAPTURE_DATA` повинен тримати той самий inline-check ("if a request is
pending, complete with `WINBIO_E_DATA_COLLECTION_IN_PROGRESS`") — це не новий
контракт, а точне дзеркало вже реалізованого `Busy`.

## 7. Компоненти, які треба створити

1. `driver/T2TouchIdBio/` — новий UMDF 2 проєкт, лінкує `protocol/BridgeXpc`,
   `protocol/BiometricKit`, `protocol/AppleKeyStore` як є.
2. INF з root-enumerated device node (Setup Class Biometric, ACL з
   `installing-a-biometric-driver`: `Security = D:P(A;;GA;;;BA)(A;;GA;;;SY)`,
   `Exclusive=1` для SystemSensor/логіну) — фізичного bus-присутності немає
   (SEP вже займає `T2TouchIdTransport.sys`), тому цей вузол — віртуальний,
   так само як зараз немає окремого physical-device вузла для `t2touchid.exe`.
3. Мінімальний Storage adapter (можна спробувати спершу вбудований MS'ів
   Software Storage Adapter — якщо формату template досить, свій писати не
   треба) — перевірити це до кастомної реалізації.
4. Engine adapter — тонкий: порівняння `matchedUuid` з enrolled записом,
   без жодної обробки sample.

## 8. Відкриті питання перед кодом

- UMDF WBDI + SystemSensor логін без WHQL — працює чи ні (§2, найризикованіше).
- Чи вистачає MS Software Storage Adapter, чи писати свій.
- Секундний бюджет: `matchWindow=20s` у `CAPTURE_DATA` — чи є в WBDI/LogonUI
  свій таймаут коротший за 20s (якщо так, треба або зменшувати
  `matchWindow` для Hello-профілю, або показувати проміжний UI "прикладіть
  палець", поки capture триває).
- Multi-user T2 (§4) — свідомо відкладено, не блокер MVP (1 акаунт = 1 палець).

Наступний практичний крок — мінімальний скелет п.7.1, що відповідає лише на
`GET_ATTRIBUTES`/`GET_SENSOR_STATUS`, щоб зняти ризик з §2 до того, як
підключати `VerificationEngine`.

## 9. SEP bootstrap: GUI (SepVault) + boot-time сервіс

Це окремий, попередній до §1–8 шар: поки SEP не пройшов
`register-ool → load-keybag → set-system-keybag → unlock handle → unlock
special bag`, `CAPTURE_DATA` з §3 просто не має з чим працювати. Ваша ручна
CLI-послідовність — точна специфікація того, що має відбуватись автоматично
до появи екрану логіна.

### 9.1 Компонент 1 — `SepVault.exe` (GUI, разовий запуск)

Робиться один раз вручну (адміністратором), не при кожному вмиканні:

1. Діалог вибору файлу → читає `user.kb` у пам'ять.
2. Поле для special bag id (`-501`), можна декілька, якщо потрібно кілька
   bag'ів.
3. Одне поле пароля — підтверджено: `unlock <handle>` і
   `unlock <special bag>` використовують **той самий** пароль облікового
   запису. Один секрет, один слот у vault, використовується двічі в
   `Client::Unlock()`.
4. Зберігає все як один blob: `%ProgramData%\T2TouchId\sep-vault.bin`,
   ACL лише SYSTEM+Administrators (той самий патерн ACL, що Windows вимагає
   для самого Biometric device node — узгоджено з §7.2).
   - `user.kb` bytes і пароль — кожен окремо через
     `CryptProtectData(..., CRYPTPROTECT_LOCAL_MACHINE)`. Machine-scope, не
     user-scope: сервіс з §9.2 стартує до будь-якого логіну, user-профілю
     ще не існує, тому user-scope DPAPI тут технічно неможливий.
   - Ніде не лишається copy у відкритому вигляді — оригінальний
     `C:\Macos\user.kb` після імпорту можна (і варто) видалити, у vault він
     не потрібен у plaintext на диску.

### 9.2 Компонент 2 — `T2SepBootstrap` (служба, `Automatic`, `LocalSystem`)

Ось де "виконати один раз за ввімкнення, не за сон" вирішується майже без
коду: звичайна Windows-служба зі стартом `Automatic` природно піднімається
рівно один раз на кожен **cold boot**, і НЕ перезапускається сама на
resume з сну (S3/modern standby) — процес служби просто продовжує існувати
призупиненим. Тобто вимога "reboot/shutdown → знову, сон → ні" — це
поведінка звичайного `SERVICE_START` за замовчуванням, додаткового
прапорця "вже виконано" в реєстрі писати не треба. Єдине, що варто явно
прибрати — SCM-політику "restart on failure" для цієї служби (або зробити
`Start()` ідемпотентним): аварійний рестарт самої служби не повинен ще раз
намагатись розблокувати вже розблокований SEP.

`Start()`-послідовність (все — прямі виклики в процесі, без
`CreateProcess("t2touchid.exe", ...)`):

```
1. Прочитати sep-vault.bin, CryptUnprotectData → keybag bytes, password
   (усе в locked/zeroable буферах — той самий підхід, що вже
   задокументований у protocol/AppleKeyStore/Client.h: "no path here
   accepts a password via anything other than a caller-owned buffer that
   this class zeroes before returning").
2. AppleKeyStore::Client::RegisterOol()
3. AppleKeyStore::Client::LoadKeybag(keybagBytes, &handle, ...)
4. AppleKeyStore::Client::MakeSystemKeybag(handle, specialUserBag, ...)
5. AppleKeyStore::Client::Unlock(handle, password, ...)
6. AppleKeyStore::Client::Unlock(specialUserBag, password, ...)  // той самий секрет
7. RtlSecureZeroMemory на password-буфері (Unlock сам зеровує
   свій аргумент — переконатись, що деshифрований keybag-буфер з кроку 1
   теж явно зеровано, Client цього за нас не зробить, бо це вхід у
   LoadKeybag, не в Unlock).
8. Виставити прапор готовності, який читає WBDI-хендлер
   IOCTL_BIOMETRIC_GET_SENSOR_STATUS (§3) — напр. named event
   `Global\T2SepReady`, а не окремий T2_TRANSPORT_STATUS біт, щоб не чіпати
   існуючий public.h KMDF-контракт.
```

Важливо: `RegisterOol`/`LoadKeybag`/`MakeSystemKeybag`/`Unlock` уже існують
як методи `protocol/AppleKeyStore::Client` (те, що зараз викликає
`tools/t2touchid/main.cpp` з CLI). Новий сервіс лінкує ту саму бібліотеку і
викликає ті самі методи в процесі — жодного нового протокольного коду,
і що важливіше: жодного проходження пароля через argv/командний рядок
дочірнього процесу (де його міг би прочитати будь-хто, хто перелічує
процеси/аргументи в системі, поки логін-екран ще не показаний). Якби
автоматизація йшла через `CreateProcess("t2touchid.exe unlock <pwd>")`,
це була б реальна діра; прямий виклик `Client::Unlock(handle, buffer)` її
не має.

### 9.3 Модель загрози — прийнято, не обговорюємо TPM

Немає TPM — отже DPAPI `CRYPTPROTECT_LOCAL_MACHINE` є фінальним рівнем
захисту, не тимчасовим рішенням "до TPM". Явно фіксую прийняту модель:
хто має фізичний доступ до ноута і хоче дістати секрет — дістане (offline
читання SAM/реєстру, витяг DPAPI-machine-ключа — відомі, задокументовані
техніки). Це прийнятний trade-off для цього проєкту: мета — не зробити
секрет недобувним, а не тримати його у відкритому вигляді на диску та не
ганяти пароль через argv/лог. `CryptProtectData`/`CryptUnprotectData` з
цим і впораються, без додаткової інфраструктури.

### 9.4 Таймаут CAPTURE_DATA і скасування

`VerifyConfig::matchWindow` (20s) — це ліміт CLI-скрипта одноразового
`verify`, і для екрану блокування він не підходить: там очікування триває,
скільки Windows сама готова чекати на скан (тайл біометрії на LogonUI
активний, поки користувач явно не піде іншим шляхом). Нема скану — нема
власного таймауту з нашого боку; є скасування — тоді й закінчуємо.

Це вимагає зміни, якої зараз немає: ні `Connection`, ні
`VerificationEngine::Verify()` не приймають зовнішній cancel-токен —
`Verify()` сам керує своїм циклом і сам вирішує, коли здатись, лише за
`matchWindow`. Для Hello-сценарію потрібен окремий режим виклику
(новий параметр, не заміна існуючого — CLI `verify` і далі працює зі
своїм фіксованим вікном):

- `Verify()` отримує опційний `HANDLE cancelEvent` (або еквівалент); цикл
  очікування (`WaitForEvent`) чекає одночасно на подію з SEP і на цей
  `HANDLE`, без верхньої межі по часу, якщо `cancelEvent` заданий.
- `IOCTL_BIOMETRIC_CAPTURE_DATA`-хендлер реєструє cancel-callback через
  `IWDFIoRequest::MarkCancelable` (уже згадано в §3) і сигналить саме цей
  `HANDLE`, коли Windows кличе `CancelIo`/`CancelIoEx` на pending-запит —
  а це і є момент "увійшли по паролю", тому що вхід по паролю завершує
  LogonUI-сесію, і Windows сама скасовує всі pending async-операції інших
  credential provider'ів (включно з вбудованим біометричним, що тримає наш
  capture). Це вже стандартна поведінка WinBio async credential provider,
  не те, що ми пишемо самі — нам треба лише правильно відповісти на
  cancel routine.
- Захисна межа, а не основний механізм: все одно варто тримати внутрішній
  "запобіжник" (напр. кілька хвилин), на випадок якщо припущення "Windows
  завжди шле cancel" не підтвердиться на реальному LogonUI — інакше один
  пропущений cancel назавжди залишить сенсор `WINBIO_E_DATA_COLLECTION_IN_PROGRESS`
  до наступного ребута.

## 10. Що ще треба продумати

- **SEP-side ліміт матчу.** `matchWindow` у коментарях `VerifyConfig` —
  це клієнтський Cancel, надісланий *до* власного idle/poll-циклу SEP.
  Невідомо, чи має сам SEP власний, незалежний від клієнта таймаут матчу
  (watchdog у прошивці) — якщо так, "чекати нескінченно" на клієнті не
  означає "SEP чекає нескінченно", і треба або періодично
  re-issue StartMatch, або узгодити реальну верхню межу. Перевіряється
  тільки на залізі.
- **Сон під час активного capture.** Якщо `CAPTURE_DATA` pending, а ноут
  іде в сон (кришка закрита на екрані блокування) — PCI-мейлбокс, ймовірно,
  йде в D3 (`device.c` вже має D0Entry liveness-перевірку). Потрібно чітко
  завершувати pending capture помилкою транспорту при suspend і давати
  WinBio почати нову спробу після resume, а не висіти.
- **Один пароль — один блок радіусу компрометації.** Це той самий пароль,
  що розблоковує весь обліковий запис/FileVault на macOS-стороні — тобто
  компрометація Windows-vault'а має наслідки за межами Windows Hello,
  не лише "хтось увійде в Windows без пальця". Варто це усвідомлювати при
  виборі, який саме пароль туди класти (обліковий чи, якщо є, окремий
  спеціально виділений під це секрет).
- **Тиша при провалі.** Якщо пароль у vault застаріє (змінили на macOS) —
  `Unlock` у `T2SepBootstrap` впаде без жодного UI (служба, Session 0).
  Потрібен видимий слід: Event Log-запис з чітким кодом причини (той самий
  `T2_LOG`/verbose-стиль, що вже є в проєкті), інакше користувач бачить
  просто "пальця нема" без пояснення чому.
- **PnP-гонка при старті служби.** `T2SepBootstrap` не повинен просто
  спати й ретраїти відкриття `GUID_DEVINTERFACE_T2TOUCHID_TRANSPORT` —
  правильно підписатись на device-interface-arrival і стартувати
  послідовність по факту появи `T2TouchIdTransport.sys`, а не за
  фіксованою затримкою.
- **`sep-vault.bin` versus BitLocker.** DPAPI-machine захищає від
  "прочитати файл", але не від "завантажити диск офлайн і витягти
  DPAPI-ключ з реєстрового кубла" — це вже поза межами того, що ми тут
  вирішуємо (§9.3), просто фіксую, що додаткового шару це не додає, якщо
  диск не зашифрований BitLocker'ом.
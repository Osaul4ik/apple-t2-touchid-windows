# T2TouchIdTransport.sys — PnP/Power Lifecycle Design (сон/пробудження за канонами KMDF)

Пристрій: `PCI\VEN_106B&DEV_1802&SUBSYS_1802106B&REV_01` (Apple T2 SEP mailbox,
BAR4). Драйвер: `driver/T2TouchIdTransport` (KMDF, Function Driver, PCI FDO).

Цей документ — архітектурне рішення *перед* написанням коду, як просив автор
завдання. Він не переписує driver.c/dma.c/mailbox.c — він фіксує, **що саме**
і **чому** зміниться, у форматі, який продовжує стиль `docs/*.md` цього
репозиторію (VERIFIED FROM SOURCE / потребує апаратної перевірки).

---

## 1. Діагноз поточного стану ("працює, але без lifecycle")

Прочитано весь `driver/T2TouchIdTransport/*.c(.h)`. Факти:

| Компонент | Стан |
|---|---|
| `EvtDevicePrepareHardware` / `EvtDeviceReleaseHardware` | Реалізовані повністю: пошук BAR4 через PCI config space, мапінг MMIO, звільнення DMA/анмапінг. |
| `EvtDeviceD0Entry` / `EvtDeviceD0Exit` | **Оголошені й підключені в `WDF_PNPPOWER_EVENT_CALLBACKS`, але тіла — порожні заглушки** (`return STATUS_SUCCESS`). Коментар у `EvtDeviceD0Entry` каже правильну річ ("ніколи не вважай стан валідним після переходу живлення"), але **нічого не інвалідує на транспортному рівні**. |
| Прапорці `OolRegisterAttempted / OolInRegistered / OolOutRegistered` | Виставляються один раз в `T2EvtIoDeviceControlRegisterOol`, ніколи не скидаються — ні при D0Exit, ні при D0Entry. |
| Idle / Wake policy | Не налаштовується явно (`WdfDeviceInitSetIdleWakeSettings` / `WDF_DEVICE_POWER_POLICY_*` відсутні). Працює на дефолтах KMDF. |
| I/O Queue | `WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE` → power-managed за замовчуванням, диспетчеризація `Sequential`. Обробники IOCTL синхронні (`WdfRequestComplete` до виходу з callback) — це добре, підходить під power-managed модель без додаткових змін. |
| DMA common buffers (OOL IN/OUT) | Виділяються (`T2DmaAllocateOolBuffers`) окремо від реєстрації на SEP (`T2DmaRegisterOolBuffers`). VA/PA стабільні, поки буфер не видалено — видаляється лише в `ReleaseHardware`, якщо OOL не було зареєстровано. |
| Surprise-removal / leak-on-purpose | `EvtDeviceReleaseHardware` свідомо НЕ звільняє OOL-буфери, якщо SEP їх бачив (бо в SEP немає опкоду дереєстрації) — коректно й задокументовано. |

**Висновок**: PnP-каркас (start/stop/remove, BAR mapping) зроблений за
канонами. Відсутня саме та частина, яку офіційно називають *"D0 entry/exit
lifecycle"* — синхронізація **внутрішнього апаратного стану SEP** (реєстрація
OOL-буферів на стороні SEP, надійність mailbox) із фактичними переходами
живлення D0↔D3, які відбуваються при:

- сні системи (S1–S3),
- гібернації (S4),
- Modern Standby / Connected Standby (якщо застосовно до PCI-функції),
- Device Manager "Disable/Enable",
- runtime power management (S0 idle), якщо колись буде увімкнено,
- (рідко) resource rebalance — там уже спрацьовує `ReleaseHardware`.

Це саме той пробіл, який дає нинішній тестовий результат "зараз працює" (у S0,
одразу після завантаження) і мовчазну відмову/зависання після першого сну —
бо `OolInRegistered`/`OolOutRegistered` продовжують брехати "TRUE" уже після
того, як SEP забув про реєстрацію.

Важливо розмежувати scope: `docs/linux-reference-analysis.md` (розділ 13) і
`docs/t2-touchid-windows-feasibility.md` вже фіксують, що **BridgeXPC/CDC-NCM
(USB-мережевий транспорт до T2 BCE) ламається навіть на Linux після глибокого
S3** — це інша підсистема (не PCI SEP mailbox, який ми правимо тут) і інший
драйвер/стек. Цей документ **не вирішує** CDC-NCM/BridgeXPC-resume проблему —
він робить транспортний PCI-драйвер (`T2TouchIdTransport.sys`) коректним і
передбачуваним відносно PnP/Power, і чесно репортує свій стан нагору, замість
мовчазної брехні "OOL зареєстровано", коли це вже неправда.

---

## 2. Канонічна модель KMDF PnP/Power, яку тут застосовуємо

### 2.1 Дві незалежні пари колбеків — не плутати їхнє призначення

| Пара | Коли викликається | Що можна робити |
|---|---|---|
| `EvtDevicePrepareHardware` / `EvtDeviceReleaseHardware` | Старт пристрою, resource rebalance, зупинка для видалення/переконфігурації ресурсів. **Не** викликається на кожен сон системи. | Мапінг/анмапінг MMIO BAR, читання PCI config space — усе, що прив'язане до конкретного набору translated resources. |
| `EvtDeviceD0Entry` / `EvtDeviceD0Exit` | **Кожен** перехід пристрою між D0 (робочий) та не-D0 (D1/D2/D3), включно з S1–S4 сном системи, Device Manager disable/enable, і S0-idle (якщо увімкнено). Ресурси (BAR mapping) залишаються дійсними — це не Prepare/ReleaseHardware. | Ініціалізація/деініціалізація апаратного *стану* пристрою: регістри, DMA-реєстрація на стороні девайса, хендшейки. Саме тут живе "sleep/resume" логіка. |

Наш пробіл — виключно в другій парі. `PrepareHardware/ReleaseHardware`
чіпати не потрібно.

### 2.2 Хто відновлює що автоматично, а що — обов'язок драйвера

- **PCI config space стандартного заголовка** (Command register, тобто біти
  Memory Space Enable / Bus Master Enable, BAR-адреси) **зберігає й відновлює
  сама шина (pci.sys)** під час D0↔D3 переходів системного сну — це
  задокументована поведінка PCI power management у Windows. Тобто після
  resume біти bus-master/memory space, які виставляє `T2EnablePciBusMaster`,
  **самі по собі мають лишитись увімкненими** — це НЕ те, що ламається.
- **Внутрішній стан самого пристрою поза стандартним PCI config header**
  (тут: чи знає SEP адреси OOL_IN/OOL_OUT, чи "живий" mailbox handshake) —
  **зберігати/відновлювати мусить драйвер**, бо ОС про це нічого не знає.
  Це саме `OolInRegistered`/`OolOutRegistered` та якість mailbox-протоколу.
  Це — ядро цього документа.
- **DMA common buffers** (host-side пам'ять OOL IN/OUT) не звільняються і не
  переалоковуються при D0Exit/D0Entry — вони живуть, поки живе device stack
  (звільняються лише в `ReleaseHardware`, за вже існуючою, коректною
  логікою "retain until reboot"). Тобто VA/PA після resume **не змінюються** —
  міняти потрібно лише *прапорець, що SEP про них знає*, а не самі буфери.

### 2.3 Наскільки "дорогим" колбеком є D0Entry — важливе обмеження дизайну

`T2SepControl` (SET_OOL_IN/SET_OOL_OUT) — синхронний, `KeStallExecutionProcessor`
у циклі, з таймаутом `T2_SEP_TIMEOUT_US` = 5 секунд у найгіршому випадку, на
PASSIVE_LEVEL. Виконувати такий виклик безпосередньо всередині
`EvtDeviceD0Entry` — погана практика: PnP/Power-менеджер очікує, що D0Entry
завершиться швидко, а 5-секундний busy-wait у колбеку резюму синхронно
затримує весь ланцюжок відновлення живлення пристрою (і потенційно —
пов'язані з ним залежні пристрої/спостерігачів power state machine).

**Рішення дизайну: "лінива" (lazy) ре-реєстрація, а не синхронна в D0Entry.**
`EvtDeviceD0Entry` лише **скидає прапорці/інкрементує лічильник генерації**
(дешева, детерміновано швидка операція під `ExchangeLock`). Реальний
mailbox-хендшейк (SET_OOL_IN/OUT) відкладається до **першого реального
запиту**, який його потребує (`IOCTL_T2_REGISTER_OOL` від user-mode, або —
за потреби — прозоро всередині `IOCTL_T2_AKS_EXCHANGE`, див. §4.3). Той
виклик і так уже синхронний та відбувається в контексті виклику з
user-mode/IOCTL-черги, а не в контексті самого power-менеджера — 5-секундний
worst case там прийнятний і вже присутній у поточному коді для звичайного
шляху.

---

## 3. Модель стану пристрою (заміна трьох булевих прапорців)

### 3.1 Проблема поточної моделі

`OolRegisterAttempted / OolInRegistered / OolOutRegistered` — три незалежні
булеві, немає єдиної точки "цей стан застарів після зміни живлення". Легко
залишити їх неузгодженими (саме це і сталося: вони не скидаються ніде).

### 3.2 Пропоноване рішення

Замінити на явний enum + лічильник генерації живлення, обидва — під
існуючим `ExchangeLock` (той самий `WDFWAITLOCK`, що вже серіалізує
mailbox/AKS-обмін — нового примітиву синхронізації не додаємо):

```c
typedef enum _T2_OOL_STATE
{
    T2OolStateNotRegistered = 0,  // ще жодного разу не реєстрували
    T2OolStateRegistered,         // SEP підтвердив SET_OOL_IN і SET_OOL_OUT
    T2OolStateStale,              // було Registered, але пристрій пройшов
                                   // через D0Exit->D3->D0Entry відтоді —
                                   // SEP міг забути реєстрацію, потрібне
                                   // повторне підтвердження перед EP7-обміном
} T2_OOL_STATE;
```

У `T2_DEVICE_CONTEXT`:

```c
T2_OOL_STATE  OolState;          // замінює OolRegisterAttempted/InRegistered/OutRegistered
ULONG         PowerUpGeneration; // інкремент на кожен EvtDeviceD0Entry;
                                  // дозволяє user-mode (BridgeXPC) виявити
                                  // "транспорт пережив цикл живлення" навіть
                                  // якщо OolState встиг знову стати Registered
                                  // до наступного опитування статусу
```

`OolInRegistered && OolOutRegistered` (як булева пара) семантично зливаються
в `T2OolStateRegistered` — SET_OOL_IN і SET_OOL_OUT в поточному коді й так
виконуються послідовно як одна логічна операція реєстрації; проміжний стан
"тільки IN зареєстровано, OUT — ні" — це стан помилки (лишається
`STATUS_UNSUCCESSFUL`/reboot-required гілка з коментаря в `dma.c`, а не
самостійний enum-стан), тож окремо його не моделюємо.

### 3.3 Таблиця переходів стану

| Подія | `OolState` до | `OolState` після | Хто виконує |
|---|---|---|---|
| `EvtDeviceAdd` (створення контексту) | — | `NotRegistered` | вже коректно (RtlZeroMemory) |
| Успішний `IOCTL_T2_REGISTER_OOL` (обидва SET_OOL_* пройшли) | `NotRegistered` або `Stale` | `Registered` | `T2EvtIoDeviceControlRegisterOol` (оновлюється) |
| Невдалий `IOCTL_T2_REGISTER_OOL` (SET_OOL_IN пройшов, SET_OOL_OUT — ні) | `NotRegistered`/`Stale` | лишається **не** `Registered` (permanent-fail гілка з коментаря "reboot before retry" — окремим кодом помилки нагору, стан не чіпаємо) | без змін логіки, лише під enum |
| `EvtDeviceD0Entry` (**будь-який** вхід у D0 — і перший старт, і resume) | `Registered` | `Stale` | новий код, §4.1 |
| `EvtDeviceD0Entry`, коли до цього був `NotRegistered` | `NotRegistered` | `NotRegistered` (без змін — нема що "застарювати") | новий код |
| Наступний `IOCTL_T2_REGISTER_OOL` після `Stale` | `Stale` | `Registered` (ре-хендшейк тими самими VA/PA буферів, без переалокації) | вже існуюча ідемпотентна гілка в `T2EvtIoDeviceControlRegisterOol`, потребує лише зняття гварда "якщо вже Attempted — нічого не робити" (§4.2) |
| `IOCTL_T2_AKS_EXCHANGE`, коли `OolState != Registered` | — | — | `STATUS_DEVICE_NOT_READY` (вже є перевірка, лишається коректною й для `Stale`) |

---

## 4. Конкретні зміни по колбеках

### 4.1 `EvtDeviceD0Entry` — нова відповідальність

```
EvtDeviceD0Entry(Device, PreviousState):
    ExchangeLock.Acquire()
    if Ctx->OolState == Registered:
        Ctx->OolState = Stale
        T2_LOG(WARNING, "OOL registration marked stale after power-up "
                         "(previous D-state=%d); re-register before next "
                         "AKS exchange", PreviousState)
    Ctx->PowerUpGeneration++
    ExchangeLock.Release()

    T2_LOG(INFO, "D0 entry #%lu (previous state=%d)",
           Ctx->PowerUpGeneration, PreviousState)
    return STATUS_SUCCESS   // ніколи не блокуємось тут на mailbox I/O — див. §2.3
```

Свідомо **не** робимо тут MMIO-читання mailbox-регістрів "для перевірки" —
це теж I/O в бік пристрою, який щойно ввімкнувся; сам факт, що MMIO BAR
залишається змапленим (`Bar4Mapped` не чіпається між PrepareHardware і
ReleaseHardware), достатній, а першу реальну перевірку живості робить перший
IOCTL, як і зараз (`IOCTL_T2_GET_STATUS` уже читає inbox status як
"liveness signal" — цей шлях лишається без змін і природно підхопить
пост-resume стан).

`PreviousState` окремо не аналізуємо гілками (D3 vs D3Final vs Sx) —
семантика однакова для наших цілей: "ми не в D0 щойно були, тому раніше
підтверджена реєстрація SEP довіри не заслуговує". Це навмисне спрощення:
розрізняти "перший старт після AddDevice" від "resume після сну" тут не
потрібно, бо в обох випадках `OolState` на вході або вже `NotRegistered`
(перший старт), або має стати `Stale` (resume) — код один і той самий.

### 4.2 `EvtDeviceD0Exit` — навмисно мінімальний

```
EvtDeviceD0Exit(Device, TargetState):
    T2_LOG(INFO, "D0 exit -> target state=%d", TargetState)
    return STATUS_SUCCESS
```

Свідомо **не** намагаємось "акуратно" дереєструвати OOL на стороні SEP перед
вимкненням: за `docs/linux-reference-analysis.md` (Milestone 1, розділ 3,
"Pinning") у SEP-протоколі **немає опкоду дереєстрації** — Linux-референс
цього теж не робить. Спроба вигадати "graceful shutdown" запит, якого
протокол не підтримує, — це протокольна помилка, а не покращення. D0Exit тут
чисто діагностичний (лог) + місце, куди природно ляже майбутній
`EvtDeviceSelfManagedIoSuspend`, якщо колись з'явиться фонова
(self-managed) активність — наразі її немає (весь I/O — синхронний, у
відповідь на IOCTL), тож Self-Managed I/O callbacks у цьому дизайні
**свідомо не додаються** (canonical guidance: не додавати callback, якому
нема що робити).

Це узгоджується з `EvtDeviceReleaseHardware`, який теж свідомо "витікає"
(retain until reboot) DMA-пам'ять, коли SEP міг її бачити — той самий
принцип: не вигадувати дереєстрацію, якої протокол не має.

### 4.3 `IOCTL_T2_REGISTER_OOL` — зняти гвардову умову "тільки один раз"

Поточний код:

```c
if (Ctx->OolRegisterAttempted) {
    // ідемпотентність: другий виклик — no-op, повертає результат першого
    ...
}
Ctx->OolRegisterAttempted = TRUE;
```

Ця ідемпотентність мала на меті "не реєструвати двічі за один power cycle" —
і це лишається правильним *у межах одного D0-періоду*. Але вона не має права
блокувати ре-реєстрацію **після** переходу в `Stale`. Нова умова:

```c
ExchangeLock.Acquire()
if Ctx->OolState == Registered:
    // ідемпотентність зберігається: у межах поточного D0-періоду другий
    // виклик — no-op success, як і зараз
    ExchangeLock.Release()
    WdfRequestComplete(Request, STATUS_SUCCESS)
    return

// OolState == NotRegistered АБО Stale — в обох випадках виконуємо
// (пере)реєстрацію. Буфери НЕ переалоковуються (T2DmaAllocateOolBuffers
// викликається лише якщо VA ще NULL — тобто фактично лише один раз за
// час життя device stack); виконується лише T2DmaRegisterOolBuffers
// (SET_OOL_IN/SET_OOL_OUT), який завжди безпечно повторний.
status = T2DmaAllocateOolBuffers(Ctx)   // no-op якщо вже виділено
status = T2DmaRegisterOolBuffers(Ctx)   // цей виклик і несе 5-секундний
                                         // worst-case mailbox-хендшейк —
                                         // тут це прийнятно (викликається
                                         // з IOCTL-контексту, не з D0Entry)
if NT_SUCCESS(status):
    Ctx->OolState = Registered
ExchangeLock.Release()
WdfRequestComplete(Request, status)
```

`T2DmaAllocateOolBuffers` потребує невеликого уточнення (не показано в
поточному коді, але випливає з `dma.c`): додати перевірку "якщо
`Ctx->OolInVa != NULL` — пропустити виділення" на самому початку функції,
щоби повторний виклик після `Stale` не намагався створити другий
`WDFDMAENABLER`/`WDFCOMMONBUFFER` поверх існуючих хендлів.

### 4.4 Прозорий авто-ресинк усередині `IOCTL_T2_AKS_EXCHANGE` — свідомо НЕ робимо

Розглядався варіант: якщо `OolState == Stale`, автоматично викликати
ре-реєстрацію просто всередині обробника AKS-обміну, непомітно для
user-mode. **Відхилено**, з двох причин:

1. Це додає непередбачувану затримку (до 5 с) до операції, яку user-mode
   (BridgeXPC/BiometricKit) очікує як швидку — гірший UX, ніж явна помилка
   "потрібна ре-реєстрація" одразу.
2. Це приховує факт "стався цикл живлення" від вищих шарів, яким за
   `docs/windows-security-model.md` (розділ про resume-invalidation) саме
   й потрібно **знати** про це, щоб самостійно інвалідувати
   BridgeXPC/BiometricKit-сесію — а не мовчки продовжити зі старим станом.

Замість цього: `IOCTL_T2_AKS_EXCHANGE` при `OolState != Registered`
повертає `STATUS_DEVICE_NOT_READY` (поведінка, яка вже є в коді для
`!OolInRegistered || !OolOutRegistered` — просто тепер покриває і `Stale`).
User-mode шар зобов'язаний спершу викликати `IOCTL_T2_REGISTER_OOL` — контракт
не змінюється, лише стає надійним після сну, а не тільки після першого
завантаження.

---

## 5. Розширення публічного контракту (`public.h`)

`T2_TRANSPORT_STATUS` (використовується `IOCTL_T2_GET_STATUS`) наразі має
лише сукупний `BOOLEAN OolRegistered`. Пропоновані додаткові поля — суто
діагностичні, не ламають ABI при додаванні в кінець структури:

```c
typedef struct _T2_TRANSPORT_STATUS
{
    BOOLEAN PciPresent;
    UINT16  VendorId;
    UINT16  DeviceId;
    BOOLEAN Bar4Mapped;
    UINT32  Bar4Size;
    BOOLEAN MailboxAccessible;
    BOOLEAN OolRegistered;       // тепер: (OolState == Registered), як і раніше
    // --- нові поля, додаються в кінець ---
    BOOLEAN OolStale;            // OolState == Stale: був зареєстрований,
                                  // пережив цикл живлення, потрібна
                                  // повторна IOCTL_T2_REGISTER_OOL
    UINT32  PowerUpGeneration;   // монотонний лічильник D0Entry; user-mode
                                  // може закешувати останнє бачене значення
                                  // й порівнювати, щоб виявити resume навіть
                                  // якщо OolStale вже встигли "залатати"
} T2_TRANSPORT_STATUS, *PT2_TRANSPORT_STATUS;
```

Це навмисно узгоджується із заявленим у `docs/windows-security-model.md`
("Power management / resume-invalidation дизайн — лише детекція намічена")
пунктом: цей документ і є тим "детекція" рішенням на транспортному рівні;
фактична інвалідація протокольної сесії (BridgeXPC/BiometricKit) лишається
за межами `T2TouchIdTransport.sys`, як і зазначено — драйвер лише чесно й
надійно репортує "SEP-реєстрація застаріла", вищий шар вирішує, що робити.

---

## 6. Idle / Wake policy — явне рішення, не дефолт мовчки

### 6.1 S0 idle (runtime power management, selective suspend)

**Рішення: НЕ вмикати.** Причини:

- Пристрій — транспорт для біометричної автентифікації; додаткові D0→D3
  цикли поза системним сном (через runtime idle) лише збільшують
  поверхню для стану "SEP забув реєстрацію" без жодної користі для
  користувача (це не пристрій з батарейним бюджетом на кшталт Wi-Fi/USB
  периферії).
- В SEP немає опкоду дереєстрації (§4.2) — часті "тихі" D3-цикли через idle
  роблять кожен спонтанний D3 потенційним джерелом протокольного
  неузгодження, яке має ретельно тестуватись; сон системи й так дає для
  цього достатньо приводів.
- KMDF PCI FDO **за замовчуванням не вмикає S0 idle**, доки драйвер явно не
  викличе `WdfDeviceInitSetIdleWakeSettings`/налаштує
  `WDF_DEVICE_POWER_POLICY_IDLE_SETTINGS` — тобто нічого додавати не треба;
  документ фіксує це як **свідомий вибір**, щоб майбутній розробник не
  "покращив" це, не розуміючи причини.

### 6.2 Device wake (SxWake / DeviceWake)

**Рішення: пристрій НЕ є джерелом пробудження.** Дактилоскопічний сенсор не
повинен будити машину із S3/S4 (на відміну від, наприклад, клавіатури чи
мережевої картки з Wake-on-LAN). Дефолт KMDF — wake-capabilities вимкнені,
доки не запитані явно — знову ж, нічого вмикати не потрібно; фіксуємо це як
намір, а не випадковість.

### 6.3 D1/D2 проміжні D-стани

Не використовуємо (мапимось прямо D0↔D3, без D1/D2) — узгоджується з тим, що
жодна частина протоколу SEP mailbox не описує проміжні low-power стани.
**Позначка "потребує апаратної перевірки"**: чи PCI Power Management
Capability цієї функції взагалі рекламує підтримку D1/D2 в config space —
не парситься поточним кодом (`T2QueryBar4ViaPciConfig` читає лише BAR
offsets, не PM capability list). Для цього документа це не критично (D0/D3
достатньо для коректності), але якщо майбутня апаратна перевірка покаже, що
пристрій **примусово** проходить через D1/D2 (деякі chipset/ACPI
конфігурації це роблять незалежно від бажання драйвера), `EvtDeviceD0Entry`
з §4.1 і так коректно обробить це — логіка "будь-який вхід у D0 з не-D0"
не залежить від того, з якого саме D-стану прийшли.

---

## 7. Сценарії й послідовності подій (для тестування)

### 7.1 Холодний старт (перше під'єднання/`AddDevice`)
```
AddDevice → EvtDeviceAdd → EvtDevicePrepareHardware (BAR4 map)
          → EvtDeviceD0Entry(PreviousState=D3)  [OolState: NotRegistered→NotRegistered]
          → пристрій Started, у D0
```
User-mode викликає `IOCTL_T2_REGISTER_OOL` → `OolState: NotRegistered→Registered`.

### 7.2 Сон системи (S1–S4) і пробудження
```
... (система засинає) ...
EvtDeviceD0Exit(TargetState=D3)             [лише лог, §4.2; State: Ready→HardwareReady]
   ... пристрій фізично в D3 ...
... (система прокидається) ...
EvtDeviceD0Entry(PreviousState=D3)          [State: (Ready або HardwareReady)→HardwareReady]
```
Наступний `IOCTL_T2_AKS_EXCHANGE` від BridgeXPC → негайний
`STATUS_DEVICE_NOT_READY` (замість мовчазного 5-секундного mailbox-timeout
при кожному обміні — саме та поведінка, що на практиці виглядає як "з'їдає
енергію уві сні": повторні заблоковані/повторювані обміни замість швидкої
відмови). BridgeXPC викликає `IOCTL_T2_REGISTER_OOL` (§4.3) →
`HardwareReady→Ready` (реальний повторний `SET_OOL_IN`/`SET_OOL_OUT`,
підтверджений відповіддю SEP, а не здогадка), далі AKS-обмін працює штатно.

**Виправлено (було регресією відносно цього документа):** початкова
реалізація Milestone 2B у `T2EvtDeviceD0Entry` при `OolInRegistered &&
OolOutRegistered` переходила напряму в `Ready`, довіряючи
пре-сон-реєстрації без перевірки — саме той сценарій, для запобігання
якому писався §2.2 цього документа. Замінено на безумовний перехід у
`HardwareReady` при кожному D0Entry (див. коментар над
`T2SetTransportState(ctx, T2TransportHardwareReady)` у `device.c`).

**Очікуваний "known limitation" для цього сценарію** (успадкований від
`docs/t2-touchid-windows-feasibility.md`): навіть після цього виправлення
транспорту, якщо BridgeXPC-сесія йде поверх CDC-NCM USB-інтерфейсу T2, який
не піднявся після S3 (задокументована в Linux-аналізі проблема), сам
транспортний рівень буде готовий (`OolState=Registered`), але вищий XPC-шар
все одно залишиться недоступним — це поза межами `T2TouchIdTransport.sys`.

### 7.3 Гібернація (S4)
Ідентично §7.2 з точки зору цього драйвера: `D0Exit(TargetState=D3)` →
повне вимкнення → після відновлення образу `D0Entry(PreviousState=D3)`.
Особливість гібернації — можливість (рідкісний edge case) відновлення на
дещо іншій конфігурації ресурсів; якщо це станеться, PnP-менеджер сам
проведе повний `ReleaseHardware`→`PrepareHardware` цикл до `D0Entry`, що вже
покрито існуючим кодом.

### 7.4 Device Manager Disable → Enable
```
EvtDeviceD0Exit(TargetState=D3) → EvtDeviceReleaseHardware
   ... (Disabled) ...
EvtDevicePrepareHardware → EvtDeviceD0Entry(PreviousState=D3)
```
Тут DMA-буфери **звільняються** в `ReleaseHardware` (якщо OOL не було
"назавжди залишено" через SEP-реєстрацію — існуюча retain-логіка) і
виділяються заново в наступному циклі `IOCTL_T2_REGISTER_OOL`
(`T2DmaAllocateOolBuffers` побачить `OolInVa == NULL` і виділить наново) —
це вже коректно, окремих змін не потребує понад §4.1/§4.3.

### 7.5 Модель тестування на реальному пристрої
1. `powercfg /a` — які стани сну взагалі підтримує ця машина (S3 vs Modern
   Standby/S0 Low Power Idle) — впливає на те, який саме сценарій §7.2
   реально відтворюється.
2. Базовий цикл: enroll → `IOCTL_T2_REGISTER_OOL` → успішний AKS-обмін →
   `powercfg /sleep` (або `shutdown /h` для S4) → пробудження →
   `IOCTL_T2_GET_STATUS` (очікується `OolRegistered=FALSE`,
   `OolStale=TRUE`) → повторний `IOCTL_T2_REGISTER_OOL` → успішний
   AKS-обмін знову.
3. Повторити 3–5 сон/резюме циклів поспіль без перезавантаження — перевірити,
   що `PowerUpGeneration` монотонно зростає і кожного разу ре-реєстрація
   проходить (немає накопичення "залишків" від попередніх common buffers).
4. Device Manager Disable/Enable — та сама перевірка через §7.4.
5. Перевірити журнал (`DbgPrintEx`/DebugView, IHVDRIVER filter — див.
   коментар у `driver.h` про `T2_LOG`) на предмет 5-секундних затримок:
   переконатись, що вони виникають **лише** всередині обробки
   `IOCTL_T2_REGISTER_OOL`, а не десь у ланцюжку самого системного resume.

---

## 8. Підсумковий чекліст змін — РЕАЛІЗОВАНО

- [x] `driver.h`: замінено 3 булеві поля на `T2_OOL_STATE OolState` +
      `ULONG PowerUpGeneration` у `T2_DEVICE_CONTEXT`.
- [x] `device.c` / `EvtDeviceD0Entry`: реалізовано §4.1 (позначення Stale,
      інкремент генерації, без mailbox I/O, під `ExchangeLock`).
- [x] `device.c` / `EvtDeviceD0Exit`: реалізовано §4.2 (лише діагностичний лог).
- [x] `device.c` / `T2EvtIoDeviceControlRegisterOol`: гвард замінено за §4.3
      (`Registered` → no-op success; `NotRegistered`/`Stale` → (пере)реєстрація;
      `OolState` виставляється в `Registered` лише після повного успіху обох
      SET_OOL_*).
- [x] `device.c` / `T2EvtIoDeviceControlAksExchange`: умова готовності —
      `OolState != T2OolStateRegistered` (коректно відхиляє і `Stale`).
- [x] `device.c` / `T2EvtIoDeviceControlGetStatus`: заповнює `OolStale`,
      `PowerUpGeneration`.
- [x] `dma.c` / `T2DmaAllocateOolBuffers`: рання перевірка "вже виділено —
      пропустити" (ідемпотентність для повторного виклику після `Stale`).
- [x] `public.h`: додано `OolStale`, `PowerUpGeneration` у
      `T2_TRANSPORT_STATUS` (у кінець структури, ABI-сумісно; існуючий
      клієнт `protocol/AppleKeyStore/Client.cpp` читає лише старе поле
      `OolRegistered` і лишається коректним без змін).
- [x] Явних змін до `.inf` (idle/wake capabilities) не вносилось — §6
      лишається задокументованим дефолтом, а не пропуском.

### 8.1 Уточнення, знайдене під час реалізації (не було в початковому плані)

Під час перенесення логіки в код виявилось, що заміна трьох булевих на
самий лише `T2_OOL_STATE` **ламає одну навмисну поведінку оригіналу**:
`EvtDeviceReleaseHardware` вирішує "лишити пам'ять до перезавантаження", якщо
`OolInRegistered || OolOutRegistered` — це навмисно спрацьовувало і при
**частковій** невдачі (SET_OOL_IN пройшов, SET_OOL_OUT — ні), бо SEP уже міг
запам'ятати адресу IN-буфера, навіть якщо повна реєстрація (потрібна для
`T2OolStateRegistered`) не відбулась.

Якщо просто прив'язати retain-рішення до `OolState != NotRegistered`, цей
частковий випадок губиться (стан лишається `NotRegistered`/`Stale`, а не
`Registered`) — і `ReleaseHardware` помилково звільнив би пам'ять, яку SEP
все ще міг вважати своєю.

**Виправлення**: додано окреме, навмисно "липке" поле поза машиною станів —
`BOOLEAN OolSepMayKnowAddress` у `T2_DEVICE_CONTEXT` (driver.h). Виставляється
в `TRUE` в `dma.c` одразу після успішного SET_OOL_IN (незалежно від
подальшого результату SET_OOL_OUT) і **ніколи** не скидається — на відміну
від `OolState`, який циклічно проходить `Registered → Stale → Registered`
при кожному сні/пробудженні. `EvtDeviceReleaseHardware` тепер перевіряє саме
`OolSepMayKnowAddress`, а не `OolState`, і це коректно покриває всі три
випадки: повну реєстрацію, часткову невдачу (як в оригіналі) і стан `Stale`
після сну (SEP усе ще міг пам'ятати адресу — це саме той сценарій, заради
якого весь цей документ і писався).

Файли `dma.c` (сеттер) і `device.c` (читач у ReleaseHardware) — обидва
показані нижче серед змінених файлів.

---

## 9. Пізніше уточнення (Milestone 2B §2) — і виправлення "D0 resume OOL
    state inconsistency"

Подальший рефакторинг (Milestone 2B §2, див. коментар над
`T2_TRANSPORT_STATE` у `driver.h`) замінив пару `OolState`/
`PowerUpGeneration` із §3–§8 вище на єдиний явний enum
`T2_TRANSPORT_STATE` (`NotInitialized / HardwareReady / RegisteringOol /
Ready / Stopping / Invalid`), а `OolInRegistered`/`OolOutRegistered`
лишились окремими булевими прапорцями (не злились у `T2OolStateRegistered`,
як планувалось у §3.2) — секції §3–§8 цього документа описують проміжну,
вже замінену модель і мають історичну, а не поточну цінність для `device.c`.

Той рефакторинг переніс §4.1 буквально: `EvtDeviceD0Entry` завжди опускав
стан до `HardwareReady` після будь-якого resume, ніколи напряму в `Ready`
(коментар "Deliberately never D0Entry -> Ready directly"). Це відтворило
рівно ту суперечність, яку §1 цього документа діагностував як баг:
`OolInRegistered`/`OolOutRegistered` лишались `TRUE` (їх ніхто не скидає -
на відміну від запланованого `OolState = Stale`), тоді як
`TransportState == HardwareReady` — тобто `status` міг репортувати
"OOL registered", а `IOCTL_T2_AKS_EXCHANGE`/`capabilities` одразу
відхилялись з `STATUS_DEVICE_NOT_READY`, бо той шлях перевіряє
`State == Ready`, а не прапорці окремо.

**Виправлення** (підтверджено апаратним тестом: та сама SEP OOL-реєстрація
продовжує працювати після звичайного sleep/resume, без повторного
`SET_OOL_IN`/`SET_OOL_OUT`): `EvtDeviceD0Entry` тепер робить дешеву mailbox
liveness-перевірку (MMIO read of `T2_SEP_INBOX_STATUS`; читання
`T2_SEP_MAILBOX_DEAD_READ` = `0xFFFFFFFF` трактується як провал живості) і,
лише коли ця перевірка проходить **і** `OolInRegistered && OolOutRegistered`
обидва вже `TRUE` з часів до сну, переходить напряму в `Ready` — без
повторного виклику `IOCTL_T2_REGISTER_OOL`. У будь-якому іншому випадку
(мертвий mailbox, або неповна/відсутня OOL-реєстрація) поведінка лишається
fail-closed, як і раніше: перехід у `HardwareReady`, наступний AKS-обмін
негайно отримує `STATUS_DEVICE_NOT_READY`, потрібен явний
`IOCTL_T2_REGISTER_OOL`. `EvtDeviceD0Exit` (демоція `Ready`/`RegisteringOol`
→ `HardwareReady` перед сном), `PrepareHardware`/`ReleaseHardware`,
`Invalid`-гілка та сам AKS/OOL-протокол не змінювались.
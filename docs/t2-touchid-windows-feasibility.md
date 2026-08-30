# T2 Touch ID → Windows Hello: Feasibility Report (Milestone 0)

Підготовлено у відповідь на п.29 ТЗ, перед створенням driver codebase.
Джерело для аналізу: README репозиторію `jmurth1234/t2-touchid-linux` (перевірено 2026-08-30) + офіційна документація Microsoft WBDI/WBF.

---

## A. Feasibility report

**Коротка відповідь: реалізовуваність — умовна "так", але з суттєво іншим risk-профілем, ніж у Linux-проєкту.**

Ключові факти з Linux reference, що впливають на feasibility:

1. Проєкт сам себе описує як **research software**, перевірене рівно на одній конфігурації: `MacBookPro16,2`, конкретний build bridgeOS (`23P1072`) і конкретна версія BridgeXPC (`39`). Це не production driver і не universal T2 support — це означає, що будь-яка Windows реалізація так само буде hardware/firmware-специфічною, і кожен новий bridgeOS build потенційно ламає протокол.
2. Enrollment **навмисно не підтримується** на Linux-стороні — верифікується лише identity, вже заенролена в macOS для user ID 501. Це знімає з нас величезний шматок роботи (не потрібно реалізовувати enrollment path), але означає, що V1 Windows-рішення **завжди залежатиме від живої macOS-інсталяції** для enrollment/re-enrollment.
3. SEP kernel-модуль **pinned після DMA registration і не може бути вивантажений** без перезавантаження. Це прямий і серйозний виклик для Windows kernel-mode драйвера: KMDF-драйвер повинен коректно обробляти D0→D3 та unload/reload сценарії, а тут маємо hardware/firmware-обмеження, яке фактично забороняє "чистий" unload. Треба закладати це в архітектуру driver lifecycle з самого початку (division of responsibility між transport-класом ресурсів, що переживають unload, і рештою стеку).
4. **Suspend/resume офіційно не працює** навіть на Linux (deep-S3 ламає `cdc_ncm` transmit path, BridgeXPC стає недосяжним, відновлення потребує повного reboot). Це не Linux-специфічна проблема — це проблема самого T2 CDC-NCM стеку під час сну. На Windows це, найімовірніше, відтвориться так само або гірше через Modern Standby, який ще агресивніше керує live USB/network інтерфейсами. **Тому Windows Hello через T2 Touch ID реалістично працюватиме тільки в S0/до першого сну**, доки Milestone 8 (power management) не дасть окреме рішення. Це критичне обмеження для user experience і має бути явно комунікованим як "known limitation", а не прихованим багом.
5. Keybag-модель вимагає **macOS-паролю для розблокування після кожного reboot**, пароль ніколи не зберігається постійно. Переносячи цю модель на Windows, ми або (а) вимагаємо ручного unlock-кроку при кожному старті Windows (прийнятно для V1 PoC), або (б) реалізуємо PAM-подібний хук через Windows Credential Provider, що передає пароль користувача в keybag-unlock helper лише в пам'яті процесу — це прямий аналог Linux `t2-pam-unlock` механізму і виглядає технічно переносним, але це вже за межами V1.
6. Протокол не є "стабільним публічним API" — це reverse-engineered поведінка конкретного bridgeOS build. Це означає, що частина "known" на Linux фактично є "known for this one build" і має трактуватися як PARTIALLY KNOWN для Windows, поки не підтверджено на цільовому апараті.

**Висновок:** Шлях T2 → SEP → BridgeXPC → BiometricKit → WBDI → Windows Hello є технічно досяжним для PoC на одній конкретній, заздалегідь протестованій машині — так само, як Linux-проєкт досяг цього на одній машині. Не варто обіцяти general-purpose T2 Touch ID driver для Windows на першому етапі; це S0-only, single-model, requires-live-macOS-enrollment рішення з ручним keybag unlock. Це узгоджується з п.17 ТЗ (не робити wildcard hardware support) і п.16 (power management — окреме дослідження).

---

## B. Protocol map (Linux → Windows)

| Linux source (file:function/role) | Призначення | Windows-компонент (component:module) |
|---|---|---|
| `src/t2_sep_transport.c` — SEP endpoint-7 DMA/keybag transport, kernel module, `register_ool=1`, pinned after registration | Низькорівневий доступ до T2 PCI, DMA-буфери, SEP endpoint 7 | `T2TouchIdTransport.sys` (KMDF) — переписаний як native state machine, з явним урахуванням "не можна безпечно unload після DMA registration" |
| `src/t2-aks-tool.c` — вузько allow-listed AppleKeyStore операції (unlock-keybag normal handle, unlock-keybag special user bag) | Керування keybag (unlock normal + special user bag через пароль) | `T2TouchIdProtocol/applekeystore/` — user-mode або LPC-міст до transport-драйвера; **тільки** операції unlock-keybag(handle) та unlock-keybag(-501) переносяться, решта AKS opcode space не реалізується (docs/apple-keystore.md обов'язковий) |
| `src/discover-biometric-port.py` — privacy-preserving RemoteXPC discovery, кешує dynamic port root-only | Динамічний пошук BridgeXPC/BiometricKit порту, без hardcode | `T2TouchIdProtocol/bridgexpc/discovery` — еквівалент RemoteXPC discovery поверх Windows CDC-NCM/network stack; кеш порту в захищеному, admin-only сховищі (аналог `/var/lib/t2-touchid`) |
| `src/bridge-xpc-probe.py` — BridgeXPC команди + логіка match/no-match | Формування/парсинг BridgeXPC envelope, виклик BiometricKit verify, читання match-result event | `T2TouchIdProtocol/bridgexpc/` + `biometrickit/` — окремий protocol-parser з unit-тестами (п.19 ТЗ: valid/invalid/truncated/wrong version/wrong UUID) |
| `src/t2-fprintd.py` — verification-only fprintd-сумісний D-Bus фасад | Експонування verification result у PAM-стек Linux | **Не переноситься 1:1** — Windows-еквівалент це `T2TouchIdWbdi` (UMDF WBDI driver), а не D-Bus service; це найбільша архітектурна розбіжність між платформами |
| `pam/*` — PAM-хуки, включно з password-passthrough (`t2-pam-unlock`) для розблокування keybag першим успішним паролем | Автоматичне розблокування keybag при вході | За межами V1. Windows-аналог — Credential Provider hook (post-password unlock keybag) — окремий Milestone після V1, потребує security review (п.14 ТЗ) |
| `systemd/t2-biometric-ready.service` — warm-up (init/calibration/identity-list) до старту fprintd, щоб уникнути "cold start race" | Уникнення помилки першого сканування через холодний старт BiometricKit | `T2TouchIdWbdi` повинен виконувати аналогічний warm-up при device arrival, до першого WBDI verification request |
| `tools/provision-credential.sh` + systemd-creds (host-key encrypted, no TPM on proven config) | Unattended boot unlock через зашифрований credential | Поза scope V1; Windows-аналог — DPAPI/TPM-backed credential, окремий Milestone |
| `tests/test_t2_fprintd.py` — hardware-free fail-closed lifecycle tests | Перевірка fail-closed поведінки без реального заліза | `T2TouchIdProtocol/tests/` — port тієї ж логіки на C++/C# unit tests |

---

## C. Hardware requirements

- **T2 PCI interface** — потрібен для transport-рівня (endpoint 7 SEP). PCI Vendor/Device ID для конкретної моделі має бути підтверджений через Device Manager/`devcon` на цільовій машині перед написанням коду (Linux README не публікує це число напряму — PARTIALLY KNOWN, треба зняти самостійно).
- **DMA** — SEP-транспорт реєструє DMA-буфери, які **pinned до reboot**. На Windows це вимагає KMDF DMA common-buffer allocation з чіткою політикою lifetime і явною забороною unload/reload без reboot у драйвері.
- **CDC-NCM / T2 USB-network інтерфейс** — BridgeXPC ходить поверх link-local IPv6 через віртуальний USB-Ethernet (CDC-NCM) інтерфейс, який T2 виставляє хосту. На Windows це означає залежність від коректної роботи вбудованого RNDIS/CDC-NCM класу (є нативна підтримка в Windows, але поведінка при S3/Modern Standby невідома — UNKNOWN, дивись розділ D).
- **RemoteXPC / dynamic port discovery** — потрібен мережевий стек, здатний виконати те саме discovery, що й `discover-biometric-port.py`, поверх link-local IPv6 на цьому CDC-NCM інтерфейсі.
- Немає підтвердженої потреби у Thunderbolt/PCIe hot-plug — сесія передбачає, що T2 присутній з boot.
- Модель для V1: **тільки** та, на якій буде реально протестовано (за аналогією з Linux-проєктом, який підтверджений лише на `MacBookPro16,2`). Не заявляти сумісність з іншими MacBookPro15,x/16,x моделями без окремого тестування (п.17, 25 ТЗ).

---

## D. Unknowns

**KNOWN (задокументовано в Linux reference, можна переносити напряму як протокол-модель):**
- Загальний ланцюжок verification: SEP → protocol-v2 match-result event → перевірка 16-байтного identity UUID → MATCH/NO MATCH.
- Fail-closed вимоги: missing/malformed/rejected/timeout → fail.
- Keybag-модель: normal handle + special user bag (-501), розблокування через macOS-пароль, пароль ніколи не персиститься.
- SEP-модуль pinned after DMA registration, unload заборонено без reboot.
- Suspend/resume зламаний навіть на Linux (deep-S3 → cdc_ncm watchdog timeout → BridgeXPC unreachable).
- Enrollment зумисно не підтримується на "не-macOS" стороні.

**PARTIALLY KNOWN (модель поведінки відома, конкретні байти/значення — ні):**
- Точний формат BridgeXPC envelope (command IDs, version fields, message IDs) — Linux README описує *існування* discovery/probe-скриптів (`discover-biometric-port.py`, `bridge-xpc-probe.py`), але не публікує самі payload-специфікації в тексті README; потрібен прямий аналіз коду цих файлів (Milestone 1) перш ніж щось документувати як "known".
- Точний PCI Vendor/Device ID T2 та точна topology для цільової моделі.
- Набір allow-listed AppleKeyStore opcode — README підтверджує, що список **вузький**, але не перелічує самі opcode в тексті; аналіз `t2-aks-tool.c` обов'язковий (docs/apple-keystore.md).
- Поведінка Windows CDC-NCM стеку саме з цим virtual adapter (може відрізнятись від Linux `cdc_ncm` driver поведінково).

**UNKNOWN (немає навіть непрямих даних, потребує окремого практичного дослідження на реальному залізі):**
- Чи відтворюється S3/Modern Standby збій на Windows так само, як на Linux, чи інакше (можливо гірше — Windows агресивніше вимикає USB-мережеві інтерфейси в Modern Standby).
- Чи можливий одночасний dual-boot доступ до keybag-файлу без конфлікту версій/стану SEP між ОС (Linux-проєкт нічого не каже про поведінку SEP endpoint state, коли хост перезавантажується в іншу ОС без "чистого" T2 reset).
- Реакція WBDI/Windows Biometric Service на non-standard capture-less verification-only device (WBDI зазвичай очікує капчер образу; verification-only модель без capture — нестандартний use case, потребує окремої перевірки сумісності з WBF architecture, а не лише з WBDI IOCTL-набором).
- Стабільність dynamic BridgeXPC port між перезавантаженнями Windows (Linux кешує його root-only; чи змінюється порт при кожному T2 device arrival — не задокументовано).

---

## E. Proposed architecture (до Milestone 1/2)

```
                          Windows Biometric Service (WBF)
                                      │
                                     WBDI
                                      │
                         T2TouchIdWbdi.dll  (UMDF, verification-only WBDI unit,
                                              warm-up on device arrival, no raw
                                              image capture exposed)
                                      │
                         T2TouchIdProtocol (user-mode)
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
              bridgexpc/         biometrickit/     applekeystore/
        (envelope parse,      (discover→init→     (unlock-keybag,
         discovery, probe)     start verify→        normal+special
                                match event)          only — allow-list)
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      │  controlled LPC/IOCTL interface
                                      ▼
                         T2TouchIdTransport.sys (KMDF)
                    PCI map/config, DMA alloc (pinned post-registration),
                    SEP endpoint-7 protocol state machine,
                    explicit "no clean unload after DMA reg" contract
                                      │
                                      ▼
                                  Apple T2 / SEP
```

Головні архітектурні рішення, що випливають з розділів A–D:
1. **Transport-драйвер ізольований і трактується як "непереживаючий" unload після DMA registration** — інші компоненти (WBDI unit, protocol-стек) не повинні залежати від можливості hot-reload transport-шару; будь-яка recovery-логіка після помилки веде до "FAILED → потребує reboot", а не до спроби unload/reload SEP-модуля.
2. **Power-menedgment трактується як окрема, явно недороблена підсистема V1**: WBDI unit при resume з S3/Modern Standby обов'язково повторно перевіряє T2 transport → BridgeXPC → BiometricKit (а не вважає стан валідним), і за замовчуванням повертає NO_MATCH/недоступний device, поки Milestone 8 не дасть окреме рішення.
3. **Keybag unlock у V1 — ручний крок** (diagnostic utility запускає unlock-keybag викликами, аналогічно `t2-aks-tool unlock-keybag`), без Credential Provider автоматизації — це прямо відповідає п.7 ТЗ ("не блокувати перший PoC повною автоматизацією keybag provisioning").
4. **BiometricKit protocol subset обмежений** до: discover → initialize → obtain identity → start verification → receive match event → stop verification, без enrollment — прямий перенос Linux-обмеження.

---

## Наступний крок

Перед Milestone 1 (`docs/linux-reference-analysis.md`) потрібен прямий доступ до вихідного коду файлів `t2_sep_transport.c`, `t2-aks-tool.c`, `discover-biometric-port.py`, `bridge-xpc-probe.py`, `t2-fprintd.py` — README дає модель поведінки, але не байтовий рівень протоколу. Без цього кроку розділи B і D цього звіту залишаються на рівні "PARTIALLY KNOWN", і будь-яка спроба вгадати формат envelope порушить п.27 ТЗ ("не вигадувати протокол").

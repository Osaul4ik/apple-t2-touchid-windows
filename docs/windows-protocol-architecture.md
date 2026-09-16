# windows-protocol-architecture.md

## Шари

```
tools/t2touchid (CLI)
        │
protocol/BiometricKit  — VerificationEngine, Commands, MatchResult
        │
protocol/BridgeXpc     — Connection (socket/HELO/event loop), Frame, PlistPayload
        │
protocol/AppleKeyStore — Client (IOCTL wrapper, password hygiene)
        │
driver/T2TouchIdTransport.sys — mailbox, DMA, AKS allow-list enforcement
```

## Що реально реалізовано в цьому PoC-скелеті

- **Frame.h/cpp** — повний, самодостатній, хардвер-незалежний парсер
  16-байтного заголовка BridgeXpc з валідацією magic/version/розміру тіла
  ДО будь-якої алокації (Milestone 2 §14 вимога).
- **MatchResult.h/cpp** — повна, самодостатня, хардвер-незалежна реалізація
  єдиної критичної логіки: constant-time сканування event payload на
  збіг з enrolled UUID. Покрита unit-тестами (`tests/ProtocolTests.cpp`)
  на malformed/no-identities/unenrolled/enrolled сценарії, прямий аналог
  `test_t2_fprintd.py`.
- **Commands.h/cpp** — кодування/декодування BM-wrapper, `match_init_data_v1`,
  identity-list парсинг з локальним capacity cap.
- **Client.cpp (AppleKeyStore)** — IOCTL wrapper з коректною password
  hygiene (`SecureZeroMemory` на кожному шляху виходу).

## Що НЕ доведено до кінця (чесно позначено TODO в коді, не приховано)

1. **PlistPayload.cpp відсутній** — це wrapper-інтерфейс над `libplist`
   (Milestone 2 §15 прямо забороняє власний bplist parser). Реальна
   реалізація вимагає підключення цієї сторонньої залежності й перевірки
   її ліцензії (LGPL-2.1) перед використанням у білді — архітектурне
   рішення, не технічна складність.
2. **Connection.cpp** містить кілька `TODO`/placeholder точок (реальний
   UUIDv4 замість фіксованих request ID, реальне вилучення `embeddedType`
   з декодованого plist) — потребують `PlistPayload.cpp`, тому логічно
   йдуть після нього.
3. **VerificationEngine::Verify** пропускає крок FDR calibration load
   (bridge-level method 11 + BM cmd 0x20) у лінійному лістингу цього PoC —
   явно позначено як TODO, **не** пропущено мовчки. Пропуск цього кроку в
   реальному білді, найімовірніше, зламає перше match-звернення (Linux
   reference виконує його щоразу).
4. **RemoteXPC discovery** (`discover-biometric-port.py` еквівалент) —
   Phase 2 реалізовано в `protocol/Discovery/RemoteXpc.{h,cpp}` і
   під'єднано до `t2touchid.exe network` (докладніше —
   `docs/gate6-discovery.md`). **Оновлення 16.09.2026: перевірено на
   реальному залізі** — Phase 2 discovery та Gate 7 phase 1 (жива
   `BridgeXpc::Connection`, HELO + `getBridgeVersion`) обидва підтверджені
   на реальному T2. `identities`/`verify` тепер під'єднані до цього
   з'єднання (Gate 8, `tools/t2touchid/main.cpp`), але сам ланцюжок
   biometric-команд (reset/calibration/identity-list/start-match) ще
   **не перевірено на реальному залізі** — див. `docs/gate6-discovery.md`.

## Чому так, а не "зробити вигляд, що готово"

Milestone 2 критичне правило №9 ("Do not implement WBDI before real
MATCH/NO_MATCH works") і загальний принцип "Never convert an assumption
into a fact" означають, що незавершені частини мають залишатись видимо
незавершеними в коді й документації, а не замасковані заглушками, які
повертають хардкоджений успіх.
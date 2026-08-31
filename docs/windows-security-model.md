# windows-security-model.md

Властивості безпеки, перенесені 1:1 з Linux-джерела (Milestone 1, розділ
14), і де саме в цьому дереві вони реалізовані:

| Властивість | Linux джерело | Windows реалізація |
|---|---|---|
| Allow-list AKS операцій, enforced у kernel | `t2_aks_operation_allowed()` | `T2AksOperationAllowed()` — викликається двічі: `device.c` (IOCTL boundary) і `akstore.c` (захист від майбутніх internal callers) |
| Ніякого arbitrary SEP command API | немає public opcode passthrough | `public.h` не експонує жодного "send raw SEP command" IOCTL — лише `IOCTL_T2_AKS_EXCHANGE` з enum-обмеженим `Operation` |
| SHA-256 digest integrity на AKS-обміні | header digest[16] | `T2AksDigest()` через `BCryptHashData` (CNG) |
| Пароль ніколи в argv/env/логах, memory-only, zeroed | `secret[1024]`, `memset` на всіх шляхах | `ReadPasswordInteractive()` (без echo) + `Client::Unlock()` викликає `SecureZeroMemory` на request-буфері й на caller-буфері незалежно від результату |
| Timeout на кожній mailbox-операції | `T2_SEP_TIMEOUT_US = 5s` | той самий константа в `driver.h`, застосована в `mailbox.c` |
| Обмежена кількість "чужих" відповідей перед помилкою | 32 ітерації | `T2_SEP_MAX_SKIPPED_REPLIES` в `mailbox.c` |
| UUID ніколи не логується повністю | `summarize_event()` не серіалізує UUID | коментарі в `MatchResult.h`/CLI явно забороняють логування повного UUID; `t2touchid.exe capabilities`/`status` не друкують UUID взагалі |
| Constant-time порівняння біометричних UUID | не застосовується в Python (не потрібно для research-коду) | **посилення понад Linux-джерело**: `ConstantTimeEquals16()` в `MatchResult.cpp` — свідомо додано для kernel/production-грейд коду, якого немає в reference-реалізації |
| Fail-closed на malformed/timeout/rejected | `verdict_from_result()` | `VerificationEngine::Verify()` — жоден шлях не повертає `Match` без явного `MatchOutcome::Match` з `ParseMatchResult` |
| Один активний exchange/verification | `exchange_lock` (Linux kernel) | `WDFWAITLOCK` (driver) + `VerificationEngine::IsBusy()` (user-mode) |
| DMA-буфери не звільняються після SEP-реєстрації | pinning behavior | `T2EvtDeviceReleaseHardware` перевіряє `OolInRegistered`/`OolOutRegistered` перед `T2DmaFreeOolBuffers` |

## Відхилення від Linux-джерела, що варто зазначити явно

- Windows-версія додає constant-time UUID comparison, якого немає в
  Python reference (Python `==` на bytes не є constant-time) — це
  посилення, зроблене свідомо, а не розбіжність, яку варто виправляти.
- Windows-версія сканує весь event payload на збіг UUID замість
  порівняння за фіксованим offset — це **тимчасовий, документований
  fallback** через невстановлений offset (Milestone 1), а не бажана
  постійна поведінка; після підтвердження точного offset на реальному
  залізі сканування варто звузити до перевірки конкретної позиції (менша
  поверхня для випадкового hash collision на короткому 16-байтному вікні,
  хоча ймовірність такого false positive в межах одного ~3KB буфера
  вкрай мала — але точність важливіша за це обчислювальне спрощення).

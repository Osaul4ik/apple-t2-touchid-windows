# T2TouchIdBio (UMDF 2, WBDI) — мінімальний скелет

Реалізує «наступний практичний крок» з `../docs/Windows-hello-design.MD` §8:
відповідає лише на `IOCTL_BIOMETRIC_GET_ATTRIBUTES` та
`IOCTL_BIOMETRIC_GET_SENSOR_STATUS`, щоб зняти головний ризик §2 (чи бачить
WinBio UMDF-драйвер без WHQL) **до** підключення `VerificationEngine`.

**Статус: не збиралося і не запускалося.** Код написано без WDK під рукою.
Назви типів/констант WinBio зібрано в `Queue.cpp` (блок `VERIFY AGAINST THE
WDK HEADERS`) — очікуйте 1–2 ітерації правок після першої збірки.

Не додано в `T2TouchId.sln`: `Cit2touchid.yml` і `BuildT2TouchId.yml`
збирають весь `.sln`, тож необкатаний UMDF-проєкт зламав би працюючий CI.

## Збірка

```
msbuild driver\T2TouchIdBio\Umdf\T2TouchIdBio.vcxproj /p:Configuration=Release /p:Platform=x64
```

Пакет (INF не в проєкті — як і в `T2TouchIdTransport`):

```
copy Umdf\T2TouchIdBio.inf  <out>\
stampinf -f <out>\T2TouchIdBio.inf -d * -a amd64 -u 2.15.0 -v *
inf2cat /driver:<out> /os:10_x64
signtool sign ...   (test-сертифікат, як для T2TouchIdTransport)
```

`-u 2.15.0` має збігатися з `UMDF_VERSION_MINOR` у `.vcxproj`.

## Встановлення і перевірка (test-signing)

```
devcon install T2TouchIdBio.inf root\T2TouchIdBio
```

1. Device Manager → клас **Biometric devices** → пристрій без Code 31/39/43.
2. DebugView (Capture Global Win32): рядки `T2TouchIdBio: IOCTL 0x...`.
3. Event Viewer → Applications and Services Logs → Microsoft → Windows →
   Biometrics → Operational: чи завантажила WBF сенсор.
4. Settings → Accounts → Sign-in options: чи з'явився Fingerprint recognition.

Якщо (4) не працює лише через відсутність WHQL/підпису для SystemSensor —
це і є ризик з design doc §2, і тоді план зсувається на KMDF+WSK.

## Далі

1. `CAPTURE_DATA` → `Connection::Connect()` + `VerificationEngine::Verify()`
   з cancel-токеном (§3, §9.4).
2. `GET_SENSOR_STATUS` за реальним станом: `IOCTL_T2_GET_STATUS` +
   `Global\T2SepReady` (§3, §9.2).
3. Vendor-формат BIR замість плейсхолдера ANSI-381 у `GET_ATTRIBUTES` (§5).
4. Storage/Engine adapter (§7.3–7.4).

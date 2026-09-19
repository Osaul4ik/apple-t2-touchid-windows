# T2SepBootstrap

Реалізує design doc §9.2. Читає `C:\ProgramData\T2TouchId\sep-vault.bin`
(пише його `tools/SepVaultGui`) і виконує
`register-ool → load-keybag → set-system-keybag → unlock → unlock`
через `protocol/AppleKeyStore::Client` — без запуску `t2touchid.exe`,
без пароля в argv.

## Проєкт у Visual Studio

Ще не додано `.vcxproj` — простіше створити його в IDE (Console App,
Character Set = Not Set, підключити `protocol/AppleKeyStore` як залежний
проєкт або додати `Client.cpp`/`Client.h` напряму в Sources), ніж
відтворювати GUID/toolset-специфічний XML вручну. Лінкер: `crypt32.lib`
(уже через `#pragma comment`), `advapi32.lib` (SCM API — зазвичай і так у
default libs).

## Встановлення (test-signing режим, той самий, що й для
`T2TouchIdTransport.sys`)

```
sc create T2SepBootstrap binPath= "C:\Path\To\T2SepBootstrap.exe" start= auto
sc failure T2SepBootstrap reset= 0 actions= ""   REM явно НЕ restart-on-failure — див. §9.2/файл .cpp
sc start T2SepBootstrap
```

Діагностика: `C:\ProgramData\T2TouchId\bootstrap.log`.

## Відкрито (не в цьому проході)

- Реальний Windows Event Log source замість файлового логу.
- Cancel-токен у `VerificationEngine::Verify()` для сценарію екрану
  блокування (design doc §9.4) — цей сервіс лише готує SEP, самого
  verify-виклику Hello тут немає.
- WBDI UMDF-скелет (design doc §2/§7.1) — досі найризикованіший
  неперевірений крок, не залежить від цього сервісу і не блокується ним.
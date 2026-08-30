# windows-transport-research.md

Ціль: визначити, чи існує Windows-драйвер, що вже надає T2 PCI enumeration, BAR
mapping, mailbox access, DMA, або keeps-alive interface, придатний для повторного
використання замість нового `T2TouchIdTransport.sys`.

Метод: пошук GitHub + прямий перегляд README трьох названих у ТЗ репозиторіїв
(виконано в Milestone 1, повторно підтверджено тут для Milestone 2 scope).

## Перевірені репозиторії

| Repository | Що робить | Рівень доступу до T2 | Дає PCI mailbox/SEP interface? |
|---|---|---|---|
| `imbushuo/mac-precision-touchpad` | Precision Touchpad HID driver для Apple трекпадів, включно з T2-приєднаним варіантом (SPI/T2-USB) | USB composite device (T2 виступає USB-хостом для трекпада через VHCI-подібний канал), KMDF для SPI/T2, UMDF для traditional USB | **НІ** — працює на рівні USB HID report, не торкається PCI BAR4/SEP mailbox |
| `imbushuo/DFRDisplayKm` | Touch Bar (DFR) дисплей | USB composite device (iBridge Display) | **НІ** — той самий рівень, USB, не PCI SEP |
| `t2linux/apple-bce-drv` | Linux (не Windows) BCE/VHCI/audio driver для T2 | PCI, але окрема функція — Buffer Copy Engine, не SEP endpoint 7 mailbox | **НІ** (і не Windows) — сам BCE це інший PCI-канал T2, ніж SEP mailbox з `t2_sep_transport.c` |

## Додатковий пошук

Запити "Apple T2 SEP Windows", "Apple T2 PCI driver Windows", "Apple T2 mailbox
Windows" не дали жодного публічного репозиторію, що реалізує PCI-доступ до SEP
endpoint 0/7 на Windows. Існує Apple Boot Camp driver pack (закритий, підписаний
Apple/Microsoft), який теоретично може містити щось подібне для внутрішніх
потреб Boot Camp (наприклад, T2 firmware update), але його бінарники не є
reverse-engineered чи документованими публічно, і використання/декомпіляція
чужого підписаного драйвера виходить за межі цього проєкту.

## Висновок (Section 2 gate)

**Готового Windows transport для SEP mailbox не існує.** Жоден із перевірених
проєктів не enumerates T2 PCI SEP function, не мапить BAR4, не звертається до
мейлбоксу і не обробляє DMA OOL buffers у сенсі, потрібному для Touch ID.

→ **Обрано Option A** (розділ 3 ТЗ): власний `T2TouchIdTransport.sys` з нуля,
за протоколом, повністю задокументованим у Milestone 1
(`docs/linux-reference-analysis.md`, розділ 3). Дублювання не відбувається,
бо дублювати нічого — це перша публічно відома реалізація цього шару на
Windows.

Корисне з проаналізованих проєктів (не код, а патерни):
`mac-precision-touchpad` підтверджує, що для T2-приєднаних периферій на
Windows 11 реально працює звичайна KMDF-модель (PCI/SPI resource enumeration
через `WdfFdoInitSetInterrupt`-подібні виклики, `WdfDeviceCreate` тощо) без
екзотичних обхідних рішень — це знижує архітектурний ризик Milestone 2.

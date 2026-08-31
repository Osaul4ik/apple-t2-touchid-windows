# windows-transport-design.md

## Рішення (evidence-driven, за результатами Section 2)

**Option A обрано**: власний `T2TouchIdTransport.sys`, KMDF, PCI + DMA
common buffer, оскільки жоден існуючий Windows-проєкт не надає SEP mailbox
доступ (`windows-transport-research.md`).

## Ключові design-рішення і їх пряме джерело

| Рішення | Джерело |
|---|---|
| BAR4, полінг замість IRQ, 5-сек timeout | VERIFIED FROM SOURCE, `t2_sep_transport.c` |
| Observation-only за замовчуванням (`IOCTL_T2_REGISTER_OOL` — явний opt-in) | Milestone 2 §5 вимога "не виконувати небезпечні/невідомі T2 commands" на старті |
| DMA: 44-bit mask, 2×16 KiB common buffers, 4 KiB alignment | VERIFIED FROM SOURCE; профіль WDF DMA enabler — **VERIFIED ON WINDOWS pending**, позначено в `dma.c` |
| Deregistration НЕ реалізована | Milestone 1: сам Linux-модуль її не реалізує; Milestone 2 §8 прямо забороняє вигадувати opcode |
| AKS allow-list enforced у kernel (не лише IOCTL contract) | Milestone 2 §25: "No generic arbitrary AKS opcode execution" — `T2AksOperationAllowed()` викликається і в `device.c`, і повторно всередині `akstore.c` |
| Один active exchange за раз (`WDFWAITLOCK`) | Milestone 2 §23 concurrency вимога |
| Retain (leak), не free, DMA-буфери після успішної SEP-реєстрації | Прямий перенос "pinning" властивості з Milestone 1, а не сліпе копіювання "cannot unload" висновку |


# EP7 transport: Windows ↔ Linux comparison

## Sequence (identical)

| Step | Linux `t2_sep_send` / `t2_aks_exchange_locked` | Windows |
|------|-----------------------------------------------|---------|
| 1 | `memset` OOL in/out | `RtlZeroMemory` |
| 2 | Build V2 header + body + digest | same |
| 3 | `word0 = ep7 \| op<<8 \| txn<<16` | same |
| 4 | `word1 = wireLen<<16`, word2=0, word3=0 | same |
| 5 | wait `!(OUTBOX_STATUS & FULL)` @ 0x10c | same |
| 6 | `writel` ×4 @ OUTBOX_DATA 0x820..0x82c, final word 0 last | same |
| 7 | poll `!(INBOX_STATUS & EMPTY)` @ 0x108 | same |
| 8 | `readl` ×4 @ INBOX_DATA 0x810..0x81c | same |

**No MMIO between SET_OOL and EP7 in Linux.** No kick/init/ack register.
Offsets/bits match (`INBOX_EMPTY` bit17, `OUTBOX_FULL` bit16).

## Evidence SEP *consumes* EP7 doorbells

Outbox status low 16 bits act as a sequence counter (observed on hardware):

```
EP0 SET_OOL_IN:  ... seq advances
EP0 SET_OOL_OUT: ... seq advances  
EP7 0x19:        ... seq advances by same stride
EP7 0x4d:        ... seq advances by same stride
```

After EP7 send, `full=0` immediately (SEP drained outbox) but `inbox empty=1` for 5s.

**Conclusion:** mailbox MMIO path is not missing a step. SEP accepts EP7 messages
the same way it accepts EP0, then does **not** post a reply. Failure is
**after** doorbell accept — most likely OOL DMA read failure or AKS endpoint
not runnable under this Windows SEP state — not a missing writel/readl.

## Ruled out (from prior runs)

- Missing bus-master / BAR4
- SystemPA ≠ Logical (IOMMU)
- WB cache without flush (readback OK)
- V2 packet / digest mismatch
- Opcode-specific body (0x4d and 0x19 both timeout)

## Minimal fix status

**No proven missing MMIO step to patch.** Next evidence must come from:
1. Linux on the same machine (does EP7 reply?)
2. Whether SEP can DMA-read OOL (e.g. known-pattern buffer + external observation)
3. bridgeOS / Apple driver interaction holding AKS endpoint

## New diagnostics in this patch

- `MMIO SEND ep=N pre/post outbox/inbox + seq_delta`
- 1s heartbeat during inbox wait (`MMIO WAIT`)

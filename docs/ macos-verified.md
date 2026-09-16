# macOS-verified BiometricKit status / command map

**Provenance.** Everything in this file comes from a macOS unified-log capture
taken on 16.09.2026 on the *same physical machine* that the Windows client
fails on: Intel MacBook Pro with Apple T2, bridgeOS build `23P5067` (the build
string the T2 itself reports in the BridgeXPC HELO of the Windows session),
uid 501, 3 enrolled identities. The capture covers ~4 minutes of live Touch ID
activity including **two successful unlocks**.

This matters because everything previously in `MatchResult.cpp` and
`Commands.cpp` came from `jmurth1234/t2-touchid-linux`, whose target firmware
is **not** the same build. Where the two disagree, the capture on the actual
target hardware wins.

Filter used:

```
log show --predicate 'process CONTAINS[c] "biometric" OR process CONTAINS[c] "sep"
  OR subsystem CONTAINS[c] "BiometricKit" OR subsystem CONTAINS[c] "com.apple.sep"
  OR composedMessage CONTAINS[c] "catacomb" OR composedMessage CONTAINS[c] "match"'
```

---

## 1. Event envelope framing (confirms what we already do)

The capture independently confirms the framing this project already
implements, including the byte offsets nothing had cross-checked before:

| field | offset in status-event `data` | evidence |
|---|---|---|
| sequence (u64) | 0 | |
| `embedded_type` (u32) | 8 | `serviceStatus:version:ordinal:data:timestamp: 0xe3ff8001` |
| version (u32) | 12 | `0x1` for status/statistics, `0x2` for match_result |
| ordinal / status_code (u64) | 24 | mac prints `0x5a` where our body decodes 90 |
| payload length (u64) | 32 | mac prints `36` where our body decodes 36 |
| payload | 40 | |

`kStatusEventHeaderBytes = 24` and `kStatusEventBodyFixedFieldsBytes = 16` are
therefore both correct as written.

Envelope versions observed: status `0xE3FF8001` v1, match_result `0xE3FF8002`
**v2**, statistics `0xE3FF8004` v1, SKS lock state `0xE3FF800A` v1.

A real match_result body on this hardware is **3228 bytes** of extracted
message data, i.e. 3244 bytes of `eventData` at our layer — comfortably above
`kMinMatchResultEventBytes` (0xC70 = 3184). That floor is fine.

## 2. Status ordinals (`0xE3FF8001`) — Apple's own names

From `-[BiometricKitDStatistics statusMessage:]`, which prints the symbolic
name next to the ordinal:

| ordinal | Apple name |
|---|---|
| 53 | ImageQueueIsEmpty |
| 55 | ImageCaptured |
| 63 | FingerOn |
| 64 | FingerOff |
| 72 | ImageForProcessing |
| 73 | TemplateListUpdated |
| 74 | RequestFingerOff |
| 80 | MatchingCancelled |
| 89 | SensorOperationModeIdle |
| 90 | SensorOperationModeCapture |
| 91 | SensorOperationModePause |
| 95 | ImageWasAccepted |

### Reference sequence of a SUCCESSFUL unlock

```
80 MatchingCancelled
89 SensorOperationModeIdle
90 SensorOperationModeCapture     <- sensor armed
63 FingerOn                       <- finger down
55 ImageCaptured                  <- THE SCAN
72 ImageForProcessing
95 ImageWasAccepted   (238B payload)
91 SensorOperationModePause
64 FingerOff
90 SensorOperationModeCapture
63 FingerOn
   >>> 0xE3FF8002 match_result, 3228B  <<<
74 RequestFingerOff
53 ImageQueueIsEmpty
91 SensorOperationModePause
73 TemplateListUpdated (3202B — adaptive template update)
80 MatchingCancelled
64 FingerOff
```

### What the failing Windows session produces instead

```
90 SensorOperationModeCapture
   statistics type 4, 35, 25
81 (not produced by macOS in any successful unlock)
63 FingerOn
91 SensorOperationModePause
78 (not produced by macOS in any successful unlock)
64 FingerOff
   statistics type 30
90 SensorOperationModeCapture
```

`55 / 72 / 95` never appear. The sensor detects the finger and the image never
reaches the matcher. Ordinals **78 and 81 do not occur in a successful macOS
unlock at all**, so `StatusCodeName()` deliberately leaves them unnamed — the
Linux enrollment table calling 81..84 a "no-op range" is contradicted by this
hardware.

## 3. `StartMatch` (cmd 4) payload size — the one hard contradiction

macOS, same machine, same 3 identities:

```
performCommand:version:inValue:inData:inSize:outData:outSize: 4 1 0 <ptr> 68
```

The inner payload of command 4 is **68 bytes total**. `68 == 8 + 3 * 20`.

This project was sending `MatchInitDataV1 (68) + uint32 count (4) + 3 * 20` =
**132 bytes**. The Linux-derived "68-byte options struct with 60 reserved
bytes" is almost certainly a misreading of a capture from a machine that also
had exactly three enrolled fingers: those 60 "reserved" bytes are the identity
array.

`MatchIdentityLayout::InlineIdentities` (new default) reproduces the 68-byte
form. `PaddedNoIdentities` is the other 68-byte reading (options only, no
identities) and is selectable for A/B — the capture cannot distinguish the two
by size alone. `LegacyCounted` reproduces the old 132-byte form.

## 4. Commands macOS actually issues on a live connection

Across the whole capture: `4, 12, 39, 40, 44, 46, 48, 56, 61, 62, 63, 74, 80,
84`.

**Never** `2` (ResetSensor) and **never** `0x20` (LoadCalibration). bridgeOS
calibrates the sensor during its own boot; macOS does not re-push an FDR blob
per match. Both are now opt-in (`--reset-sensor`, `--load-calibration`).

Named callers recovered from the capture, for future work:

| cmd | macOS caller |
|---|---|
| 4 | `startMatchOperation:` |
| 12 | `cancelWithClient:` |
| 39 | `performGetSKSLockStateCommand:` |
| 40 | `performGetBiometrickitdInfoCommand:` |
| 46 | `performGetProtectedConfigCommand:` |
| 48 | `getEnabledForUnlock` |
| 56 | `performGetCatacombUUIDCommand:` / `performConfirmSaveCatacombCommand:` |
| 61 (v2) | `performPrepareSaveCatacombCommand:` / `performGetCatacombHashCommand` |
| 62 (v2) | `performCompleteSaveCatacombCommand:` |
| 63 (v2) | `performConfirmSaveCatacombCommand:` |
| 74 | `performSaveBioLockoutRecordCommand:` |
| 80 | `performGetCatacombStateCommand:` / `performGetCatacombGroupStateCommand:` |

Note `56` is `CatacombUuid` in `Commands.h` — consistent. `0x3a`/`0x3c` are
used by this project as CatacombHash/CatacombState; in the capture the v2
catacomb hash/state opcodes are 61/80, so those two mappings remain unverified
against this firmware.

## 5. Statistics events (`0xE3FF8004`)

Body is **12 bytes**: `uint32 type` + `uint64 value`, where the value is
either an integer counter or the bit pattern of an IEEE-754 double depending
on the type. macOS prints both:

```
MesaCoreAnalytics statisticsMessage: type 21 fixed: 4637863191261478912 floating: 116.000000
MesaCoreAnalytics statisticsMessage: type 25 fixed: 3262 floating: 0.000000
```

Types observed on macOS during a successful unlock: `0, 1, 2, 3, 4, 7, 9, 11,
21, 25, 26, 27, 28, 29, 30, 32, 33, 34, 35, 36`. Types **0, 1 and 2 are
doubles in the 0.02–0.14 range** — image-quality scores that only ever appear
once an image has been processed.

Types observed in the failing Windows session: `4, 25, 30, 35` only. No 0/1/2.
Independent confirmation that no image ever reached the matcher.

## 6. Identity list

The `0x42` reply is `N * 20` bytes of `uint32 userId + 16-byte uuid` — the
Windows session parses 3 identities correctly, and the UUID macOS reports on a
successful match (`D6AE7EAA-…`) is the second record in that same list. The
identity path is **not** the problem: the templates are there and reachable.

## 7. Second hardware capture — the payload-size fix, tested and ruled out as sole cause

**16.09.2026, second capture.** Ran `t2touchid verify -v` again on the same
Windows machine after shipping the section-3 fix (`MatchIdentityLayout::
InlineIdentities`, 68-byte `StartMatch` payload) and disabling `ResetSensor`
and `LoadCalibration` by default (both confirmed opt-in in the log:
`skipping ResetSensor ... skipping LoadCalibration ...`). The command line
itself confirms the fix landed correctly on the wire:

```
[verify] start match: layout=inline payload=68B (macOS reference for 3 identities = 68B)
[sendBiometricCommand] -> ... inner=76B (424d040001000000...)   ; 8 header + 68 payload
```

**Result: bit-identical failure shape to the pre-fix capture.** Two full
finger-touch cycles, same status-code sequence both times, same statistics
types, zero image-pipeline events either time:

```
81 (unnamed)  -> 63 FingerOn -> 91 Pause -> [~1.5s] -> 78 (unnamed) -> 64 FingerOff -> stat(30)
81 (unnamed)  -> 63 FingerOn -> 91 Pause -> [~1.5s] -> 78 (unnamed) -> 64 FingerOff -> stat(30)
```

Statistics observed per cycle, in order: `type=4 value=1`, `type=35 value=1`,
`type=25 value=<growing>` (2646 then 7207 — tracks elapsed ms since session
start, not a quality score), then after FingerOff `type=30 value=<growing>`
(4477 then 8686). None of 0/1/2 (the quality-score types) ever appear, same
as the first capture.

**Conclusion: the StartMatch payload content/size is not what gates image
capture.** The fix in section 3 is still correct (it matches what macOS puts
on the wire) and stays in place, but it is not — by itself — the fix for this
symptom. Whatever decides "does the sensor hand a captured image to the
matcher" is evidently independent of what's inside the `StartMatch` blob.

### Updated read of ordinals 81 and 78

Both captures now agree: `81` fires once per cycle, consistently *before*
`63 FingerOn` even arrives (at +3197ms here, finger touch logged at
+3280ms) — i.e. it is not a finger-presence-derived signal, it looks
autonomous/sensor-initiated. `78` fires once per cycle, consistently *after*
`91 Pause` and well before `64 FingerOff` (≈1.5s gap both times). Neither
ordinal appears anywhere in the macOS reference capture's two successful
unlocks. Still not naming these — no source for what they mean — but the
consistency across two independent hardware runs makes "sensor-side
retry/rejection loop, unrelated to which bytes we put in StartMatch" a much
better-supported reading than before.

### Why LoadCalibration is now the leading candidate

The macOS *live* capture (section 4) never re-issues `LoadCalibration`
per match — but that only proves biometrickitd doesn't need to. On macOS,
whatever calibrates the sensor for TouchID plausibly happens once, earlier,
as part of the OS's own boot sequence — a step this project has no unified-log
visibility into, because by the time biometrickitd starts talking over
BridgeXPC on macOS, that step (if it exists) has already run. A Boot Camp
Windows boot that never boots macOS in the same power cycle may skip
whatever that step is, leaving the sensor perpetually "armed but
uncalibrated" — consistent with a sensor that reports finger presence
(mechanical/capacitive detection, likely handled by hardware regardless of
calibration) but never produces a usable image (which needs the calibration
blob). This is a hypothesis, not a verified fact — recorded here as the
reasoning behind reordering the CLI's suggested next step, not as a new
"VERIFIED FROM SOURCE" claim.

**Next diagnostic step:** `t2touchid verify -v --load-calibration`, then, if
that also fails, `--match-layout padded` to rule out the other 68-byte
reading of the StartMatch header.
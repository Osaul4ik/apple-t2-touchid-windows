# Milestone 2B — Windows-native PnP / Power / DMA lifecycle hardening

Status: source changes complete, **not hardware-validated** (same constraint
as Milestone 2 — no physical MacBook/WDK build environment available here).
Build/static-analysis/Driver Verifier checks from §13 of the milestone brief
have NOT been run; they require an actual WDK toolchain.

## What changed

### `driver/T2TouchIdTransport/driver.h`
- New `T2_TRANSPORT_STATE` enum (`NotInitialized`, `HardwareReady`,
  `RegisteringOol`, `Ready`, `Stopping`, `Invalid`) replacing the ad hoc
  boolean flags as the source of truth for whether AKS exchange/OOL
  registration may proceed. Full transition table documented inline.
- `State` field added to `T2_DEVICE_CONTEXT`, guarded by the existing
  `ExchangeLock` — no new lock introduced (§2 "do not duplicate
  synchronization").
- `T2_SEP_TRANSACTION_DEADLINE_US` (15s) — overall wall-clock bound for a
  single control/AKS transaction's receive loop, independent of how many
  unrelated messages get skipped.

### `driver/T2TouchIdTransport/device.c`
- `T2SetTransportState()` — single logged choke point for all transitions.
- `T2EvtDeviceAdd`: registers `EvtIoStop` on the (already power-managed)
  default queue.
- `T2EvtIoStop`: acknowledges the stop (`WdfRequestStopAcknowledge(..,
  FALSE)`) and lets the owning handler complete the request itself once its
  mailbox transaction concludes (bounded by the transaction deadline above).
  Does not attempt to force-complete or abort an in-flight SEP transaction —
  whether that's even safe for this protocol is unknown, and forcing
  completion here would race the owning handler's own completion call.
- `T2EvtDevicePrepareHardware`: sets `HardwareReady`, or `Invalid` if this
  context already has OOL registered with SEP (retained-memory case from a
  prior release/prepare cycle on the same device object).
- `T2EvtDeviceReleaseHardware`: moves to `Stopping` first (under the lock,
  blocking new exchange/registration attempts), then to `Invalid` or
  `NotInitialized` depending on whether SEP-owned OOL memory is being
  retained — same "never free live SEP memory" behavior as before, now
  state-machine-driven and documented.
- `T2EvtDeviceD0Entry` / `T2EvtDeviceD0Exit`: D0Exit drops `Ready` back to
  `HardwareReady` before the power transition proceeds (and, because it
  acquires the same `ExchangeLock` an in-flight exchange holds for its
  entire duration, naturally blocks until that exchange finishes or times
  out — no separate "in-flight" tracking needed). D0Entry does a real
  mailbox liveness read and only resumes `Ready` if OOL was actually
  registered before the transition; never assumes SEP session state
  survived unverified.
- `IOCTL_T2_REGISTER_OOL` handler: state-gated instead of using a permanent
  `OolRegisterAttempted` flag. A clean failure (nothing reached SEP) returns
  to `HardwareReady` and is retryable; a partial failure (`SET_OOL_IN`
  succeeded, `SET_OOL_OUT` didn't) lands in `Invalid` and is deliberately
  **not** retryable, since SEP may already hold that OOL_IN address.
- `IOCTL_T2_AKS_EXCHANGE` handler: cheap pre-check outside the lock (avoids
  allocating scratch buffers for requests that will be rejected anyway),
  plus an authoritative `State == Ready` check taken atomically with the
  exchange itself under `ExchangeLock`.

### `driver/T2TouchIdTransport/dma.c`
- `T2DmaAllocateOolBuffers`: every failure path now calls
  `T2DmaFreeOolBuffers` before returning (previously could leak a
  `DmaEnabler` and/or `OolInBuffer` on a later failure in the same call).
- `T2DmaRegisterOolBuffers`: unchanged behavior, rationale expanded in
  comments — failures before SEP ever saw an address are fully recoverable
  (caller frees and retries); a `SET_OOL_IN` success followed by a
  `SET_OOL_OUT` failure is deliberately left un-freed and reported via
  `OolInRegistered` staying `TRUE`, which `device.c` uses to select the
  `Invalid` terminal state.

### `driver/T2TouchIdTransport/mailbox.c`
- Added `T2NowUs()` (monotonic, `KeQueryInterruptTime`-based).
- `T2SepControl` and `T2SepAksTransaction` both now bound their receive
  loops to `T2_SEP_TRANSACTION_DEADLINE_US` total, computing a shrinking
  per-poll timeout each iteration instead of re-arming a full
  `T2_SEP_TIMEOUT_US` (5s) wait for every one of up to
  `T2_SEP_MAX_SKIPPED_REPLIES` (32) skipped messages. No wire-protocol
  change — this only caps how long we keep polling for our own reply.

### `protocol/AppleKeyStore/Client.h` / `Client.cpp`
- Copy constructor/assignment deleted (the class owns a raw `HANDLE`; a
  copy would double-`CloseHandle`). Move construction/assignment added.
- `Open()` now closes any existing handle before opening a new one, so a
  repeated `Open()`/reconnect no longer leaks the previous handle.
- `Unlock()` now zeroizes the full `capacity()` of `req` and the caller's
  `secretUtf8` buffer, not just their `size()`, in case either vector's
  backing storage is larger than what was actually written.

### `protocol/BiometricKit/VerificationEngine.cpp`
- Added a `CancelGuard` RAII object constructed immediately after the
  `StartMatch` IPC call succeeds. Its destructor sends the cancel command
  (best-effort) unconditionally, so every exit path from that point on —
  malformed reply, device-rejected match, later transport error, timeout,
  or normal match/no-match completion — now triggers cleanup. Previously
  two early-return paths (malformed reply, rejected-by-device) skipped the
  cancel call entirely, since it only ran unconditionally after the event
  loop.

### Real-hardware verify session, 16.09.2026
- Captured a `--verbose` log of three back-to-back `verify` runs: connect/HELO/version negotiation, reset+cancel, FDR calibration load, identity list (3 enrolled identities returned), start-match accepted (status=0), then a ~10s event loop that received nothing but small (131-167B) async events, timed out every time, and reconnected for the next run - never a single match_result event (which needs >= 0xC70B).
- First hypothesis (later corrected below): docs/linux-reference-analysis.md section 6 point 6 documents, per the Linux project's README and not independently verified on this hardware, that BiometricKit verification cannot yield a real matching identity while the keybag/catacomb is unavailable.
- Correction after the person reported they HAD already run `unlock` (AKS load-keybag + set-system-keybag + change-lock-state) before this capture: “keybag” and “Catacomb” are two different SEP-side subsystems, not two names for the same thing. `unlock` only touches the AppleKeyStore keybag (the FileVault-style data-protection keybag, endpoint 7) - a protocol path the analysis doc itself (section 6 point 7) says is independent of BiometricKit verification, sharing only SEP state. Catacomb is BiometricKit's own SEP-side store of enrolled identity records; its name and query opcodes (0x38 uuid, 0x3a hash, 0x3c state) come from Apple's own BiometricSupport.framework (CatacombComponent.mm / CatacombStateCache.mm, per the Linux project's FINDINGS.md decompiled-source references), not from the AKS keybag machinery at all. Since IdentityList (0x42) in this same capture already returned 3 real records, the Catacomb clearly has data - so AKS-side unlock status was never the right thing to check here.
- Changes made in response, all diagnostic-only (no guessed protocol semantics):
  - `protocol/BiometricKit/Commands.h`: added `SksLockState = 0x27`, `CatacombUuid = 0x38`, `CatacombHash = 0x3a` (shapes already VERIFIED FROM SOURCE in the analysis doc and in the reference's own bridge-xpc-probe.py; `CatacombState = 0x3c` already existed). Byte-level meaning of any of these replies is NOT verified, so nothing interprets them.
  - `protocol/BiometricKit/VerificationEngine.cpp`: the event loop now `T2_LOG`s every non-match event it discards, naming it status/statistics/unknown by `embedded_type` and its body size, so a `--verbose` hardware run is legible instead of an opaque wall of “event acked” lines.
  - `tools/t2touchid/main.cpp` (`CmdVerify`): before the match window, queries SKS lock state (0x27) and Catacomb uuid/hash/state (0x38/0x3a/0x3c) and prints all four raw replies, each labeled as unverified-meaning.
- Still not understood: why the match window only ever sees small status/statistics events and no match_result, given identities are present and start-match is accepted. Next step on real hardware: compare the four raw diagnostic replies above across a run where the person deliberately does NOT touch the sensor versus one where they do, to see whether the Catacomb-state bytes change at all with finger presence - that would confirm the sensor is even being engaged, before looking further into MatchResult parsing (kMinMatchResultEventBytes/kEmbeddedTypeMatchResult) as an alternative explanation.

### Follow-up, 16.09.2026: no missing command found; matchWindow default was wrong
- Given a second `--verbose` capture of the same symptom plus a claim from another agent that a command was missing, did a full command-by-command diff of `VerificationEngine::Verify` against the reference's actual **runtime** verify path — not just the diagnostic probe's optional flags. Traced `t2-fprintd.py`'s `T2Backend.verify()` → `_run_probe()` to the exact subprocess argv it builds (`--initialize --reset-sensor --cancel-operation --load-calibration --identity-list --macos-user-id N --match-seconds N --stop-on-match-result`, plus `--match-finger-name`/`--resolve-any-finger-name` only when a specific finger is being resolved) and confirmed every command this project actually sends — reset(2)/cancel(0x0c)/load-calibration(0x20,v=3)/identity-list(0x42)/start-match(4), with the exact same version/value/outputCapacity defaults `biometric_command()` uses — has a byte-for-byte match on the reference side. Commands the reference defines but this project doesn't implement (0x40 load-catacomb-archive, 0x4b load-bio-lockout, 0x51 global-identity-list, 0x0F/0x41 capacity) are all gated behind flags `_run_probe()` never passes for an ordinary verify — they belong to enrollment/restore or named-finger resolution (a Catacomb-store layer this project's PoC scope excludes), not to a basic verify call. No missing command found; did not add any command without a cited call site in the reference's own runtime path, per the project's "no guessing undocumented protocol details" rule.
- Did find a real, previously-uncited discrepancy: `VerifyConfig::matchWindow` defaulted to `10` seconds with no source ever cited for that number, while `t2-fprintd.py`'s own `--match-seconds` argparse default is `20.0` and is never overridden by a normal `verify()` call. Both hardware captures to date (16.09.2026, this run and the earlier one) time out at almost exactly 10s elapsed — consistent with the Windows client cutting the match window, and sending its own Cancel, before SEP's normal per-session cycle would have run its course on real macOS. Fixed `protocol/BiometricKit/VerificationEngine.h`'s default to `20`, matching the cited source; documented in `docs/linux-reference-analysis.md`.
- This is flagged as a real fix, not a confirmed root cause: it does not by itself explain why zero match_result-shaped events (>= 0xC70B) appeared even in the first ~5.6s that *were* captured within the old 10s window, before the event stream went quiet. That part is still most consistent with no finger actually touching the sensor during either capture, but that has not been confirmed on hardware — the previous session's suggested next step (compare Catacomb-state diagnostic bytes across a deliberate no-touch run vs. an actual-touch run within the *new* 20s window) is still the right next hardware test.

### Follow-up, same day: person confirmed matchWindow wasn't it (already tried 30s); "macOS log shows an `image` event after finger-down, Windows doesn't"
- Widening the match window did not change the symptom (person had already tested with 30s). Re-focused on the person's new observation instead of the timing fix.
- Found in `enrollment_research/FINDINGS.md`'s "Raw service-envelope map" (VERIFIED FROM SOURCE — recovered from the matching daemon's own 16-entry dispatch jump table, not enrollment-scoped): this project only ever named 3 of the 16 possible `embedded_type` envelopes (`0xE3FF8001` status, `0xE3FF8002` match_result, `0xE3FF8004` statistics). The other 13 include `0xE3FF800F` "Accessory image-information message" and `0xE3FF8010` "Mesa hardware-pass report" — either is a plausible candidate for whatever the person's macOS log calls "image", but which one (or something else, e.g. logged by macOS at a layer entirely outside this BridgeXPC connection) is not yet confirmed — asked the person for the exact macOS log line/excerpt rather than guessing.
- Added all 16 envelope names to `Commands.h`/`EmbeddedTypeName()` (`MatchResult.h/.cpp`) so any of them appearing in a future capture is now logged by name instead of generic `unknown`, with a bounded hex dump (same `< kMinMatchResultEventBytes` safety bound already used for statistics) for any newly-named type whose body is small enough to be safe to print.
- Cross-checked both 16.09.2026 hardware captures against this full map: only `0xE3FF8001` and `0xE3FF8004` were ever actually received in either one — none of the other 14 types, `0xE3FF800F`/`0xE3FF8010` included, appeared on the wire at all. So this isn't "Windows fails to interpret an incoming image event" — no such event arrived during either capture.
- Separately found `enrollment_research/FINDINGS.md`'s "Enrollment event-flow conformance matrix", an ordinal (status_code) semantics table for `0xE3FF8001` — but it is decompiled from `BKEnrollOperation` (enrollment), not `BKMatchOperation` (verification), so it is explicitly **not verified for the verify path**. Added it anyway as a clearly-labeled `StatusOrdinalHypothesis()` (`MatchResult.cpp`), logged as `ordinal_hypothesis=HYPOTHESIS(enrollment-sourced): ...` — never used in any match/no-match decision. Applied to both captures' observed status_codes (90, 91, 81, 63, 78, 64) *if the hypothesis holds for verify too*: 63 = finger-present, 78 = rejected-capture (retry), 64 = finger-removed, 90/91/81 = no-op — i.e. finger presence is detected but every capture attempt is rejected before SEP would ever get to send an image/match-event/match-result. Not confirmed; flagged to the person as the new most-plausible lead, pending their macOS log excerpt to pin down the actual "image" envelope and pending independent confirmation that the enrollment ordinal table applies during verify at all.
### Follow-up, 17.09.2026: cross-checked StartMatch layout, stability gate, and HELO self-identification against the reference's real runtime path
- Independently re-derived (not just re-read) whether the current `MatchIdentityLayout::LegacyCounted` default (132B, flags=0) is actually right, since this doc's own 16.09.2026 entries leaned toward the 68-byte `InlineIdentities` alternative being the fix. Traced `bridge-xpc-probe.py`'s match_data construction (`struct.pack("<II60x", flags, uid) + selected_identities`, `--identity-blob-format` default `"counted"`, `--match-processed-flags` default `0`) and confirmed `T2Backend._run_probe()` passes neither flag, so the real production path builds exactly 68 (header) + 4 (count) + 3*20 (identities) = 132 bytes for 3 enrolled identities - byte-for-byte what this project already sends as `LegacyCounted`. The 68-byte macOS capture this doc cited earlier is therefore more consistent with the already-existing `PaddedNoIdentities` variant (no identity blob appended at all) than with a hypothetical 8-byte-header `InlineIdentities` layout. No code change: `LegacyCounted` stays the default, VERIFIED rather than assumed.
- Same cross-check for the 0x42->0x51->0x42->0x51 stability gate in `VerificationEngine::Verify()`: confirmed `t2-fprintd.py`'s real `VerifyStart` entrypoint (`verify_fprint()` -> `verify(resolve_any_finger=True)` whenever an \"any finger\" match is requested and the local projection is complete) does take this gate (`t2_fprint_match_gate.prepare_all`), and that `prepare_all()` returns the identities the FIRST 0x42 read unmodified (no reordering/filtering). Matches this project's existing comment and code exactly - no change.
- New finding, not previously in this doc: the raw 36-byte `status_data` body for status_code 81 is byte-for-byte identical to status_code 63 (FingerOn)'s body in the same capture, and 78's body is identical to 64 (FingerOff)'s. This closes the `StatusOrdinalHypothesis()` "78/81 might be a differently-numbered image-pipeline code on this firmware" possibility for good - they are duplicate reports of the same finger-contact event (likely a raw/debounced pair), not disguised ImageCaptured/ImageForProcessing events.
- Real finding: `Connection.cpp`'s `BuildClientHeloBody()` self-identified this client as `OSBuild:"Windows"`, `ProcessName:"t2touchid"` - the one field in the entire pre-StartMatch sequence that had never been diffed against the reference, because every other field/command/reply already matched. The real, working Linux client (`t2_bridge_wire.py send_helo()`, invoked with `ProcessName` hardcoded to `"t2-touchid-probe"` by `T2Backend._run_probe()`) sends `OSBuild:"Linux"`, `ProcessName:"t2-touchid-probe"`. Changed both literals to match the reference exactly (string-only change, zero wire-shape/parsing impact) on the chance that bridgeOS/SEP gates full image-pipeline mode on client self-identification rather than treating it as inert metadata. Not confirmed as root cause - next hardware capture will tell.
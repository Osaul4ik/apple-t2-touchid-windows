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
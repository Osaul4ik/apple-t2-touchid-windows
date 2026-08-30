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

## Not done / explicitly out of scope here

- No WDK toolchain available in this environment, so none of §13's checks
  (`/W4 /WX` build, PREfast/CodeQL, Driver Verifier, the lifecycle test
  matrix) have actually been run. Basic brace/paren balance and a manual
  read-through were done instead; a real build is still required before
  this is trustworthy.
- `akstore.c` was reviewed against the new state machine and needs no
  changes — it only touches `Ctx->OolInVa`/`OolOutVa` and is only ever
  called by `device.c` after `State == Ready` has already been verified
  under the lock.
- No changes to the AKS/OOL wire protocol, mailbox message format, or
  KMDF→WDM architecture, per §12.
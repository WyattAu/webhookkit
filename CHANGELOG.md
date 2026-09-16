# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [2.1.0] - 2026-09-16

### Changed

- **`ReplayGuard` and `RedisReplayGuard` are re-expressed over
  [`idempotency-kit`](https://crates.io/crates/idempotency-kit) — the
  estate's single claim primitive — replacing webhookkit's private
  HashMap+Mutex bookkeeping. The public API is unchanged** (constructors,
  `check`/`remove`/`len`/`is_empty`/`capacity`/`expiry`,
  `DEFAULT_REPLAY_CAPACITY`, `WebhookError` variants), and the full unit,
  integration, and Redis (testcontainers) suites pass without
  modification: the proof of equivalence.
  - Fail-closed capacity semantics are now inherited from
    `idempotency-kit`'s memory store (`StoreError::CapacityExceeded` →
    `WebhookError::ReplayGuardFull`), with the same sweep cadence as
    before: every 1,024 inserts, forced at capacity. webhookkit no longer
    owns TTL-sweep or capacity code.
  - Claim mapping: `Claim::First` → `Ok(())`; `Claim::InFlight` and
    `Claim::Replay(_)` → `ReplayDetected`. An unfinished claim means the
    event was already accepted within the window — webhook dedup has no
    response-replay stage, so this differs from `idempotency-kit`'s
    executor semantics (where `InFlight` is retryable).
  - The memory guard's expiry window is now measured from the first
    claim of an event ID, matching the Redis guard's `SET NX EX`
    behavior (2.0.0's memory guard re-armed the window on duplicate
    checks). An internal unification; not observable through the API.
  - `RedisReplayGuard` keys are now `idempotency-kit:webhook:{blake3}`
    (BLAKE3 of the event ID) instead of `webhookkit:replay:{event_id}`:
    raw event IDs no longer appear in Redis, and webhook dedup state
    interoperates with `idempotency-kit::RedisStore` under the `webhook`
    scope. 2.0.0 Redis state is not migrated — event IDs seen in the
    final window of a 2.0.0 deployment may be delivered once more after
    upgrading.
  - Public auto-trait surface is preserved: the guard is still
    `RefUnwindSafe` (explicitly re-asserted over the new store
    internals, with the soundness rationale documented at the impl).
  - New optional dependency `idempotency-kit = "0.1"` (memory store under
    `std`, Redis store under `redis`). The `redis` feature keeps
    webhookkit's own `redis` 0.27 dependency for the `ConnectionManager`
    constructor parameter; the version is aligned with idempotency-kit's,
    so one `redis` is compiled into the graph.

## [2.0.0] - 2026-09-15

### Fixed (security)

- **`ReplayGuard` no longer fails open at capacity.** The 1.1.0 guard
  silently wiped every tracked event ID once the set exceeded 10,000
  entries, re-opening a replay window exactly under load. Entries are now
  tracked with insertion instants, expired entries are swept lazily
  (every 1024 inserts and whenever at capacity), and a guard that is full
  of still-fresh IDs fails **closed** with the new
  `WebhookError::ReplayGuardFull` instead of forgetting seen IDs.
- **Stripe signature verification accepts every `v1=` entry.** The parser
  collapsed duplicate `v1=` values into a map, so during signing-secret
  rotation (Stripe sends one `v1=` per active secret) legitimate webhooks
  were rejected. All `v1=` signatures are now tried and any match verifies.
- `WebhookError` is now `#[non_exhaustive]` ( breaking — matchers must add
  a wildcard arm).
- Removed incorrect `#[allow(dead_code)]` from used parser functions.

### Added

- `ReplayGuard::with_capacity(expiry, capacity)` and accessors
  `capacity()` / `expiry()`; default capacity 65,536.
- `verify_stripe_webhook_with_tolerance(body, sig, secret, tolerance_secs)`
  — configurable timestamp tolerance (default 300s via
  `verify_stripe_webhook`, now exposed as
  `DEFAULT_STRIPE_TOLERANCE_SECS`).
- Fuzz target `fuzz_stripe_signature` for the signature header parser.

## [1.1.2] - 2026-09-12

### Added

- Adversarial signature-verification integration suite
  (`tests/integration.rs`, 17 tests): forged signatures, tampered
  payloads and signatures (same-length flips), wrong-length signatures
  failing closed with the identical error (no length oracle),
  non-hex parse errors, Stripe header formats, expired/future timestamp
  rejection (the replay window), GoCardless round trip and rejections,
  `ReplayGuard` dedup/remove/capacity semantics, and the full
  verify-then-dedup pipeline rejecting replayed webhook deliveries.
- Distributed replay-guard suite (`tests/redis_replay.rs`, 6 tests)
  against a real Redis spun up per run with testcontainers: atomic
  `SET NX EX` claims across separate guard instances (shared worker
  state), first-claim-wins, distinct-id independence, window expiry
  re-admission, minimum-1s TTL enforcement, and the two-layer
  verify + dedup pipeline end to end.

### CI

- New `integration` job running the verification suite, the redis replay
  suite (testcontainers), and an `ffi` feature compile-check.

## [1.1.1] - 2026-09-09

### Fixed
- `RedisReplayGuard` is re-exported at the crate root and correctly
  gated behind the `redis` feature (the export previously leaked
  without the feature enabled, breaking `--no-default-features`
  builds).
- `build.rs` panics now carry context messages instead of failing
  silently; lint allowances added for the test suite under
  `-D warnings`.

## [1.1.0] - 2026-09-09

### Added
- `no_std` support: stateless HMAC-SHA256 verification, GoCardless
  verification/parsing, and the `ffi` surface build core-only with
  `--no-default-features` (thumbv7em-none-eabihf passes `cargo check`).
  New `std` feature (on by default — default builds are unchanged).

### Changed
- `timestamp`, `replay`, and `stripe` modules are gated behind the new
  `std` feature: they require a wall clock (`SystemTime`) and/or a std
  mutex, which have no `no_std` equivalent without a lock backend.
  Crypto/parsing dependencies (`hmac`, `sha2`, `hex`, `subtle`, `serde`,
  `serde_json`) now build without their std default features.

### Docs
- README and crate docs now lead with the differentiators (`no_std`
  verification core, `ReplayGuard`, Stripe/GoCardless parsers) and add a
  feature matrix vs `async-stripe` (full Stripe API — different scope) and
  `svix` (webhook sending — different direction), with honest notes on
  where webhookkit lags.

## [1.0.0] - 2026-09-05

First stable release. The public API surface is now covered by semver
stability guarantees (verified with `cargo-semver-checks` on every release).

### Added

- C FFI tests exercising the full `ffi` module contract from Rust
  (valid → `1`, tampered → `0`, invalid hex / non-UTF-8 / null → `-1`,
  `webhookkit_version` returns the crate version) — no C toolchain required.
- `THREAT-MODEL.md`: STRIDE analysis with verifying-test citations.
- `SECURITY.md`: vulnerability disclosure policy and scope.

### Fixed

- `webhookkit_verify_hmac_sha256` now returns `0` for an invalid signature
  and `-1` only for errors, matching its documented contract and the
  generated `webhookkit.h` header (previously every failure returned `-1`).

### Changed

- 1.0.0 marks the API as stable: `verify_hmac_sha256`,
  `verify_stripe_webhook`, `verify_gocardless_webhook`, `verify_timestamp`,
  `ReplayGuard`, `WebhookError`, and the `ffi` module.

## [0.2.0] - 2026-09-04

### Added

- C FFI bindings (`ffi` feature): `webhookkit_verify_hmac_sha256` and
  `webhookkit_version` with standard C linkage for cross-language interop.
- Build-time generation of a C header (`webhookkit.h`) into `OUT_DIR` when
  the `ffi` feature is enabled.
- `#![deny(unsafe_code)]` at the crate level, with the `ffi` module as the
  single reviewed exception.
- Fuzz targets `fuzz_verify_hmac` and `fuzz_verify` (cargo-fuzz) asserting
  verification never panics on arbitrary input.

## [0.1.0] - 2026-08-30

### Added

- Initial release: HMAC-SHA256 signature verification with constant-time
  comparison (`verify_hmac_sha256`).
- Provider-specific webhook parsers: Stripe (`verify_stripe_webhook`, with
  300 s timestamp tolerance) and GoCardless (`verify_gocardless_webhook`).
- Timestamp freshness validation (`verify_timestamp`).
- Replay-attack prevention (`ReplayGuard`) with bounded memory.
- Property tests (proptest) for sign/verify roundtrips.

[Unreleased]: https://github.com/WyattAu/webhookkit/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/WyattAu/webhookkit/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/WyattAu/webhookkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WyattAu/webhookkit/releases/tag/v0.1.0

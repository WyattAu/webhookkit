# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

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

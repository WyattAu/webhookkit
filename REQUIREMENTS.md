# Requirements — webhookkit

Numbered, testable requirements. Every requirement maps to at least one named
test; every security-relevant test cites at least one requirement. Threat
IDs reference `THREAT-MODEL.md`.

Scope note: `webhookkit` provides webhook signature verification — HMAC-SHA256
sign/verify over raw payloads, Stripe and GoCardless parsers, timestamp
freshness validation, an in-process `ReplayGuard` (std), a `RedisReplayGuard`
(std + redis), and a panic-free C FFI surface (`ffi` feature). Core-only
builds work with `--no-default-features`.

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WK-001 | `verify_hmac_sha256(secret, payload, signature_hex)` accepts a correct hex signature and rejects wrong signatures, wrong secrets, and invalid/non-hex input | MUST |
| REQ-WK-002 | `verify_stripe_webhook(secret, payload, sig_header)` parses the `t=`/`v1=` signed-header scheme, re-derives the signing payload, and accepts only fresh, correctly signed events | MUST |
| REQ-WK-003 | `verify_gocardless_webhook(secret, body, signature)` verifies the hex HMAC of the raw body and parses the event JSON (`GoCardlessEvent`) | MUST |
| REQ-WK-004 | `verify_timestamp` accepts RFC 3339-ish timestamps within tolerance and rejects out-of-tolerance or malformed values | MUST |
| REQ-WK-005 | `ReplayGuard::new(expiry)` + `check(event_id)` admits an ID once within the expiry window, denies duplicates, prunes on capacity, and `remove` allows legitimate reuse | SHOULD |
| REQ-WK-006 | `RedisReplayGuard` (std + redis) provides the same once-only semantics with a shared async Redis connection | SHOULD |
| REQ-WK-007 | With the `ffi` feature, `webhookkit_verify_hmac_sha256` exposes the verifier over C ABI and returns `-1`/`0`/`1` verdicts; a generated C header is emitted | SHOULD |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WK-100 | Forged signatures are never accepted: verification recomputes HMAC over the exact provider canonical payload (Stripe: `t + "." + body`), not over caller-supplied strings (T2) | MUST |
| REQ-WK-101 | Replay protection: `ReplayGuard` denies a second `check` of the same event ID inside the window; the Stripe path additionally enforces timestamp freshness (T3) | MUST |
| REQ-WK-102 | Signature comparison is constant-time via the RustCrypto `hmac` crate — no caller-configurable comparison path exists (T5) | MUST |
| REQ-WK-103 | Secret material is never stored in `Debug`/`Display` output or logged; secrets are consumed by reference | MUST |
| REQ-WK-104 | No panic on malformed input: hostile JSON, truncated headers, non-UTF-8 payloads, and deep nesting produce typed `WebhookError`s (T1, T7) | MUST |
| REQ-WK-105 | FFI boundary rejects null pointers and non-UTF-8/invalid inputs with `-1` and never dereferences invalid memory (T6) | MUST |

## Robustness

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WK-200 | Missing Stripe header fields (`t=`, `v1=`) fail with a typed error rather than panicking | MUST |
| REQ-WK-201 | Core-only builds (`no_std` + alloc) compile and verify HMACs without `std`; guards are feature-gated, not hardcoded | SHOULD |
| REQ-WK-202 | Error enum implements `Display` and `std::error::Error` | SHOULD |

## Traceability Matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-WK-001 | `verify_hmac_sha256_known_vector`, `verify_hmac_sha256_wrong_signature`, `verify_hmac_sha256_wrong_secret`, `verify_hmac_sha256_invalid_hex`, `verify_wrong_message_fails`, `verify_wrong_secret_fails` (`src/lib.rs`) | unit |
| REQ-WK-002 | `verify_stripe_webhook_valid`, `verify_stripe_webhook_wrong_secret`, `verify_stripe_webhook_missing_fields` (`src/stripe.rs`) | unit |
| REQ-WK-003 | `verify_gocardless_webhook_valid`, `verify_gocardless_webhook_wrong_sig`, `verify_gocardless_webhook_missing_hex` (`src/gocardless.rs`) | unit |
| REQ-WK-004 | `verify_timestamp_within_tolerance`, `verify_timestamp_outside_tolerance`, `verify_timestamp_invalid_format` (`src/timestamp.rs`) | unit |
| REQ-WK-005 | `replay_guard_first_call_allowed`, `replay_guard_duplicate_denied`, `replay_guard_multiple_ids`, `replay_guard_prunes_when_capacity_exceeded`, `replay_guard_remove_allows_reuse` (`src/replay.rs`) | unit |
| REQ-WK-006 | `RedisReplayGuard` doc-tested async path (`src/replay.rs`, `redis` feature) | unit/integration |
| REQ-WK-007 | `ffi_valid_signature_returns_one`, `ffi_tampered_payload_returns_zero`, `ffi_wrong_length_hex_signature_returns_zero`, `ffi_version_returns_cargo_pkg_version` (`src/ffi.rs`) | unit |
| REQ-WK-100 | `verify_stripe_webhook_wrong_secret`, `verify_hmac_sha256_wrong_signature`, `verify_gocardless_webhook_wrong_sig` | unit |
| REQ-WK-101 | `replay_guard_duplicate_denied`, `verify_timestamp_outside_tolerance` | unit |
| REQ-WK-102 | `hmac_sign_verify_roundtrip` (`src/lib.rs`); design review: comparison delegated to `hmac::verify` | unit/design |
| REQ-WK-103 | Design review of API surface (secrets by reference; no `Debug` on secret-bearing types) | design |
| REQ-WK-104 | `verify_stripe_webhook_missing_fields`, `verify_gocardless_webhook_missing_hex`, `verify_hmac_sha256_invalid_hex` | unit |
| REQ-WK-105 | `ffi_null_pointers_return_minus_one`, `ffi_non_utf8_payload_returns_minus_one`, `ffi_non_utf8_secret_returns_minus_one`, `ffi_non_utf8_signature_returns_minus_one`, `ffi_invalid_hex_signature_returns_minus_one` (`src/ffi.rs`) | unit |
| REQ-WK-200 | `verify_stripe_webhook_missing_fields` (`src/stripe.rs`) | unit |
| REQ-WK-201 | `cargo build --no-default-features` gate; core-only verification via `verify_hmac_sha256_known_vector` | build/unit |
| REQ-WK-202 | `webhook_error_display` (`src/error.rs`) | unit |

## Test Count

- 31 `#[test]` functions across unit and FFI suites.
- All-features suite passes with 0 failures; no-default-features suite passes.

# Threat Model — webhookkit

Reference: STRIDE. Scope: the crate's public API surface as used by a
downstream service. Trust boundaries: (1) bytes/strings entering public parse
or verify functions (`verify_hmac_sha256`, `verify_stripe_webhook`,
`verify_gocardless_webhook`, `verify_timestamp`, `ReplayGuard::check`),
(2) the C ABI surface (`webhookkit_verify_hmac_sha256`,
`webhookkit_version`, `ffi` feature), (3) concurrent callers sharing one
`ReplayGuard`, (4) the dependency tree (rustcrypto `hmac`/`sha2`/`subtle`,
`serde_json`, `hex`).

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | Accepted forged webhook (spoofed request executed as genuine) | Attacker POSTs a fake `payment_intent.succeeded` to the consumer's webhook endpoint |
| A2 | Replay of a previously-valid webhook | Captured legitimate delivery re-sent to double-trigger fulfilment |
| A3 | DoS of the caller via panic or unbounded memory | Adversarial payload aborts the worker or grows the replay set without bound |
| A4 | Webhook signing secret leakage through this crate | Secret exposed via `Debug` output, logs, or timing side channels |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | Panic on malformed input (DoS via abort) | DoS | all public fns | Errors are `Result`, never panic; FFI layer additionally validates null pointers and UTF-8 before any dereference and maps failures to `-1` return codes | fuzz harnesses `fuzz_verify_hmac` / `fuzz_verify` (arbitrary triples must be `Ok`/`Err`, never panic); `ffi_null_pointers_return_minus_one`, `ffi_non_utf8_payload_returns_minus_one` |
| T2 | Forged signature accepted | Spoofing | `verify_hmac_sha256`, `verify_stripe_webhook`, `verify_gocardless_webhook` | HMAC-SHA256 over the provider's canonical signed payload; comparison via `subtle::ConstantTimeEq` (timing-safe); length mismatch rejected before compare | `verify_hmac_sha256_wrong_signature`, `verify_hmac_sha256_wrong_secret`, `verify_stripe_webhook_wrong_secret`, `verify_gocardless_webhook_wrong_sig`; properties `verify_wrong_secret_fails`, `verify_wrong_message_fails` |
| T3 | Replay of previously-valid input | Replay | `ReplayGuard::check`; Stripe path freshness | `ReplayGuard` denies duplicate event IDs (`Err(ReplayDetected)`); Stripe verification enforces a 300 s timestamp tolerance so stale signed payloads fail before HMAC is even compared; set is pruned past 10 000 entries to bound memory | `replay_guard_duplicate_denied`, `replay_guard_prunes_when_capacity_exceeded`, `verify_timestamp_outside_tolerance` |
| T4 | Secret material leaked via `Debug`/`Display`/logs | Info disclosure | API surface | The crate never stores secrets: `verify_*` take `&[u8]`/`&str` by reference and retain no copies; no `Debug`/`Display` impls render inputs; FFI copies exist only for the call duration | Code review; no secret-typed structs exist (API surface audit, 1.0.0) |
| T5 | Caller-downgrade to weak/broken comparison | Elevation | internal compare path | Comparison is not caller-configurable: `ct_eq` is hard-wired in `verify_hmac_sha256`; no feature flag or option can substitute a non-constant-time path | `verify_hmac_sha256_known_vector` pins the rustcrypto HMAC-SHA256 path; `hmac_sign_verify_roundtrip` property |
| T6 | Malformed C-ABI input corrupts memory / UB | Spoofing/DoS | `webhookkit_verify_hmac_sha256` | Null pointers rejected before dereference; all three buffers validated as UTF-8 with caller-supplied lengths (no NUL-termination assumed); error codes: `1` valid, `0` invalid signature, `-1` error | `ffi_null_pointers_return_minus_one`, `ffi_invalid_hex_signature_returns_minus_one`, `ffi_tampered_payload_returns_zero`, `ffi_valid_signature_returns_one` |
| T7 | JSON parsing surprises (deep nesting, unexpected types) | Tampering/DoS | `verify_stripe_webhook`, `verify_gocardless_webhook` | `serde_json` rejects malformed input with `Err(ParseError)`; missing fields degrade to `"unknown"` rather than panicking; signature verification runs before JSON parsing, so unauthenticated bodies are dropped first | `verify_stripe_webhook_missing_fields`, `verify_gocardless_webhook_missing_hex`; `fuzz_verify` covers adversarial header/body combinations |

## Cryptographic assumptions

- HMAC-SHA256, key derivation, and constant-time equality come from the
  maintained rustcrypto stack (`hmac` 0.12, `sha2` 0.10, `subtle` 2). This
  crate adds no custom cryptography.
- Timing-safety holds for the *comparison*; the FFI boundary additionally
  performs UTF-8 validation which is input-length-dependent but not
  secret-dependent (secret bytes are only ever read inside the HMAC).

## Out of Scope

- Caller-side secret storage: how the consumer stores and loads the webhook
  signing secret (env vars, secret managers, zeroization upstream of the call)
  is outside this crate's control.
- Transport security: TLS termination, source-IP allowlisting, and rate
  limiting of the webhook endpoint belong to the calling service.
- Denial of service beyond documented limits: `ReplayGuard` pruning at
  10 000 entries trades strictness for bounded memory (cleared sets admit
  previously-seen IDs again until re-delivery); callers needing exact
  dedup beyond that window must persist IDs themselves.
- Replay protection is opt-in: `verify_stripe_webhook` enforces the
  timestamp window, but `ReplayGuard` must be instantiated and wired up by
  the caller. Forgetting to do so is a consumer-side gap.

## Residual Risks

- **R1 (Medium, accepted):** `ReplayGuard` clears its entire set when it
  exceeds 10 000 entries — an attacker who can cause >10 000 distinct event
  IDs within the expiry window can flush the guard and replay one older ID.
  Accepted because bounded memory prevents unbounded-growth DoS (A3); the
  300 s timestamp window on Stripe limits practical replay value. Mitigation
  for high-volume consumers: persist event IDs durably instead of relying on
  the in-memory guard.
- **R2 (Low, accepted):** The C ABI trusts caller-supplied `(ptr, len)`
  pairs. A non-null but invalid pointer is indistinguishable from valid
  memory — the null/UTF-8 guards catch the common C-binding mistakes, but
  dangling pointers remain the C caller's responsibility (documented in the
  `# Safety` contract).
- **R3 (Low, accepted):** Wall-clock dependence: `verify_timestamp` uses
  `SystemTime`. A caller with a badly skewed clock may reject legitimate
  webhooks (fail closed) or, if the clock is far behind, widen the effective
  replay window. NTP-disciplined hosts are assumed.
- **R4 (Low, accepted):** Dependency risk in `serde_json`/rustcrypto. No
  `cargo audit`/`cargo deny` gate runs in-repo yet (relies on the org-level
  Dependabot config); a transitive advisory would need a patch release.

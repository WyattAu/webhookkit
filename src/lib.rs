#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Webhook signature verification for Rust.
//!
//! webhookkit does one thing — **verify inbound webhook signatures** — with
//! three differentiators:
//!
//! - **A `no_std` verification core.** The stateless HMAC-SHA256 path
//!   ([`verify_hmac_sha256`], its signing counterpart [`sign_payload`],
//!   GoCardless parsing, the `ffi` surface) builds with
//!   `--no-default-features` on `core` + `alloc`, on top of RustCrypto
//!   `hmac`/`sha2` (both `no_std`); CI checks it against
//!   `thumbv7em-none-eabihf`.
//! - **Multi-provider support.** Signature formats for **Stripe**
//!   (`t=…,v1=…`) and **GoCardless** (`hex=…`) are parsed and verified for
//!   you, with constant-time comparison (`subtle`).
//! - **Replay protection.** [`ReplayGuard`] tracks processed event IDs with
//!   a TTL window, so at-least-once delivery doesn't mean double side
//!   effects — backed by [`idempotency-kit`](https://crates.io/crates/idempotency-kit)'s
//!   claim stores, the estate's single dedup primitive.
//!
//! It is not a Stripe SDK (see `async-stripe` for the full Stripe REST API)
//! and it does not send webhooks (see `svix` for outbound delivery) — it
//! sits strictly on the *consume-and-verify* side, including where those
//! crates can't run: embedded and FFI.
//!
//! Every verify path has a signing counterpart for tests and fixtures —
//! [`sign_payload`] (raw HMAC-SHA256, hex) and
//! [`sign_stripe_timestamped`] (the Stripe `v1=` value) — so consuming
//! hosts can build genuine signatures (faked provider deliveries, replay
//! suites) without duplicating the crypto stack in `[dev-dependencies]`.
//!
//! # no_std
//!
//! Stateless verification ([`verify_hmac_sha256`], GoCardless parsing, the
//! `ffi` surface) builds core-only with `--no-default-features`. The
//! `timestamp`, `replay`, and `stripe` modules require a wall clock / std
//! and are gated behind the `std` feature (on by default).
//!
//! # Quick Start
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # fn demo() -> Result<(), webhookkit::WebhookError> {
//! use webhookkit::{verify_hmac_sha256, verify_stripe_webhook, WebhookError};
//!
//! fn handle_stripe(payload: &str, sig_header: &str, secret: &str) -> Result<(), WebhookError> {
//!     let event = verify_stripe_webhook(payload, sig_header, secret)?;
//!     println!("event type: {}", event.event_type);
//!     Ok(())
//! }
//!
//! # Ok(())
//! # }
//! # fn main() {}
//! ```

mod error;
mod gocardless;

// Wall-clock / std-mutex-dependent surfaces.
#[cfg(feature = "std")]
mod replay;
#[cfg(feature = "std")]
mod stripe;
#[cfg(feature = "std")]
mod timestamp;

extern crate alloc;

/// C FFI bindings for cross-language interop.
///
/// When the `ffi` feature is enabled, a C header file (`webhookkit.h`) is
/// generated at build time in the crate's `OUT_DIR`. The header declares
/// [`ffi::webhookkit_verify_hmac_sha256`] and [`ffi::webhookkit_version`] with
/// standard C linkage.
///
/// To locate the header at build time:
///
/// ```sh
/// echo "$(cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "webhookkit") | .manifest_path' | xargs dirname)/target/debug/build/webhookkit-*/out/webhookkit.h"
/// ```
#[cfg(feature = "ffi")]
#[allow(unsafe_code)]
pub mod ffi;

pub use error::WebhookError;
pub use gocardless::{GoCardlessEvent, verify_gocardless_webhook};
#[cfg(all(feature = "std", feature = "redis"))]
pub use replay::RedisReplayGuard;
#[cfg(feature = "std")]
pub use replay::ReplayGuard;
#[cfg(feature = "std")]
pub use stripe::{StripeEvent, sign_stripe_timestamped, verify_stripe_webhook};
#[cfg(feature = "std")]
pub use timestamp::verify_timestamp;

use alloc::string::ToString;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Verify an HMAC-SHA256 signature against a payload and secret.
///
/// Uses `subtle::ConstantTimeEq` to prevent timing side-channels.
pub fn verify_hmac_sha256(
    payload: &[u8],
    secret: &[u8],
    expected_signature: &[u8],
) -> Result<(), WebhookError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| WebhookError::ParseError(e.to_string()))?;
    mac.update(payload);

    let signature_bytes =
        hex::decode(expected_signature).map_err(|e| WebhookError::ParseError(e.to_string()))?;

    let result = mac.finalize().into_bytes();

    if result.len() != signature_bytes.len() {
        return Err(WebhookError::InvalidSignature);
    }

    use subtle::ConstantTimeEq;
    if result.ct_eq(&signature_bytes).into() {
        Ok(())
    } else {
        Err(WebhookError::InvalidSignature)
    }
}

/// Compute the HMAC-SHA256 of `payload` under `secret` and return it as a
/// lowercase hex string — the signing counterpart of
/// [`verify_hmac_sha256`].
///
/// This is the primitive behind every signature scheme in the crate: a
/// signature is valid for exactly one `(payload, secret)` pair, so tests
/// and fixtures can produce genuine signatures for any provider format
/// without pulling `hmac`/`sha2` into `[dev-dependencies]` (Stripe's
/// timestamped variant is [`sign_stripe_timestamped`]).
///
/// # Examples
///
/// Sign and verify round-trip:
///
/// ```
/// use webhookkit::{sign_payload, verify_hmac_sha256};
///
/// let payload = br#"{"order":"created","amount":4200}"#;
/// let secret = b"whsec_test";
/// let signature = sign_payload(payload, secret);
/// assert!(verify_hmac_sha256(payload, secret, signature.as_bytes()).is_ok());
/// // Any other secret rejects it.
/// assert!(verify_hmac_sha256(payload, b"wrong", signature.as_bytes()).is_err());
/// ```
pub fn sign_payload(payload: &[u8], secret: &[u8]) -> alloc::string::String {
    // HMAC-SHA256 accepts keys of every length, so initialization cannot
    // fail; the scoped allow documents that invariant.
    #[allow(clippy::expect_used)]
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
// Test code: unwrap is the idiomatic way to assert outcomes.
#[allow(clippy::unwrap_used)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hmac_sign_verify_roundtrip(key in "\\PC{1,256}", message in "\\PC{1,256}") {
            let sig = sign_payload(message.as_bytes(), key.as_bytes());
            prop_assert!(verify_hmac_sha256(message.as_bytes(), key.as_bytes(), sig.as_bytes()).is_ok());
        }

        #[test]
        fn verify_wrong_secret_fails(key1 in "\\PC{1,256}", key2 in "\\PC{1,256}", message in "\\PC{1,256}") {
            prop_assume!(key1 != key2);
            let sig = sign_payload(message.as_bytes(), key1.as_bytes());
            prop_assert!(verify_hmac_sha256(message.as_bytes(), key2.as_bytes(), sig.as_bytes()).is_err());
        }

        #[test]
        fn verify_wrong_message_fails(key in "\\PC{1,256}", msg1 in "\\PC{1,256}", msg2 in "\\PC{1,256}") {
            prop_assume!(msg1 != msg2);
            let sig = sign_payload(msg1.as_bytes(), key.as_bytes());
            prop_assert!(verify_hmac_sha256(msg2.as_bytes(), key.as_bytes(), sig.as_bytes()).is_err());
        }
    }
}

#[cfg(all(test, feature = "std"))]
// Test code: unwrap is the idiomatic way to assert outcomes.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn verify_hmac_sha256_known_vector() {
        let payload = b"hello world";
        let secret = b"my-secret";
        let sig = sign_payload(payload, secret);
        assert!(verify_hmac_sha256(payload, secret, sig.as_bytes()).is_ok());
    }

    #[test]
    fn sign_payload_rfc4231_known_vector() {
        // RFC 4231 test case 2: key "Jefe",
        // data "what do ya want for nothing?".
        let sig = sign_payload(b"what do ya want for nothing?", b"Jefe");
        assert_eq!(
            sig,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn sign_payload_roundtrips_through_verify() {
        let payload = br#"{"order":"created","amount":4200}"#;
        let secret = b"whsec_live_9f8e7d6c";
        let signature = sign_payload(payload, secret);
        verify_hmac_sha256(payload, secret, signature.as_bytes()).unwrap();
        // The signature is bound to the exact (payload, secret) pair.
        assert!(verify_hmac_sha256(payload, b"whsec_other", signature.as_bytes()).is_err());
        assert!(verify_hmac_sha256(br#"{"amount":900}"#, secret, signature.as_bytes()).is_err());
    }

    #[test]
    fn sign_payload_is_lowercase_hex_of_32_bytes() {
        let sig = sign_payload(b"payload", b"secret");
        assert_eq!(sig.len(), 64);
        assert!(
            sig.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn verify_hmac_sha256_wrong_signature() {
        let payload = b"hello world";
        let secret = b"my-secret";
        let bad_sig = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(verify_hmac_sha256(payload, secret, bad_sig.as_bytes()).is_err());
    }

    #[test]
    fn verify_hmac_sha256_wrong_secret() {
        let payload = b"hello world";
        let secret1 = b"secret-one";
        let secret2 = b"secret-two";
        let sig = sign_payload(payload, secret1);
        assert!(verify_hmac_sha256(payload, secret2, sig.as_bytes()).is_err());
    }

    #[test]
    fn verify_hmac_sha256_invalid_hex() {
        let payload = b"test";
        let secret = b"key";
        assert!(verify_hmac_sha256(payload, secret, b"not-hex").is_err());
    }

    #[test]
    fn verify_stripe_webhook_valid() {
        let body = r#"{"type":"payment_intent.succeeded","id":"evt_123"}"#;
        let secret = "whsec_test_secret";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signed_payload = format!("{}.{}", now, body);
        let v1 = sign_payload(signed_payload.as_bytes(), secret.as_bytes());
        let sig_header = format!("t={},v1={}", now, v1);

        let event = verify_stripe_webhook(body, &sig_header, secret).unwrap();
        assert_eq!(event.event_type, "payment_intent.succeeded");
    }

    #[test]
    fn verify_stripe_webhook_wrong_secret() {
        let body = r#"{"type":"payment_intent.succeeded"}"#;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signed_payload = format!("{}.{}", now, body);
        let v1 = sign_payload(signed_payload.as_bytes(), b"wrong-secret");
        let sig_header = format!("t={},v1={}", now, v1);

        let result = verify_stripe_webhook(body, &sig_header, "correct-secret");
        assert!(result.is_err());
    }

    #[test]
    fn verify_stripe_webhook_missing_fields() {
        let result = verify_stripe_webhook("{}", "t=1000", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn verify_gocardless_webhook_valid() {
        let body = r#"{"resource_type":"payments","action":"created"}"#;
        let secret = "gc_secret";
        let hex_sig = sign_payload(body.as_bytes(), secret.as_bytes());
        let sig_header = format!("hex={}", hex_sig);

        let event = verify_gocardless_webhook(body, &sig_header, secret).unwrap();
        assert_eq!(event.resource_type, "payments");
        assert_eq!(event.action, "created");
    }

    #[test]
    fn verify_gocardless_webhook_wrong_sig() {
        let body = r#"{"resource_type":"payments","action":"created"}"#;
        let sig_header = "hex=deadbeef00000000000000000000000000000000000000000000000000000000";
        let result = verify_gocardless_webhook(body, sig_header, "gc_secret");
        assert!(result.is_err());
    }

    #[test]
    fn verify_gocardless_webhook_missing_hex() {
        let result = verify_gocardless_webhook("{}", "v1=fakesig", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn verify_timestamp_within_tolerance() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(verify_timestamp(&now.to_string(), 300).is_ok());
    }

    #[test]
    fn verify_timestamp_outside_tolerance() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old = now - 600;
        assert!(verify_timestamp(&old.to_string(), 300).is_err());
    }

    #[test]
    fn verify_timestamp_invalid_format() {
        assert!(verify_timestamp("not-a-number", 300).is_err());
    }

    #[test]
    fn replay_guard_first_call_allowed() {
        let guard = ReplayGuard::new(Duration::from_secs(300));
        assert!(guard.check("evt-1").is_ok());
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn replay_guard_duplicate_denied() {
        let guard = ReplayGuard::new(Duration::from_secs(300));
        assert!(guard.check("evt-1").is_ok());
        assert!(matches!(
            guard.check("evt-1"),
            Err(WebhookError::ReplayDetected)
        ));
    }

    #[test]
    fn replay_guard_remove_allows_reuse() {
        let guard = ReplayGuard::new(Duration::from_secs(300));
        assert!(guard.check("evt-1").is_ok());
        guard.remove("evt-1");
        assert!(guard.is_empty());
        assert!(guard.check("evt-1").is_ok());
    }

    #[test]
    fn replay_guard_multiple_ids() {
        let guard = ReplayGuard::new(Duration::from_secs(300));
        assert!(guard.check("a").is_ok());
        assert!(guard.check("b").is_ok());
        assert!(guard.check("c").is_ok());
        assert_eq!(guard.len(), 3);
        assert!(guard.check("a").is_err());
        assert!(guard.check("b").is_err());
        assert!(guard.check("d").is_ok());
    }

    #[test]
    fn replay_guard_fails_closed_at_capacity() {
        // Security regression: 1.1.0 silently wiped the whole set once it
        // exceeded 10,000 entries (replay window reopened under load).
        // The guard must now sweep expired entries and reject new claims
        // while every tracked ID is still fresh.
        let guard = ReplayGuard::with_capacity(Duration::from_secs(300), 128);
        for i in 0..128 {
            assert!(guard.check(&format!("evt-{i}")).is_ok());
        }
        assert_eq!(guard.len(), 128);
        // At capacity with all-fresh entries: reject, don't wipe.
        assert!(matches!(
            guard.check("evt-overflow"),
            Err(WebhookError::ReplayGuardFull)
        ));
        assert_eq!(guard.len(), 128);
        // Previously-seen IDs remain protected (no silent clear).
        assert!(matches!(
            guard.check("evt-0"),
            Err(WebhookError::ReplayDetected)
        ));
        assert_eq!(guard.len(), 128);
    }

    #[test]
    fn replay_guard_sweeps_expired_entries() {
        // Zero expiry ⇒ everything is immediately prunable; the forced
        // sweep at capacity must reclaim slots instead of filling up.
        let guard = ReplayGuard::with_capacity(Duration::ZERO, 4);
        for round in 0..8 {
            assert!(
                guard.check(&format!("evt-round{round}")).is_ok(),
                "round {round}: capacity should be reclaimed by sweeping"
            );
        }
    }

    #[test]
    fn webhook_error_display() {
        assert_eq!(
            WebhookError::InvalidSignature.to_string(),
            "invalid webhook signature"
        );
        assert_eq!(
            WebhookError::ExpiredTimestamp.to_string(),
            "webhook timestamp expired"
        );
        assert_eq!(
            WebhookError::ReplayDetected.to_string(),
            "replay attack detected"
        );
        assert_eq!(
            WebhookError::ParseError("bad input".into()).to_string(),
            "webhook parse error: bad input"
        );
    }
}

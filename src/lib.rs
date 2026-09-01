#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Webhook signature verification for Rust.
//!
//! Provides HMAC-SHA256 verification, timestamp validation, replay-attack
//! prevention, and provider-specific parsers for **Stripe** and
//! **GoCardless** webhooks.
//!
//! # Quick Start
//!
//! ```no_run
//! use webhookkit::{verify_hmac_sha256, verify_stripe_webhook, WebhookError};
//!
//! fn handle_stripe(payload: &str, sig_header: &str, secret: &str) -> Result<(), WebhookError> {
//!     let event = verify_stripe_webhook(payload, sig_header, secret)?;
//!     println!("event type: {}", event.event_type);
//!     Ok(())
//! }
//! ```

mod error;
mod gocardless;
mod replay;
mod stripe;
mod timestamp;

pub use error::WebhookError;
pub use gocardless::{GoCardlessEvent, verify_gocardless_webhook};
pub use replay::ReplayGuard;
pub use stripe::{StripeEvent, verify_stripe_webhook};
pub use timestamp::verify_timestamp;

use hmac::{Hmac, Mac};
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

    let signature_bytes = hex::decode(expected_signature)
        .map_err(|e| WebhookError::ParseError(e.to_string()))?;

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

/// Compute an HMAC-SHA256 signature and return it as a hex string.
/// Used in tests to generate valid signatures.
#[cfg(test)]
pub(crate) fn compute_hmac_sha256(payload: &[u8], secret: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hmac_sign_verify_roundtrip(key in "\\PC{1,256}", message in "\\PC{1,256}") {
            let sig = compute_hmac_sha256(message.as_bytes(), key.as_bytes());
            prop_assert!(verify_hmac_sha256(message.as_bytes(), key.as_bytes(), sig.as_bytes()).is_ok());
        }

        #[test]
        fn verify_wrong_secret_fails(key1 in "\\PC{1,256}", key2 in "\\PC{1,256}", message in "\\PC{1,256}") {
            prop_assume!(key1 != key2);
            let sig = compute_hmac_sha256(message.as_bytes(), key1.as_bytes());
            prop_assert!(verify_hmac_sha256(message.as_bytes(), key2.as_bytes(), sig.as_bytes()).is_err());
        }

        #[test]
        fn verify_wrong_message_fails(key in "\\PC{1,256}", msg1 in "\\PC{1,256}", msg2 in "\\PC{1,256}") {
            prop_assume!(msg1 != msg2);
            let sig = compute_hmac_sha256(msg1.as_bytes(), key.as_bytes());
            prop_assert!(verify_hmac_sha256(msg2.as_bytes(), key.as_bytes(), sig.as_bytes()).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::time::Duration;

    #[test]
    fn verify_hmac_sha256_known_vector() {
        let payload = b"hello world";
        let secret = b"my-secret";
        let sig = compute_hmac_sha256(payload, secret);
        assert!(verify_hmac_sha256(payload, secret, sig.as_bytes()).is_ok());
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
        let sig = compute_hmac_sha256(payload, secret1);
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
        let v1 = compute_hmac_sha256(signed_payload.as_bytes(), secret.as_bytes());
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
        let v1 = compute_hmac_sha256(signed_payload.as_bytes(), b"wrong-secret");
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
        let hex_sig = compute_hmac_sha256(body.as_bytes(), secret.as_bytes());
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
        assert!(matches!(guard.check("evt-1"), Err(WebhookError::ReplayDetected)));
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

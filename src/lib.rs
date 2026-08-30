#![forbid(unsafe_code)]
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
pub use gocardless::GoCardlessEvent;
pub use replay::ReplayGuard;
pub use stripe::StripeEvent;
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

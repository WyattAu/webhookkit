use alloc::string::{String, ToString};

use crate::verify_hmac_sha256;

/// Compute the Stripe-convention HMAC-SHA256 signature for an already
/// assembled signed payload, hex-encoded. The pure (alloc-only) primitive
/// under [`sign_stripe_style`].
#[must_use]
pub fn sign_hmac_sha256(signed_payload: &[u8], secret: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(signed_payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Sign an outbound webhook body in the Stripe `t=`/`v1=` header
/// convention. Returns `(signature_header, timestamp_header)`.
///
/// The signed payload is `{timestamp}.{body}`, so receivers verify with
/// [`crate::verify_stripe_webhook_with_tolerance`] without any new
/// receiver code. `now_secs` is caller-supplied: this module is
/// alloc-only and takes no clock.
#[must_use]
pub fn sign_stripe_style(body: &str, secret: &str, now_secs: u64) -> (String, String) {
    let timestamp = now_secs.to_string();
    let signed_payload = format!("{}.{}", timestamp, body);
    let signature = sign_hmac_sha256(signed_payload.as_bytes(), secret.as_bytes());
    (format!("t={timestamp},v1={signature}"), timestamp)
}

/// Sign with the current unix timestamp. Requires the `std` feature.
#[cfg(feature = "std")]
#[must_use]
pub fn sign_stripe_style_now(body: &str, secret: &str) -> (String, String) {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    sign_stripe_style(body, secret, now_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test";
    const BODY: &str = r#"{"event":"user.registered"}"#;

    #[test]
    fn signature_matches_manual_hmac() {
        let sig = sign_hmac_sha256(BODY.as_bytes(), SECRET.as_bytes());
        crate::verify_hmac_sha256(BODY.as_bytes(), SECRET.as_bytes(), sig.as_bytes())
            .expect("signature verifies against the raw payload");
    }

    #[test]
    fn round_trips_through_the_stripe_verifier() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs();
        let (header, timestamp) = sign_stripe_style(BODY, SECRET, now);
        let event = crate::verify_stripe_webhook(BODY, &header, SECRET)
            .expect("round-trip verifies");
        // Non-Stripe payloads carry event_type "unknown" (the verifier's
        // known-type table does not map them); the payload round-trips.
        assert_eq!(event.payload["event"], "user.registered");
        assert_eq!(timestamp, now.to_string());
    }

    #[test]
    fn tampered_body_is_refused() {
        let (header, _) = sign_stripe_style(BODY, SECRET, 1_700_000_000);
        let other = r#"{"event":"user.deleted"}"#;
        assert!(crate::verify_stripe_webhook(other, &header, SECRET).is_err());
    }
}

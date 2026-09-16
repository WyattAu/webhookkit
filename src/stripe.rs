use crate::{WebhookError, verify_hmac_sha256, verify_timestamp};

/// Default verification tolerance: 300 seconds, matching Stripe's docs.
pub const DEFAULT_STRIPE_TOLERANCE_SECS: u64 = 300;

/// A parsed Stripe webhook event.
#[derive(Debug, Clone)]
pub struct StripeEvent {
    /// The Stripe event type (e.g. `payment_intent.succeeded`).
    pub event_type: String,
    /// The raw JSON payload.
    pub payload: serde_json::Value,
}

/// Verify and parse a Stripe webhook request using the default 300-second
/// timestamp tolerance.
///
/// Expects `sig_header` to be the value of the `Stripe-Signature` header,
/// which contains `t=...,v1=...` pairs. When Stripe sends multiple `v1=`
/// signatures (secret rotation), **each** signature is tried and the
/// webhook is accepted if any one verifies — see
/// [`verify_stripe_webhook_with_tolerance`] for the variant with an
/// explicit tolerance.
pub fn verify_stripe_webhook(
    body: &str,
    sig_header: &str,
    secret: &str,
) -> Result<StripeEvent, WebhookError> {
    verify_stripe_webhook_with_tolerance(body, sig_header, secret, DEFAULT_STRIPE_TOLERANCE_SECS)
}

/// Like [`verify_stripe_webhook`], with an explicit timestamp tolerance in
/// seconds.
///
/// # Errors
///
/// - [`WebhookError::ParseError`] for malformed signature headers, a
///   missing `t=`/`v1=` component, or a non-JSON body.
/// - [`WebhookError::ExpiredTimestamp`] when the timestamp is outside
///   `tolerance_secs`.
/// - [`WebhookError::InvalidSignature`] when no `v1=` signature verifies.
pub fn verify_stripe_webhook_with_tolerance(
    body: &str,
    sig_header: &str,
    secret: &str,
    tolerance_secs: u64,
) -> Result<StripeEvent, WebhookError> {
    let (timestamp, v1_signatures) = parse_stripe_signature(sig_header)?;

    verify_timestamp(&timestamp, tolerance_secs)?;

    let signed_payload = format!("{}.{}", timestamp, body);
    let verified = v1_signatures.iter().any(|v1| {
        verify_hmac_sha256(signed_payload.as_bytes(), secret.as_bytes(), v1.as_bytes()).is_ok()
    });
    if !verified {
        return Err(WebhookError::InvalidSignature);
    }

    let payload: serde_json::Value =
        serde_json::from_str(body).map_err(|e| WebhookError::ParseError(e.to_string()))?;

    let event_type = payload
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    Ok(StripeEvent {
        event_type,
        payload,
    })
}

/// Parse a `Stripe-Signature` header into the timestamp and the ordered
/// list of `v1=` signatures.
///
/// Stripe may include multiple `v1=` entries when signing secrets are
/// rotated (each entry is made with one secret); the order is preserved so
/// every candidate is tried.
fn parse_stripe_signature(header: &str) -> Result<(String, Vec<String>), WebhookError> {
    let mut timestamp: Option<String> = None;
    let mut v1_signatures: Vec<String> = Vec::new();

    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut kv = part.splitn(2, '=');
        let key = kv
            .next()
            .ok_or_else(|| WebhookError::ParseError("empty signature part".into()))?
            .trim();
        let value = kv
            .next()
            .ok_or_else(|| WebhookError::ParseError(format!("missing value for {key}")))?
            .trim();
        match key {
            "t" => {
                if timestamp.is_none() {
                    timestamp = Some(value.to_string());
                }
            }
            "v1" => v1_signatures.push(value.to_string()),
            // Unknown scheme components (e.g. `v0=`, `ho=`) are ignored,
            // matching Stripe's guidance.
            _ => {}
        }
    }

    let timestamp = timestamp
        .ok_or_else(|| WebhookError::ParseError("missing timestamp in Stripe-Signature".into()))?;
    if v1_signatures.is_empty() {
        return Err(WebhookError::ParseError(
            "missing v1 signature in Stripe-Signature".into(),
        ));
    }
    Ok((timestamp, v1_signatures))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    fn sign(timestamp: &str, body: &str, secret: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
        mac.update(format!("{timestamp}.{body}").as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    const BODY: &str = r#"{"id":"evt_1","type":"payment_intent.succeeded"}"#;

    /// Current unix time: signature timestamps must be near `now` for the
    /// tolerance check to pass, so tests sign at `now` unless testing expiry.
    fn now_secs() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            .to_string()
    }

    #[test]
    fn single_signature_verifies() {
        let t = now_secs();
        let sig = sign(&t, BODY, "whsec_test");
        let event = verify_stripe_webhook_with_tolerance(
            BODY,
            &format!("t={t},v1={sig}"),
            "whsec_test",
            3600,
        )
        .expect("verify");
        assert_eq!(event.event_type, "payment_intent.succeeded");
    }

    #[test]
    fn rotated_secret_second_v1_verifies() {
        // Stripe sends one v1 per active signing secret; the request is
        // signed with the NEW secret while the receiver still knows both.
        let t = now_secs();
        let old_sig = sign(&t, BODY, "whsec_old");
        let new_sig = sign(&t, BODY, "whsec_new");
        let header = format!("t={t},v1={old_sig},v1={new_sig}");
        // The old single-v1 parser dropped `new_sig`; this must verify now.
        verify_stripe_webhook_with_tolerance(BODY, &header, "whsec_new", 3600)
            .expect("second v1 (rotated secret) must verify");
        // And vice versa: first v1 verifies against the old secret too.
        verify_stripe_webhook_with_tolerance(BODY, &header, "whsec_old", 3600)
            .expect("first v1 must verify");
    }

    #[test]
    fn none_of_the_v1_signatures_match() {
        let t = now_secs();
        let sig = sign(&t, BODY, "whsec_other");
        let err = verify_stripe_webhook_with_tolerance(
            BODY,
            &format!("t={t},v1={sig}"),
            "whsec_test",
            3600,
        )
        .expect_err("no matching signature");
        assert!(matches!(err, WebhookError::InvalidSignature));
    }

    #[test]
    fn tampered_body_rejected() {
        let t = now_secs();
        let sig = sign(&t, BODY, "whsec_test");
        let err = verify_stripe_webhook_with_tolerance(
            r#"{"id":"evt_1","type":"charge.refunded"}"#,
            &format!("t={t},v1={sig}"),
            "whsec_test",
            3600,
        )
        .expect_err("tampered body");
        assert!(matches!(err, WebhookError::InvalidSignature));
    }

    #[test]
    fn missing_v1_is_parse_error() {
        let err = verify_stripe_webhook_with_tolerance(BODY, "t=1700000000", "whsec_test", 3600)
            .expect_err("missing v1");
        assert!(matches!(err, WebhookError::ParseError(_)));
    }

    #[test]
    fn missing_timestamp_is_parse_error() {
        let sig = sign(&now_secs(), BODY, "whsec_test");
        let err =
            verify_stripe_webhook_with_tolerance(BODY, &format!("v1={sig}"), "whsec_test", 3600)
                .expect_err("missing t");
        assert!(matches!(err, WebhookError::ParseError(_)));
    }

    #[test]
    fn unknown_schemes_ignored_but_v1_still_required() {
        let t = now_secs();
        let sig = sign(&t, BODY, "whsec_test");
        let event = verify_stripe_webhook_with_tolerance(
            BODY,
            &format!("ho=host,t={t},v0=legacy,v1={sig}"),
            "whsec_test",
            3600,
        )
        .expect("unknown schemes ignored");
        assert_eq!(event.event_type, "payment_intent.succeeded");
    }

    #[test]
    fn tolerance_is_configurable() {
        // Timestamp 6 minutes in the past: rejected at 300s default,
        // accepted with a 600s tolerance.
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            - 360;
        let t = past.to_string();
        let sig = sign(&t, BODY, "whsec_test");
        let header = format!("t={t},v1={sig}");
        assert!(verify_stripe_webhook(BODY, &header, "whsec_test").is_err());
        verify_stripe_webhook_with_tolerance(BODY, &header, "whsec_test", 600)
            .expect("within 600s tolerance");
    }

    #[test]
    fn whitespace_and_empty_parts_tolerated() {
        let t = now_secs();
        let sig = sign(&t, BODY, "whsec_test");
        verify_stripe_webhook_with_tolerance(
            BODY,
            &format!("t={t}, , v1={sig},"),
            "whsec_test",
            3600,
        )
        .expect("blank parts skipped");
    }
}

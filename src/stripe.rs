use std::collections::HashMap;

use crate::{WebhookError, verify_hmac_sha256, verify_timestamp};

/// A parsed Stripe webhook event.
#[derive(Debug, Clone)]
pub struct StripeEvent {
    /// The Stripe event type (e.g. `payment_intent.succeeded`).
    pub event_type: String,
    /// The raw JSON payload.
    pub payload: serde_json::Value,
}

/// Verify and parse a Stripe webhook request.
///
/// Expects `sig_header` to be the value of the `Stripe-Signature` header,
/// which contains `t=...,v1=...` pairs.
pub fn verify_stripe_webhook(
    body: &str,
    sig_header: &str,
    secret: &str,
) -> Result<StripeEvent, WebhookError> {
    let parts = parse_stripe_signature(sig_header)?;

    let timestamp = parts
        .get("t")
        .ok_or_else(|| WebhookError::ParseError("missing timestamp in Stripe-Signature".into()))?;
    let v1 = parts.get("v1").ok_or_else(|| {
        WebhookError::ParseError("missing v1 signature in Stripe-Signature".into())
    })?;

    verify_timestamp(timestamp, 300)?;

    let signed_payload = format!("{}.{}", timestamp, body);
    verify_hmac_sha256(signed_payload.as_bytes(), secret.as_bytes(), v1.as_bytes())?;

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

#[allow(dead_code)]
fn parse_stripe_signature(header: &str) -> Result<HashMap<String, String>, WebhookError> {
    let mut map = HashMap::new();
    for part in header.split(',') {
        let mut kv = part.splitn(2, '=');
        let key = kv
            .next()
            .ok_or_else(|| WebhookError::ParseError("empty signature part".into()))?
            .trim();
        let value = kv
            .next()
            .ok_or_else(|| WebhookError::ParseError(format!("missing value for {}", key)))?
            .trim();
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}

use crate::{verify_hmac_sha256, WebhookError};

/// A parsed GoCardless webhook event.
#[derive(Debug, Clone)]
pub struct GoCardlessEvent {
    /// The event resource type (e.g. `payments`).
    pub resource_type: String,
    /// The action (e.g. `created`, `submitted`).
    pub action: String,
    /// The raw JSON payload.
    pub payload: serde_json::Value,
}

/// Verify and parse a GoCardless webhook request.
///
/// Expects `sig_header` to be the value of the `Webhook-Signature` header,
/// which contains `hex=...` pairs.
pub fn verify_gocardless_webhook(
    body: &str,
    sig_header: &str,
    secret: &str,
) -> Result<GoCardlessEvent, WebhookError> {
    let hex_sig = parse_gocardless_signature(sig_header)?;

    verify_hmac_sha256(body.as_bytes(), secret.as_bytes(), hex_sig.as_bytes())?;

    let payload: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| WebhookError::ParseError(e.to_string()))?;

    let resource_type = payload
        .get("resource_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let action = payload
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    Ok(GoCardlessEvent {
        resource_type,
        action,
        payload,
    })
}

#[allow(dead_code)]
fn parse_gocardless_signature(header: &str) -> Result<String, WebhookError> {
    for part in header.split(',') {
        let mut kv = part.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let value = kv.next().unwrap_or("").trim();
        if key == "hex" {
            return Ok(value.to_string());
        }
    }
    Err(WebhookError::ParseError(
        "missing hex signature in Webhook-Signature".into(),
    ))
}

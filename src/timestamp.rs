use std::time::{SystemTime, UNIX_EPOCH};

use crate::WebhookError;

/// Verify that a timestamp string is within `tolerance` seconds of now.
pub fn verify_timestamp(timestamp: &str, tolerance_secs: u64) -> Result<(), WebhookError> {
    let ts: u64 = timestamp
        .parse()
        .map_err(|e| WebhookError::ParseError(format!("invalid timestamp: {}", e)))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| WebhookError::ParseError(e.to_string()))?
        .as_secs();

    let diff = now.abs_diff(ts);
    if diff > tolerance_secs {
        return Err(WebhookError::ExpiredTimestamp);
    }

    Ok(())
}

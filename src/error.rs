/// Errors from webhook verification.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// The computed signature does not match the provided signature.
    #[error("invalid webhook signature")]
    InvalidSignature,

    /// The webhook timestamp is outside the acceptable tolerance window.
    #[error("webhook timestamp expired")]
    ExpiredTimestamp,

    /// The webhook event has already been processed (replay detected).
    #[error("replay attack detected")]
    ReplayDetected,

    /// Failed to parse the webhook payload or headers.
    #[error("webhook parse error: {0}")]
    ParseError(String),
}

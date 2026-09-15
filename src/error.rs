use alloc::string::String;

/// Errors from webhook verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

    /// The in-memory replay guard is at capacity and every tracked ID is
    /// still inside its expiry window. The guard fails **closed**: new
    /// claims are rejected rather than forgetting already-seen IDs.
    ///
    /// Remediate by scaling out (Redis-backed [`ReplayGuard`](crate::RedisReplayGuard)
    /// shares dedup state across instances) or raising the capacity.
    #[error("replay guard at capacity; all tracked IDs still within expiry")]
    ReplayGuardFull,

    /// Failed to parse the webhook payload or headers.
    #[error("webhook parse error: {0}")]
    ParseError(String),
}

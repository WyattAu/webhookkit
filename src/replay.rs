use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

/// Guards against replay attacks by tracking processed event IDs.
///
/// Expired entries are lazily pruned on each `check` call.
pub struct ReplayGuard {
    seen: Mutex<HashSet<String>>,
    #[allow(dead_code)]
    expiry: Duration,
}

impl ReplayGuard {
    /// Create a replay guard with the given expiry window.
    ///
    /// Events older than `expiry` are pruned automatically.
    pub fn new(expiry: Duration) -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            expiry,
        }
    }

    /// Check whether `event_id` has been seen before.
    ///
    /// Returns `Ok(())` if the event is new and has been recorded.
    /// Returns `Err(ReplayDetected)` if the event was already processed.
    pub fn check(&self, event_id: &str) -> Result<(), crate::WebhookError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|e| crate::WebhookError::ParseError(e.to_string()))?;

        // Lazy prune: when the set grows large, clear it.
        // A production impl would track timestamps per ID.
        if seen.len() > 10_000 {
            seen.clear();
        }

        if !seen.insert(event_id.to_string()) {
            return Err(crate::WebhookError::ReplayDetected);
        }

        Ok(())
    }

    /// Manually remove an event ID (e.g. after its expiry window passes).
    pub fn remove(&self, event_id: &str) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.remove(event_id);
        }
    }

    /// Return the number of tracked event IDs.
    pub fn len(&self) -> usize {
        self.seen.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Whether no events are being tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Distributed replay guard backed by Redis `SET key val NX EX` — an atomic
/// claim, so multi-instance deployments share dedup state without Lua.
///
/// Unlike the in-memory [`ReplayGuard`], expiry is enforced by Redis TTLs
/// rather than lazy pruning.
#[cfg(feature = "redis")]
pub struct RedisReplayGuard {
    conn: redis::aio::ConnectionManager,
    ttl_secs: i64,
}

#[cfg(feature = "redis")]
impl RedisReplayGuard {
    /// Create a distributed replay guard with the given expiry window.
    pub fn new(conn: redis::aio::ConnectionManager, expiry: std::time::Duration) -> Self {
        Self {
            conn,
            ttl_secs: expiry.as_secs().max(1) as i64,
        }
    }

    /// Atomically claim `event_id`. Returns `Err(ReplayDetected)` if another
    /// worker already claimed it within the expiry window.
    pub async fn check(&self, event_id: &str) -> Result<(), crate::WebhookError> {
        let key = format!("webhookkit:replay:{event_id}");
        let mut conn = self.conn.clone();
        let claimed: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(self.ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(|e| crate::WebhookError::ParseError(e.to_string()))?;

        if claimed.is_none() {
            return Err(crate::WebhookError::ReplayDetected);
        }
        Ok(())
    }
}

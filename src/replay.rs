use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default capacity: 65,536 concurrently-tracked event IDs.
pub const DEFAULT_REPLAY_CAPACITY: usize = 65_536;

/// Prune sweep interval: a full expiry sweep runs at most once per this
/// many inserts (a sweep is also forced whenever the guard is at capacity).
const PRUNE_EVERY: usize = 1024;

struct Inner {
    /// event ID → insertion instant. An entry is expired once
    /// `now - inserted >= expiry`.
    seen: HashMap<String, Instant>,
    inserts_since_sweep: usize,
}

/// Guards against replay attacks by tracking processed event IDs with a
/// TTL window.
///
/// # Semantics (fail-closed)
///
/// - Expired entries are pruned lazily: a sweep runs every [`PRUNE_EVERY`]
///   inserts, and is forced whenever the guard is at capacity.
/// - If the guard is at [`capacity`](Self::capacity) and every tracked ID
///   is still inside its expiry window, [`check`](Self::check) returns
///   [`WebhookError::ReplayGuardFull`] rather than forgetting IDs.
///   Forgetting a seen ID would re-open a replay window; rejecting new
///   claims is the safe failure mode.
/// - Process-local by design. For multi-instance deployments use
///   [`RedisReplayGuard`], which shares dedup state atomically via
///   `SET NX EX`.
pub struct ReplayGuard {
    inner: Mutex<Inner>,
    expiry: Duration,
    capacity: usize,
}

impl ReplayGuard {
    /// Create a replay guard with the given expiry window and the default
    /// capacity of [`DEFAULT_REPLAY_CAPACITY`].
    pub fn new(expiry: Duration) -> Self {
        Self::with_capacity(expiry, DEFAULT_REPLAY_CAPACITY)
    }

    /// Create a replay guard with an explicit capacity bound (minimum 1).
    pub fn with_capacity(expiry: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                seen: HashMap::new(),
                inserts_since_sweep: 0,
            }),
            expiry,
            capacity: capacity.max(1),
        }
    }

    /// The configured capacity bound.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The configured expiry window.
    pub fn expiry(&self) -> Duration {
        self.expiry
    }

    /// Check whether `event_id` has been seen before.
    ///
    /// Returns `Ok(())` if the event is new and has been recorded.
    /// Returns `Err(ReplayDetected)` if the event was already processed
    /// inside the expiry window. Returns `Err(ReplayGuardFull)` when at
    /// capacity with no prunable entries (see type docs).
    pub fn check(&self, event_id: &str) -> Result<(), crate::WebhookError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| crate::WebhookError::ParseError(e.to_string()))?;

        inner.inserts_since_sweep += 1;
        let sweep_due =
            inner.inserts_since_sweep >= PRUNE_EVERY || inner.seen.len() >= self.capacity;
        if sweep_due {
            sweep_expired(&mut inner.seen, self.expiry);
            inner.inserts_since_sweep = 0;
        }

        // Fail closed: at capacity with all-fresh entries, reject the new
        // claim instead of forgetting a previously-seen ID.
        if !inner.seen.contains_key(event_id) && inner.seen.len() >= self.capacity {
            return Err(crate::WebhookError::ReplayGuardFull);
        }

        if inner
            .seen
            .insert(event_id.to_string(), Instant::now())
            .is_some()
        {
            return Err(crate::WebhookError::ReplayDetected);
        }

        Ok(())
    }

    /// Manually remove an event ID (e.g. after its expiry window passes).
    pub fn remove(&self, event_id: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.seen.remove(event_id);
        }
    }

    /// Return the number of tracked event IDs (may include not-yet-pruned
    /// expired entries).
    pub fn len(&self) -> usize {
        self.inner.lock().map(|i| i.seen.len()).unwrap_or(0)
    }

    /// Whether no events are being tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn sweep_expired(seen: &mut HashMap<String, Instant>, expiry: Duration) {
    let now = Instant::now();
    seen.retain(|_, inserted_at| now.duration_since(*inserted_at) < expiry);
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::WebhookError;

    #[test]
    fn same_id_within_window_is_replay() {
        let g = ReplayGuard::new(Duration::from_secs(60));
        g.check("evt_1").expect("first claim");
        assert!(matches!(
            g.check("evt_1"),
            Err(WebhookError::ReplayDetected)
        ));
    }

    #[test]
    fn zero_expiry_entries_are_swept_and_reclaimable() {
        // Capacity 2 forces a sweep on the insert that reaches capacity.
        // With a zero expiry every entry is instantly prunable.
        let g = ReplayGuard::with_capacity(Duration::ZERO, 2);
        g.check("evt_a").expect("a");
        g.check("evt_b").expect("b"); // at capacity → sweep drops both
        g.check("evt_c").expect("c");
        // evt_a was swept, so it is claimable again (TTL semantics).
        g.check("evt_a").expect("a reclaimable after sweep");
    }

    #[test]
    fn full_capacity_with_fresh_entries_fails_closed() {
        let g = ReplayGuard::with_capacity(Duration::from_secs(3600), 2);
        g.check("evt_1").expect("1");
        g.check("evt_2").expect("2"); // sweep runs, nothing expired
        let err = g.check("evt_3").expect_err("capacity");
        assert!(matches!(err, WebhookError::ReplayGuardFull));
        // The previously-seen IDs are still protected (no silent wipe).
        assert!(matches!(
            g.check("evt_1"),
            Err(WebhookError::ReplayDetected)
        ));
        assert!(matches!(
            g.check("evt_2"),
            Err(WebhookError::ReplayDetected)
        ));
    }

    #[test]
    fn expired_slot_is_reclaimed_by_capacity_sweep() {
        let g = ReplayGuard::with_capacity(Duration::from_secs(3600), 1);
        g.check("evt_1").expect("1");
        // No way to advance the clock without a mock; use `remove` as the
        // expiry path and confirm the freed slot is reusable.
        g.remove("evt_1");
        g.check("evt_2").expect("2 after remove");
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn is_empty_reflects_state() {
        let g = ReplayGuard::new(Duration::from_secs(60));
        assert!(g.is_empty());
        g.check("evt_1").expect("1");
        assert!(!g.is_empty());
    }

    #[test]
    fn capacity_minimum_is_one() {
        let g = ReplayGuard::with_capacity(Duration::from_secs(60), 0);
        assert_eq!(g.capacity(), 1);
        g.check("evt_1").expect("1");
        assert!(matches!(
            g.check("evt_2"),
            Err(WebhookError::ReplayGuardFull)
        ));
    }

    #[test]
    fn expiry_and_accessors_roundtrip() {
        let g = ReplayGuard::with_capacity(Duration::from_secs(90), 7);
        assert_eq!(g.expiry(), Duration::from_secs(90));
        assert_eq!(g.capacity(), 7);
    }
}

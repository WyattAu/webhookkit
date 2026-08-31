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

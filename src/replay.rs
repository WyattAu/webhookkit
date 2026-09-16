//! Replay protection over the estate's single claim primitive,
//! [`idempotency-kit`](https://crates.io/crates/idempotency-kit): an
//! event ID is claimed under the `webhook` scope for the guard's expiry
//! window, and any second claim inside that window is a replay.
//!
//! # Claim mapping (webhook semantics)
//!
//! | `idempotency-kit` outcome | webhookkit result |
//! |---|---|
//! | `Claim::First` | `Ok(())` — process the event |
//! | `Claim::InFlight` (unfinished claim) | `Err(ReplayDetected)` |
//! | `Claim::Replay(_)` (recorded response) | `Err(ReplayDetected)` |
//! | `StoreError::CapacityExceeded` | `Err(ReplayGuardFull)` |
//! | `StoreError::Backend(_)` | `Err(ParseError)` |
//!
//! `InFlight` deliberately maps to `ReplayDetected` — not to a retryable
//! "concurrent request" outcome, as `idempotency-kit`'s
//! `IdempotencyExecutor` would produce — because webhook dedup has no
//! response-replay stage: these guards never call `complete`, so an
//! unfinished claim is not "another worker is mid-execution, try again"
//! but "this event ID was already accepted within the expiry window",
//! i.e. an at-least-once redelivery. `Replay` is unreachable for the
//! same reason (nothing ever records a response) but is mapped
//! identically so the guard is total over `Claim`.
//!
//! TTL and fail-closed capacity semantics are owned by the store: the
//! expiry window is measured from the first claim of an event ID, and a
//! full store rejects new claims (`ReplayGuardFull`) rather than
//! forgetting seen ones.

use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use idempotency_kit::{Claim, IdempotencyKey, IdempotencyStore, MemoryStore, StoreError};

/// Scope every replay claim is derived under: keys are
/// `webhook:{blake3(event_id)}`, interoperable with the rest of the
/// estate claiming under the same scope.
const SCOPE: &str = "webhook";

/// Default capacity: 65,536 concurrently-tracked event IDs (the
/// `idempotency-kit` memory store's default bound).
pub const DEFAULT_REPLAY_CAPACITY: usize = idempotency_kit::DEFAULT_CAPACITY;

/// Derive the claim key for an event ID. The `"webhook"` scope is a
/// compile-time constant satisfying the `[a-z0-9_.-]{1,64}` key-scope
/// grammar, so derivation cannot fail; the error mapping is kept total
/// regardless.
fn claim_key(event_id: &str) -> Result<IdempotencyKey, crate::WebhookError> {
    IdempotencyKey::derive(SCOPE, event_id.as_bytes())
        .map_err(|e| crate::WebhookError::ParseError(e.to_string()))
}

/// Map a store claim outcome onto the webhook error surface (see the
/// module docs for the rationale).
fn claim_outcome(outcome: Result<Claim, StoreError>) -> Result<(), crate::WebhookError> {
    match outcome {
        Ok(Claim::First) => Ok(()),
        // Any live claim on an event ID — unfinished or holding a
        // recorded response — is a replay in webhook semantics.
        Ok(Claim::InFlight | Claim::Replay(_)) => Err(crate::WebhookError::ReplayDetected),
        // Fail closed: the store is full of still-fresh claims and
        // refuses the new one rather than evicting a seen ID.
        Err(StoreError::CapacityExceeded) => Err(crate::WebhookError::ReplayGuardFull),
        Err(StoreError::Backend(msg)) => Err(crate::WebhookError::ParseError(msg)),
        // `StoreError` is `#[non_exhaustive]`: future store failures are
        // plumbing diagnostics, mapped onto the existing parse-error
        // surface like the 2.0.0 guard mapped lock poisoning.
        Err(other) => Err(crate::WebhookError::ParseError(other.to_string())),
    }
}

/// Drive a store future to completion on the calling thread.
///
/// The memory store's futures are synchronous bodies wrapped by
/// `#[async_trait]` — they never park — so a poll-to-completion loop
/// with a no-op waker adapts them to the sync [`ReplayGuard`] API
/// without pulling in an executor. (The Redis guard is async natively
/// and simply `.await`s the same contract.)
fn wait<F: Future>(fut: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            // Defensive: the memory store never yields. Yielding the
            // thread keeps this correct (if inefficient) even if a
            // future store implementation parks.
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// Guards against replay attacks by tracking processed event IDs with a
/// TTL window.
///
/// Backed by `idempotency-kit`'s `MemoryStore` — the same claim
/// primitive as the rest of the estate — with webhook-specific claim
/// mapping (see the [module docs](self)).
///
/// # Semantics (fail-closed)
///
/// - Expired entries are pruned lazily by the store: a sweep runs every
///   1,024 inserts, and is forced whenever the store is at capacity.
/// - If the guard is at [`capacity`](Self::capacity) and every tracked ID
///   is still inside its expiry window, [`check`](Self::check) returns
///   [`WebhookError::ReplayGuardFull`] rather than forgetting IDs.
///   Forgetting a seen ID would re-open a replay window; rejecting new
///   claims is the safe failure mode.
/// - Process-local by design. For multi-instance deployments use
///   [`RedisReplayGuard`], which shares dedup state atomically via
///   `SET NX EX`.
pub struct ReplayGuard {
    store: MemoryStore,
    expiry: Duration,
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
            store: MemoryStore::with_capacity(capacity),
            expiry,
        }
    }

    /// The configured capacity bound.
    pub fn capacity(&self) -> usize {
        self.store.capacity()
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
        let key = claim_key(event_id)?;
        claim_outcome(wait(self.store.claim(&key, self.expiry)))
    }

    /// Manually remove an event ID (e.g. after its expiry window passes).
    pub fn remove(&self, event_id: &str) {
        // Best-effort by contract: a failed release is swallowed exactly
        // as a poisoned lock always was.
        if let Ok(key) = claim_key(event_id) {
            let _ = wait(self.store.release(&key));
        }
    }

    /// Return the number of tracked event IDs (may include not-yet-pruned
    /// expired entries).
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether no events are being tracked.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

// Restore the 2.0.0 auto-trait surface: the memory store's `DashMap`
// internals opt this wrapper out of `RefUnwindSafe`, which would be an
// unintended breaking change for downstream generic code. The assertion
// is sound here: a panic through `&self` cannot break the guard's
// invariants — shard locks release on unwind, entries are plain data (a
// deadline), and no user code runs inside the store's critical
// sections — so a `&ReplayGuard` captured across `catch_unwind` keeps
// behaving per contract after a panic.
impl std::panic::RefUnwindSafe for ReplayGuard {}

// Pin the guarantee: the semver gate compares auto traits against the
// 2.0.0 baseline.
const fn assert_ref_unwind_safe<T: std::panic::RefUnwindSafe>() {}
const _: () = assert_ref_unwind_safe::<ReplayGuard>();

/// Distributed replay guard backed by Redis `SET key val NX EX` — an atomic
/// claim, so multi-instance deployments share dedup state without Lua.
///
/// Delegates to `idempotency-kit`'s `RedisStore`: keys are
/// `idempotency-kit:webhook:{blake3(event_id)}` — raw event IDs never
/// appear in Redis — and dedup state is shared with any other estate
/// component claiming under the `webhook` scope. Unlike the in-memory
/// [`ReplayGuard`], expiry is enforced by Redis TTLs rather than lazy
/// pruning, with the TTL floored at one second.
#[cfg(feature = "redis")]
pub struct RedisReplayGuard {
    store: idempotency_kit::RedisStore,
    expiry: Duration,
}

#[cfg(feature = "redis")]
impl RedisReplayGuard {
    /// Create a distributed replay guard with the given expiry window.
    pub fn new(conn: redis::aio::ConnectionManager, expiry: Duration) -> Self {
        Self {
            store: idempotency_kit::RedisStore::new(conn),
            expiry,
        }
    }

    /// Atomically claim `event_id`. Returns `Err(ReplayDetected)` if another
    /// worker already claimed it within the expiry window.
    pub async fn check(&self, event_id: &str) -> Result<(), crate::WebhookError> {
        let key = claim_key(event_id)?;
        claim_outcome(self.store.claim(&key, self.expiry).await)
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

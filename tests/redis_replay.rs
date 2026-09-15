// Tests talk to a real Redis in docker; unwrap/expect is the test signal.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "redis")]

//! Distributed replay-guard integration tests against a real Redis server
//! (testcontainers, docker required).
//!
//! ```sh
//! cargo test --features redis --test redis_replay
//! ```
//!
//! Proves the security-critical distributed properties the in-memory
//! guard can't: atomic `SET NX EX` claims across separate guard instances
//! (i.e. separate service workers), replay rejection within the window,
//! and window expiry re-admitting the event id.

use std::time::Duration;

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::redis::Redis;
use webhookkit::RedisReplayGuard;
use webhookkit::WebhookError::ReplayDetected;

async fn spawn_redis() -> (
    testcontainers::ContainerAsync<Redis>,
    redis::aio::ConnectionManager,
) {
    let container = Redis::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(6379).await.unwrap();
    let url = format!("redis://{host}:{port}/");
    let conn = redis::Client::open(url)
        .unwrap()
        .get_connection_manager()
        .await
        .unwrap();
    (container, conn)
}

#[tokio::test]
async fn first_claim_wins_duplicate_rejected() {
    let (_c, conn) = spawn_redis().await;
    let guard = RedisReplayGuard::new(conn, Duration::from_secs(300));

    guard.check("evt_first").await.unwrap();
    let err = guard.check("evt_first").await.unwrap_err();
    assert!(
        matches!(err, ReplayDetected),
        "a second claim on the same id must be rejected as replay: {err:?}"
    );
}

#[tokio::test]
async fn separate_workers_share_dedup_state() {
    // Two guard instances over the same Redis — the multi-instance
    // deployment shape. The claim is atomic, so only one worker wins.
    let (_c, conn) = spawn_redis().await;
    let worker_a = RedisReplayGuard::new(conn.clone(), Duration::from_secs(300));
    let worker_b = RedisReplayGuard::new(conn, Duration::from_secs(300));

    worker_a.check("evt_shared").await.unwrap();
    let err = worker_b.check("evt_shared").await.unwrap_err();
    assert!(
        matches!(err, ReplayDetected),
        "worker B must see worker A's claim"
    );
}

#[tokio::test]
async fn distinct_event_ids_are_independent() {
    let (_c, conn) = spawn_redis().await;
    let guard = RedisReplayGuard::new(conn, Duration::from_secs(300));

    for i in 0..25 {
        guard.check(&format!("evt_{i}")).await.unwrap();
    }
    // Re-checking every id after a full sweep: all must be rejected.
    for i in 0..25 {
        let err = guard.check(&format!("evt_{i}")).await.unwrap_err();
        assert!(matches!(err, ReplayDetected));
    }
}

#[tokio::test]
async fn window_expiry_re_admits_event_ids() {
    let (_c, conn) = spawn_redis().await;
    let guard = RedisReplayGuard::new(conn, Duration::from_secs(2));

    guard.check("evt_expiring").await.unwrap();
    assert!(matches!(
        guard.check("evt_expiring").await,
        Err(ReplayDetected)
    ));

    // Past the expiry window the claim's Redis TTL lapses and the id may
    // be processed again (at-least-once redelivery outside the window is
    // the application's responsibility — the guard bounds the window).
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    guard.check("evt_expiring").await.unwrap();
}

#[tokio::test]
async fn minimum_one_second_ttl_is_enforced() {
    let (_c, conn) = spawn_redis().await;
    // A zero expiry must not produce a PX 0 (instant-expire) claim.
    let guard = RedisReplayGuard::new(conn, Duration::ZERO);
    guard.check("evt_min_ttl").await.unwrap();
    assert!(matches!(
        guard.check("evt_min_ttl").await,
        Err(ReplayDetected)
    ));
}

#[tokio::test]
async fn realistic_webhook_pipeline_end_to_end() {
    // Signature verification (stateless) + distributed replay guard,
    // mirroring the documented two-layer consumption flow.
    use hmac::Mac as _;
    use webhookkit::verify_hmac_sha256;

    let (_c, conn) = spawn_redis().await;
    let guard = RedisReplayGuard::new(conn, Duration::from_secs(300));

    let secret = b"whsec_shared";
    let event_id = "evt_pipeline_1";
    let payload = format!(r#"{{"id":"{event_id}","type":"payout.paid"}}"#);

    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    // Delivery 1: valid signature, fresh id → processed.
    verify_hmac_sha256(payload.as_bytes(), secret, sig.as_bytes()).unwrap();
    guard.check(event_id).await.unwrap();

    // Delivery 2 (at-least-once redelivery): signature verifies again, the
    // guard rejects — no double side effects.
    verify_hmac_sha256(payload.as_bytes(), secret, sig.as_bytes()).unwrap();
    let err = guard.check(event_id).await.unwrap_err();
    assert!(matches!(err, ReplayDetected));
}

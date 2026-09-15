// Security-critical verification paths; unwrap/expect is the test signal.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for webhookkit's signature verification surface,
//! driven through the public API with realistic adversarial inputs:
//! forged signatures, tampered payloads, replayed events, expired
//! timestamps, and the provider parsers (Stripe, GoCardless).
//!
//! These prove the properties the crate exists for:
//! - a signature is valid **only** for its exact payload + secret pair;
//! - any tampering with payload, signature, timestamp, or secret fails
//!   closed with `InvalidSignature`/`ExpiredTimestamp`;
//! - replayed event IDs are rejected by the [`ReplayGuard`];
//! - constant-time comparison is used on every path (both mismatch
//!   shapes surface the identical error, never a distinct "length"
//!   signal through the error type).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use webhookkit::{
    ReplayGuard, WebhookError, verify_gocardless_webhook, verify_hmac_sha256,
    verify_stripe_webhook, verify_timestamp,
};
type HmacSha256 = Hmac<sha2::Sha256>;

fn sign(payload: &[u8], secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------------------
// verify_hmac_sha256 — forged / tampered / malformed
// ---------------------------------------------------------------------------

#[test]
fn valid_signature_roundtrips() {
    let payload = br#"{"order":"created","amount":4200}"#;
    let secret = b"whsec_live_9f8e7d6c";
    let sig = sign(payload, secret);
    verify_hmac_sha256(payload, secret, sig.as_bytes()).unwrap();
}

#[test]
fn forged_signature_fails() {
    // Attacker signs their own payload with their own secret but presents
    // it against the real secret.
    let payload = br#"{"order":"created"}"#;
    let attacker_sig = sign(payload, b"attacker-known-secret");
    let err = verify_hmac_sha256(payload, b"whsec_real", attacker_sig.as_bytes()).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature), "{err:?}");
}

#[test]
fn tampered_payload_fails_with_valid_signature_of_original() {
    let original = br#"{"amount":100}"#;
    let secret = b"whsec_real";
    let sig = sign(original, secret);
    // Same length, same secret — only the payload byte flipped.
    let tampered = br#"{"amount":900}"#;
    assert_eq!(original.len(), tampered.len());
    let err = verify_hmac_sha256(tampered, secret, sig.as_bytes()).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));
}

#[test]
fn tampered_signature_fails() {
    let payload = b"payload";
    let secret = b"whsec_real";
    let mut sig = sign(payload, secret);
    // Flip one hex nibble at a fixed position.
    let middle = sig.len() / 2;
    let c = sig.as_bytes()[middle];
    sig.replace_range(middle..middle + 1, if c == b'0' { "1" } else { "0" });
    let err = verify_hmac_sha256(payload, secret, sig.as_bytes()).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));
}

#[test]
fn signature_of_different_length_fails_closed_with_same_error() {
    let payload = b"payload";
    let secret = b"whsec_real";
    let sig = sign(payload, secret);

    // Truncated and over-padded signatures must produce exactly the same
    // error as a wrong-but-well-sized signature: no length oracle.
    let truncated = &sig[..sig.len() - 2];
    let padded = format!("{sig}00");
    let mismatched = sign(payload, b"other").repeat(2);

    for candidate in [truncated.to_string(), padded, mismatched] {
        let err = verify_hmac_sha256(payload, secret, candidate.as_bytes()).unwrap_err();
        assert!(
            matches!(err, WebhookError::InvalidSignature),
            "{candidate}: {err:?}"
        );
    }
}

#[test]
fn non_hex_signature_is_a_parse_error_not_invalid_signature() {
    let err = verify_hmac_sha256(b"p", b"s", b"zzzz-not-hex").unwrap_err();
    assert!(matches!(err, WebhookError::ParseError(_)), "{err:?}");
}

#[test]
fn empty_secret_and_payload_still_verify() {
    let sig = sign(b"", b"");
    verify_hmac_sha256(b"", b"", sig.as_bytes()).unwrap();
    let err = verify_hmac_sha256(b"", b"", b"00").unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));
}

// ---------------------------------------------------------------------------
// verify_stripe_webhook — header format, timestamps, replay windows
// ---------------------------------------------------------------------------

fn stripe_header(payload: &[u8], secret: &str, ts: u64) -> String {
    let signed = format!("{ts}.{}", String::from_utf8_lossy(payload));
    format!("t={ts},v1={}", sign(signed.as_bytes(), secret.as_bytes()))
}

const STRIPE_BODY: &str = r#"{"id":"evt_456","type":"checkout.session.completed"}"#;

#[test]
fn stripe_valid_event_parses_type_and_id() {
    let event = verify_stripe_webhook(
        STRIPE_BODY,
        &stripe_header(STRIPE_BODY.as_bytes(), "whsec_s", now_secs()),
        "whsec_s",
    )
    .unwrap();
    assert_eq!(event.event_type, "checkout.session.completed");
    assert_eq!(event.payload["id"], "evt_456");
}

#[test]
fn stripe_forged_signature_rejected() {
    let header = stripe_header(STRIPE_BODY.as_bytes(), "attacker", now_secs());
    let err = verify_stripe_webhook(STRIPE_BODY, &header, "whsec_s").unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));
}

#[test]
fn stripe_tampered_body_rejected() {
    let secret = "whsec_s";
    let header = stripe_header(STRIPE_BODY.as_bytes(), secret, now_secs());
    let tampered = r#"{"id":"evt_456","type":"refund.created"}"#;
    let err = verify_stripe_webhook(tampered, &header, secret).unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));
}

#[test]
fn stripe_expired_timestamp_rejected_even_with_valid_signature() {
    // A captured (signature, timestamp) pair stays cryptographically valid
    // forever — the timestamp window is what bounds the replay window.
    let secret = "whsec_s";
    let stale = now_secs() - 3600;
    let header = stripe_header(STRIPE_BODY.as_bytes(), secret, stale);
    let err = verify_stripe_webhook(STRIPE_BODY, &header, secret).unwrap_err();
    assert!(
        matches!(err, WebhookError::ExpiredTimestamp),
        "replay window must reject a 1h-old timestamp: {err:?}"
    );
}

#[test]
fn stripe_future_timestamp_rejected() {
    let secret = "whsec_s";
    let future = now_secs() + 3600;
    let header = stripe_header(STRIPE_BODY.as_bytes(), secret, future);
    let err = verify_stripe_webhook(STRIPE_BODY, &header, secret).unwrap_err();
    assert!(matches!(err, WebhookError::ExpiredTimestamp));
}

#[test]
fn stripe_malformed_headers_fail_without_panicking() {
    for header in ["", "t=abc", "v1=deadbeef", "t=1000", "garbage"] {
        assert!(
            verify_stripe_webhook(STRIPE_BODY, header, "whsec_s").is_err(),
            "header {header:?} must not verify"
        );
    }
}

// ---------------------------------------------------------------------------
// verify_timestamp
// ---------------------------------------------------------------------------

#[test]
fn timestamp_window_boundaries() {
    let now = now_secs();
    assert!(verify_timestamp(&now.to_string(), 300).is_ok());
    assert!(verify_timestamp(&(now - 299).to_string(), 300).is_ok());
    assert!(verify_timestamp(&(now - 301).to_string(), 300).is_err());
    // The window is symmetric (abs_diff): modest clock skew into the
    // future is tolerated, anything beyond the tolerance is not.
    assert!(verify_timestamp(&(now + 100).to_string(), 300).is_ok());
    assert!(verify_timestamp(&(now + 301).to_string(), 300).is_err());
    assert!(verify_timestamp("not-a-number", 300).is_err());
    assert!(verify_timestamp("", 300).is_err());
}

// ---------------------------------------------------------------------------
// verify_gocardless_webhook
// ---------------------------------------------------------------------------

#[test]
fn gocardless_roundtrip_and_rejections() {
    let body = r#"{"resource_type":"billing_requests","action":"fulfilled"}"#;
    let secret = "gc_secret";

    let event = verify_gocardless_webhook(
        body,
        &format!("hex={}", sign(body.as_bytes(), secret.as_bytes())),
        secret,
    )
    .unwrap();
    assert_eq!(event.resource_type, "billing_requests");
    assert_eq!(event.action, "fulfilled");

    // Forged.
    let err = verify_gocardless_webhook(
        body,
        &format!("hex={}", sign(body.as_bytes(), b"other")),
        secret,
    )
    .unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));

    // Tampered.
    let sig = sign(body.as_bytes(), secret.as_bytes());
    let err = verify_gocardless_webhook(
        r#"{"resource_type":"payments","action":"confirmed"}"#,
        &format!("hex={sig}"),
        secret,
    )
    .unwrap_err();
    assert!(matches!(err, WebhookError::InvalidSignature));

    // Wrong header scheme.
    assert!(verify_gocardless_webhook(body, "v1=abcd", secret).is_err());
}

// ---------------------------------------------------------------------------
// ReplayGuard — dedup and eviction semantics
// ---------------------------------------------------------------------------

#[test]
fn replay_guard_rejects_duplicates_within_window() {
    let guard = ReplayGuard::new(Duration::from_secs(300));
    assert!(guard.check("evt_A").is_ok());
    assert!(matches!(
        guard.check("evt_A"),
        Err(WebhookError::ReplayDetected)
    ));
    // Distinct ids stay independent.
    assert!(guard.check("evt_B").is_ok());
    assert_eq!(guard.len(), 2);
}

#[test]
fn replay_guard_full_pipeline_rejects_replayed_webhooks() {
    // The realistic flow: verify the signature (accepts forever after
    // capture), then dedup by event id — a replayed delivery passes crypto
    // but must hit the replay guard.
    let guard = ReplayGuard::new(Duration::from_secs(300));
    let secret = "whsec_flow";
    let header = stripe_header(STRIPE_BODY.as_bytes(), secret, now_secs());

    for delivery in 0..2 {
        let verified = verify_stripe_webhook(STRIPE_BODY, &header, secret);
        assert!(
            verified.is_ok(),
            "delivery {delivery}: signature must verify"
        );
        let event_id = verified.unwrap().payload["id"]
            .as_str()
            .unwrap()
            .to_string();
        let result = guard.check(&event_id);
        if delivery == 0 {
            assert!(result.is_ok(), "first delivery processes");
        } else {
            assert!(
                matches!(result, Err(WebhookError::ReplayDetected)),
                "second delivery of the same event must be rejected as replay"
            );
        }
    }
}

#[test]
fn replay_guard_remove_reopens_window_and_capacity_fails_closed() {
    let guard = ReplayGuard::new(Duration::from_secs(300));
    guard.check("evt_X").unwrap();
    guard.remove("evt_X");
    assert!(guard.is_empty());
    assert!(guard.check("evt_X").is_ok(), "removal re-allows the id");

    // Security regression (2.0.0): at capacity the guard fails CLOSED.
    // 1.1.0 silently wiped the set here, re-opening a replay window under
    // load. Now: fresh IDs are never forgotten; overflow claims are
    // rejected with ReplayGuardFull and seen IDs stay protected.
    let capped = ReplayGuard::with_capacity(Duration::from_secs(300), 64);
    for i in 0..64 {
        capped.check(&format!("flood-{i}")).unwrap();
    }
    assert!(matches!(
        capped.check("flood-overflow"),
        Err(WebhookError::ReplayGuardFull)
    ));
    assert!(matches!(
        capped.check("flood-0"),
        Err(WebhookError::ReplayDetected),
    ));
    assert_eq!(capped.len(), 64, "guard must not forget seen ids");
}

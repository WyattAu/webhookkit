# webhookkit

Webhook signature verification for Rust — HMAC-SHA256, timestamp validation,
and provider-specific parsers for **Stripe**, **GoCardless**, and more.

[![CI](https://github.com/WyattAu/webhookkit/actions/workflows/ci.yml/badge.svg)](https://github.com/WyattAu/webhookkit/actions)
[![crates.io](https://img.shields.io/crates/v/webhookkit)](https://crates.io/crates/webhookkit)
[![license](https://img.shields.io/crates/l/webhookkit)](LICENSE-MIT)

## Features

- HMAC-SHA256 verification with **constant-time comparison**
- Configurable timestamp tolerance (prevents stale replay)
- `ReplayGuard` for nonce / event-ID tracking
- Stripe webhook parser (`t=...,v1=...` signature format)
- GoCardless webhook parser (`hex=...` signature format)
- `#![forbid(unsafe_code)]` throughout

## Quick Start

### Stripe

```rust
use webhookkit::{verify_stripe_webhook, WebhookError};

fn handle(body: &str, stripe_sig: &str, secret: &str) -> Result<(), WebhookError> {
    let event = verify_stripe_webhook(body, stripe_sig, secret)?;
    match event.event_type.as_str() {
        "payment_intent.succeeded" => { /* ... */ }
        "invoice.paid" => { /* ... */ }
        _ => {}
    }
    Ok(())
}
```

### GoCardless

```rust
use webhookkit::{verify_gocardless_webhook, WebhookError};

fn handle(body: &str, gc_sig: &str, secret: &str) -> Result<(), WebhookError> {
    let event = verify_gocardless_webhook(body, gc_sig, secret)?;
    println!("{}: {}", event.resource_type, event.action);
    Ok(())
}
```

### Replay Protection

```rust
use std::time::Duration;
use webhookkit::ReplayGuard;

let guard = ReplayGuard::new(Duration::from_secs(300));

// On each incoming webhook:
guard.check(evt_id)?;  // returns Err(ReplayDetected) if already seen
```

### Raw HMAC Verification

```rust
use webhookkit::{verify_hmac_sha256, WebhookError};

fn verify(payload: &[u8], secret: &[u8], sig_hex: &[u8]) -> Result<(), WebhookError> {
    verify_hmac_sha256(payload, secret, sig_hex)
}
```

## How It Works

```
Stripe-Signature: t=1700000000,v1=abc123...

1. Parse t and v1 from the header
2. Check timestamp is within 300 s of now
3. Build signed_payload = "{timestamp}.{body}"
4. HMAC-SHA256(signed_payload, secret) == v1?
5. Constant-time comparison (no timing oracle)
```

## Comparison with Manual HMAC

|                         | webhookkit          | Manual HMAC                   |
|-------------------------|---------------------|-------------------------------|
| Constant-time compare   | Yes (`subtle`)      | Easy to forget                |
| Timestamp validation    | Built-in            | Manual                        |
| Replay guard            | Built-in            | Manual                        |
| Provider parsers        | Stripe, GoCardless  | Write your own                |
| `forbid(unsafe_code)`   | Yes                 | Depends on your impl          |

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option.

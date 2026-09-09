# webhookkit

Verify webhook signatures in Rust — with a **`no_std`-compatible core**.

[![CI](https://github.com/WyattAu/webhookkit/actions/workflows/ci.yml/badge.svg)](https://github.com/WyattAu/webhookkit/actions)
[![crates.io](https://img.shields.io/crates/v/webhookkit)](https://crates.io/crates/webhookkit)
[![license](https://img.shields.io/crates/l/webhookkit)](LICENSE-MIT)

## Why webhookkit

- **`no_std` verification core.** The stateless HMAC-SHA256 path —
  [`verify_hmac_sha256`](https://docs.rs/webhookkit/latest/webhookkit/fn.verify_hmac_sha256.html),
  GoCardless parsing, and the C FFI surface — builds with
  `--no-default-features` on `core` + `alloc` (CI checks it against
  `thumbv7em-none-eabihf`). The heavy lifting is RustCrypto `hmac`/`sha2`,
  both `no_std`. The wall-clock/mutex surfaces (`timestamp`, `replay`,
  `stripe`) are gated behind the on-by-default `std` feature.
- **Multi-provider out of the box.** Signature formats for **Stripe**
  (`t=…,v1=…`) and **GoCardless** (`hex=…`) are parsed and verified for you —
  no hand-rolled header parsing.
- **Replay protection built in.** [`ReplayGuard`](https://docs.rs/webhookkit/latest/webhookkit/struct.ReplayGuard.html)
  tracks processed event IDs with a TTL window, so "webhooks arrive at least
  once" doesn't become "side effects run twice".
- **Hardened by default.** Constant-time signature comparison (`subtle`),
  configurable timestamp tolerance, `#![forbid(unsafe_code)]`.

## Feature matrix

webhookkit does one thing: **verify inbound webhook signatures**. That puts
it next to — not against — two crates it's often compared with:

|                              | webhookkit            | async-stripe                    | svix                            |
|------------------------------|-----------------------|---------------------------------|--------------------------------|
| Scope                        | inbound verification  | full Stripe REST API client     | webhook *sending* platform     |
| `no_std` core                | yes                   | no                              | no                             |
| Stripe webhook verify        | yes                   | yes (`webhook-events` feature)  | —                              |
| GoCardless webhook verify    | yes                   | —                               | —                              |
| Replay / timestamp guard     | built-in (`ReplayGuard`) | manual                        | platform-side (signing + retries) |
| Send webhooks / delivery     | —                     | —                               | yes                            |
| Stripe REST API calls        | —                     | yes                             | —                              |
| C FFI surface                | yes (generated header)| no                              | no                             |
| Runtime                      | sync, no transport    | async (reqwest/hyper)           | async HTTP                     |

### Where webhookkit lags (honestly)

- **No Stripe API.** async-stripe covers the entire Stripe REST surface and
  its webhook verification is solid — if you're already calling the Stripe
  API, use it. webhookkit earns its keep when verification is all you need,
  or when `no_std`/FFI/small-dependency constraints apply.
- **No webhook sending.** svix (and the `svix` crate) handle outbound
  delivery: endpoint management, retries, signing for events *you* emit.
  webhookkit only consumes inbound webhooks.
- **Two providers, not fifty.** Stripe and GoCardless today. The raw
  `verify_hmac_sha256` path covers anything with an HMAC-SHA256 scheme.
- **Single-process `ReplayGuard`.** It's an in-memory std mutex; multi-instance
  deployments should front it with a shared store.

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

### Raw HMAC Verification (no_std path)

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
| `no_std` core           | Yes                 | Depends on your impl          |
| `forbid(unsafe_code)`   | Yes                 | Depends on your impl          |

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option.

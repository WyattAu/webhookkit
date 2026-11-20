# Pattern adoption: webhookkit

Webhook signing, verification, and replay protection. Declared per
`pattern-standards/references/adoption-format.md`.

| Pattern | Status | Evidence |
|---|---|---|
| P54 | adopted | src/stripe.rs:1 and src/gocardless.rs:1 (per-provider signature verification) and src/timestamp.rs:6 (timestamp tolerance window) |
| T33 | adopted | src/replay.rs:115 (ReplayGuard tracks processed event IDs; any second claim inside the expiry window is a replay) |
| P50 | partial | tests/redis_replay.rs:6 (distributed guard integration against a real Redis in testcontainers) |

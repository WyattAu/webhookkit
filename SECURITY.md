# Security Policy — webhookkit

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x    | ✅ |
| < 1.0    | ❌ (upgrade) |

## Reporting a Vulnerability

**Do not open a public issue.** Email **wyatt_au@protonmail.com** with:

1. Affected crate + version (`webhookkit <version>`)
2. A minimal reproduction or proof-of-concept
3. Impact assessment (what an attacker gains)
4. Suggested mitigation if known

You will receive an acknowledgment within 72 hours. Coordinated disclosure
window: 90 days from report, or earlier by mutual agreement. Reporters are
credited in the advisory unless anonymity is requested.

For issues in the underlying primitives (HMAC-SHA256, constant-time
comparison), also consider reporting upstream to
[RustCrypto](https://github.com/RustCrypto/SECURITY.md) — this crate defers
cryptographic correctness to `hmac`/`sha2`/`subtle`.

## Scope

In scope: anything that breaks the crate's documented security contract —
panic on adversarial input in code paths documented as panic-free
(`verify_hmac_sha256`, `verify_stripe_webhook`, `verify_gocardless_webhook`,
`verify_timestamp`, `ReplayGuard::check`, and the `ffi` feature's exported
functions), signature/MAC bypass, timing side channels in secret-dependent
operations, injection via parsed input, dependency-introduced vulnerabilities.

Out of scope: denial of service by resource exhaustion on already-documented
limits (e.g. `ReplayGuard`'s 10 000-entry prune), caller-side secret storage
and transport security, vulnerabilities in downstream consumer code.

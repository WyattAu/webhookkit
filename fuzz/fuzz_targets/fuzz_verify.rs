#![no_main]

use libfuzzer_sys::fuzz_target;
use webhookkit::{
    verify_gocardless_webhook, verify_hmac_sha256, verify_stripe_webhook, verify_timestamp,
};

fuzz_target!(|data: &[u8]| {
    // Bound input so HMAC/JSON parsing stays fast.
    let data = &data[..data.len().min(4096)];

    // Split into (payload, secret, signature) from one arbitrary buffer.
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3);
    let mut rest = data;
    while parts.len() < 2 && rest.len() > 2 {
        let cut = rest[0] as usize % rest.len();
        parts.push(&rest[1..1 + cut.min(rest.len() - 1)]);
        rest = &rest[1 + cut.min(rest.len() - 1)..];
    }
    parts.push(rest);
    while parts.len() < 3 {
        parts.push(b"");
    }
    let payload = parts[0];
    let secret = parts[1];
    let signature = parts[2];

    // Arbitrary triples must yield Ok/Err, never panic (incl. empty secret,
    // non-hex signatures, wrong lengths).
    let _ = verify_hmac_sha256(payload, secret, signature);

    // Provider parsers wrap HMAC + JSON parsing on adversarial headers/bodies.
    let body = String::from_utf8_lossy(payload);
    let sig_header = String::from_utf8_lossy(signature);
    let secret_str = String::from_utf8_lossy(secret);
    let _ = verify_stripe_webhook(&body, &sig_header, &secret_str);
    let _ = verify_gocardless_webhook(&body, &sig_header, &secret_str);

    // Timestamp validation — arbitrary strings must parse-or-Err, not panic.
    let ts = String::from_utf8_lossy(payload);
    let _ = verify_timestamp(&ts, 300);
    let _ = verify_timestamp(&ts, u64::MAX);
});

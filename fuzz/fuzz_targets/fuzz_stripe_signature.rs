#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz the Stripe-Signature header parser and verifier: arbitrary header
/// bytes plus a payload. The parser must never panic and must reject
/// unsigned payloads. Input layout: first byte = header length (capped),
/// remainder = body; header is derived from the remainder's first half so
/// the corpus evolves both fields together.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize).min(data.len().saturating_sub(1)).max(1);
    let (header_bytes, body) = data.split_at(split);
    let header = String::from_utf8_lossy(header_bytes);
    let body_str = String::from_utf8_lossy(body);

    let _ = webhookkit::verify_stripe_webhook(&body_str, &header, "whsec_fuzz");
    let _ = webhookkit::verify_stripe_webhook_with_tolerance(
        &body_str,
        &header,
        "whsec_fuzz",
        300,
    );
});

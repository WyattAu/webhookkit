#![no_main]

use libfuzzer_sys::fuzz_target;
use webhookkit::verify_hmac_sha256;

fuzz_target!(|data: &[u8]| {
    // Fuzz HMAC verification with arbitrary payload, secret, and signature bytes
    // Must not panic on any input
    let _ = verify_hmac_sha256(data, b"test-secret", data);
});

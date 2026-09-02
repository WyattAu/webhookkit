fn main() {
    // Only generate header when ffi feature is enabled
    if std::env::var("CARGO_FEATURE_FFI").is_ok() {
        let header = r#"#ifndef WEBHOOKKIT_H
#define WEBHOOKKIT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Verify an HMAC-SHA256 signature.
/// Returns 1 if valid, 0 if invalid, -1 on error.
int32_t webhookkit_verify_hmac_sha256(
    const char* payload_ptr,
    uintptr_t payload_len,
    const char* secret_ptr,
    uintptr_t secret_len,
    const char* signature_ptr,
    uintptr_t signature_len
);

/// Get the library version string.
/// Returns a pointer to a static null-terminated string.
const char* webhookkit_version(void);

#ifdef __cplusplus
}
#endif

#endif // WEBHOOKKIT_H
"#;
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let dest_path = std::path::Path::new(&out_dir).join("webhookkit.h");
        std::fs::write(dest_path, header).unwrap();
    }
}

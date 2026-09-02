use std::os::raw::c_char;

use crate::verify_hmac_sha256;

/// Verify an HMAC-SHA256 signature (C FFI).
///
/// # Safety
///
/// Caller must ensure:
/// - `payload_ptr` points to a valid UTF-8 string of `payload_len` bytes
/// - `secret_ptr` points to a valid UTF-8 string of `secret_len` bytes
/// - `signature_ptr` points to a valid hex string of `signature_len` bytes
/// - All pointers are valid for the duration of the call
///
/// # Returns
///
/// - 1 if the signature is valid
/// - 0 if the signature is invalid
/// - -1 if an error occurred (invalid hex, etc.)
#[unsafe(no_mangle)]
pub extern "C" fn webhookkit_verify_hmac_sha256(
    payload_ptr: *const c_char,
    payload_len: usize,
    secret_ptr: *const c_char,
    secret_len: usize,
    signature_ptr: *const c_char,
    signature_len: usize,
) -> i32 {
    if payload_ptr.is_null() || secret_ptr.is_null() || signature_ptr.is_null() {
        return -1;
    }

    let payload = unsafe {
        let slice = std::slice::from_raw_parts(payload_ptr as *const u8, payload_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let secret = unsafe {
        let slice = std::slice::from_raw_parts(secret_ptr as *const u8, secret_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let signature = unsafe {
        let slice = std::slice::from_raw_parts(signature_ptr as *const u8, signature_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    match verify_hmac_sha256(payload.as_bytes(), secret.as_bytes(), signature.as_bytes()) {
        Ok(()) => 1,
        Err(_) => -1,
    }
}

/// Get the library version string (C FFI).
///
/// # Safety
///
/// Returns a pointer to a static string. The caller must NOT free this pointer.
#[unsafe(no_mangle)]
pub extern "C" fn webhookkit_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

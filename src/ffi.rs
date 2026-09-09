use core::ffi::c_char;

use crate::{WebhookError, verify_hmac_sha256};

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
        Err(WebhookError::InvalidSignature) => 0,
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

#[cfg(test)]
// Test code: unwrap is the idiomatic way to assert setup success.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use alloc::ffi::CString;
    use core::ffi::CStr;

    use super::*;

    /// The FFI functions are safe `extern "C"` fns: they validate pointers
    /// (null check) and encoding (UTF-8 check) before any dereference, so
    /// tests can call them directly from Rust without a C toolchain.
    fn call_ffi(
        payload: *const c_char,
        payload_len: usize,
        secret: *const c_char,
        secret_len: usize,
        signature: *const c_char,
        signature_len: usize,
    ) -> i32 {
        webhookkit_verify_hmac_sha256(
            payload,
            payload_len,
            secret,
            secret_len,
            signature,
            signature_len,
        )
    }

    fn args(
        payload: &CString,
        secret: &CString,
        signature: &CString,
    ) -> (
        *const c_char,
        usize,
        *const c_char,
        usize,
        *const c_char,
        usize,
    ) {
        (
            payload.as_ptr(),
            payload.as_bytes().len(),
            secret.as_ptr(),
            secret.as_bytes().len(),
            signature.as_ptr(),
            signature.as_bytes().len(),
        )
    }

    #[test]
    fn ffi_valid_signature_returns_one() {
        let payload = CString::new("hello world").unwrap();
        let secret = CString::new("my-secret").unwrap();
        let sig = CString::new(crate::compute_hmac_sha256(b"hello world", b"my-secret")).unwrap();
        let (p, pl, s, sl, g, gl) = args(&payload, &secret, &sig);
        assert_eq!(call_ffi(p, pl, s, sl, g, gl), 1);
    }

    #[test]
    fn ffi_tampered_payload_returns_zero() {
        let payload = CString::new("hello tampered").unwrap();
        let secret = CString::new("my-secret").unwrap();
        let sig = CString::new(crate::compute_hmac_sha256(b"hello world", b"my-secret")).unwrap();
        let (p, pl, s, sl, g, gl) = args(&payload, &secret, &sig);
        assert_eq!(call_ffi(p, pl, s, sl, g, gl), 0);
    }

    #[test]
    fn ffi_wrong_length_hex_signature_returns_zero() {
        let payload = CString::new("hello world").unwrap();
        let secret = CString::new("my-secret").unwrap();
        let sig = CString::new("abcd").unwrap();
        let (p, pl, s, sl, g, gl) = args(&payload, &secret, &sig);
        assert_eq!(call_ffi(p, pl, s, sl, g, gl), 0);
    }

    #[test]
    fn ffi_invalid_hex_signature_returns_minus_one() {
        let payload = CString::new("hello world").unwrap();
        let secret = CString::new("my-secret").unwrap();
        let sig = CString::new("not-hex").unwrap();
        let (p, pl, s, sl, g, gl) = args(&payload, &secret, &sig);
        assert_eq!(call_ffi(p, pl, s, sl, g, gl), -1);
    }

    #[test]
    fn ffi_non_utf8_payload_returns_minus_one() {
        let payload = CString::new(vec![0xFF, 0xFE]).unwrap();
        let secret = CString::new("my-secret").unwrap();
        let sig = CString::new("aabb").unwrap();
        let (p, pl, s, sl, g, gl) = args(&payload, &secret, &sig);
        assert_eq!(call_ffi(p, pl, s, sl, g, gl), -1);
    }

    #[test]
    fn ffi_non_utf8_secret_returns_minus_one() {
        let payload = CString::new("hello world").unwrap();
        let secret = CString::new(vec![0xFF]).unwrap();
        let sig = CString::new("aabb").unwrap();
        let (p, pl, s, sl, g, gl) = args(&payload, &secret, &sig);
        assert_eq!(call_ffi(p, pl, s, sl, g, gl), -1);
    }

    #[test]
    fn ffi_non_utf8_signature_returns_minus_one() {
        let payload = CString::new("hello world").unwrap();
        let secret = CString::new("my-secret").unwrap();
        let sig = CString::new(vec![0xFF]).unwrap();
        let (p, pl, s, sl, g, gl) = args(&payload, &secret, &sig);
        assert_eq!(call_ffi(p, pl, s, sl, g, gl), -1);
    }

    #[test]
    fn ffi_null_pointers_return_minus_one() {
        assert_eq!(
            call_ffi(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0
            ),
            -1
        );
    }

    #[test]
    fn ffi_version_returns_cargo_pkg_version() {
        let ver = unsafe { CStr::from_ptr(webhookkit_version()) }
            .to_str()
            .expect("version is valid UTF-8");
        assert_eq!(ver, env!("CARGO_PKG_VERSION"));
    }
}

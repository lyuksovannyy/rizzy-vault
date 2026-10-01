//! Secrets crossing the boundary as bytes (ADR 0019 §3, "Secrets cross as bytes"; CRYPTO.md
//! §12.2, "JavaScript strings").
//!
//! The master password, the Secret Key and the export password come in as a `Uint8Array` of
//! UTF-8 (`TextEncoder`), never as a JavaScript string, and the Emergency Kit's Secret Key and
//! recovery code go out as one. Coming in, the binding takes the array as `&mut [u8]`:
//! wasm-bindgen copies it into wasm memory for the call and copies the slice back into the
//! caller's array afterwards. `take_secret` copies the text into a [`Zeroizing`] string and
//! wipes the slice, so both the wasm-memory copy and the caller's array hold zeroes when the
//! call returns; `packages/core` zeroes its array again in a `finally`, for the error paths
//! that never reach this crate.
//!
//! # Honest limit
//!
//! A secret going out (`Vec<u8>`) is copied by the glue from wasm memory into a fresh
//! `Uint8Array`, and the wasm-memory copy is freed without a wipe: the glue owns that buffer
//! and offers no hook to zero it. The host can zero its own array after rendering; the freed
//! wasm bytes stay until the allocator reuses them. This is the shared-heap limit the crate
//! docs and ADR 0013 §4 name; it is not a security boundary (TB-10).

use rizzy_client::ClientError;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CoreResult;

/// Takes a secret the host passed as UTF-8 bytes: returns it as a wiped-on-drop string and
/// zeroes `bytes` (module docs), on success and on error alike.
///
/// # Errors
/// `invalid_input` when `bytes` is not UTF-8.
pub(crate) fn take_secret(bytes: &mut [u8]) -> CoreResult<Zeroizing<String>> {
    // `to_owned` allocates the exact length once, so no reallocation leaves a stray copy.
    let taken = core::str::from_utf8(bytes).map(|text| Zeroizing::new(text.to_owned()));
    bytes.zeroize();
    taken.map_err(|_| ClientError::InvalidInput.into())
}

/// A secret going out, as bytes the host can zero (module docs, "Honest limit").
pub(crate) fn give_secret(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_secret_is_wiped_from_the_input() {
        let mut bytes = *b"correct horse";
        let taken = take_secret(&mut bytes).unwrap();
        assert_eq!(taken.as_str(), "correct horse");
        assert_eq!(bytes, [0; 13]);
    }

    #[test]
    fn invalid_utf8_is_refused_and_still_wiped() {
        let mut bytes = [0xff, 0xfe, b'a'];
        assert_eq!(
            take_secret(&mut bytes).unwrap_err().as_str(),
            "invalid_input"
        );
        assert_eq!(bytes, [0; 3]);
    }
}

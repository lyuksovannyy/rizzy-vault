//! Fuzzes the Padmé frame reader (CRYPTO.md §8.5): never panics, and an accepted frame is the
//! canonical frame of its data.
//!
//! [`unframe`] reads `u32(data_len) ‖ data ‖ zero padding`. When it accepts, the target frames
//! the returned data again with [`frame`] and asserts that the result is byte-for-byte the
//! input: the reader accepts only a frame of exactly `padded_len(data_len)` bytes with all-zero
//! padding, so each `data` has one frame and the padding cannot carry hidden bytes. In
//! production the reader runs on decrypted envelope plaintext; fuzzing it on raw bytes covers a
//! malicious sender who holds the key. Part of CRYPTO.md §15 item 7 ("Padmé frame parser").
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::padding::{frame, unframe};

fuzz_target!(|data: &[u8]| {
    if let Ok(inner) = unframe(data) {
        let reframed = frame(inner).expect("accepted data frames again");
        assert_eq!(reframed.expose_secret(), data);
    }
});

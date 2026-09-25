//! Fuzzes the Padmé frame reader (CRYPTO.md §8.5): never panics, and an accepted frame is the
//! canonical frame of its data.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::padding::{frame, unframe};

fuzz_target!(|data: &[u8]| {
    if let Ok(inner) = unframe(data) {
        let reframed = frame(inner).expect("accepted data frames again");
        assert_eq!(reframed.expose_secret(), data);
    }
});

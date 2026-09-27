//! Fuzzes the Secret Key and recovery-code parsers (CRYPTO.md §7, §15 item 7): never panic, and
//! an accepted code formats and parses back to the same 16 bytes.
//!
//! Non-UTF-8 input is skipped. For each input:
//!
//! - [`SecretKey::parse`] (`RV1-` prefix, Crockford Base32, check characters): if it accepts,
//!   `to_formatted()` parses back to the same 16 bytes, and `matches_last_group` runs on the
//!   raw input without panicking.
//! - [`RecoveryCode::parse`] (`RVR1-` prefix): the same round trip.
//!
//! These parsers take text a user types or pastes, and read it leniently (any case, `O` as `0`,
//! `I` and `L` as `1`, dashes and spaces ignored), so many inputs map to one code. The fuzzed
//! codes are not real secrets; `expose_secret()` is called only to compare them.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::secret_key::{RecoveryCode, SecretKey};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(sk) = SecretKey::parse(text) {
        let again = SecretKey::parse(&sk.to_formatted()).expect("a formatted key parses");
        assert_eq!(again.expose_secret(), sk.expose_secret());
        let _ = sk.matches_last_group(text);
    }
    if let Ok(code) = RecoveryCode::parse(text) {
        let again = RecoveryCode::parse(&code.to_formatted()).expect("a formatted code parses");
        assert_eq!(again.expose_secret(), code.expose_secret());
    }
});

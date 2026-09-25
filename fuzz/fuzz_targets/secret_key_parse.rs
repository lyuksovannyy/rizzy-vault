//! Fuzzes the Secret Key and recovery-code parsers (CRYPTO.md §7, §15 item 7): never panic, and
//! an accepted code formats and parses back to the same 16 bytes.
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

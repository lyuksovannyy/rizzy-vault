//! Fuzzes the login-name and server-origin normalisers (CRYPTO.md §2): never panic, and each is
//! idempotent on what it accepts.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::normalize::{LoginName, ServerOrigin};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(name) = LoginName::parse(text) {
        assert_eq!(LoginName::parse(name.as_str()).as_ref(), Ok(&name));
    }
    if let Ok(origin) = ServerOrigin::parse(text) {
        assert_eq!(ServerOrigin::parse(origin.as_str()).as_ref(), Ok(&origin));
    }
});

//! Fuzzes the login-name and server-origin normalisers (CRYPTO.md §2): never panic, and each is
//! idempotent on what it accepts.
//!
//! Non-UTF-8 input is skipped, because both functions take `&str`. For each input:
//!
//! - [`LoginName::parse`]: if it accepts, parsing the normalised form again must give the same
//!   value. The account lookup, the uniqueness check and the fake credential id all use this
//!   one string (§5.9), so a second normalisation that changed it would split one account in
//!   two.
//! - [`ServerOrigin::parse`]: the same property for the canonical origin that is bound into the
//!   OPAQUE Context (§5.3) and device authentication (§5.10). A non-idempotent origin would make
//!   client and server disagree on the binding.
//!
//! Both inputs arrive from users and from API bodies, so a panic here is a remote crash.
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

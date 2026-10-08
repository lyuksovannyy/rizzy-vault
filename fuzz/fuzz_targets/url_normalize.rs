//! Fuzzes `rizzy-match`'s URL and bare-domain normalisers (ADR 0037 §2): never panic, and
//! [`NormalizedUrl::parse`] is idempotent on what it accepts (normalising its own
//! `normalized_string()` output again must give the same value and the same string back —
//! `rizzy-client`'s match decision relies on this to compare two normalisations of the same
//! input consistently).
//!
//! Non-UTF-8 input is skipped, because both functions take `&str`. A URL arrives from an
//! item's `uri/<id>/value` and from the page a user is on, so a panic here is a crash from
//! untrusted input in a security-sensitive path (phishing-relevant matching, ADR 0037 §1).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_match::normalize::{normalize_domain, NormalizedUrl};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(first) = NormalizedUrl::parse(text) {
        let normalized = first.normalized_string();
        let again = NormalizedUrl::parse(&normalized)
            .expect("a URL this crate just normalised must normalise again");
        assert_eq!(first, again);
        assert_eq!(normalized, again.normalized_string());
    }
    if let Ok(domain) = normalize_domain(text) {
        assert_eq!(normalize_domain(&domain).as_deref(), Ok(domain.as_str()));
    }
});

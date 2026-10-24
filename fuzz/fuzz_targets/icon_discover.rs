// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the `icons` role's discovery and URL handling (ADR 0052 points 2–3; INV-51): a page
//! and its `Location` headers are attacker-chosen.
//!
//! On arbitrary bytes as a page: `icon_hrefs` never panics and returns at most
//! `MAX_CANDIDATES` non-empty `href`s of at most `MAX_REFERENCE_LEN` bytes, none ending in
//! `.svg`. Each, and the input itself as a `Location`, resolves against a base request either
//! to an error or to a target that is `http` or `https`, on port 80 or 443, with an RFC 1123
//! host and a path of accepted characters that starts with `/`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_icon_proxy::discover::{MAX_CANDIDATES, icon_hrefs};
use rizzy_icon_proxy::target::{MAX_REFERENCE_LEN, Scheme, Target};
use rizzy_proto::icons::{IconHost, is_valid_host};

fuzz_target!(|data: &[u8]| {
    let hrefs = icon_hrefs(data);
    assert!(hrefs.len() <= MAX_CANDIDATES);
    let host = IconHost::parse("example.com").expect("a valid host");
    let bases = [
        Target::origin(&host, Scheme::Https, "/dir/page?q"),
        Target::origin(&host, Scheme::Http, "/"),
    ];
    for href in &hrefs {
        assert!(!href.is_empty() && href.len() <= MAX_REFERENCE_LEN);
        assert!(href.is_ascii());
        for base in &bases {
            check(base, href);
        }
    }
    if let Ok(text) = core::str::from_utf8(data) {
        for base in &bases {
            check(base, text);
        }
    }
});

/// `reference` resolved against `base` is an error or an INV-51-shaped target.
fn check(base: &Target, reference: &str) {
    let Ok(t) = base.resolve(reference) else {
        return;
    };
    assert!(matches!(t.scheme(), Scheme::Http | Scheme::Https));
    assert!(t.port() == 80 || t.port() == 443);
    assert!(is_valid_host(t.host()));
    assert!(t.path().starts_with('/'));
    assert!(t.path().len() <= MAX_REFERENCE_LEN * 2);
    assert!(
        t.path()
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"\\\"<>{}|^`".contains(&b))
    );
    assert!(!t.path().contains('#'));
}

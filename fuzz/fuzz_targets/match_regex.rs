// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes `rizzy-match`'s *Regex* mode (ADR 0097 §3, §6 step 3): an arbitrary pattern and an
//! arbitrary page never panic, through [`pattern::compile`] alone and through [`decide`]
//! behind both gates; a pattern is only ever searched in a haystack of at most `MAX_URL_LEN`
//! (4,096) bytes; and a *Regex* `Match` implies the registrable-domain gate passed.
//!
//! The pattern is an item's `uri/<id>/pattern`, written by any writer of the item (a shared
//! vault member included), and the page is whatever site the user is on: both are untrusted.
//! Input layout: the first byte splits the rest into a pattern and a page, so the fuzzer
//! mutates both. Non-UTF-8 halves are skipped, because both are `&str`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_match::error::MAX_URL_LEN;
use rizzy_match::pattern::{compile, is_anchored, RegexSession};
use rizzy_match::{decide, EquivalenceView, MatchMode, MatchOutcome, NormalizedUrl};

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let split = usize::from(split).min(rest.len());
    let (pattern, page) = rest.split_at(split);
    let (Ok(pattern), Ok(page)) = (core::str::from_utf8(pattern), core::str::from_utf8(page)) else {
        return;
    };

    // The editor's path: compile and the anchoring check alone.
    let _ = is_anchored(pattern);
    if let Ok(compiled) = compile(pattern) {
        let haystack = page.get(..MAX_URL_LEN.min(page.len())).unwrap_or("");
        let _ = compiled.is_match(haystack);
    }

    // The matching path: a page on its own site, through both gates.
    let Ok(page) = NormalizedUrl::parse(page) else {
        return;
    };
    let value = format!("{}://{}/", page.scheme().as_str(), page.host());
    let Ok(value) = NormalizedUrl::parse(&value) else {
        return;
    };
    let mut session = RegexSession::new();
    let outcome = decide(
        &page,
        &value,
        MatchMode::Regex,
        MatchMode::BaseDomain,
        &EquivalenceView::empty(),
        Some(pattern),
        &mut session,
    );
    if page.normalized_string().len() > MAX_URL_LEN {
        assert_eq!(outcome, MatchOutcome::NoMatch);
        assert_eq!(session.evaluations(), 0, "an oversize haystack is never searched");
    }
    if matches!(outcome, MatchOutcome::Match(_)) {
        assert!(page.registrable_domain().is_some());
        assert_eq!(page.registrable_domain(), value.registrable_domain());
    }

    // The gate: the same pattern against a foreign site's URI is never even evaluated.
    let Ok(foreign) = NormalizedUrl::parse("https://foreign.invalid-site.example/") else {
        return;
    };
    if foreign.registrable_domain() != page.registrable_domain() {
        let mut session = RegexSession::new();
        let outcome = decide(
            &page,
            &foreign,
            MatchMode::Regex,
            MatchMode::BaseDomain,
            &EquivalenceView::empty(),
            Some(pattern),
            &mut session,
        );
        assert_eq!(outcome, MatchOutcome::NoMatch);
        assert_eq!(session.evaluations(), 0);
    }
});

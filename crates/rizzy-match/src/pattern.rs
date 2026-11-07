// SPDX-License-Identifier: AGPL-3.0-only

//! The *Regex* match mode's patterns (ADR 0097 §3).
//!
//! A pattern is an item's `uri/<id>/pattern` field. It is untrusted input: any writer of the
//! item, including a shared-vault member, chooses it. So:
//!
//! - [`compile`] is the one validity check (ADR 0097 §3.3). The editor and [`crate::decide`]
//!   both call it. It refuses an empty, over-long ([`MAX_PATTERN_LEN`]) or non-printable-ASCII
//!   pattern before the regex builder sees it, and hands the rest to `regex-lite` with a
//!   program size limit and a nesting limit. `regex-lite` searches in linear time.
//! - [`RegexSession`] is the per-call budget (ADR 0097 §3.4): at most
//!   [`MAX_REGEX_EVALUATIONS`] *Regex* URIs per call, and a cache so identical pattern strings
//!   compile once. It lives only for one matching call; nothing is kept between calls.
//! - [`crate::decide`] runs the HTTPS→HTTP rule and the registrable-domain gate *before* it
//!   asks the session for anything, so a pattern on another site is never even compiled
//!   (ADR 0097 §3.2; INV-38).
//!
//! The pattern is searched in the page's normalised URL only (ADR 0097 §2), never in the saved
//! `value`. Matching is case-insensitive by default (ASCII only; the haystack is ASCII), and a
//! pattern may switch that off with `(?-i)`.

use core::fmt;
use std::collections::BTreeMap;

use regex_lite::{Regex, RegexBuilder};

use crate::error::{
    MAX_PATTERN_LEN, MAX_REGEX_EVALUATIONS, MAX_URL_LEN, PATTERN_NEST_LIMIT, PATTERN_SIZE_LIMIT,
    PatternError,
};

/// A compiled, valid *Regex* pattern (ADR 0097 §3.3).
#[derive(Clone)]
pub struct Pattern(Regex);

impl Pattern {
    /// Whether the pattern matches anywhere in `haystack` (a search; it matches the whole
    /// haystack only if it anchors itself).
    #[must_use]
    pub fn is_match(&self, haystack: &str) -> bool {
        self.0.is_match(haystack)
    }
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pattern(..)")
    }
}

/// Compiles `pattern` with exactly ADR 0097 §3.3's builder, after its length and ASCII checks.
///
/// # Errors
///
/// [`PatternError::Empty`] for `""`, [`PatternError::TooLong`] above [`MAX_PATTERN_LEN`]
/// bytes, [`PatternError::NotAscii`] for any byte outside `0x20`–`0x7E`, and
/// [`PatternError::Invalid`] for every error of the builder (syntax, size limit, nesting
/// limit).
pub fn compile(pattern: &str) -> Result<Pattern, PatternError> {
    if pattern.is_empty() {
        return Err(PatternError::Empty);
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(PatternError::TooLong);
    }
    if !pattern.bytes().all(|byte| (0x20..=0x7E).contains(&byte)) {
        return Err(PatternError::NotAscii);
    }
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(PATTERN_SIZE_LIMIT)
        .nest_limit(PATTERN_NEST_LIMIT)
        .build()
        .map(Pattern)
        .map_err(|_| PatternError::Invalid)
}

/// Whether `pattern` anchors itself at the start of the address (ADR 0097 §3.6): after any
/// leading inline-flag groups of the form `(?flags)` (flags from `imsUxR-`), it begins with
/// `^` or `\A`. The editor warns about an unanchored pattern but still saves it.
#[must_use]
pub fn is_anchored(pattern: &str) -> bool {
    let mut rest = pattern;
    while let Some(after) = rest.strip_prefix("(?") {
        let flags_rest = after.trim_start_matches(['i', 'm', 's', 'U', 'x', 'R', '-']);
        match flags_rest.strip_prefix(')') {
            Some(next) => rest = next,
            None => break,
        }
    }
    rest.starts_with('^') || rest.starts_with("\\A")
}

/// What [`RegexSession::evaluate`] decided for one URI (ADR 0097 §3.2 steps 4–7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegexEvaluation {
    /// The pattern matched the page.
    Match,
    /// The pattern did not match, or the page's normalised URL is over [`MAX_URL_LEN`].
    NoMatch,
    /// The pattern is not valid ([`compile`]).
    InvalidPattern,
    /// This session already evaluated [`MAX_REGEX_EVALUATIONS`] URIs.
    BudgetExceeded,
}

/// The per-call *Regex* budget and compile cache (ADR 0097 §3.4).
///
/// A host's matching call creates one, passes it to every [`crate::decide`] of that call, and
/// drops it at the end. Only URIs that already passed the HTTPS→HTTP rule and the
/// registrable-domain gate reach it, so patterns for other sites cost nothing.
#[derive(Default)]
pub struct RegexSession {
    evaluations: usize,
    cache: BTreeMap<String, Result<Pattern, PatternError>>,
}

impl fmt::Debug for RegexSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegexSession")
            .field("evaluations", &self.evaluations)
            .field("compiled", &self.cache.len())
            .finish()
    }
}

impl RegexSession {
    /// A fresh session with its whole budget.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many URIs this session has taken past the budget check (ADR 0097 §3.2 step 5).
    #[must_use]
    pub const fn evaluations(&self) -> usize {
        self.evaluations
    }

    /// Whether a further URI would be refused as over budget.
    #[must_use]
    pub const fn is_spent(&self) -> bool {
        self.evaluations >= MAX_REGEX_EVALUATIONS
    }

    /// ADR 0097 §3.2 steps 4–7 for one URI that already passed the gates: the haystack length,
    /// the budget, validity, then the search. `pattern` is the URI's raw `uri/<id>/pattern`;
    /// `None` (absent or `Cleared`) is invalid, and still counts against the budget.
    pub fn evaluate(
        &mut self,
        pattern: Option<&str>,
        page_normalised_url: &str,
    ) -> RegexEvaluation {
        if page_normalised_url.len() > MAX_URL_LEN {
            return RegexEvaluation::NoMatch;
        }
        if self.is_spent() {
            return RegexEvaluation::BudgetExceeded;
        }
        self.evaluations = self.evaluations.saturating_add(1);
        let pattern = pattern.unwrap_or("");
        let compiled = match self.cache.get(pattern) {
            Some(cached) => cached,
            None => self
                .cache
                .entry(String::from(pattern))
                .or_insert_with(|| compile(pattern)),
        };
        match compiled {
            Ok(regex) if regex.is_match(page_normalised_url) => RegexEvaluation::Match,
            Ok(_) => RegexEvaluation::NoMatch,
            Err(_) => RegexEvaluation::InvalidPattern,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_limits() {
        // A 1,024-byte pattern that also fits PATTERN_SIZE_LIMIT. (1,024 case-insensitive
        // literals do not: they exceed the program size limit and are `Invalid`.)
        let ok = format!("(?-i){}", "a".repeat(MAX_PATTERN_LEN - 5));
        assert_eq!(ok.len(), MAX_PATTERN_LEN);
        assert!(compile(&ok).is_ok());
        assert_eq!(
            compile(&"a".repeat(MAX_PATTERN_LEN)).unwrap_err(),
            PatternError::Invalid
        );
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert_eq!(compile(&long).unwrap_err(), PatternError::TooLong);
        assert_eq!(compile("").unwrap_err(), PatternError::Empty);
    }

    #[test]
    fn refusals_are_invalid_pattern() {
        assert_eq!(compile("caf\u{e9}").unwrap_err(), PatternError::NotAscii);
        assert_eq!(compile("a\tb").unwrap_err(), PatternError::NotAscii);
        for invalid in [
            r"\p{L}",
            r"foo(?=bar)",
            r"(?<!x)y",
            r"(a)\1",
            "[a-z]{5000}",
            "(",
            "a{2,1}",
        ] {
            assert_eq!(
                compile(invalid).unwrap_err(),
                PatternError::Invalid,
                "{invalid}"
            );
        }
        let nested = format!("{}a{}", "(".repeat(40), ")".repeat(40));
        assert_eq!(compile(&nested).unwrap_err(), PatternError::Invalid);
    }

    #[test]
    fn case_insensitive_by_default() {
        assert!(
            compile(r"^HTTPS://EXAMPLE\.COM/")
                .unwrap()
                .is_match("https://example.com/")
        );
        assert!(
            !compile(r"(?-i)^HTTPS://")
                .unwrap()
                .is_match("https://example.com/")
        );
    }

    #[test]
    fn anchoring() {
        assert!(is_anchored("^https://"));
        assert!(is_anchored(r"\Ahttps://"));
        assert!(is_anchored("(?i)^https://"));
        assert!(is_anchored("(?-i)(?x)^https://"));
        assert!(!is_anchored("https://"));
        assert!(!is_anchored("(?i)https://"));
        assert!(!is_anchored("(?:^a)"));
        assert!(!is_anchored("(?i"));
        assert!(!is_anchored(""));
    }

    #[test]
    fn budget_counts_every_evaluation_and_caches() {
        let mut session = RegexSession::new();
        for _ in 0..MAX_REGEX_EVALUATIONS {
            assert_eq!(
                session.evaluate(Some("example"), "https://example.com/"),
                RegexEvaluation::Match
            );
        }
        assert_eq!(session.cache.len(), 1);
        assert_eq!(
            session.evaluate(Some("example"), "https://example.com/"),
            RegexEvaluation::BudgetExceeded
        );
    }

    #[test]
    fn invalid_and_absent_patterns_count_against_the_budget() {
        let mut session = RegexSession::new();
        assert_eq!(
            session.evaluate(None, "https://example.com/"),
            RegexEvaluation::InvalidPattern
        );
        assert_eq!(
            session.evaluate(Some("("), "https://example.com/"),
            RegexEvaluation::InvalidPattern
        );
        assert_eq!(session.evaluations(), 2);
    }

    #[test]
    fn an_oversize_haystack_is_no_match_without_spending_budget() {
        let mut session = RegexSession::new();
        let page = format!("https://example.com/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(
            session.evaluate(Some(".*"), &page),
            RegexEvaluation::NoMatch
        );
        assert_eq!(session.evaluations(), 0);
    }

    #[test]
    fn debug_never_shows_the_pattern() {
        let mut session = RegexSession::new();
        let _ = session.evaluate(Some("secretish"), "https://example.com/");
        assert!(!format!("{session:?}").contains("secretish"));
        assert!(!format!("{:?}", compile("secretish").unwrap()).contains("secretish"));
    }
}

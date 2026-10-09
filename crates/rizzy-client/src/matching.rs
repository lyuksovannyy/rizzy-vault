//! URL matching for autofill (ADR 0037, ADR 0038), over `rizzy-match`.
//!
//! [ADR 0016] §3's row for `rizzy-client` plans `rizzy-match` as an internal dependency, and
//! [ADR 0037] §3 says it plainly: "every client (web vault, extension, CLI, and later
//! desktop/mobile) calls the same `rizzy-match` functions through `rizzy-client`." This module
//! is that call: it re-exports `rizzy-match`'s pure types unchanged ([`EquivalenceView`],
//! [`MatchMode`], [`MatchOutcome`], [`MatchedVia`], [`NormalizedUrl`]) and adds exactly the
//! batching and frame-narrowing glue a host needs that is not itself a per-URL decision:
//!
//! - looping [`rizzy_match::decide`] over every saved URI of the items a host is offering for
//!   autofill, instead of one call per URI (ADR 0037 §4);
//! - the frame-narrowing gate of ADR 0037 §5: "same registrable domain" top-frame iframes are
//!   treated as the top frame; any other iframe gets no automatic candidates. This is narrowing
//!   only (INV-38): it can only remove candidates the registrable-domain gate already allowed,
//!   never add one.
//!
//! No new decision is made here: [`decide_candidates`] never widens what
//! [`rizzy_match::modes::decide`] would return for a single (page, URI) pair; it only decides
//! which pairs to ask and whether to ask at all for this frame. Still no I/O, no randomness,
//! builds for `wasm32-unknown-unknown` (inherits `rizzy-match`'s and `rizzy-core`'s R1
//! properties; ADR 0016 §4 R1).
//!
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0037]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0037-url-matching-and-autofill-rules.md

pub use rizzy_match::{
    EquivalenceGroup, EquivalenceList, EquivalenceView, GroupId, MatchMode, MatchOutcome,
    MatchedVia, NormalizedUrl, Scheme, normalize_domain,
};

use crate::error::ClientError;

/// The compiled-in global equivalence list's groups (ADR 0038 §1–§2, §7; gap 27(a) in the M2
/// gap audit), or empty when none is compiled in yet, or when a compiled-in list fails to
/// verify.
///
/// **Only the global-list half of ADR 0038 §5's merged view is wired here.** The account's own
/// disabled-global-group set and user-defined groups are a separate, larger gap (27(b)/"G3" in
/// the audit): reading them needs `ACCOUNT_SETTINGS`'s plaintext layout, which [ADR 0042] has
/// not fixed yet (`Status: Proposed`). Until it lands, a caller passes this function's result
/// as the `global` slice of [`EquivalenceView::new`] with an empty `disabled_global` set and an
/// empty `user_defined` slice — exactly what [`EquivalenceView::empty`] in all other respects,
/// widened only by whatever the compiled-in global list itself allows.
///
/// **`highest_accepted_version` is always `0`.** Persisting the caller's highest accepted
/// `list_version` across launches (INV-39) is gap 27(b), which needs a new ADR: [ADR 0026]'s
/// `cache_meta` format (Accepted) has no field for it, and CLAUDE.md requires an Accepted ADR
/// for a persistent-format change. `0` is the value [`rizzy_match::compiled::global_list`]'s
/// own docs name for "a caller that has never accepted any list," so this is the correct,
/// conservative value to pass until that ADR exists — never a placeholder. The practical effect
/// today is nil either way: [`rizzy_match::compiled::GLOBAL_LIST`] is `None`, so
/// `global_list` always returns `Ok(None)` regardless of the version passed in.
///
/// **A list that fails verification is treated as absent, not as a hard error.** ADR 0038 §1
/// already requires rejecting an unsigned list; extending that to a structurally invalid,
/// badly-signed or stale compiled-in list means a corrupt constant narrows matching back to
/// plain registrable-domain equality for that process's lifetime rather than breaking autofill
/// entirely. This is unreachable while `GLOBAL_LIST` is `None`.
///
/// [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
/// [ADR 0042]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0042-account-settings-matching-layout.md
#[must_use]
pub fn global_equivalence_groups() -> Vec<EquivalenceGroup> {
    rizzy_match::compiled::global_list(0)
        .ok()
        .flatten()
        .map(|list| list.groups().to_vec())
        .unwrap_or_default()
}

/// One saved URI to match against (ADR 0037 §2, §4): an item's `uri/<id>`.
#[derive(Clone, Copy, Debug)]
pub struct ItemUri<'a> {
    /// The item this URI belongs to.
    pub item_id: [u8; 16],
    /// The URI's own id (an item may hold several).
    pub uri_id: [u8; 16],
    /// The saved string: a URL for every mode but *Regex*, where it is the pattern source
    /// (ADR 0037 §4 row `0x0005`; not evaluated by this build, `rizzy_match::modes::decide`
    /// already refuses it as [`MatchOutcome::NotSupported`]).
    pub value: &'a str,
    /// The URI's own match mode; `0x0000` resolves against `account_default` inside
    /// [`rizzy_match::modes::decide`].
    pub mode: MatchMode,
}

/// What the content script reports about the frame asking for candidates (ADR 0037 §5).
#[derive(Clone, Copy, Debug)]
pub struct FrameContext<'a> {
    /// Whether this is the page's top frame.
    pub is_top_frame: bool,
    /// This frame's own origin (`scheme://host[:port]`), as the browser reports it. Unused,
    /// and never read, when `is_top_frame` is `true`.
    pub frame_origin: &'a str,
}

/// One candidate offered for autofill: a saved URI that matched, and why.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// The matching item.
    pub item_id: [u8; 16],
    /// The matching URI.
    pub uri_id: [u8; 16],
    /// Why it matched, and whether the equivalence warning is needed
    /// ([`MatchedVia::needs_warning`]).
    pub matched_via: MatchedVia,
    /// The saved URI's own exact normalised host, A-label form (ADR 0037 §5 "Exact host
    /// shown"; §2 point 4). The fill UI shows this as "the saved site" in the equivalence-only
    /// warning — never decoded to Unicode outside `rizzy-match`, so a mixed-script host still
    /// displays in its punycode `xn--` form.
    pub saved_host: String,
}

/// Why no candidate was offered for one URI, or for the frame as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skipped {
    /// `rizzy_match::modes::decide` returned [`MatchOutcome::NoMatch`].
    NoMatch,
    /// The URI is *Regex* mode, which this build cannot evaluate.
    RegexNotSupported,
    /// The saved URI did not parse as a normalised URL (ADR 0037 §2).
    UriDidNotNormalize,
}

/// The result of one [`decide_candidates`] call.
#[derive(Debug, Default)]
pub struct Decision {
    /// The page's own exact normalised host, A-label form (ADR 0037 §5 "Exact host shown").
    /// Empty only in the never-reached `Default` value; every value this module returns from
    /// [`decide_candidates`] fills it from the already-parsed, already-validated page URL.
    pub page_host: String,
    /// Every URI that matched, in the order given.
    pub candidates: Vec<Candidate>,
    /// One line per URI this build could not evaluate or that did not match for a reason worth
    /// surfacing (never for a plain [`MatchOutcome::NoMatch`], which is the common case and
    /// not a warning); and the one line of the frame-narrowing gate when it applies.
    pub warnings: Vec<&'static str>,
}

/// Decides which of `item_uris` are autofill candidates for `page_url`, requested by `frame`
/// (ADR 0037 §4, §5; module docs).
///
/// # Errors
/// [`ClientError::InvalidInput`] if `page_url` does not parse as a normalised URL
/// ([`NormalizedUrl::parse`]); never for a saved URI that fails to parse, which is reported as
/// [`Skipped::UriDidNotNormalize`] in `warnings` instead (a user's bad legacy entry must not
/// fail every other item's candidates).
pub fn decide_candidates(
    page_url: &str,
    frame: &FrameContext<'_>,
    account_default: MatchMode,
    item_uris: &[ItemUri<'_>],
    equivalence: &EquivalenceView<'_>,
) -> Result<Decision, ClientError> {
    let page = NormalizedUrl::parse(page_url).map_err(|_| ClientError::InvalidInput)?;
    let mut out = Decision {
        page_host: page.host().to_owned(),
        ..Decision::default()
    };
    // ADR 0037 §5: a non-top frame gets automatic candidates only when it shares the page's
    // registrable domain; any other frame is narrowed to none, with one explanatory warning
    // (never silently, and never by guessing a candidate it cannot defend).
    if !frame.is_top_frame {
        let same = NormalizedUrl::parse(frame.frame_origin)
            .ok()
            .is_some_and(|f| {
                page.registrable_domain().is_some()
                    && f.registrable_domain() == page.registrable_domain()
            });
        if !same {
            out.warnings.push(
                "matching: frame is not the top frame and does not share its registrable domain; no automatic candidates",
            );
            return Ok(out);
        }
    }
    for item_uri in item_uris {
        let Ok(uri) = NormalizedUrl::parse(item_uri.value) else {
            out.warnings
                .push("matching: a saved URI did not normalise and was skipped");
            continue;
        };
        match rizzy_match::decide(&page, &uri, item_uri.mode, account_default, equivalence) {
            MatchOutcome::Match(matched_via) => out.candidates.push(Candidate {
                item_id: item_uri.item_id,
                uri_id: item_uri.uri_id,
                matched_via,
                saved_host: uri.host().to_owned(),
            }),
            MatchOutcome::NoMatch => {}
            MatchOutcome::NotSupported => {
                out.warnings
                    .push("matching: a saved URI uses Regex mode, not supported by this build");
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn uri(value: &str, mode: MatchMode) -> ItemUri<'_> {
        ItemUri {
            item_id: [1; 16],
            uri_id: [2; 16],
            value,
            mode,
        }
    }

    fn top(origin: &str) -> FrameContext<'_> {
        FrameContext {
            is_top_frame: true,
            frame_origin: origin,
        }
    }

    #[test]
    fn same_registrable_domain_matches_by_default() {
        let equivalence = EquivalenceView::empty();
        let uris = [uri(
            "https://login.example.com/signin",
            MatchMode::BaseDomain,
        )];
        let decision = decide_candidates(
            "https://example.com/",
            &top(""),
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert_eq!(decision.candidates.len(), 1);
        assert!(decision.warnings.is_empty());
        assert_eq!(
            decision.candidates[0].matched_via,
            MatchedVia::RegistrableDomain
        );
        assert_eq!(decision.page_host, "example.com");
        assert_eq!(decision.candidates[0].saved_host, "login.example.com");
    }

    #[test]
    fn different_domain_has_no_candidate_and_no_warning() {
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://other.example/", MatchMode::BaseDomain)];
        let decision = decide_candidates(
            "https://example.com/",
            &top(""),
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert!(decision.candidates.is_empty());
        assert!(decision.warnings.is_empty());
    }

    #[test]
    fn regex_mode_is_reported_not_matched() {
        let equivalence = EquivalenceView::empty();
        let uris = [uri("not a real pattern", MatchMode::Regex)];
        let decision = decide_candidates(
            "https://example.com/",
            &top(""),
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert!(decision.candidates.is_empty());
        assert_eq!(decision.warnings.len(), 1);
    }

    #[test]
    fn a_saved_uri_that_does_not_normalize_is_skipped_not_fatal() {
        let equivalence = EquivalenceView::empty();
        let uris = [
            uri("not a url at all", MatchMode::BaseDomain),
            uri("https://example.com/other", MatchMode::BaseDomain),
        ];
        let decision = decide_candidates(
            "https://example.com/",
            &top(""),
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert_eq!(decision.candidates.len(), 1);
        assert_eq!(decision.warnings.len(), 1);
    }

    #[test]
    fn a_non_top_frame_on_another_domain_is_narrowed_to_no_candidates() {
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://example.com/", MatchMode::BaseDomain)];
        let frame = FrameContext {
            is_top_frame: false,
            frame_origin: "https://attacker.example/",
        };
        let decision = decide_candidates(
            "https://example.com/",
            &frame,
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert!(decision.candidates.is_empty());
        assert_eq!(decision.warnings.len(), 1);
    }

    #[test]
    fn a_non_top_frame_on_the_same_domain_is_treated_as_top() {
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://example.com/", MatchMode::BaseDomain)];
        let frame = FrameContext {
            is_top_frame: false,
            frame_origin: "https://pay.example.com/",
        };
        let decision = decide_candidates(
            "https://example.com/",
            &frame,
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert_eq!(decision.candidates.len(), 1);
        assert!(decision.warnings.is_empty());
    }

    #[test]
    fn a_page_url_that_does_not_normalize_is_invalid_input() {
        let equivalence = EquivalenceView::empty();
        let disabled: BTreeSet<GroupId> = BTreeSet::new();
        let _ = &disabled; // exercised via EquivalenceView::empty() above; kept for doc clarity.
        let error = decide_candidates(
            "not a url",
            &top(""),
            MatchMode::BaseDomain,
            &[],
            &equivalence,
        )
        .unwrap_err();
        assert_eq!(error, ClientError::InvalidInput);
    }

    /// `rizzy_match::compiled::GLOBAL_LIST` is `None` today (no production list-signing key
    /// exists yet), so [`global_equivalence_groups`] must return an empty `Vec`, never a
    /// placeholder or an error.
    #[test]
    fn global_equivalence_groups_is_empty_while_no_list_is_compiled_in() {
        assert!(global_equivalence_groups().is_empty());
    }

    /// The merge path a production caller would exercise once a list *is* compiled in: a
    /// global group, fed through [`EquivalenceView::new`] exactly as a caller would pass
    /// [`global_equivalence_groups`]'s result as the `global` slice (with no disabled groups
    /// and no user-defined groups, since the account-settings half is out of scope here),
    /// still produces an `Equivalence` candidate that needs the ADR 0037 §5 warning. This
    /// cannot go through `global_equivalence_groups` itself (no real signed list exists to
    /// compile in), so it builds the view from a fixture group directly, the same shape
    /// `EquivalenceList::groups()` would hand back.
    #[test]
    fn a_fixture_global_group_still_produces_a_warned_equivalence_candidate() {
        let global = vec![
            EquivalenceGroup::new(
                GroupId::from_bytes([7; 16]),
                ["example.com", "example.net"],
                false,
            )
            .unwrap(),
        ];
        let disabled: BTreeSet<GroupId> = BTreeSet::new();
        let user_defined: Vec<EquivalenceGroup> = Vec::new();
        let equivalence = EquivalenceView::new(&global, &disabled, &user_defined);

        let uris = [uri("https://example.net/login", MatchMode::BaseDomain)];
        let decision = decide_candidates(
            "https://example.com/",
            &top(""),
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert_eq!(decision.candidates.len(), 1);
        assert!(decision.candidates[0].matched_via.needs_warning());
        assert_eq!(
            decision.candidates[0].matched_via,
            MatchedVia::Equivalence(GroupId::from_bytes([7; 16]))
        );
        // ADR 0037 §5 "Exact host shown": the fill UI needs both hosts to name the matched
        // site and the saved site in the equivalence-only warning.
        assert_eq!(decision.page_host, "example.com");
        assert_eq!(decision.candidates[0].saved_host, "example.net");
    }
}

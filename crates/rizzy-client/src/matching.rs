// SPDX-License-Identifier: AGPL-3.0-only

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
//! - the frame-narrowing gate of ADR 0037 §5: a *same-origin* (scheme, host and port all equal)
//!   non-top-frame iframe is treated as the top frame; any other iframe gets no automatic
//!   candidates. Same-registrable-domain is explicitly **not** enough (§5: relaxing it that way
//!   "is a later, explicitly reviewed change, not an implicit consequence of Base domain
//!   matching"). This is narrowing only (INV-38): it can only remove candidates the
//!   registrable-domain gate already allowed, never add one.
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

use rizzy_match::security::frame_may_request_candidates;

use rizzy_core::item::schema::{ATTR_MATCH, ATTR_VALUE, LIST_URI};
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::ValueRef;
use rizzy_sync::merge::ItemLifecycle;
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::settings::AccountSettingsRecord;
use crate::sync::VaultSync;

/// The compiled-in global equivalence list's groups (ADR 0038 §1–§2, §7), and the new floor a
/// host must persist ([ADR 0051] §4).
///
/// **This is the global-list half of ADR 0038 §5's merged view.** The account's own
/// disabled-global-group set and user-defined groups come from `ACCOUNT_SETTINGS` ([ADR 0042]
/// §3): [`decide_with_settings`] builds the merged view from this function's result and the
/// account's [`crate::settings::AccountSettingsRecord`].
///
/// `highest_accepted_version` is the caller's persisted floor (INV-39): the
/// `highest_equivalence_list_version` row of its cache ([`crate::store::floors::Floors::highest_equivalence_list_version`]),
/// or `0` for a host that keeps no cache (the web vault, ADR 0051 §5). The first slot is the
/// list's groups when [`rizzy_match::compiled::global_list`] verifies one, and empty when none
/// is compiled in or verification fails for any reason (bad signature, malformed, wrong key,
/// or `NotNewer`, which narrows matching to plain registrable-domain equality: the intended
/// effect of the no-downgrade rule, ADR 0051 §3; ADR 0044 "A PSL bump"). The second slot is
/// `Some(list_version)` only for a verified list strictly newer than `highest_accepted_version`:
/// the value the host writes back, once, in its load transaction (point 3); every other case
/// is `None` and the stored value is left untouched. [`startup_equivalence_groups`] does both
/// for a host with a cache.
///
/// **Call it once per session or process, at startup**, never per decision (ADR 0051 §4): the
/// compiled-in list cannot change while a process runs, so the groups are kept in memory and
/// passed to every later decision.
///
/// [ADR 0042]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0042-account-settings-matching-layout.md
/// [ADR 0051]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0051-equivalence-list-version-persistence.md
#[must_use]
pub fn global_equivalence_groups(
    highest_accepted_version: u32,
) -> (Vec<EquivalenceGroup>, Option<u32>) {
    groups_and_new_floor(
        rizzy_match::compiled::global_list(highest_accepted_version),
        highest_accepted_version,
    )
}

/// [`global_equivalence_groups`]'s decision over one [`rizzy_match::compiled::global_list`]
/// result, separate so it can be tested with a list signed by a test key.
fn groups_and_new_floor(
    verified: Result<Option<EquivalenceList>, rizzy_match::EquivalenceListError>,
    highest_accepted_version: u32,
) -> (Vec<EquivalenceGroup>, Option<u32>) {
    match verified {
        Ok(Some(list)) => {
            let raised =
                (list.list_version() > highest_accepted_version).then(|| list.list_version());
            (list.groups().to_vec(), raised)
        }
        Ok(None) | Err(_) => (Vec::new(), None),
    }
}

/// The startup step of ADR 0051 §4 for a host with a cache: reads the floor from `floors` (the
/// [`crate::store::load::Loaded::floors`] of the load), calls [`global_equivalence_groups`],
/// and returns its groups (to keep in memory for the session) with the changeset that persists a
/// raised floor: one `Write::Meta` of `highest_equivalence_list_version`, or nothing. The host
/// passes the changeset through [`crate::store::floors::Floors::admit`] and commits it with the
/// load (INV-75: a crash before the commit only re-verifies the same list at the next load).
#[must_use]
pub fn startup_equivalence_groups(
    floors: &crate::store::floors::Floors,
) -> (Vec<EquivalenceGroup>, crate::store::rows::Changeset) {
    let (groups, raised) = global_equivalence_groups(floors.highest_equivalence_list_version());
    (groups, floor_writes(raised))
}

/// The write that persists a raised floor (ADR 0051 §1, §3), or an empty changeset.
fn floor_writes(raised: Option<u32>) -> crate::store::rows::Changeset {
    let mut changeset = crate::store::rows::Changeset::new();
    if let Some(version) = raised {
        changeset.push(crate::store::rows::Write::Meta {
            key: crate::store::rows::meta::HIGHEST_EQUIVALENCE_LIST_VERSION,
            value: u64::from(version).to_be_bytes().to_vec(),
        });
    }
    changeset
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
    /// The saved URI's own port, only when it is not its scheme's default (ADR 0037 §2 rule 5;
    /// [`NormalizedUrl::port`]). A caller that needs "the same site, not merely the same host"
    /// for a destructive decision (an update-vs-save gate, never autofill itself, which is
    /// `BaseDomain`-mode narrowing-only by design) must compare this alongside `saved_host`
    /// against the page's own [`Decision::page_port`] — `saved_host` alone is exactly the gap
    /// `rizzy_match::modes::decide`'s `Host` mode fix closes: two different ports on the same
    /// host are two different sites.
    pub saved_port: Option<u16>,
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
    /// The page's own port, only when it is not its scheme's default ([`Candidate::saved_port`]
    /// explains why a caller doing "same site" for a destructive decision must compare this
    /// too, not `page_host` alone).
    pub page_port: Option<u16>,
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
        page_port: page.port(),
        ..Decision::default()
    };
    // ADR 0037 §5 (INV-37): a non-top frame gets automatic candidates only when it is
    // same-origin with the page (scheme, host and port all equal) — not merely same
    // registrable domain, which §5 explicitly reserves for "a later, explicitly reviewed
    // change, not an implicit consequence of Base domain matching". Any other frame is
    // narrowed to none, with one explanatory warning (never silently, and never by guessing a
    // candidate it cannot defend). The same-origin boolean itself is computed here (rizzy-match
    // has no frame-origin string parsing of its own to compare), but the resulting policy
    // decision is `rizzy-match`'s own function, not a convention left to this caller (ADR 0037
    // §5: "a `rizzy-match` function, not a convention left to callers").
    if !frame.is_top_frame {
        let same_origin = NormalizedUrl::parse(frame.frame_origin)
            .ok()
            .is_some_and(|f| {
                f.scheme() == page.scheme() && f.host() == page.host() && f.port() == page.port()
            });
        if !frame_may_request_candidates(same_origin) {
            out.warnings.push(
                "matching: frame is not the top frame and is not same-origin with it; no automatic candidates",
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
                saved_port: uri.port(),
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

/// [`decide_candidates`] under the account's own settings (ADR 0042 §3, §6; ADR 0037 §6–§7): the
/// account-level match default resolves every `0x0000` URI mode, and the merged view is the
/// compiled-in global list's groups `global` (the session's in-memory result of
/// [`global_equivalence_groups`], computed once at startup, ADR 0051 §4) minus the account's
/// disabled groups, plus its user-defined groups. Read `settings` with [`crate::settings::account_settings`] or a
/// [`crate::settings::SettingsCache`]; a record that does not read fails there, never here, so
/// no decision is ever made under settings this client could not read (`crate::settings` module
/// docs).
///
/// # Errors
/// As [`decide_candidates`].
pub fn decide_with_settings(
    page_url: &str,
    frame: &FrameContext<'_>,
    item_uris: &[ItemUri<'_>],
    settings: &AccountSettingsRecord,
    global: &[EquivalenceGroup],
) -> Result<Decision, ClientError> {
    let matching = settings.matching();
    decide_candidates(
        page_url,
        frame,
        matching.match_default(),
        item_uris,
        &matching.view(global),
    )
}

/// One saved URI of a vault item, owned, as [`vault_item_uris`] collects them: what an
/// [`ItemUri`] borrows ([`SavedUri::as_item_uri`]). The value is item data, so it wipes itself and
/// `Debug` shows nothing.
pub struct SavedUri {
    /// The item.
    pub item_id: [u8; 16],
    /// The URI's element id.
    pub uri_id: [u8; 16],
    /// `uri/<id>/value`.
    pub value: Zeroizing<String>,
    /// `uri/<id>/match`: [`MatchMode::AccountDefault`] when absent or cleared, and
    /// [`MatchMode::Never`] for a value this build does not know (`0x0007`+, written by a newer
    /// client; narrowing only, INV-38).
    pub mode: MatchMode,
}

impl core::fmt::Debug for SavedUri {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SavedUri([REDACTED])")
    }
}

impl SavedUri {
    /// The borrowed form [`decide_candidates`] takes.
    #[must_use]
    pub fn as_item_uri(&self) -> ItemUri<'_> {
        ItemUri {
            item_id: self.item_id,
            uri_id: self.uri_id,
            value: self.value.as_str(),
            mode: self.mode,
        }
    }
}

/// Every saved URI of every active item of `vault` (not trashed, not the vault-settings item),
/// in item and list order: the input of one autofill decision over the whole vault (ADR 0037 §4).
/// A URI without a text value is left out.
#[must_use]
pub fn vault_item_uris(vault: &VaultSync) -> Vec<SavedUri> {
    let mut out = Vec::new();
    for item in vault.item_ids() {
        if vault.item_lifecycle(item) != ItemLifecycle::Active
            || vault.item_type(item) == Some(ItemType::VAULT_SETTINGS)
        {
            continue;
        }
        for element in vault.list_elements(item, LIST_URI) {
            let Some(uri_id) = element_id(element.element.as_str()) else {
                continue;
            };
            let value_key = format!("{LIST_URI}/{}/{ATTR_VALUE}", element.element.as_str());
            let Some(value) = vault.field_value(item, &value_key) else {
                continue;
            };
            let Ok(ValueRef::Text(text)) = value.decode() else {
                continue;
            };
            let match_key = format!("{LIST_URI}/{}/{ATTR_MATCH}", element.element.as_str());
            let mode = match vault.field_value(item, &match_key).map(|v| {
                v.decode().ok().and_then(|r| match r {
                    ValueRef::Enum(n) => Some(n),
                    _ => None,
                })
            }) {
                None => MatchMode::AccountDefault,
                Some(Some(n)) => MatchMode::from_wire(n).unwrap_or(MatchMode::Never),
                Some(None) => MatchMode::Never,
            };
            out.push(SavedUri {
                item_id: *item.as_bytes(),
                uri_id,
                value: Zeroizing::new(text.to_owned()),
                mode,
            });
        }
    }
    out
}

/// A 16-byte element id from its 32 lowercase hex digits.
fn element_id(hex: &str) -> Option<[u8; 16]> {
    let digits = hex.as_bytes();
    if digits.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let nibble = |d: u8| match d {
            b'0'..=b'9' => Some(d - b'0'),
            b'a'..=b'f' => Some(d - b'a' + 10),
            _ => None,
        };
        if let [high, low] = pair {
            *byte = (nibble(*high)? << 4) | nibble(*low)?;
        }
    }
    Some(out)
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
    fn a_match_carries_the_page_and_saved_ports_for_a_host_gate_on_top() {
        // `decide_candidates` resolves every URI to `BaseDomain` (`sessionItemUris`'s own
        // choice in the extension), which is port-blind by design (ADR 0037 §4) — so a caller
        // doing a destructive "same site" decision on top (an update-vs-save gate, never
        // autofill) must use `page_port`/`saved_port`, not just `page_host`/`saved_host`, which
        // this test confirms are both threaded through for a page and a saved URI on different
        // explicit ports.
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://example.com:9000/login", MatchMode::BaseDomain)];
        let decision = decide_candidates(
            "https://example.com:8443/",
            &top(""),
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert_eq!(decision.candidates.len(), 1);
        assert_eq!(decision.page_port, Some(8443));
        assert_eq!(decision.candidates[0].saved_port, Some(9000));
        assert_ne!(decision.page_port, decision.candidates[0].saved_port);
    }

    #[test]
    fn a_default_port_decision_carries_no_port() {
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://example.com/login", MatchMode::BaseDomain)];
        let decision = decide_candidates(
            "https://example.com/",
            &top(""),
            MatchMode::BaseDomain,
            &uris,
            &equivalence,
        )
        .unwrap();
        assert_eq!(decision.page_port, None);
        assert_eq!(decision.candidates[0].saved_port, None);
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
    fn a_non_top_frame_on_the_same_registrable_domain_but_a_different_host_is_narrowed_to_no_candidates()
     {
        // ADR 0037 §5 (INV-37): "a same-origin iframe is treated as the top frame. A
        // cross-origin iframe gets no automatic candidate list... relaxing it for
        // same-registrable-domain iframes is a later, explicitly reviewed change." `pay.
        // example.com` is cross-origin to `example.com` (different host) even though both
        // share the registrable domain `example.com`, so this must get zero candidates, the
        // same as any other cross-origin iframe.
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
        assert!(decision.candidates.is_empty());
        assert_eq!(decision.warnings.len(), 1);
    }

    #[test]
    fn a_non_top_frame_that_is_cross_scheme_but_otherwise_identical_is_narrowed_to_no_candidates() {
        // Same host, same (default) port, different scheme: still cross-origin. Confirms the
        // gate compares the scheme too, not just host and port.
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://example.com/", MatchMode::BaseDomain)];
        let frame = FrameContext {
            is_top_frame: false,
            frame_origin: "http://example.com/",
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
    fn a_non_top_frame_that_is_truly_same_origin_is_treated_as_top() {
        // Exact scheme + host + port match: this is the one case ADR 0037 §5 actually grants
        // automatic candidates to for a non-top frame.
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://example.com/", MatchMode::BaseDomain)];
        let frame = FrameContext {
            is_top_frame: false,
            frame_origin: "https://example.com/some/path",
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
    fn a_non_top_frame_same_origin_on_an_explicit_non_default_port_is_treated_as_top() {
        // Same-origin still requires the port to match when one is explicit (ADR 0037 §2 rule
        // 5): confirms the gate does not drop the port half of the comparison.
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://example.com:8443/", MatchMode::BaseDomain)];
        let frame = FrameContext {
            is_top_frame: false,
            frame_origin: "https://example.com:8443/",
        };
        let decision = decide_candidates(
            "https://example.com:8443/",
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
    fn a_non_top_frame_same_host_but_a_different_explicit_port_is_narrowed_to_no_candidates() {
        let equivalence = EquivalenceView::empty();
        let uris = [uri("https://example.com:8443/", MatchMode::BaseDomain)];
        let frame = FrameContext {
            is_top_frame: false,
            frame_origin: "https://example.com:9000/",
        };
        let decision = decide_candidates(
            "https://example.com:8443/",
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
        assert_eq!(global_equivalence_groups(0), (Vec::new(), None));
        assert_eq!(global_equivalence_groups(u32::MAX), (Vec::new(), None));
        let (groups, writes) = startup_equivalence_groups(&crate::store::floors::Floors::empty());
        assert!(groups.is_empty());
        assert!(
            writes.is_empty(),
            "no list verified, so the floor is never written"
        );
    }

    /// `rizzy-match`'s known-answer list (`equivalence.rs`, `verify_known_answer_with_a_test_key`):
    /// `list_version` 1, one group, signed by a test key.
    fn known_answer_list(
        highest_accepted_version: u32,
    ) -> Result<Option<EquivalenceList>, rizzy_match::EquivalenceListError> {
        let hex = |text: &str| -> Vec<u8> {
            let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        };
        let key: [u8; 32] = hex("c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242")
            .try_into()
            .unwrap();
        let wire = hex(
            "0001000000010000018bcfe568000001010101010101010101010101010101\
             01000200000009 6170706c652e636f6d 0000000a 69636c6f75642e636f6d \
             00 3c1ba71349483563cbf92065d233029763443542d04721d6e1aa226a1722\
             ad3769496a230c9493d86df64e49c9d72ad9721588bf9f1d5e5c7424dc46c78\
             f500f",
        );
        EquivalenceList::verify(&wire, &key, highest_accepted_version).map(Some)
    }

    /// ADR 0051 §4: a verified, strictly newer list returns its groups and its version as the
    /// new floor; the same list against that floor is `NotNewer`: no groups, no write.
    #[test]
    fn a_newer_list_raises_the_floor_and_the_same_list_never_does_again() {
        let (groups, raised) = groups_and_new_floor(known_answer_list(0), 0);
        assert_eq!(raised, Some(1));
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].domains(), ["apple.com", "icloud.com"]);
        let floor = floor_writes(raised);
        assert_eq!(floor.writes().len(), 1);
        match &floor.writes()[0] {
            crate::store::rows::Write::Meta { key, value } => {
                assert_eq!(
                    *key,
                    crate::store::rows::meta::HIGHEST_EQUIVALENCE_LIST_VERSION
                );
                assert_eq!(
                    value.as_slice(),
                    [0, 0, 0, 0, 0, 0, 0, 1],
                    "zero-extended u64 BE"
                );
            }
            _ => panic!("not a meta write"),
        }

        // A restart with the persisted floor: the same (or a rolled-back, older) build's list
        // is refused, matching narrows to plain registrable-domain equality, nothing is written.
        assert_eq!(
            known_answer_list(1).unwrap_err(),
            rizzy_match::EquivalenceListError::NotNewer
        );
        assert_eq!(
            groups_and_new_floor(known_answer_list(1), 1),
            (Vec::new(), None)
        );
        assert_eq!(
            groups_and_new_floor(known_answer_list(7), 7),
            (Vec::new(), None)
        );
        assert!(floor_writes(None).is_empty());
    }

    /// Every failure, and an absent list, leaves the floor alone (ADR 0051 §3).
    #[test]
    fn a_failed_or_absent_list_never_moves_the_floor() {
        for error in [
            rizzy_match::EquivalenceListError::BadSignature,
            rizzy_match::EquivalenceListError::Malformed,
            rizzy_match::EquivalenceListError::NotNewer,
        ] {
            assert_eq!(groups_and_new_floor(Err(error), 3), (Vec::new(), None));
        }
        assert_eq!(groups_and_new_floor(Ok(None), 3), (Vec::new(), None));
        // A verified list that is not strictly above the caller's floor (unreachable through
        // `verify`, which already refuses it) still never produces a write.
        assert_eq!(groups_and_new_floor(known_answer_list(0), 1).1, None);
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

// SPDX-License-Identifier: AGPL-3.0-only

//! URL matching for autofill (ADR 0037, ADR 0038), over [`rizzy_client::matching`], which in
//! turn is `rizzy-client`'s thin wrap of `rizzy-match` (that module's own docs explain the
//! split: no decision is made twice, in no layer).
//!
//! # What this binding adds, and what it defers
//!
//! This is the one boundary that is genuinely mechanical (unlike [`crate::device`]): every
//! check and every narrowing rule is already [`rizzy_client::matching::decide_candidates`]'s;
//! this module only turns its `[u8; 16]` ids and typed `MatchMode`/`MatchedVia` into the
//! strings and small integers `wasm-bindgen` can hand to JavaScript (ADR 0013 §3 rule 6, "the
//! API is coarse": one call, [`decide_match_candidates`], per autofill request).
//!
//! **Two entry points.** The free [`decide_match_candidates`] holds no session and so no account
//! settings: it takes the account default as an argument and builds its [`EquivalenceView`]
//! from the compiled-in global list alone, as a [`GlobalEquivalence`] the host verified once
//! (ADR 0037 §7, ADR 0038 §5, [ADR 0051] §4). A host with a session calls the session's
//! `decideMatchCandidates` (`crate::Session`, `crate::DeviceSession`) instead: that reads the
//! account's `ACCOUNT_SETTINGS` once per object ([ADR 0042] §6,
//! `rizzy_client::settings::SettingsCache`) and applies its match default, disabled global groups
//! and user groups (`decide_with_account`), over the global groups the session verified when it
//! started: a `crate::DeviceSession` against its cache's persisted
//! `highest_equivalence_list_version` (INV-39; ADR 0051 §1–§4, raised in its first cache
//! write when a newer list verifies), a `crate::Session` (the web vault, no cache) from `0`
//! (ADR 0051 §5). While `rizzy_match::compiled::GLOBAL_LIST` is `None`, the only equivalence
//! groups are the account's own.
//!
//! [ADR 0042]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0042-account-settings-matching-layout.md
//! [ADR 0051]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0051-equivalence-list-version-persistence.md

use core::fmt;
use std::collections::BTreeSet;

use rizzy_client::ClientError;
use rizzy_client::matching::{
    self, EquivalenceGroup, EquivalenceView, FrameContext, GroupId, ItemUri, MatchMode, MatchedVia,
    global_equivalence_groups,
};
use rizzy_client::rizzy_match::MatchingSettings;
use rizzy_client::settings::AccountSettingsRecord;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::{CoreError, CoreResult};
use crate::items::{hex, parse_id};

/// Decodes a wire `MatchMode` value (ADR 0037 §4), refusing `0x0007`–`0xFFFF`.
fn mode_of(value: u16) -> Result<MatchMode, CoreError> {
    MatchMode::from_wire(value).ok_or_else(|| CoreError::from(ClientError::InvalidInput))
}

/// One saved URI to match against (module docs; ADR 0037 §2, §4), as JavaScript gives it.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct UriInput {
    /// The item's id, hex (`js_name` kept as `itemId` for the TypeScript side).
    item_id: String,
    /// The URI's own id, hex.
    uri_id: String,
    /// The saved string.
    value: String,
    /// The wire `MatchMode` value (`0x0000`–`0x0006`).
    mode: u16,
}

#[wasm_bindgen]
impl UriInput {
    /// Builds one input row.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(item_id: String, uri_id: String, value: String, mode: u16) -> Self {
        Self {
            item_id,
            uri_id,
            value,
            mode,
        }
    }
}

/// One candidate offered for autofill.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct MatchCandidate {
    /// The matching item's id, hex.
    item_id: String,
    /// The matching URI's id, hex.
    uri_id: String,
    /// Whether the equivalence-only warning is needed before the fill ([`MatchedVia::needs_warning`]).
    needs_warning: bool,
    /// The saved URI's own exact normalised host, A-label form (ADR 0037 §5 "Exact host
    /// shown"): "the saved site" in the equivalence-only warning. Never decode this to Unicode
    /// in a host UI; a mixed-script host must keep showing its punycode `xn--` form.
    saved_host: String,
    /// The saved URI's own port, only when it is not its scheme's default
    /// (`rizzy_client::matching::Candidate::saved_port`'s own doc explains why a host that does
    /// a "same site" gate for a destructive decision, never autofill itself, must compare this
    /// alongside `saved_host`, not `saved_host` alone).
    saved_port: Option<u16>,
}

#[wasm_bindgen]
impl MatchCandidate {
    /// The matching item's id, hex.
    #[wasm_bindgen(getter, js_name = itemId)]
    #[must_use]
    pub fn item_id(&self) -> String {
        self.item_id.clone()
    }

    /// The matching URI's id, hex.
    #[wasm_bindgen(getter, js_name = uriId)]
    #[must_use]
    pub fn uri_id(&self) -> String {
        self.uri_id.clone()
    }

    /// Whether the fill UI must show the equivalence-only warning (ADR 0037 §5).
    #[wasm_bindgen(getter, js_name = needsWarning)]
    #[must_use]
    pub fn needs_warning(&self) -> bool {
        self.needs_warning
    }

    /// The saved URI's exact normalised host, A-label form (ADR 0037 §5 "Exact host shown").
    #[wasm_bindgen(getter, js_name = savedHost)]
    #[must_use]
    pub fn saved_host(&self) -> String {
        self.saved_host.clone()
    }

    /// The saved URI's own port, only when it is not its scheme's default (module docs,
    /// [`MatchCandidate::saved_host`]'s own doc). `undefined` on the JavaScript side exactly
    /// when the port is the scheme's default or absent, same as [`MatchDecision::page_port`].
    #[wasm_bindgen(getter, js_name = savedPort)]
    #[must_use]
    pub fn saved_port(&self) -> Option<u16> {
        self.saved_port
    }
}

/// The result of one [`decide_match_candidates`] call.
#[wasm_bindgen]
#[derive(Clone, Debug, Default)]
pub struct MatchDecision {
    /// The page's own exact normalised host, A-label form (ADR 0037 §5 "Exact host shown"):
    /// "the page" in the equivalence-only warning, and what the fill UI always shows, matching
    /// or not.
    page_host: String,
    /// The page's own port, only when it is not its scheme's default
    /// (`rizzy_client::matching::Decision::page_port`'s own doc).
    page_port: Option<u16>,
    /// Every matching candidate, in the order given.
    candidates: Vec<MatchCandidate>,
    /// Lines explaining a URI or the frame as a whole that this build could not evaluate
    /// (module docs, `rizzy_client::matching::Decision`).
    warnings: Vec<String>,
}

#[wasm_bindgen]
impl MatchDecision {
    /// The page's exact normalised host, A-label form (ADR 0037 §5 "Exact host shown").
    #[wasm_bindgen(getter, js_name = pageHost)]
    #[must_use]
    pub fn page_host(&self) -> String {
        self.page_host.clone()
    }

    /// The page's own port, only when it is not its scheme's default (module docs,
    /// [`MatchDecision::page_host`]'s own doc). A caller doing a "same site" gate for a
    /// destructive decision (an update-vs-save gate, never autofill, which is `BaseDomain`-mode
    /// narrowing-only by design, ADR 0037 §4) must compare this against each candidate's own
    /// [`MatchCandidate::saved_port`], not `page_host`/`savedHost` alone — two different ports
    /// on the same host are two different sites (ADR 0037 §2 rule 5).
    #[wasm_bindgen(getter, js_name = pagePort)]
    #[must_use]
    pub fn page_port(&self) -> Option<u16> {
        self.page_port
    }

    /// Every matching candidate.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn candidates(&self) -> Vec<MatchCandidate> {
        self.candidates.clone()
    }

    /// The warning lines.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }
}

/// The page's own normalised URL (ADR 0037 §2), for a host that wants to show or log it in the
/// same canonical form matching uses.
///
/// # Errors
/// `invalid_input` if `url` does not parse as an absolute `http`/`https` URL.
#[wasm_bindgen(js_name = normalizePageUrl)]
pub fn normalize_page_url(url: &str) -> Result<String, CoreError> {
    matching::NormalizedUrl::parse(url)
        .map(|u| u.normalized_string())
        .map_err(|_| CoreError::from(ClientError::InvalidInput))
}

/// The page's registrable domain (eTLD+1, ADR 0037 §2 rule 7), for a host that needs to key
/// state by "the same site" across a same-tab navigation without re-implementing PSL lookup
/// outside `rizzy-match` — for example the extension's save-prompt continuity
/// (`apps/extension/src/core-host/core-context.ts`): a login form's submit often navigates to a
/// different host of the same site (`login.example.com` → `example.com`), and the pending offer
/// must survive that, but never follow the tab on to an unrelated site reached later. `None`
/// only for a bare public suffix (`co.uk`, `com`), which has no registrable domain beneath it
/// (`NormalizedUrl::registrable_domain`'s own doc) — the caller treats that as "nothing to key
/// the offer by," not an error, same as a saved URI that fails to normalise elsewhere in this
/// module. An IP-literal host is `Some` of itself (never run through the PSL, which has no
/// concept of one), so a self-hosted/intranet login reached by IP literal still keys correctly.
///
/// # Errors
/// `invalid_input` if `url` does not parse as an absolute `http`/`https` URL.
#[wasm_bindgen(js_name = registrableDomainOf)]
pub fn registrable_domain_of(url: &str) -> Result<Option<String>, CoreError> {
    matching::NormalizedUrl::parse(url)
        .map(|u| u.registrable_domain().map(str::to_owned))
        .map_err(|_| CoreError::from(ClientError::InvalidInput))
}

/// The compiled-in global equivalence list's groups, verified once and passed to every
/// [`decide_match_candidates`] call instead of being verified per decision (ADR 0051 §4).
#[wasm_bindgen]
pub struct GlobalEquivalence {
    /// The verified groups; empty while no list is compiled in or one fails to verify.
    groups: Vec<EquivalenceGroup>,
}

impl fmt::Debug for GlobalEquivalence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalEquivalence")
            .field("groups", &self.groups.len())
            .finish()
    }
}

#[wasm_bindgen]
impl GlobalEquivalence {
    /// Verifies the compiled-in list for a host that keeps no cache, and so no persisted floor:
    /// from `highest_accepted_version = 0`, as the web vault does every session (ADR 0051 §5).
    /// A host with a cache uses its `DeviceSession` instead, which verifies against the
    /// cache's persisted floor and raises it.
    #[wasm_bindgen(js_name = withoutCache)]
    #[must_use]
    pub fn without_cache() -> Self {
        Self {
            groups: global_equivalence_groups(0).0,
        }
    }

    /// How many global groups verified (`0` while no list is compiled in).
    #[wasm_bindgen(getter, js_name = groupCount)]
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
}

/// Decides which of `uris` are autofill candidates for `page_url`, requested by the frame at
/// `frame_origin` (module docs; `rizzy_client::matching::decide_candidates`), over the global
/// groups `global` the host verified once (ADR 0051 §4).
///
/// `is_top_frame` and `frame_origin` are the content script's own report (ADR 0037 §5);
/// `account_default_mode` resolves any URI whose own mode is `0x0000`.
///
/// # Errors
/// `invalid_input` if `page_url` or `account_default_mode` does not parse; a malformed item or
/// URI id in `uris` is `invalid_input` too (unlike a saved URI that fails to *normalise*, which
/// this call reports as a warning instead, per `rizzy_client::matching`'s own docs).
#[wasm_bindgen(js_name = decideMatchCandidates)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen hands this exported call ownership of the JS array as Vec<UriInput>, never a slice"
)]
pub fn decide_match_candidates(
    page_url: &str,
    is_top_frame: bool,
    frame_origin: &str,
    account_default_mode: u16,
    uris: Vec<UriInput>,
    global: &GlobalEquivalence,
) -> Result<MatchDecision, CoreError> {
    let account_default = mode_of(account_default_mode)?;
    let mut owned_ids = Vec::with_capacity(uris.len());
    for input in &uris {
        let item_id = parse_id(&input.item_id)?;
        let uri_id = parse_id(&input.uri_id)?;
        let mode = mode_of(input.mode)?;
        owned_ids.push((item_id, uri_id, mode));
    }
    let item_uris: Vec<ItemUri<'_>> = uris
        .iter()
        .zip(&owned_ids)
        .map(|(input, (item_id, uri_id, mode))| ItemUri {
            item_id: *item_id,
            uri_id: *uri_id,
            value: input.value.as_str(),
            mode: *mode,
        })
        .collect();
    let frame = FrameContext {
        is_top_frame,
        frame_origin,
    };
    // The compiled-in global list's groups the host verified once (`global`, ADR 0051 §4),
    // with no disabled groups and no user-defined groups: this free function holds no session,
    // so no account settings. A host with a session calls the session's own
    // `decideMatchCandidates` instead, which applies them (ADR 0042 §6).
    let no_disabled_groups: BTreeSet<GroupId> = BTreeSet::new();
    let no_user_defined_groups: Vec<EquivalenceGroup> = Vec::new();
    let equivalence =
        EquivalenceView::new(&global.groups, &no_disabled_groups, &no_user_defined_groups);
    let decision =
        matching::decide_candidates(page_url, &frame, account_default, &item_uris, &equivalence)
            .map_err(CoreError::from)?;
    Ok(decision_view(decision))
}

/// The JavaScript form of a decision.
pub(crate) fn decision_view(decision: matching::Decision) -> MatchDecision {
    MatchDecision {
        page_host: decision.page_host,
        page_port: decision.page_port,
        candidates: decision
            .candidates
            .into_iter()
            .map(|c| MatchCandidate {
                item_id: hex(&c.item_id),
                uri_id: hex(&c.uri_id),
                needs_warning: matches!(c.matched_via, MatchedVia::Equivalence(_)),
                saved_host: c.saved_host,
                saved_port: c.saved_port,
            })
            .collect(),
        warnings: decision.warnings.into_iter().map(str::to_owned).collect(),
    }
}

/// [`decide_match_candidates`] under an account's own settings (ADR 0042 §6;
/// `rizzy_client::matching::decide_with_settings`): every URI mode `0x0000` resolves to the
/// account's match default, and the merged view takes its disabled and user groups.
///
/// # Errors
/// As [`decide_match_candidates`].
pub(crate) fn decide_with_account(
    page_url: &str,
    is_top_frame: bool,
    frame_origin: &str,
    uris: &[UriInput],
    settings: &AccountSettingsRecord,
    global: &[EquivalenceGroup],
) -> Result<MatchDecision, CoreError> {
    let mut owned_ids = Vec::with_capacity(uris.len());
    for input in uris {
        owned_ids.push((
            parse_id(&input.item_id)?,
            parse_id(&input.uri_id)?,
            mode_of(input.mode)?,
        ));
    }
    let item_uris: Vec<ItemUri<'_>> = uris
        .iter()
        .zip(&owned_ids)
        .map(|(input, (item_id, uri_id, mode))| ItemUri {
            item_id: *item_id,
            uri_id: *uri_id,
            value: input.value.as_str(),
            mode: *mode,
        })
        .collect();
    let frame = FrameContext {
        is_top_frame,
        frame_origin,
    };
    let decision = matching::decide_with_settings(page_url, &frame, &item_uris, settings, global)?;
    Ok(decision_view(decision))
}

/// One equivalence group, as the settings screen shows it: public global-list data, or the
/// account's own group (its domains are the user's data, shown only to the user).
#[wasm_bindgen]
#[derive(Clone)]
pub struct EquivalenceGroupView {
    /// The group id, 32 lowercase hex digits.
    id: String,
    /// The member domains, A-label form, sorted.
    domains: Vec<String>,
    /// For a global group: whether the account disabled it. Always `false` for a user group.
    disabled: bool,
}

impl fmt::Debug for EquivalenceGroupView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EquivalenceGroupView")
            .field("domains", &self.domains.len())
            .field("disabled", &self.disabled)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl EquivalenceGroupView {
    /// The group id, hex.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// The member domains (A-label form; never decode them to Unicode for display, ADR 0037 §2
    /// point 4).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn domains(&self) -> Vec<String> {
        self.domains.clone()
    }

    /// Whether the account disabled this global group.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn disabled(&self) -> bool {
        self.disabled
    }
}

/// The account's matching settings (ADR 0037 §6–§7; ADR 0042 §3), for the settings screen.
#[wasm_bindgen]
#[derive(Clone)]
pub struct MatchSettingsView {
    /// The account-level match default, a wire value `0x0001`–`0x0006`.
    match_default: u16,
    /// The account's own groups.
    user_groups: Vec<EquivalenceGroupView>,
    /// Every group of the compiled-in global list, each with its disabled flag; empty while no
    /// signed list is compiled in.
    global_groups: Vec<EquivalenceGroupView>,
    /// Disabled ids that name no group of this build's global list (a list that dropped them,
    /// or a newer one), hex: still disabled, and can be enabled again.
    other_disabled: Vec<String>,
}

impl fmt::Debug for MatchSettingsView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatchSettingsView")
            .field("match_default", &self.match_default)
            .field("user_groups", &self.user_groups.len())
            .field("global_groups", &self.global_groups.len())
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl MatchSettingsView {
    /// The account-level match default (`MatchMode` wire value).
    #[wasm_bindgen(getter, js_name = matchDefault)]
    #[must_use]
    pub fn match_default(&self) -> u16 {
        self.match_default
    }

    /// The account's own groups, sorted by id.
    #[wasm_bindgen(getter, js_name = userGroups)]
    #[must_use]
    pub fn user_groups(&self) -> Vec<EquivalenceGroupView> {
        self.user_groups.clone()
    }

    /// The compiled-in global list's groups.
    #[wasm_bindgen(getter, js_name = globalGroups)]
    #[must_use]
    pub fn global_groups(&self) -> Vec<EquivalenceGroupView> {
        self.global_groups.clone()
    }

    /// Disabled ids outside this build's global list, hex.
    #[wasm_bindgen(getter, js_name = otherDisabled)]
    #[must_use]
    pub fn other_disabled(&self) -> Vec<String> {
        self.other_disabled.clone()
    }
}

/// The settings screen's view of `settings` against the compiled-in global list's groups
/// `global`, as the session verified them at its start (ADR 0051 §4).
pub(crate) fn settings_view(
    settings: &MatchingSettings,
    global: &[EquivalenceGroup],
) -> MatchSettingsView {
    let disabled = settings.disabled_global();
    let group_view = |g: &EquivalenceGroup, disabled: bool| EquivalenceGroupView {
        id: hex(g.id().as_bytes()),
        domains: g.domains().to_vec(),
        disabled,
    };
    MatchSettingsView {
        match_default: settings.match_default().to_wire(),
        user_groups: settings
            .user_groups()
            .iter()
            .map(|g| group_view(g, false))
            .collect(),
        global_groups: global
            .iter()
            .map(|g| group_view(g, disabled.contains(&g.id())))
            .collect(),
        other_disabled: disabled
            .iter()
            .filter(|id| !global.iter().any(|g| g.id() == **id))
            .map(|id| hex(id.as_bytes()))
            .collect(),
    }
}

/// Parses a group id the host passes back (32 hex digits).
///
/// # Errors
/// `invalid_input`.
pub(crate) fn group_id_of(text: &str) -> CoreResult<GroupId> {
    Ok(GroupId::from_bytes(parse_id(text)?))
}

/// A URI mode the host passes as the account default (`0x0001`–`0x0006`).
///
/// # Errors
/// `invalid_input` for `0x0000` or an unassigned value.
pub(crate) fn default_mode_of(value: u16) -> CoreResult<MatchMode> {
    match mode_of(value)? {
        MatchMode::AccountDefault => Err(ClientError::InvalidInput.into()),
        mode => Ok(mode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_a_page_url() {
        assert_eq!(
            normalize_page_url("HTTPS://Example.com/Path?x=1").unwrap(),
            "https://example.com/Path"
        );
        assert_eq!(
            normalize_page_url("not a url").unwrap_err().as_str(),
            "invalid_input"
        );
    }

    #[test]
    fn registrable_domain_of_a_page_url() {
        assert_eq!(
            registrable_domain_of("https://login.example.com/path").unwrap(),
            Some("example.com".to_owned())
        );
        // An IP literal is its own registrable domain (never a PSL lookup, this fn's own doc).
        assert_eq!(
            registrable_domain_of("http://127.0.0.1:8080/").unwrap(),
            Some("127.0.0.1".to_owned())
        );
        // A bare public suffix has no registrable domain beneath it.
        assert_eq!(registrable_domain_of("https://co.uk/").unwrap(), None);
        assert_eq!(
            registrable_domain_of("not a url").unwrap_err().as_str(),
            "invalid_input"
        );
    }

    #[test]
    fn decides_a_matching_candidate() {
        let uris = vec![UriInput::new(
            hex(&[1; 16]),
            hex(&[2; 16]),
            "https://example.com/login".to_owned(),
            0x0001,
        )];
        let decision = decide_match_candidates(
            "https://example.com/",
            true,
            "",
            0x0001,
            uris,
            &GlobalEquivalence::without_cache(),
        )
        .unwrap();
        assert_eq!(decision.candidates().len(), 1);
        assert!(!decision.candidates()[0].needs_warning());
        assert!(decision.warnings().is_empty());
        assert_eq!(decision.page_host(), "example.com");
        assert_eq!(decision.candidates()[0].saved_host(), "example.com");
    }

    /// Gap 27(a): the global list's groups now flow through to the merged `EquivalenceView`
    /// this call builds, so `rizzy_match::compiled::GLOBAL_LIST` being `None` today means
    /// exactly what it always meant — no equivalence-only candidate — never a different
    /// outcome than before this binding wired the global list in.
    #[test]
    fn with_no_compiled_in_global_list_matching_is_unchanged() {
        let uris = vec![UriInput::new(
            hex(&[1; 16]),
            hex(&[2; 16]),
            "https://other.example/".to_owned(),
            0x0001,
        )];
        let decision = decide_match_candidates(
            "https://example.com/",
            true,
            "",
            0x0001,
            uris,
            &GlobalEquivalence::without_cache(),
        )
        .unwrap();
        assert!(decision.candidates().is_empty());
    }

    #[test]
    fn exposes_the_page_and_saved_ports_for_a_host_gate_on_top() {
        // ADR 0037 §2 rule 5: a destructive "same site" decision on top of `BaseDomain`-mode
        // candidates (never autofill itself) needs the port, not just `pageHost`/`savedHost`,
        // so this binding must thread it through to JavaScript.
        let uris = vec![UriInput::new(
            hex(&[1; 16]),
            hex(&[2; 16]),
            "https://example.com:9000/login".to_owned(),
            0x0001,
        )];
        let decision = decide_match_candidates(
            "https://example.com:8443/",
            true,
            "",
            0x0001,
            uris,
            &GlobalEquivalence::without_cache(),
        )
        .unwrap();
        assert_eq!(decision.page_port(), Some(8443));
        assert_eq!(decision.candidates()[0].saved_port(), Some(9000));
    }

    #[test]
    fn default_ports_expose_as_undefined_on_both_sides() {
        let uris = vec![UriInput::new(
            hex(&[1; 16]),
            hex(&[2; 16]),
            "https://example.com/login".to_owned(),
            0x0001,
        )];
        let decision = decide_match_candidates(
            "https://example.com/",
            true,
            "",
            0x0001,
            uris,
            &GlobalEquivalence::without_cache(),
        )
        .unwrap();
        assert_eq!(decision.page_port(), None);
        assert_eq!(decision.candidates()[0].saved_port(), None);
    }

    #[test]
    fn refuses_an_unassigned_mode() {
        let error = decide_match_candidates(
            "https://example.com/",
            true,
            "",
            0x0099,
            vec![],
            &GlobalEquivalence::without_cache(),
        )
        .unwrap_err();
        assert_eq!(error.as_str(), "invalid_input");
    }

    #[test]
    fn refuses_a_malformed_item_id() {
        let uris = vec![UriInput::new(
            "not hex".to_owned(),
            hex(&[2; 16]),
            "https://example.com/".to_owned(),
            0x0001,
        )];
        let error = decide_match_candidates(
            "https://example.com/",
            true,
            "",
            0x0001,
            uris,
            &GlobalEquivalence::without_cache(),
        )
        .unwrap_err();
        assert_eq!(error.as_str(), "invalid_input");
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap(), 16).unwrap())
            .collect()
    }

    /// A record (ADR 0042 §2–§3) with Base domain, two disabled ids and one user group of
    /// `example.com` and `example.net` (`rizzy-client`'s `matching-groups` vector).
    const WITH_GROUP: &str = "000100010001000000570001000211111111111111111111111111111111\
        222222222222222222222222222222220001a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000020000000b6578616d\
        706c652e636f6d0000000b6578616d706c652e6e657400";

    #[test]
    fn the_account_settings_widen_through_a_user_group_and_resolve_the_default() {
        let saved = |value: &str, mode: u16| {
            vec![UriInput::new(
                hex(&[1; 16]),
                hex(&[2; 16]),
                value.to_owned(),
                mode,
            )]
        };
        let with_group =
            AccountSettingsRecord::decode(&unhex(&WITH_GROUP.replace(' ', ""))).unwrap();
        let decision = decide_with_account(
            "https://example.net/",
            true,
            "",
            &saved("https://example.com/", 0x0000),
            &with_group,
            &[],
        )
        .unwrap();
        assert_eq!(decision.candidates().len(), 1);
        assert!(decision.candidates()[0].needs_warning(), "equivalence only");
        // The free function, with no settings, never widens.
        let free = decide_match_candidates(
            "https://example.net/",
            true,
            "",
            0x0001,
            saved("https://example.com/", 0x0000),
            &GlobalEquivalence::without_cache(),
        )
        .unwrap();
        assert!(free.candidates().is_empty());

        // An account default of Host narrows a 0x0000 URI to its exact host.
        let host =
            AccountSettingsRecord::decode(&unhex("00010001000100000006000200000000")).unwrap();
        let narrowed = decide_with_account(
            "https://www.example.com/",
            true,
            "",
            &saved("https://example.com/", 0x0000),
            &host,
            &[],
        )
        .unwrap();
        assert!(narrowed.candidates().is_empty());
        // A URI's own mode still wins over the account default.
        let own = decide_with_account(
            "https://www.example.com/",
            true,
            "",
            &saved("https://example.com/", 0x0001),
            &host,
            &[],
        )
        .unwrap();
        assert_eq!(own.candidates().len(), 1);
    }

    #[test]
    fn the_settings_view_lists_groups_and_disabled_ids() {
        let record = AccountSettingsRecord::decode(&unhex(&WITH_GROUP.replace(' ', ""))).unwrap();
        let view = settings_view(record.matching(), &[]);
        assert_eq!(view.match_default(), 0x0001);
        assert_eq!(view.user_groups().len(), 1);
        assert_eq!(view.user_groups()[0].id(), "a0".repeat(16));
        assert_eq!(
            view.user_groups()[0].domains(),
            ["example.com", "example.net"]
        );
        // No global list is compiled in: both disabled ids are "other".
        assert!(view.global_groups().is_empty());
        assert_eq!(view.other_disabled(), ["11".repeat(16), "22".repeat(16)]);
        assert_eq!(default_mode_of(0).unwrap_err().as_str(), "invalid_input");
        assert_eq!(default_mode_of(7).unwrap_err().as_str(), "invalid_input");
        assert_eq!(default_mode_of(2).unwrap(), MatchMode::Host);
        assert_eq!(group_id_of("zz").unwrap_err().as_str(), "invalid_input");
    }
}

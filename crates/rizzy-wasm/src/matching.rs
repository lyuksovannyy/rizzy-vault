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
//! **Deferred (reported, not attempted here):** the account's equivalence settings
//! (ADR 0037 §7, ADR 0038 §5 — the compiled-in global list, which `rizzy-match` itself does
//! not ship yet, the account's disabled-global-group set, and its own user-defined groups) are
//! not threaded through this call yet; every decision runs against
//! [`EquivalenceView::empty`], so matching narrows to plain registrable-domain equality and
//! never offers an equivalence-only candidate. Wiring the account's settings in is the
//! integration step's job once `ACCOUNT_SETTINGS`'s equivalence fields are read on the
//! extension side; this binding's signature (`uris` and the two mode values) does not change
//! when that lands, only the `equivalence` argument gains real groups.

use rizzy_client::ClientError;
use rizzy_client::matching::{self, EquivalenceView, FrameContext, ItemUri, MatchMode, MatchedVia};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::CoreError;
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
}

/// The result of one [`decide_match_candidates`] call.
#[wasm_bindgen]
#[derive(Clone, Debug, Default)]
pub struct MatchDecision {
    /// Every matching candidate, in the order given.
    candidates: Vec<MatchCandidate>,
    /// Lines explaining a URI or the frame as a whole that this build could not evaluate
    /// (module docs, `rizzy_client::matching::Decision`).
    warnings: Vec<String>,
}

#[wasm_bindgen]
impl MatchDecision {
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

/// Decides which of `uris` are autofill candidates for `page_url`, requested by the frame at
/// `frame_origin` (module docs; `rizzy_client::matching::decide_candidates`).
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
    // Deferred (module docs): no account equivalence settings are threaded through yet.
    let equivalence = EquivalenceView::empty();
    let decision =
        matching::decide_candidates(page_url, &frame, account_default, &item_uris, &equivalence)
            .map_err(CoreError::from)?;
    Ok(MatchDecision {
        candidates: decision
            .candidates
            .into_iter()
            .map(|c| MatchCandidate {
                item_id: hex(&c.item_id),
                uri_id: hex(&c.uri_id),
                needs_warning: matches!(c.matched_via, MatchedVia::Equivalence(_)),
            })
            .collect(),
        warnings: decision.warnings.into_iter().map(str::to_owned).collect(),
    })
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
    fn decides_a_matching_candidate() {
        let uris = vec![UriInput::new(
            hex(&[1; 16]),
            hex(&[2; 16]),
            "https://example.com/login".to_owned(),
            0x0001,
        )];
        let decision =
            decide_match_candidates("https://example.com/", true, "", 0x0001, uris).unwrap();
        assert_eq!(decision.candidates().len(), 1);
        assert!(!decision.candidates()[0].needs_warning());
        assert!(decision.warnings().is_empty());
    }

    #[test]
    fn refuses_an_unassigned_mode() {
        let error =
            decide_match_candidates("https://example.com/", true, "", 0x0099, vec![]).unwrap_err();
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
        let error =
            decide_match_candidates("https://example.com/", true, "", 0x0001, uris).unwrap_err();
        assert_eq!(error.as_str(), "invalid_input");
    }
}

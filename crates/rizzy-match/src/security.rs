//! The security rules of ADR 0037 §5, each as its own pure decision function, "not a
//! convention left to callers": the extension's background/content-script pair calls these
//! directly, so every client enforces them identically.
//!
//! `rizzy-match` has no DOM access, so it cannot itself detect a hidden or invisible field, or
//! whether a click was a trusted user gesture — those checks stay the extension's (ADR 0036
//! §5; the threat model's A7 names them). What *is* expressible as a pure function of the data
//! `rizzy-match` already has is implemented here: the HTTPS→HTTP rule, the cross-origin-frame
//! default, and whether a match needs the equivalence-only warning.

use crate::modes::MatchedVia;
use crate::normalize::Scheme;

/// **No HTTPS → HTTP fill** (ADR 0037 §5; INV-37). A URI saved as `https://…` is never offered
/// as a match against a page served over plain `http://`. An HTTP-saved URI may still match an
/// HTTPS page (the common case of a site that redirects to HTTPS).
///
/// Returns `true` when the fill must be refused on this ground alone.
#[must_use]
pub const fn https_downgrade_blocks(uri_scheme: Scheme, page_scheme: Scheme) -> bool {
    matches!((uri_scheme, page_scheme), (Scheme::Https, Scheme::Http))
}

/// **No cross-origin iframe fill by default** (ADR 0037 §5; INV-37). Matching and filling run
/// against the top frame's origin; a same-origin iframe is treated as the top frame. A
/// cross-origin iframe gets no automatic candidate list for M2: this is a hard default, not
/// something a mode or an equivalence group can relax.
///
/// `rizzy-match` has no notion of a frame tree; the caller (the extension's content script,
/// which does have one) answers the one question this function decides: given that a frame is
/// either the top frame or is same-origin with it, may `rizzy-match` be asked for candidates at
/// all? Pass `false` for a cross-origin iframe, `true` for the top frame or a same-origin
/// iframe.
#[must_use]
pub const fn frame_may_request_candidates(is_top_frame_or_same_origin: bool) -> bool {
    is_top_frame_or_same_origin
}

/// **Equivalence-only match warning** (ADR 0037 §5). When the only reason a candidate matched
/// is an equivalence group rather than an exact registrable-domain equality, the fill UI
/// **must** show a visible notice naming the matched site and the saved site before the user
/// confirms the fill. A plain registrable-domain match or better never carries this flag.
#[must_use]
pub const fn needs_equivalence_warning(matched_via: MatchedVia) -> bool {
    matched_via.needs_warning()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::equivalence::GroupId;

    #[test]
    fn https_saved_blocks_http_page() {
        assert!(https_downgrade_blocks(Scheme::Https, Scheme::Http));
    }

    #[test]
    fn http_saved_does_not_block_https_page() {
        assert!(!https_downgrade_blocks(Scheme::Http, Scheme::Https));
    }

    #[test]
    fn same_scheme_never_blocks() {
        assert!(!https_downgrade_blocks(Scheme::Https, Scheme::Https));
        assert!(!https_downgrade_blocks(Scheme::Http, Scheme::Http));
    }

    #[test]
    fn cross_origin_iframe_refused_by_default() {
        assert!(!frame_may_request_candidates(false));
        assert!(frame_may_request_candidates(true));
    }

    #[test]
    fn warning_flag_matches_matched_via() {
        assert!(!needs_equivalence_warning(MatchedVia::RegistrableDomain));
        assert!(needs_equivalence_warning(MatchedVia::Equivalence(
            GroupId::from_bytes([0; 16])
        )));
    }
}

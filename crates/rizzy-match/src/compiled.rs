//! The compiled-in global equivalence list and its pinned public key (ADR 0038 §1–§3).
//!
//! **Both are `None` today.** The production list-signing keypair does not exist yet — the
//! owner generates it offline and signs a first list with `cargo xtask equivalence-list`
//! (`docs/equivalence-list.md`). There is deliberately no placeholder public key and no
//! zeroed or dummy signed blob here: a `[u8; 32]` filled with zeros is a valid-looking constant
//! that a future change could forget to replace, and `rizzy-core`'s key parsing would in fact
//! reject it outright (`is_weak`, the all-zero encoding is a small-order point) — but relying
//! on that rejection as the safety net would be the wrong layer to trust. Representing absence
//! as `None` at the type level means a caller cannot reach a verification call with a key that
//! was never meant to verify anything.
//!
//! Until the owner adds them, [`global_list`] always returns `Ok(None)`, and a client's merged
//! [`crate::equivalence::EquivalenceView`] has no global groups: equivalence matching runs
//! from the account's own user-defined groups only, never from an unsigned source (ADR 0038
//! §1: "clients reject an unsigned list").
//!
//! **When the owner ships a signed list**, this file changes to:
//! ```ignore
//! pub const GLOBAL_LIST: Option<&[u8]> = Some(include_bytes!("../data/equivalence/list.bin"));
//! pub const LIST_SIGNING_PUBLIC_KEY: Option<[u8; 32]> = Some([ /* 32 bytes */ ]);
//! ```
//! both set together, in the same reviewed change (`docs/equivalence-list.md` "Shipping a
//! signed list").

use crate::equivalence::EquivalenceList;
use crate::error::EquivalenceListError;

/// The compiled-in signed global list's wire bytes (ADR 0038 §1), or `None` before the owner
/// ships a first signed list.
pub const GLOBAL_LIST: Option<&[u8]> = None;

/// The pinned Ed25519 public key the compiled-in global list is signed with (ADR 0038 §3), or
/// `None` before the owner ships a first signed list. Always set together with
/// [`GLOBAL_LIST`]: one being `Some` and the other `None` is a build error this module's own
/// test below catches.
pub const LIST_SIGNING_PUBLIC_KEY: Option<[u8; 32]> = None;

/// Verifies and returns the compiled-in global list, or `Ok(None)` when none is compiled in
/// yet.
///
/// `highest_accepted_version` is the caller's highest `list_version` ever accepted (persisted
/// by the caller; `rizzy-match` keeps no state itself, ADR 0016 R1). Pass `0` the first time a
/// caller has never accepted any list.
///
/// # Errors
/// The errors of [`EquivalenceList::verify`], if a list is compiled in but malformed, badly
/// signed, or not newer than `highest_accepted_version`.
pub fn global_list(
    highest_accepted_version: u32,
) -> Result<Option<EquivalenceList>, EquivalenceListError> {
    match (GLOBAL_LIST, LIST_SIGNING_PUBLIC_KEY) {
        (None, _) | (_, None) => Ok(None),
        (Some(wire), Some(public_key)) => {
            EquivalenceList::verify(wire, &public_key, highest_accepted_version).map(Some)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_are_absent_together() {
        assert_eq!(GLOBAL_LIST.is_some(), LIST_SIGNING_PUBLIC_KEY.is_some());
    }

    #[test]
    fn absent_list_matches_only_from_user_defined_groups() {
        assert_eq!(global_list(0), Ok(None));
    }
}

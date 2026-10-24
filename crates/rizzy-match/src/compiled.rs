// SPDX-License-Identifier: AGPL-3.0-only

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
//! pub const GLOBAL_LIST: Option<&[u8]> =
//!     Some(include_bytes!("../../../data/equivalence/list.bin"));
//! pub const LIST_SIGNING_PUBLIC_KEY: Option<[u8; 32]> = Some([ /* 32 bytes */ ]);
//! ```
//! both set together, in the same reviewed change (`docs/equivalence-list.md` §4 "Shipping a
//! signed list"). `data/equivalence/list.bin` at the repository root, next to its source
//! `data/equivalence/groups.txt`, is the one path of the signed list; the crate is never
//! published on its own (`publish = false`), so the include may reach outside it.
//!
//! The tests below already check a shipped list (it verifies at floor 0 and at its own version,
//! decodes to exactly the groups of `groups.txt`, every member passes ADR 0044, no domain is in
//! two groups; ADR 0080 §8). While both constants are `None` they check the absent state
//! instead, and they start checking the list in the change that sets them, with no edit here.

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
        if GLOBAL_LIST.is_none() {
            assert_eq!(global_list(0), Ok(None));
            assert_eq!(global_list(u32::MAX), Ok(None));
        }
    }

    /// The committed source the shipped list must be a build of: `(group domains)` per
    /// non-comment line of `data/equivalence/groups.txt`, sorted the way the list stores them.
    fn source_groups() -> Vec<Vec<String>> {
        let source = include_str!("../../../data/equivalence/groups.txt");
        let mut groups: Vec<Vec<String>> = source
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let domains = line.rsplit('|').next().unwrap_or_default();
                let mut domains: Vec<String> = domains
                    .split(',')
                    .map(|d| d.trim().to_owned())
                    .filter(|d| !d.is_empty())
                    .collect();
                domains.sort();
                domains
            })
            .collect();
        groups.sort();
        groups
    }

    /// ADR 0080 §8, "once the list ships". Runs on every build: while no list is compiled in
    /// (`GLOBAL_LIST` is `None` until the owner signs one offline, docs/equivalence-list.md
    /// §4) it checks only that nothing verifies; the change that sets both constants makes it
    /// check the shipped list itself.
    #[test]
    fn the_shipped_list_verifies_at_floor_zero_and_at_its_own_version() {
        let (Some(wire), Some(public_key)) = (GLOBAL_LIST, LIST_SIGNING_PUBLIC_KEY) else {
            assert_eq!(global_list(0), Ok(None));
            return;
        };
        let list = EquivalenceList::verify(wire, &public_key, 0).unwrap();
        let version = list.list_version();
        assert!(
            version >= 1,
            "list_version 0 is never published (ADR 0080 §6)"
        );
        // The next start of a cache-backed client re-verifies at its own version (ADR 0080 §6).
        assert_eq!(global_list(version).unwrap(), Some(list.clone()));
        if let Some(above) = version.checked_add(1) {
            assert_eq!(global_list(above), Err(EquivalenceListError::NotNewer));
        }
    }

    /// ADR 0080 §8, "once the list ships": the compiled-in list is a build of the committed
    /// `groups.txt` (same group count, same members), every member passes ADR 0044, and no
    /// domain is in two groups (ADR 0080 §2). Vacuous until a list is compiled in.
    #[test]
    fn the_shipped_list_is_exactly_the_committed_source() {
        let (Some(wire), Some(public_key)) = (GLOBAL_LIST, LIST_SIGNING_PUBLIC_KEY) else {
            return;
        };
        let list = EquivalenceList::verify(wire, &public_key, 0).unwrap();
        let mut shipped: Vec<Vec<String>> =
            list.groups().iter().map(|g| g.domains().to_vec()).collect();
        shipped.sort();
        assert_eq!(shipped, source_groups());
        let mut seen = std::collections::BTreeSet::new();
        for group in list.groups() {
            for member in group.domains() {
                assert!(crate::equivalence::is_valid_member(member), "{member}");
                assert!(seen.insert(member.clone()), "{member} is in two groups");
            }
        }
    }

    /// The committed source is the ADR 0080 seed this module will ship: 22 groups and 184
    /// domains (a cross-check of the reader above, independent of `cargo xtask`).
    #[test]
    fn the_committed_source_is_the_adr_0080_seed() {
        let groups = source_groups();
        assert_eq!(groups.len(), 22);
        assert_eq!(groups.iter().map(Vec::len).sum::<usize>(), 184);
    }
}

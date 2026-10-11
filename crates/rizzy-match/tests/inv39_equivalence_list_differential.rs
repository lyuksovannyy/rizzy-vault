// SPDX-License-Identifier: AGPL-3.0-only

//! Differential test for INV-39 (`THREAT_MODEL.md` §8: "Clients accept a global equivalence list
//! only with a valid signature from the list key and a version strictly higher than the last
//! one they accepted") against `EquivalenceList::verify`.
//!
//! This is a small, exhaustive table over the two dimensions INV-39's text names — signature
//! validity and version freshness — rather than a proptest generator: the decision space is
//! `{valid, wrong key, corrupted byte} × {lower, equal, higher}`, nine combinations, and every
//! one of them is checked, which is strictly more coverage than sampling nine from a larger
//! space would be. Structural malformation of the wire bytes themselves (truncation, a bad
//! `format_version`, trailing garbage) is already covered by `equivalence.rs`'s own
//! `verify_never_panics` proptest; this file's job is specifically the signature/freshness
//! boundary ADR 0038 §1-§2 states signature verification runs *before* the freshness check, so
//! a list that fails both is reported as a bad signature, not as stale — a design choice this
//! oracle also encodes, from that ordering note rather than from `EquivalenceList::verify`'s
//! own source.
//!
//! The test keypair is minted with `ed25519-dalek` directly (a dev-dependency added for this
//! file; see `Cargo.toml`), independent of `rizzy_core::sign::sign_detached`'s own call into the
//! same crate: both call the same well-known Ed25519 math, which is not the thing under test
//! here — `EquivalenceList::verify`'s accept/reject decision is.

use ed25519_dalek::SigningKey as DalekSigningKey;
use rizzy_match::{EquivalenceGroup, EquivalenceList, EquivalenceListError, GroupId};

const VALID_SEED: [u8; 32] = [0x42; 32];
const WRONG_SEED: [u8; 32] = [0x99; 32];
const HIGHEST_ACCEPTED: u32 = 100;

fn valid_public_key() -> [u8; 32] {
    DalekSigningKey::from_bytes(&VALID_SEED)
        .verifying_key()
        .to_bytes()
}

#[expect(
    clippy::expect_used,
    reason = "test fixture: these literal domains/version are known-valid by construction"
)]
fn build_list(list_version: u32) -> EquivalenceList {
    let group = EquivalenceGroup::new(
        GroupId::from_bytes([7; 16]),
        ["example.com", "example.net"],
        false,
    )
    .expect("two distinct domains");
    EquivalenceList::new(list_version, 1_700_000_000_000, vec![group]).expect("one valid group")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signing {
    Valid,
    WrongKey,
    CorruptedByte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VersionRelation {
    Lower,
    Equal,
    Higher,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    Accept,
    BadSignature,
    NotNewer,
}

/// INV-39's text, plus ADR 0038 §1-§2's ordering note (signature before freshness): a bad
/// signature is reported as a bad signature even when the version is also stale, never masked
/// by `NotNewer`.
fn oracle_decide(signing: Signing, relation: VersionRelation) -> Expected {
    match signing {
        Signing::WrongKey | Signing::CorruptedByte => Expected::BadSignature,
        Signing::Valid => match relation {
            VersionRelation::Lower | VersionRelation::Equal => Expected::NotNewer,
            VersionRelation::Higher => Expected::Accept,
        },
    }
}

#[expect(
    clippy::expect_used,
    reason = "test fixture: this fixed-size context and 32-byte seed always encode/sign"
)]
fn build_wire(relation: VersionRelation, signing: Signing) -> Vec<u8> {
    let list_version = match relation {
        VersionRelation::Lower => HIGHEST_ACCEPTED - 50,
        VersionRelation::Equal => HIGHEST_ACCEPTED,
        VersionRelation::Higher => HIGHEST_ACCEPTED + 50,
    };
    let list = build_list(list_version);
    let ctx = list.encode_ctx().expect("small, bounded context encodes");
    let seed = match signing {
        Signing::Valid | Signing::CorruptedByte => VALID_SEED,
        Signing::WrongKey => WRONG_SEED,
    };
    let mut signature =
        rizzy_core::sign::sign_detached(rizzy_core::labels::SIG_EQUIVALENCE_LIST, &ctx, &seed)
            .expect("a 32-byte seed always signs");
    if signing == Signing::CorruptedByte {
        signature[0] ^= 0x01;
    }
    let mut wire = ctx;
    wire.extend_from_slice(&signature);
    wire
}

fn run_case(relation: VersionRelation, signing: Signing) -> Result<(), String> {
    let wire = build_wire(relation, signing);
    let real = EquivalenceList::verify(&wire, &valid_public_key(), HIGHEST_ACCEPTED);
    let expected = oracle_decide(signing, relation);
    let agrees = matches!(
        (&real, expected),
        (Ok(_), Expected::Accept)
            | (
                Err(EquivalenceListError::BadSignature),
                Expected::BadSignature
            )
            | (Err(EquivalenceListError::NotNewer), Expected::NotNewer)
    );
    if agrees {
        Ok(())
    } else {
        Err(format!(
            "disagreement: relation={relation:?} signing={signing:?} real={real:?} \
             expected={expected:?}"
        ))
    }
}

#[test]
fn inv39_oracle_agrees_with_equivalence_list_verify_over_every_combination() {
    let relations = [
        VersionRelation::Lower,
        VersionRelation::Equal,
        VersionRelation::Higher,
    ];
    let signings = [Signing::Valid, Signing::WrongKey, Signing::CorruptedByte];
    let mut checked = 0;
    for relation in relations {
        for signing in signings {
            run_case(relation, signing).unwrap_or_else(|e| panic!("{e}"));
            checked += 1;
        }
    }
    assert_eq!(checked, 9, "every combination of the 3x3 table must run");
}

/// A positive control: two lists signed with the *same* valid key and context, differing only
/// in `list_version`, must themselves differ (sanity that `build_wire` actually varies the
/// signed content across the table, not just the claimed `Expected`).
#[test]
fn different_versions_produce_different_signed_bytes() {
    let lower = build_wire(VersionRelation::Lower, Signing::Valid);
    let higher = build_wire(VersionRelation::Higher, Signing::Valid);
    assert_ne!(lower, higher);
}

//! Fuzzes `rizzy-match`'s equivalence-list parser (ADR 0038 §1): [`EquivalenceList::verify`]
//! never panics on arbitrary bytes, under a fixed public key unrelated to any real signature,
//! and a list this process builds and signs itself (domains derived from the fuzzer's own
//! bytes, so libFuzzer's coverage feedback still varies the group content it explores)
//! round-trips back through it under the matching known test key.
//!
//! The list arrives compiled into the binary (never over the network, ADR 0038 §2), but the
//! decoder is still fuzzed like any other untrusted-input parser (CRYPTO.md §15 item 7):
//! `rizzy-match`'s own release process is the "untrusted" boundary here, in the sense that a
//! corrupted or truncated build artifact must fail closed, not panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::labels;
use rizzy_match::equivalence::{EquivalenceGroup, EquivalenceList, GroupId};

/// A fixed test seed (the same fixture as `rizzy-match`'s own
/// `equivalence::tests::verify_known_answer_with_a_test_key`), reused here purely so the
/// round-trip property below has a key pair without deriving one from fuzzer input.
const SEED: [u8; 32] = [0x55; 32];
/// The public key matching [`SEED`] (independently computed with Python `cryptography`
/// 50.0.2, not this code).
const PUBLIC_KEY: [u8; 32] = [
    0xc6, 0x82, 0x26, 0x37, 0xc7, 0xd3, 0x10, 0xec, 0x57, 0x62, 0x7b, 0xe0, 0x0b, 0xa2, 0x59, 0xd2,
    0x53, 0x74, 0x9f, 0x4a, 0xaf, 0x64, 0x44, 0x70, 0xcf, 0xfb, 0xe5, 0x3a, 0x35, 0xf7, 0x32, 0x42,
];
/// An unrelated fixed public key for property 1, so a verification can never accidentally
/// succeed against truly arbitrary bytes while exercising the parser.
const UNRELATED_PUBLIC_KEY: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    // Property 1: arbitrary bytes never panic the parser.
    let _ = EquivalenceList::verify(data, &UNRELATED_PUBLIC_KEY, 0);

    // Property 2: a list built from the fuzzer's own bytes, signed with the fixed test key,
    // round-trips through `verify`. The hex suffix is bounded to at most 16 input bytes (32
    // hex characters) regardless of `data`'s length, so the generated domain always fits
    // comfortably under the host-length bound without needing to reject long inputs outright.
    let n = data.len().min(16);
    let suffix: String = data[..n].iter().map(|b| format!("{b:02x}")).collect();
    let a = format!("a-{suffix}.example");
    let b = format!("b-{suffix}.example");
    let Ok(group) = EquivalenceGroup::new(GroupId::from_bytes([0xAB; 16]), [a, b], false) else {
        return;
    };
    let Ok(list) = EquivalenceList::new(1, 0, vec![group]) else {
        return;
    };
    let Ok(ctx) = list.encode_ctx() else {
        return;
    };
    let Ok(signature) = rizzy_core::sign::sign_detached(labels::SIG_EQUIVALENCE_LIST, &ctx, &SEED)
    else {
        return;
    };
    let Ok(wire) = list.encode_signed(&signature) else {
        return;
    };
    let verified =
        EquivalenceList::verify(&wire, &PUBLIC_KEY, 0).expect("self-signed list must verify");
    assert_eq!(verified, list);
});

// SPDX-License-Identifier: AGPL-3.0-only

//! Unit and property tests of the matching settings (ADR 0042 §3–§4, §8).

use super::*;
use proptest::prelude::*;

fn gid(byte: u8) -> GroupId {
    GroupId::from_bytes([byte; 16])
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `str(x)` written by hand, independent of `rizzy_core::encoding`.
fn spec_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// A `user_group` written field by field (ADR 0038 §1), independent of the codec.
fn spec_group(out: &mut Vec<u8>, id: u8, domains: &[&str], flag: u8) {
    out.extend_from_slice(&[id; 16]);
    out.extend_from_slice(&u16::try_from(domains.len()).unwrap().to_be_bytes());
    for d in domains {
        spec_str(out, d);
    }
    out.push(flag);
}

/// A whole section written field by field.
fn spec(default: u16, disabled: &[u8], groups: &[(u8, &[&str], u8)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&default.to_be_bytes());
    out.extend_from_slice(&u16::try_from(disabled.len()).unwrap().to_be_bytes());
    for id in disabled {
        out.extend_from_slice(&[*id; 16]);
    }
    out.extend_from_slice(&u16::try_from(groups.len()).unwrap().to_be_bytes());
    for (id, domains, flag) in groups {
        spec_group(&mut out, *id, domains, *flag);
    }
    out
}

#[test]
fn the_default_is_base_domain_with_nothing_disabled_and_no_user_groups() {
    let s = MatchingSettings::default();
    assert_eq!(s.match_default(), MatchMode::BaseDomain);
    assert!(s.disabled_global().is_empty());
    assert!(s.user_groups().is_empty());
    assert_eq!(s.encode().unwrap(), hex("0001 0000 0000"));
    assert_eq!(MatchingSettings::decode(&hex("0001 0000 0000")).unwrap(), s);
}

#[test]
fn a_full_section_matches_the_spec_bytes_and_round_trips() {
    let mut s = MatchingSettings::default();
    s.set_match_default(MatchMode::Host).unwrap();
    s.disable_global(gid(0x22)).unwrap();
    s.disable_global(gid(0x11)).unwrap();
    s.add_user_group(user_group(gid(0xb0), ["Example.NET.", "example.com"]).unwrap())
        .unwrap();
    s.add_user_group(user_group(gid(0xa0), ["xn--bcher-kva.example", "rizzy.dev"]).unwrap())
        .unwrap();
    let expected = spec(
        0x0002,
        &[0x11, 0x22],
        &[
            (0xa0, &["rizzy.dev", "xn--bcher-kva.example"], 0),
            (0xb0, &["example.com", "example.net"], 0),
        ],
    );
    let encoded = s.encode().unwrap();
    assert_eq!(encoded, expected);
    let decoded = MatchingSettings::decode(&encoded).unwrap();
    assert_eq!(decoded, s);
    assert_eq!(decoded.encode().unwrap(), encoded);
}

#[test]
fn user_group_refuses_a_public_suffix_and_a_subdomain() {
    for bad in [
        "co.uk",
        "github.io",
        "com",
        "www.example.com",
        "a.b.example.co.uk",
    ] {
        assert_eq!(
            user_group(gid(1), [bad, "example.org"]).unwrap_err(),
            MatchingSettingsError::NotRegistrableDomain,
            "{bad}"
        );
    }
    // A registrable domain under a multi-label suffix is fine.
    assert!(user_group(gid(1), ["example.co.uk", "example.org"]).is_ok());
}

#[test]
fn user_group_refuses_bad_shapes() {
    assert_eq!(
        user_group(gid(1), ["example.com"]).unwrap_err(),
        MatchingSettingsError::InvalidGroup
    );
    assert_eq!(
        user_group(gid(1), ["example.com", "EXAMPLE.com."]).unwrap_err(),
        MatchingSettingsError::InvalidGroup
    );
    assert_eq!(
        user_group(gid(1), ["", "example.com"]).unwrap_err(),
        MatchingSettingsError::InvalidDomain
    );
    let many: Vec<String> = (0..=64).map(|i| format!("site{i}.example")).collect();
    assert_eq!(
        user_group(gid(1), &many).unwrap_err(),
        MatchingSettingsError::InvalidGroup
    );
    let flag = user_group(gid(1), ["example.com", "example.org"]).unwrap();
    assert!(!flag.third_party_hostable(), "always 0x00 for a user group");
}

#[test]
fn edits_keep_the_bounds() {
    let mut s = MatchingSettings::default();
    assert_eq!(
        s.set_match_default(MatchMode::AccountDefault).unwrap_err(),
        MatchingSettingsError::InvalidMatchDefault
    );
    // A group built with the reviewed-exception flag is never a user group.
    let flagged = EquivalenceGroup::new(gid(9), ["example.com", "example.org"], true).unwrap();
    assert_eq!(
        s.add_user_group(flagged).unwrap_err(),
        MatchingSettingsError::NotRegistrableDomain
    );
    let suffix = EquivalenceGroup::new(gid(9), ["co.uk", "example.org"], false).unwrap();
    assert_eq!(
        s.add_user_group(suffix).unwrap_err(),
        MatchingSettingsError::NotRegistrableDomain
    );
    s.add_user_group(user_group(gid(1), ["a.example", "b.example"]).unwrap())
        .unwrap();
    assert_eq!(
        s.add_user_group(user_group(gid(1), ["c.example", "d.example"]).unwrap())
            .unwrap_err(),
        MatchingSettingsError::DuplicateGroup
    );
    for i in 2..=u8::try_from(MAX_USER_GROUPS).unwrap() {
        s.add_user_group(user_group(gid(i), ["a.example", "b.example"]).unwrap())
            .unwrap();
    }
    assert_eq!(s.user_groups().len(), usize::from(MAX_USER_GROUPS));
    assert_eq!(
        s.add_user_group(user_group(gid(0xff), ["a.example", "b.example"]).unwrap())
            .unwrap_err(),
        MatchingSettingsError::TooManyUserGroups
    );
    assert!(s.remove_user_group(gid(1)));
    assert!(!s.remove_user_group(gid(1)));

    let mut d = MatchingSettings::default();
    for i in 0..MAX_DISABLED_GROUPS {
        let mut id = [0u8; 16];
        id[..2].copy_from_slice(&i.to_be_bytes());
        d.disable_global(GroupId::from_bytes(id)).unwrap();
    }
    // Disabling one already disabled is no change, even at the bound.
    d.disable_global(GroupId::from_bytes([0; 16])).unwrap();
    assert_eq!(
        d.disable_global(gid(0xff)).unwrap_err(),
        MatchingSettingsError::TooManyDisabledGroups
    );
    assert!(d.enable_global(GroupId::from_bytes([0; 16])));
    assert!(!d.enable_global(GroupId::from_bytes([0; 16])));
    d.disable_global(gid(0xff)).unwrap();
    // The worst case of `d` alone stays far under the 1 MiB entry bound (ADR 0042 §3–§4).
    assert_eq!(d.encode().unwrap().len(), 2 + 2 + 1024 * 16 + 2);
}

#[test]
fn the_view_merges_global_minus_disabled_plus_user_groups() {
    let global = [
        EquivalenceGroup::new(gid(1), ["youtube.com", "youtu.be"], false).unwrap(),
        EquivalenceGroup::new(gid(2), ["apple.com", "icloud.com"], false).unwrap(),
    ];
    let mut s = MatchingSettings::default();
    s.disable_global(gid(2)).unwrap();
    s.add_user_group(user_group(gid(3), ["example.com", "example.net"]).unwrap())
        .unwrap();
    let view = s.view(&global);
    assert_eq!(view.same_group("youtube.com", "youtu.be"), Some(gid(1)));
    assert_eq!(view.same_group("apple.com", "icloud.com"), None, "disabled");
    assert_eq!(view.same_group("example.com", "example.net"), Some(gid(3)));
    assert_eq!(view.same_group("example.com", "youtube.com"), None);
}

/// The negative cases of ADR 0042 §8 that belong to this section, one violation each.
#[test]
fn decode_rejects_each_violation() {
    let ok_group: (u8, &[&str], u8) = (1, &["example.com", "example.net"], 0);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("match_default 0x0000", spec(0x0000, &[], &[])),
        ("match_default 0x0007", spec(0x0007, &[], &[])),
        ("match_default 0xffff", spec(0xffff, &[], &[])),
        ("disabled ids out of order", spec(1, &[2, 1], &[])),
        ("duplicate disabled id", spec(1, &[1, 1], &[])),
        ("duplicate group_id", spec(1, &[], &[ok_group, ok_group])),
        (
            "user groups out of order",
            spec(1, &[], &[(2, &["a.example", "b.example"], 0), ok_group]),
        ),
        (
            "one-domain user group",
            spec(1, &[], &[(1, &["example.com"], 0)]),
        ),
        (
            "public-suffix domain",
            spec(1, &[], &[(1, &["co.uk", "example.com"], 0)]),
        ),
        (
            "subdomain",
            spec(1, &[], &[(1, &["example.com", "www.example.net"], 0)]),
        ),
        (
            "flag = 1",
            spec(1, &[], &[(1, &["example.com", "example.net"], 1)]),
        ),
        (
            "flag = 2",
            spec(1, &[], &[(1, &["example.com", "example.net"], 2)]),
        ),
        (
            "domains not sorted",
            spec(1, &[], &[(1, &["example.net", "example.com"], 0)]),
        ),
        (
            "domain not canonical",
            spec(1, &[], &[(1, &["Example.com", "example.net"], 0)]),
        ),
        ("truncated", spec(1, &[1], &[])[..10].to_vec()),
        ("empty", Vec::new()),
        ("trailing byte", {
            let mut v = spec(1, &[], &[]);
            v.push(0);
            v
        }),
        ("d above the bound", {
            let mut v = hex("0001");
            v.extend_from_slice(&(MAX_DISABLED_GROUPS + 1).to_be_bytes());
            v
        }),
        ("u above the bound", {
            let mut v = hex("0001 0000");
            v.extend_from_slice(&(MAX_USER_GROUPS + 1).to_be_bytes());
            v
        }),
    ];
    for (name, bytes) in cases {
        assert_eq!(
            MatchingSettings::decode(&bytes).unwrap_err(),
            MatchingSettingsError::Malformed,
            "{name}"
        );
    }
}

#[test]
fn debug_shows_counts_only() {
    let mut s = MatchingSettings::default();
    s.add_user_group(user_group(gid(0xab), ["secret-site.example", "other.example"]).unwrap())
        .unwrap();
    let shown = format!("{s:?}");
    assert!(!shown.contains("secret-site"), "{shown}");
    assert!(!shown.contains("171"), "no id bytes: {shown}");
}

fn domain() -> impl Strategy<Value = String> {
    // Short labels can hit a private PSL suffix (`us.com`, `eu.org`); those are refused by
    // design, so the generator keeps only domains that are their own registrable domain.
    "[a-z]{1,8}\\.(com|net|org|co\\.uk)"
        .prop_filter("registrable", |d| is_own_registrable_domain(d))
}

fn arb_settings() -> impl Strategy<Value = MatchingSettings> {
    (
        1u16..=6,
        proptest::collection::btree_set(any::<[u8; 16]>(), 0..8),
        proptest::collection::btree_map(
            any::<[u8; 16]>(),
            proptest::collection::btree_set(domain(), 2..6),
            0..5,
        ),
    )
        .prop_map(|(default, disabled, groups)| {
            let mut s = MatchingSettings::default();
            s.set_match_default(MatchMode::from_wire(default).unwrap())
                .unwrap();
            for id in disabled {
                s.disable_global(GroupId::from_bytes(id)).unwrap();
            }
            for (id, domains) in groups {
                s.add_user_group(user_group(GroupId::from_bytes(id), domains).unwrap())
                    .unwrap();
            }
            s
        })
}

proptest! {
    /// ADR 0042 §8: encode → decode → encode is the identity.
    #[test]
    fn encode_decode_encode_is_the_identity(s in arb_settings()) {
        let first = s.encode().unwrap();
        let decoded = MatchingSettings::decode(&first).unwrap();
        prop_assert_eq!(&decoded, &s);
        prop_assert_eq!(decoded.encode().unwrap(), first);
    }

    /// Untrusted bytes never panic, and whatever decodes re-encodes to the same bytes (one
    /// accepted encoding per value).
    #[test]
    fn decode_never_panics_and_is_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(s) = MatchingSettings::decode(&bytes) {
            prop_assert_eq!(s.encode().unwrap(), bytes);
        }
    }
}

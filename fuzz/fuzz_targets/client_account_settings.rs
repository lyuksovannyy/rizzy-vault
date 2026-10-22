// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the `ACCOUNT_SETTINGS` plaintext parsers (ADR 0042 §2–§4): `rizzy-client`'s outer
//! record ([`AccountSettingsRecord::decode`]) and `rizzy-match`'s matching section
//! ([`MatchingSettings::decode`], tag `0x0001`). The plaintext is what an envelope the server
//! serves opens to: authenticated, but written by any client of the account, a newer or a buggy
//! one, so it is parsed as untrusted input.
//!
//! For each input:
//!
//! - neither parser panics; the record parser fails only with `invalid_server_response` (a
//!   rejected record) or `settings_update_required` (`format_version ≠ 1`, parked);
//! - one value has one encoding: whatever parses encodes back to the input, byte for byte, and
//!   parses again to the same value (ADR 0042 §8: encode → decode → encode is the identity);
//! - a parsed record stays within the bounds of ADR 0042 §3–§4: at most 64 user groups, at most
//!   1,024 disabled ids, every user group with `flag_third_party_hostable = 0x00`;
//! - every edit the host can make on a parsed record either is refused with a stable error or
//!   leaves a record that encodes and parses back to itself, with every unknown tag carried.
//!
//! ```text
//! cargo +nightly fuzz run client_account_settings
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::ClientError;
use rizzy_client::rizzy_match::error::{MAX_DISABLED_GROUPS, MAX_USER_GROUPS};
use rizzy_client::rizzy_match::{GroupId, MatchMode, MatchingSettings, user_group};
use rizzy_client::settings::AccountSettingsRecord;

/// The section's bounds and the user-group rules hold for `m`.
fn assert_bounds(m: &MatchingSettings) {
    assert!(m.user_groups().len() <= usize::from(MAX_USER_GROUPS));
    assert!(m.disabled_global().len() <= usize::from(MAX_DISABLED_GROUPS));
    assert_ne!(m.match_default(), MatchMode::AccountDefault);
    for group in m.user_groups() {
        assert!(!group.third_party_hostable());
        assert!((2..=64).contains(&group.domains().len()));
    }
}

fuzz_target!(|data: &[u8]| {
    // The matching section alone, as tag 0x0001's value.
    if let Ok(section) = MatchingSettings::decode(data) {
        assert_bounds(&section);
        let encoded = section.encode().expect("a parsed section encodes");
        assert_eq!(encoded, data, "one encoding per section");
        assert_eq!(MatchingSettings::decode(&encoded).as_ref(), Ok(&section));
    }

    // The whole record.
    let record = match AccountSettingsRecord::decode(data) {
        Ok(record) => record,
        Err(e) => {
            assert!(matches!(
                e,
                ClientError::InvalidServerResponse | ClientError::SettingsUpdateRequired
            ));
            return;
        }
    };
    assert_bounds(record.matching());
    let encoded = record.encode().expect("a parsed record encodes");
    assert_eq!(encoded.as_slice(), data, "one encoding per record");
    let again = AccountSettingsRecord::decode(&encoded).expect("and parses again");
    assert_eq!(again, record);

    // The edits a host makes, on the parsed section (the record applies them the same way).
    let unknown: Vec<u16> = record.unknown_tags().collect();
    let mut m = record.matching().clone();
    let _ = m.set_match_default(MatchMode::Exact);
    let _ = m.disable_global(GroupId::from_bytes([0x5a; 16]));
    let _ = m.enable_global(GroupId::from_bytes([0x5a; 16]));
    if let Ok(group) = user_group(GroupId::from_bytes([0xa5; 16]), ["example.com", "example.net"]) {
        let _ = m.add_user_group(group);
    }
    if let Some(first) = m.user_groups().first().map(|g| g.id()) {
        let _ = m.remove_user_group(first);
    }
    assert_bounds(&m);
    let bytes = m.encode().expect("an edited section encodes");
    assert_eq!(MatchingSettings::decode(&bytes).as_ref(), Ok(&m));
    assert_eq!(again.unknown_tags().collect::<Vec<_>>(), unknown);
});

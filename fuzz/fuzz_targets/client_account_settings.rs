// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the `ACCOUNT_SETTINGS` plaintext parsers (ADR 0042 §2–§4): `rizzy-client`'s outer
//! record ([`AccountSettingsRecord::decode`]) and `rizzy-match`'s matching section
//! ([`MatchingSettings::decode`], tag `0x0001`). The plaintext is what an envelope the server
//! serves opens to: authenticated, but written by any client of the account, a newer or a buggy
//! one, so it is parsed as untrusted input.
//!
//! For each input:
//!
//! - neither parser panics; the record parser fails only with `settings_unreadable` (an
//!   unreadable record) or `settings_update_required` (`format_version ≠ 1`, parked), never
//!   with `invalid_server_response` (ADR 0097 §1, §4.6); a recognised tag that breaks its own
//!   layout is an unreadable section of a record that parses;
//! - one value has one encoding: whatever parses encodes back to the input, byte for byte, and
//!   parses again to the same value (ADR 0042 §8: encode → decode → encode is the identity);
//! - a parsed record stays within the bounds of ADR 0042 §3–§4: at most 64 user groups, at most
//!   1,024 disabled ids, every user group with `flag_third_party_hostable = 0x00`;
//! - every edit the host can make on a parsed record either is refused with a stable error or
//!   leaves a record that encodes and parses back to itself, with every unknown tag carried;
//!   inert user groups and unreadable sections survive every edit byte for byte (ADR 0097
//!   §4.2, §4.4);
//! - the website-icons switch (tag `0x0005`, ADR 0099 §1) is never an unknown tag, reads off only
//!   from an explicit one-byte `0x00` entry, and reads off for every record that does not parse.
//!
//! ```text
//! cargo +nightly fuzz run client_account_settings
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::ClientError;
use rizzy_client::rizzy_match::error::{MAX_DISABLED_GROUPS, MAX_USER_GROUPS};
use rizzy_client::rizzy_match::{GroupId, MatchMode, MatchingSettings, user_group};
use rizzy_client::icons::IconsSetting;
use rizzy_client::settings::{AccountSettingsRecord, TAG_WEBSITE_ICONS};

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
            // A record that cannot be read never falls back to the (wider) default.
            assert!(!IconsSetting::from_read(Err(e)).is_on());
            assert!(matches!(
                e,
                ClientError::SettingsUnreadable | ClientError::SettingsUpdateRequired
            ));
            return;
        }
    };
    let unreadable: Vec<u16> = record.unreadable_sections().collect();
    match record.matching() {
        Ok(m) => assert_bounds(m),
        Err(e) => {
            assert_eq!(e, ClientError::SettingsUnreadable);
            assert!(unreadable.contains(&0x0001));
        }
    }
    let encoded = record.encode().expect("a parsed record encodes");
    assert_eq!(encoded.as_slice(), data, "one encoding per record");
    let again = AccountSettingsRecord::decode(&encoded).expect("and parses again");
    assert_eq!(again, record);

    // Website icons: off only from an explicit 0x00 entry; never kept as an unknown tag.
    assert_eq!(again.website_icons(), record.website_icons());
    assert!(record.unknown_tags().all(|tag| tag != TAG_WEBSITE_ICONS));
    if !record.website_icons().is_on() {
        let off_entry = [0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert!(data.windows(off_entry.len()).any(|w| w == off_entry));
    }

    // The edits a host makes, on the parsed section (the record applies them the same way).
    let unknown: Vec<u16> = record.unknown_tags().collect();
    let Ok(m) = record.matching() else {
        assert_eq!(again.unreadable_sections().collect::<Vec<_>>(), unreadable);
        return;
    };
    let inert = m.inert_groups().to_vec();
    let mut m = m.clone();
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
    assert!(m.inert_groups() == inert.as_slice(), "inert groups survive every edit");
    let bytes = m.encode().expect("an edited section encodes");
    assert_eq!(MatchingSettings::decode(&bytes).as_ref(), Ok(&m));
    assert_eq!(again.unknown_tags().collect::<Vec<_>>(), unknown);
    assert_eq!(again.unreadable_sections().collect::<Vec<_>>(), unreadable);
});

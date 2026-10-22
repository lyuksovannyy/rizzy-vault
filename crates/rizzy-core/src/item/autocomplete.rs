// SPDX-License-Identifier: AGPL-3.0-only

//! Custom-field autocomplete ids ([ADR 0076] §2.1–§2.2, §3).
//!
//! A custom field may carry an **autocomplete id** in `field/<id>/autocomplete` (Text, a content
//! attribute, not concealed). The extension fills the field's value into a page field whose
//! `autocomplete` attribute is exactly that id. This module owns the id's meaning, as the item
//! schema owns value meaning (ADR 0018 §2): the grammar and the reserved set, as one pure
//! function, [`check_autocomplete_id`]. The item-state checks (W3 duplicates, W4 kind, W5 the
//! Display Name) need the item and live in `rizzy-client`.
//!
//! **Grammar** (ADR 0076 §2.2, RFC 5234):
//!
//! ```text
//! ac_id = 1*64( %x61-7A / DIGIT / "-" / "_" / "." )   ; lowercase ASCII token, 1–64 bytes
//! ```
//!
//! **Reserved set R** (§3): the WHATWG keywords and prefix tokens, every value beginning with
//! `section-`, the login roles, every other WHATWG autofill field name, the WHATWG contact names
//! and the manager aliases. [`RESERVED_AUTOCOMPLETE_IDS`] is the list, frozen by the ADR.
//!
//! Nothing is normalised here: an id with an uppercase letter is refused, not lowercased. The
//! editors lowercase ASCII input before they write (§2.2). The errors never echo the id
//! (ADR 0013 §3 rule 4): it is item content.
//!
//! [ADR 0076]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0076-autocomplete-driven-autofill.md

use core::fmt;

/// The longest autocomplete id, in bytes (ADR 0076 §2.2: `1*64`).
pub const MAX_AUTOCOMPLETE_ID_LEN: usize = 64;

/// The prefix no autocomplete id may begin with (ADR 0076 §2.2, §3 row 1).
pub const RESERVED_AUTOCOMPLETE_PREFIX: &str = "section-";

/// The reserved set R of ADR 0076 §3, without the `section-` prefix rule
/// ([`RESERVED_AUTOCOMPLETE_PREFIX`]), in the table's row order. Frozen by the ADR: changing it
/// needs a new ADR.
pub const RESERVED_AUTOCOMPLETE_IDS: [&str; 70] = [
    // Row 1: WHATWG keywords and prefix tokens.
    "on",
    "off",
    "webauthn",
    "shipping",
    "billing",
    "home",
    "work",
    "mobile",
    "fax",
    "pager",
    // Row 2: the login roles.
    "username",
    "current-password",
    "new-password",
    "one-time-code",
    // Row 3: every other WHATWG autofill field name.
    "name",
    "honorific-prefix",
    "given-name",
    "additional-name",
    "family-name",
    "honorific-suffix",
    "nickname",
    "organization-title",
    "organization",
    "street-address",
    "address-line1",
    "address-line2",
    "address-line3",
    "address-level4",
    "address-level3",
    "address-level2",
    "address-level1",
    "country",
    "country-name",
    "postal-code",
    "cc-name",
    "cc-given-name",
    "cc-additional-name",
    "cc-family-name",
    "cc-number",
    "cc-exp",
    "cc-exp-month",
    "cc-exp-year",
    "cc-csc",
    "cc-type",
    "transaction-currency",
    "transaction-amount",
    "language",
    "bday",
    "bday-day",
    "bday-month",
    "bday-year",
    "sex",
    "url",
    "photo",
    // Row 4: WHATWG contact names.
    "tel",
    "tel-country-code",
    "tel-national",
    "tel-area-code",
    "tel-local",
    "tel-local-prefix",
    "tel-local-suffix",
    "tel-extension",
    "email",
    "impp",
    // Row 5: manager aliases.
    "password",
    "totp",
    "otp",
    "2fa",
    "mfa",
    "passkey",
];

/// Why an autocomplete id is refused (ADR 0076 §2.3 W1, W2). Carries no part of the id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AutocompleteIdError {
    /// W1 `AutocompleteInvalid`: the id breaks the §2.2 grammar (empty, over 64 bytes, or a
    /// byte outside `a-z`, `0-9`, `-`, `_`, `.`).
    Invalid,
    /// W2 `AutocompleteReserved`: the id is in the §3 set, or begins with `section-`.
    Reserved,
}

impl fmt::Display for AutocompleteIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "the autocomplete id breaks the grammar",
            Self::Reserved => "the autocomplete id is reserved",
        })
    }
}

impl std::error::Error for AutocompleteIdError {}

/// `true` if `id` fits the §2.2 `ac_id` grammar (reserved or not).
#[must_use]
pub fn is_ac_id_grammar(id: &[u8]) -> bool {
    !id.is_empty()
        && id.len() <= MAX_AUTOCOMPLETE_ID_LEN
        && id
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

/// `true` if `id` is in the reserved set R (§3): one of [`RESERVED_AUTOCOMPLETE_IDS`], or any
/// value beginning with `section-`. Compared byte for byte, so only a lowercase value matches.
#[must_use]
pub fn is_reserved_autocomplete_id(id: &[u8]) -> bool {
    id.starts_with(RESERVED_AUTOCOMPLETE_PREFIX.as_bytes())
        || RESERVED_AUTOCOMPLETE_IDS
            .iter()
            .any(|reserved| reserved.as_bytes() == id)
}

/// Checks an autocomplete id against the §2.2 grammar, then the §3 reserved set: `Ok` only for
/// an id a custom field may hold and the extension may match.
///
/// # Errors
/// [`AutocompleteIdError::Invalid`] for a grammar break (checked first, so an uppercase
/// `USERNAME` is invalid, not reserved); [`AutocompleteIdError::Reserved`] for an id in R.
pub fn check_autocomplete_id(id: &[u8]) -> Result<(), AutocompleteIdError> {
    if !is_ac_id_grammar(id) {
        return Err(AutocompleteIdError::Invalid);
    }
    if is_reserved_autocomplete_id(id) {
        return Err(AutocompleteIdError::Reserved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn grammar_table() {
        let max = "a".repeat(MAX_AUTOCOMPLETE_ID_LEN);
        let over = "a".repeat(MAX_AUTOCOMPLETE_ID_LEN + 1);
        for (id, expected) in [
            ("x", Ok(())),
            (max.as_str(), Ok(())),
            ("custominput", Ok(())),
            ("member-no", Ok(())),
            ("acct_id.2", Ok(())),
            ("0", Ok(())),
            ("nope", Ok(())),
            ("", Err(AutocompleteIdError::Invalid)),
            (over.as_str(), Err(AutocompleteIdError::Invalid)),
            ("Custom", Err(AutocompleteIdError::Invalid)),
            ("USERNAME", Err(AutocompleteIdError::Invalid)),
            ("a b", Err(AutocompleteIdError::Invalid)),
            (" a", Err(AutocompleteIdError::Invalid)),
            ("a\t", Err(AutocompleteIdError::Invalid)),
            ("a\n", Err(AutocompleteIdError::Invalid)),
            ("caf\u{e9}", Err(AutocompleteIdError::Invalid)),
            ("\u{131}d", Err(AutocompleteIdError::Invalid)),
            ("a/b", Err(AutocompleteIdError::Invalid)),
            ("a+b", Err(AutocompleteIdError::Invalid)),
            ("section-", Err(AutocompleteIdError::Reserved)),
            ("section-login", Err(AutocompleteIdError::Reserved)),
            ("section", Ok(())),
            ("sections-x", Ok(())),
            ("username", Err(AutocompleteIdError::Reserved)),
            ("email", Err(AutocompleteIdError::Reserved)),
            ("tel", Err(AutocompleteIdError::Reserved)),
            ("totp", Err(AutocompleteIdError::Reserved)),
            ("2fa", Err(AutocompleteIdError::Reserved)),
            ("passkey", Err(AutocompleteIdError::Reserved)),
            ("passkeys", Ok(())),
        ] {
            assert_eq!(check_autocomplete_id(id.as_bytes()), expected, "{id:?}");
        }
    }

    /// R equals ADR 0076 §3's list exactly: every row, in order, and nothing else.
    #[test]
    fn reserved_set_is_the_adr_list() {
        let adr: &[&str] = &[
            "on",
            "off",
            "webauthn",
            "shipping",
            "billing",
            "home",
            "work",
            "mobile",
            "fax",
            "pager",
            "username",
            "current-password",
            "new-password",
            "one-time-code",
            "name",
            "honorific-prefix",
            "given-name",
            "additional-name",
            "family-name",
            "honorific-suffix",
            "nickname",
            "organization-title",
            "organization",
            "street-address",
            "address-line1",
            "address-line2",
            "address-line3",
            "address-level4",
            "address-level3",
            "address-level2",
            "address-level1",
            "country",
            "country-name",
            "postal-code",
            "cc-name",
            "cc-given-name",
            "cc-additional-name",
            "cc-family-name",
            "cc-number",
            "cc-exp",
            "cc-exp-month",
            "cc-exp-year",
            "cc-csc",
            "cc-type",
            "transaction-currency",
            "transaction-amount",
            "language",
            "bday",
            "bday-day",
            "bday-month",
            "bday-year",
            "sex",
            "url",
            "photo",
            "tel",
            "tel-country-code",
            "tel-national",
            "tel-area-code",
            "tel-local",
            "tel-local-prefix",
            "tel-local-suffix",
            "tel-extension",
            "email",
            "impp",
            "password",
            "totp",
            "otp",
            "2fa",
            "mfa",
            "passkey",
        ];
        assert_eq!(RESERVED_AUTOCOMPLETE_IDS.as_slice(), adr);
        for id in adr {
            // Every member fits the grammar, so W2 (not W1) reports it.
            assert!(is_ac_id_grammar(id.as_bytes()), "{id}");
            assert_eq!(
                check_autocomplete_id(id.as_bytes()),
                Err(AutocompleteIdError::Reserved)
            );
        }
        let mut sorted = adr.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), adr.len(), "no duplicates in R");
    }

    #[test]
    fn errors_never_echo_the_id() {
        for e in [AutocompleteIdError::Invalid, AutocompleteIdError::Reserved] {
            let text = format!("{e} {e:?}");
            assert!(!text.contains("custominput"));
        }
    }

    proptest! {
        /// Every accepted id is lowercase ASCII of 1–64 bytes, round-trips through UTF-8
        /// unchanged, and is still accepted after ASCII lowercasing (a no-op on it).
        #[test]
        fn accepted_ids_are_lowercase_ascii(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
            if check_autocomplete_id(&bytes).is_ok() {
                prop_assert!((1..=MAX_AUTOCOMPLETE_ID_LEN).contains(&bytes.len()));
                prop_assert!(bytes.iter().all(|b| b.is_ascii() && !b.is_ascii_uppercase()));
                let text = core::str::from_utf8(&bytes);
                prop_assert!(text.is_ok());
                let text = text.unwrap_or_default();
                prop_assert_eq!(text.as_bytes(), bytes.as_slice());
                prop_assert_eq!(text.to_ascii_lowercase(), text);
            }
        }

        /// The grammar's own alphabet: any 1–64 such bytes are accepted unless reserved.
        #[test]
        fn grammar_strings_pass_unless_reserved(id in "[a-z0-9._-]{1,64}") {
            let result = check_autocomplete_id(id.as_bytes());
            if is_reserved_autocomplete_id(id.as_bytes()) {
                prop_assert_eq!(result, Err(AutocompleteIdError::Reserved));
            } else {
                prop_assert_eq!(result, Ok(()));
            }
        }

        /// An id with any uppercase ASCII letter is refused as invalid, never lowercased.
        #[test]
        fn uppercase_is_refused(id in "[a-z0-9]{0,10}[A-Z][a-z0-9]{0,10}") {
            prop_assert_eq!(check_autocomplete_id(id.as_bytes()), Err(AutocompleteIdError::Invalid));
        }
    }
}

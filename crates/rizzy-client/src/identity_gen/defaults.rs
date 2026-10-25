// SPDX-License-Identifier: AGPL-3.0-only

//! The generator's synced defaults, `ACCOUNT_SETTINGS` tag `0x0004` ([ADR 0079] Open question 7,
//! answered (a); [ADR 0042] §2's registry).
//!
//! ```text
//! identity_defaults
//!   u8 sex_default        0 = random, 1 = male, 2 = female
//!   [2] country           ASCII A–Z, or 0x0000 = none
//!   u8 age_min            18 <= age_min <= age_max <= 99
//!   u8 age_max
//!   u8 email_style        1 = name and birthday, 2 = nickname
//!   str(email_domain)     u32 len ‖ UTF-8; empty = unset, else ADR 0079 §3's syntax, lower case,
//!                         at most 253 bytes
//! ```
//!
//! Any other value is a violation inside a recognised tag, so ADR 0042 §2's reject rule applies.
//! The age mode is not stored: a client derives it on open (ADR 0079 §10). The tag number is
//! the one that was next free at implementation: `0x0002` and `0x0003` were free in code but
//! reserved by [ADR 0081] (vault directory, contact pins; then Proposed, Accepted since), so
//! this tag takes `0x0004`.
//!
//! [ADR 0042]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0042-account-settings-matching-layout.md
//! [ADR 0079]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0079-identity-generator.md
//! [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md

use rizzy_core::encoding::{Reader, put_str, put_u8};

use super::{AgeRange, CountryCode, EmailDomain, EmailStyle, MAX_DOMAIN_LEN, SexChoice};

/// The `ACCOUNT_SETTINGS` tag of the generator's defaults.
pub const TAG_IDENTITY_DEFAULTS: u16 = 0x0004;

/// The identity generator's defaults (module docs). `Default` is the first-time state: a drawn
/// sex, no country, 18–27, name and birthday, no domain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IdentityDefaults {
    /// The default sex.
    pub sex: SexChoice,
    /// The default country, if one is set.
    pub country: Option<CountryCode>,
    /// The last-used age range.
    pub age: AgeRange,
    /// The default email style.
    pub email_style: EmailStyle,
    /// The email domain for generated identities, if set (ADR 0079 §8).
    pub email_domain: Option<EmailDomain>,
}

impl IdentityDefaults {
    /// The tag's value bytes.
    ///
    /// # Errors
    /// None in practice: the domain is at most 253 bytes. Kept fallible for the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, rizzy_core::error::EncodeError> {
        let mut out = Vec::with_capacity(10 + MAX_DOMAIN_LEN);
        put_u8(
            &mut out,
            match self.sex {
                SexChoice::Random => 0,
                SexChoice::Male => 1,
                SexChoice::Female => 2,
            },
        );
        match &self.country {
            Some(c) => out.extend_from_slice(c.as_str().as_bytes()),
            None => out.extend_from_slice(&[0, 0]),
        }
        put_u8(&mut out, self.age.min());
        put_u8(&mut out, self.age.max());
        put_u8(
            &mut out,
            match self.email_style {
                EmailStyle::NameAndBirthday => 1,
                EmailStyle::Nickname => 2,
            },
        );
        put_str(
            &mut out,
            self.email_domain.as_ref().map_or("", EmailDomain::as_str),
        )?;
        Ok(out)
    }

    /// Decodes the tag's value; `None` for any violation (module docs).
    #[must_use]
    pub fn decode(value: &[u8]) -> Option<Self> {
        let mut r = Reader::new(value);
        let sex = match r.u8().ok()? {
            0 => SexChoice::Random,
            1 => SexChoice::Male,
            2 => SexChoice::Female,
            _ => return None,
        };
        let country = match [r.u8().ok()?, r.u8().ok()?] {
            [0, 0] => None,
            [a, b] if a.is_ascii_uppercase() && b.is_ascii_uppercase() => {
                Some(CountryCode::parse(core::str::from_utf8(&[a, b]).ok()?).ok()?)
            }
            _ => return None,
        };
        let age = AgeRange::new(r.u8().ok()?, r.u8().ok()?).ok()?;
        let email_style = match r.u8().ok()? {
            1 => EmailStyle::NameAndBirthday,
            2 => EmailStyle::Nickname,
            _ => return None,
        };
        let domain = r.str().ok()?;
        let email_domain = if domain.is_empty() {
            None
        } else {
            let parsed = EmailDomain::parse(domain).ok()?;
            // Canonical: stored lower case, so a decode re-encodes to the same bytes.
            if parsed.as_str() != domain {
                return None;
            }
            Some(parsed)
        };
        r.finish().ok()?;
        Some(Self {
            sex,
            country,
            age,
            email_style,
            email_domain,
        })
    }
}

// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the identity generator's option validation (ADR 0079 §3, §12 "Fuzz targets"): the age
//! text (preset `id`, custom range `MIN-MAX`, exact age `N`), the email domain, the country
//! code, and the synced defaults' layout (ACCOUNT_SETTINGS tag `0x0004`, Open question 7).
//! Never panic, and what is accepted obeys its rules:
//!
//! - an accepted age range has `18 <= min <= max <= 99`;
//! - an accepted domain is lower-case LDH, two or more labels of 1–63 bytes, at most 253 bytes,
//!   and parses to itself;
//! - accepted defaults re-encode to the same bytes;
//! - with all three accepted and the country bundled, a generated identity's completed age is in
//!   the range and its email ends with the domain.
//!
//! Input: the first 8 bytes seed the RNG, the next 4 give today's day number offset; the rest,
//! split at NUL, is the age text, the domain text and the country text. The whole input is also
//! decoded as a tag `0x0004` value.
#![no_main]

use std::convert::Infallible;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_client::identity_gen::{
    AgeRange, CivilDate, CountryCode, EmailDomain, IdentityDefaults, IdentityField,
    IdentityOptions, embedded_data, generate_identity,
};

/// SplitMix64, seeded from the input.
struct SplitMix(u64);

impl TryRng for SplitMix {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let [a, b, c, d, ..] = self.try_next_u64()?.to_le_bytes();
        Ok(u32::from_le_bytes([a, b, c, d]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for SplitMix {}

fuzz_target!(|bytes: &[u8]| {
    if let Some(defaults) = IdentityDefaults::decode(bytes) {
        assert_eq!(defaults.encode().unwrap(), bytes);
    }
    let (head, rest) = bytes.split_at(bytes.len().min(12));
    let mut h = [0u8; 12];
    h[..head.len()].copy_from_slice(head);
    let seed = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
    let offset = i64::from(u32::from_le_bytes([h[8], h[9], h[10], h[11]]) % 100_000);
    let Ok(text) = core::str::from_utf8(rest) else {
        return;
    };
    let mut parts = text.split('\0');
    let (age_text, domain_text, country_text) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let age = AgeRange::parse(age_text);
    if let Ok(range) = age {
        assert!(18 <= range.min() && range.min() <= range.max() && range.max() <= 99);
    }
    let domain = EmailDomain::parse(domain_text);
    if let Ok(d) = &domain {
        let s = d.as_str();
        assert!(s.len() <= 253 && s.split('.').count() >= 2);
        assert!(s.split('.').all(|l| (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')));
        assert_eq!(EmailDomain::parse(s).as_ref(), Ok(d));
    }
    let country = CountryCode::parse(country_text);
    let (Ok(age), Ok(domain), Ok(country)) = (age, domain, country) else {
        return;
    };
    let data = embedded_data().unwrap();
    let Some(today) = CivilDate::from_days(CivilDate::new(1970, 1, 1).unwrap().days() + offset) else {
        return;
    };
    let mut options = IdentityOptions::new(country);
    options.age = age;
    options.email_domain = Some(domain.clone());
    match generate_identity(&mut SplitMix(seed), data, &options, today) {
        Ok(id) => {
            let years = id.birthday().age_on(today).unwrap();
            assert!((u32::from(age.min())..=u32::from(age.max())).contains(&years));
            let email = id.get(IdentityField::Email).unwrap();
            assert!(email.ends_with(&format!("@{}", domain.as_str())));
        }
        Err(_) => assert!(data.country(country.as_str()).is_none()),
    }
});

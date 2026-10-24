// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the identity data parser (ADR 0079 §5, §12 "Fuzz targets"): never panic on arbitrary
//! bytes, and every file it accepts can generate an identity for each of its countries that
//! keeps the generator's invariants (the age range, the country, a state of the country).
//!
//! The RNG is a seeded SplitMix64, not a CSPRNG: nothing here depends on unpredictability, and
//! a crash must reproduce from its input alone.
#![no_main]

use std::convert::Infallible;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_client::identity_gen::{
    CivilDate, CountryCode, IdentityField, IdentityOptions, data, generate_identity,
    regenerate_field,
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
    let Ok(parsed) = data::parse(bytes) else {
        return;
    };
    let today = CivilDate::new(2026, 10, 23).unwrap();
    let mut rng = SplitMix(bytes.len() as u64);
    for country in parsed.countries() {
        let options = IdentityOptions::new(CountryCode::parse(country.code()).unwrap());
        let id = generate_identity(&mut rng, &parsed, &options, today).unwrap();
        let age = id.birthday().age_on(today).unwrap();
        assert!((18..=27).contains(&age));
        assert_eq!(id.get(IdentityField::Country), Some(country.code()));
        let state = id.get(IdentityField::State).unwrap();
        assert!(country.subdivision_names().any(|s| s == state));
        for field in IdentityField::ALL {
            let again = regenerate_field(&mut rng, &parsed, &options, today, field, &id).unwrap();
            assert_eq!(again.get(IdentityField::Country), Some(country.code()));
        }
    }
});

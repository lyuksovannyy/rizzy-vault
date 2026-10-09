//! Fuzzes the `WebAuthn` passkey ceremonies (`rizzy_client::passkey::{create_credential,
//! get_assertion}`, [ADR 0039] §1, §2, §4) on attacker/relying-party-controlled input: the
//! origin and `rpId` strings a malicious or buggy page can send through the extension's
//! interception layer, and the challenge bytes a relying party picks ([ADR 0039] §2's INV-64
//! note: "never trusting any field of the intercepted call for the RP origin"). This is the
//! fuzz target [ADR 0039]'s Consequences section asks for ("Hand-writing WebAuthn's CBOR
//! structures... needs its own fuzz target"): `create_credential` and `get_assertion` are the
//! only entry points that ever drive the hand-written CBOR (`passkey::cbor`) and wire-format
//! (`passkey::wire`) encoders with external-shaped input — those two modules are
//! `pub(super)`-private encoders of already-length-bounded, internally generated data
//! ([`rizzy_client::passkey::cbor`]'s own doc comments), never decoders of untrusted bytes, so
//! fuzzing them directly would just restate what the type system already guarantees
//! (`Vec::extend_from_slice` cannot panic on any length). Fuzzing through the public ceremony
//! functions instead exercises the same encoders with genuinely untrusted-length origin/`rpId`
//! strings and challenge bytes, matching every other target in this directory (fuzz the
//! boundary where untrusted data actually enters, not an internal helper).
//!
//! `data` is split at the first two `0x00` bytes into `origin`, `rp_id` and `challenge`
//! (non-UTF-8 `origin`/`rp_id` is skipped, since both are `&str`); a `SplitMix64` seeded from
//! the input stands in for the injected CSPRNG ([`generator_options`]'s own target documents
//! the same substitution) — nothing here depends on unpredictability, and a crash must
//! reproduce from its input alone.
//!
//! For every input, neither ceremony function may panic. When [`create_credential`] accepts:
//! - `credential_id` is exactly 32 bytes and `public_key_cose`, `client_data_json` and
//!   `attestation_object` are all non-empty;
//! - `client_data_json` is UTF-8 JSON naming the `"webauthn.create"` ceremony type;
//! - the same `origin`/`rp_id` pair, which already passed INV-64 once for creation, must pass
//!   it again for [`get_assertion`] (the check is a pure function of those two strings, module
//!   docs), and the resulting assertion's signature must verify under the credential's own
//!   freshly generated public key.
//!
//! [ADR 0039]: ../../docs/adr/0039-passkeys-vault-and-extension.md
//!
//! ```text
//! cargo +nightly fuzz run passkey_ceremony
//! ```
#![no_main]

use std::convert::Infallible;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_client::passkey::{create_credential, get_assertion};
use rizzy_core::passkey::client_data_hash;

/// `SplitMix64`, seeded from the input. Not a CSPRNG: see the module docs.
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

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |&b| b == 0);
    let Some(origin) = parts.next() else { return };
    let Some(rp_id) = parts.next() else { return };
    let challenge = parts.next().unwrap_or(&[]);
    let Ok(origin) = core::str::from_utf8(origin) else { return };
    let Ok(rp_id) = core::str::from_utf8(rp_id) else { return };

    let mut seed = 0u64;
    for &byte in origin.as_bytes().iter().chain(rp_id.as_bytes()).chain(challenge) {
        seed = seed.wrapping_mul(31).wrapping_add(u64::from(byte));
    }
    let mut rng = SplitMix(seed);

    let Ok(created) = create_credential(&mut rng, origin, rp_id, challenge) else {
        return;
    };

    assert_eq!(created.credential_id.len(), 32);
    assert!(!created.public_key_cose.is_empty());
    assert!(!created.client_data_json.is_empty());
    assert!(!created.attestation_object.is_empty());

    let client_data_text =
        core::str::from_utf8(&created.client_data_json).expect("clientDataJSON is UTF-8 JSON");
    assert!(client_data_text.contains(r#""type":"webauthn.create""#));

    // The same origin/rp_id that just passed INV-64 for creation is a pure function of those
    // two strings, so it must pass again for an assertion (module docs on `verify_rp_id`).
    let assertion =
        get_assertion(&created.signing_key, &created.credential_id, origin, rp_id, challenge)
            .expect("the origin/rp_id that created the credential must also pass for assertion");
    assert_eq!(assertion.credential_id, created.credential_id);

    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&client_data_hash(&assertion.client_data_json));
    created
        .signing_key
        .verifying_key()
        .verify_der(&message, &assertion.signature_der)
        .expect("the assertion signature must verify under the credential's own public key");
});

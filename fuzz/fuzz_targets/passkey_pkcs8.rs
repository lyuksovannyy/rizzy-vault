// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes rizzy-core's hand-written PKCS#8 reader (ADR 0074 §4: "with its own fuzz target"),
//! the DER a CXF passkey's `key` carries. It may not panic, whatever the input; whatever it
//! accepts must be a 32-byte private value of one of the two algorithms that writes back to a
//! key the reader accepts again, with the same algorithm and value (the writers emit one fixed
//! shape each, so a reparse of the written form is a fixed point).
//!
//! ```text
//! cargo +nightly fuzz run passkey_pkcs8
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::passkey::pkcs8::{Pkcs8Algorithm, encode_eddsa_seed, encode_es256, parse};
use rizzy_core::passkey::{EdDsaSigningKey, Es256SigningKey};

fuzz_target!(|data: &[u8]| {
    let Ok(key) = parse(data) else {
        return;
    };
    let secret = key.secret().expose_secret();
    let written = match key.algorithm() {
        Pkcs8Algorithm::Es256 => {
            let Ok(signing) = Es256SigningKey::from_bytes(secret) else {
                panic!("an accepted ES256 scalar must be a valid key");
            };
            encode_es256(&signing)
        }
        Pkcs8Algorithm::EdDsa => {
            assert!(EdDsaSigningKey::from_seed(secret).is_ok());
            let Ok(written) = encode_eddsa_seed(secret) else {
                panic!("an accepted Ed25519 seed must be 32 bytes");
            };
            written
        }
    };
    let Ok(again) = parse(written.expose_secret()) else {
        panic!("a written key must parse");
    };
    assert_eq!(again.algorithm(), key.algorithm());
    assert_eq!(again.secret().expose_secret(), secret);
});

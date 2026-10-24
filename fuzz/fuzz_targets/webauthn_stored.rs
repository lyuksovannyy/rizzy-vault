// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the decoders of `rizzy-domain-auth`'s stored `WebAuthn` JSON (ADR 0077 §§2, 4): the
//! `security_key` of a `webauthn_credential` row and the ceremony state of a challenge row,
//! both `webauthn-rs` 0.5.x serde JSON read back from the database. A database writer controls
//! them, so each read is bounded (64 KiB, a known format number) and must refuse anything else
//! without a panic.
//!
//! The first two input bytes are the stored format number (big-endian), the rest the stored
//! text (lossy UTF-8). Nothing panics, and nothing above 64 KiB or with an unknown format is ever
//! accepted.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_domain_auth::fuzz_stored_json;

fuzz_target!(|data: &[u8]| {
    let Some((format, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let format = u16::from_be_bytes(*format);
    let text = String::from_utf8_lossy(rest);
    let accepted = fuzz_stored_json(format, &text);
    assert!(accepted <= 3);
    if format != 1 || text.len() > 64 * 1024 {
        assert_eq!(accepted, 0);
    }
});

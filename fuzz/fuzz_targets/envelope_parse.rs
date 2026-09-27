//! Fuzzes the envelope parsers (CRYPTO.md §9.5 rule 5): never panics, never allocates in
//! proportion to a length field, and a successful parse re-serialises to the same bytes.
//!
//! What runs on each input:
//!
//! - [`parse`], the purpose-agnostic layout parser for the symmetric (`0x01`) and HPKE (`0x10`,
//!   `0x12`) envelopes. When it accepts, the target asserts that `to_vec()` gives back exactly
//!   the input and that `encoded_len()` is its length, so the layout has one encoding and the
//!   parser drops or invents no byte.
//! - [`parse_for_purpose`], the decryption-path parser, once per registered purpose with that
//!   purpose's client allow-list and once with its server allow-list. It runs the §9.5 checks
//!   (length, `format_version`, algorithm allow-list) before any crypto; the target only
//!   requires that it returns instead of panicking.
//!
//! No key is involved, so nothing here reaches the commitment or the AEAD. Both parsers borrow
//! from the input and allocate nothing; libFuzzer's malloc limit would report an allocation a
//! length field could drive. Part of CRYPTO.md §15 item 7 ("envelope parser").
//!
//! ```text
//! cargo +nightly fuzz run envelope_parse
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::envelope::Purpose;
use rizzy_core::envelope::parse::{parse, parse_for_purpose};

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = parse(data) {
        assert_eq!(envelope.to_vec(), data);
        assert_eq!(envelope.encoded_len(), data.len());
    }
    for purpose in Purpose::ALL {
        let _ = parse_for_purpose(data, purpose.client_decrypt_allow_list());
        let _ = parse_for_purpose(data, purpose.server_decrypt_allow_list());
    }
});

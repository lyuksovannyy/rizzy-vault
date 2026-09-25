//! Fuzzes the envelope parsers (CRYPTO.md §9.5 rule 5): never panics, never allocates in
//! proportion to a length field, and a successful parse re-serialises to the same bytes.
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

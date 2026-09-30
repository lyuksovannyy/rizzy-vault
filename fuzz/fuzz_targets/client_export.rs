//! Fuzzes `rizzy-client`'s export-file JSON reader (CRYPTO.md §11.14, §15 item 7): the whole-
//! file size cap and the strict parser never panic, and the header checks that follow never
//! panic either.
//!
//! For each input:
//!
//! - [`parse_export_json`] on the raw bytes. When it accepts, every string member is printable
//!   ASCII without a backslash or quote (the parser admits nothing else), and re-serialising
//!   the seven members in the canonical order parses back to the same fields.
//! - [`read_export_header`] on the raw bytes: it accepts only what the parser accepts.
//!
//! Argon2id never runs: only the parser and the `rizzy-core` header decoders (length checks and
//! base64url of two 22-character fields). The decryption path is covered by `export_fields`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::export::{parse_export_json, read_export_header};

fuzz_target!(|data: &[u8]| {
    let parsed = parse_export_json(data);
    if let Ok(f) = parsed {
        for s in [f.format, f.export_salt, f.export_id, f.data] {
            assert!(
                s.bytes()
                    .all(|b| (0x20..0x7F).contains(&b) && b != b'\\' && b != b'"')
            );
        }
        let canonical = format!(
            "{{\"format\":\"{}\",\"version\":{},\"kdf_id\":{},\"export_salt\":\"{}\",\
             \"export_id\":\"{}\",\"created_at\":{},\"data\":\"{}\"}}",
            f.format, f.version, f.kdf_id, f.export_salt, f.export_id, f.created_at, f.data
        );
        assert_eq!(parse_export_json(canonical.as_bytes()), Ok(f));
    }
    if read_export_header(data).is_ok() {
        assert!(parsed.is_ok());
    }
});

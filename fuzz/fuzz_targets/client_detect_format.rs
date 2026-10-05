//! Fuzzes `rizzy-client`'s import-format recognition (`export::detect`; owner decision
//! 2026-10-05: the app recognises an import file's format itself): on arbitrary bytes it never
//! panics, and it agrees with the strict reader of our encrypted export.
//!
//! For each input:
//!
//! - [`detect_format`] runs to an answer. Every reader it uses (the encrypted export's JSON
//!   reader, `rizzy-import`'s JSON and CSV readers) is bounded and fuzzed on its own; this
//!   target covers the dispatch between them.
//! - Whatever [`parse_export_json`] accepts with our format string is recognised as our
//!   encrypted export.
//!
//! Argon2id never runs: recognition only parses.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::export::detect::{DetectedFormat, detect_format};
use rizzy_client::export::parse_export_json;

fuzz_target!(|data: &[u8]| {
    let detected = detect_format(data);
    if parse_export_json(data).is_ok_and(|f| f.format == "rizzy-vault-export") {
        assert_eq!(detected, Some(DetectedFormat::RizzyEncrypted));
    }
});

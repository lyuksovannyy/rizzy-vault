//! Fuzzes `AliasVault`'s `.avux` importer (roadmap §4.2, M1; threat model A16: zip bombs,
//! malicious import files): the zip reader and the manifest's item mapping
//! (`crates/rizzy-import/src/aliasvault.rs`). Neither may panic, and every item that comes out
//! keeps the importer's guarantees ([`import_common::check`]).
//!
//! The first byte picks what the rest is:
//!
//! - `0`: a whole archive, imported as `.avux`; `manifest.json` is also extracted on its own.
//! - `1`: a `manifest.json` document, imported without an archive
//!   (`import_aliasvault_manifest_data`), so the mapping is reached without the fuzzer
//!   building a zip.
//! - `2`: the same document, wrapped here in a stored zip archive and imported as `.avux`, so
//!   the zip path runs on archives that are valid.
//!
//! ```text
//! cargo +nightly fuzz run import_aliasvault_avux
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::limits::MAX_EXPANDED_LEN;
use rizzy_import::{Format, import, import_aliasvault_manifest_data, zip};

/// A zip archive holding `data` as its one stored member `manifest.json`.
fn stored_archive(data: &[u8]) -> Vec<u8> {
    let name = b"manifest.json";
    let size = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let crc = rizzy_import::inflate::crc32(data);
    let mut out = Vec::with_capacity(data.len() + 128);
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(data);
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    out.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name);
    let cd_size = out.len() as u32 - cd_offset;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let rng = &mut import_common::CountingRng(0);
    match mode % 3 {
        0 => {
            if let Ok(member) = zip::extract(rest, "manifest.json", MAX_EXPANDED_LEN) {
                assert!(member.len() <= MAX_EXPANDED_LEN);
            }
            import_common::check(import(Format::AliasVaultAvux, rest, rng));
        }
        1 => import_common::check(import_aliasvault_manifest_data(rest, rng)),
        _ => import_common::check(import(Format::AliasVaultAvux, &stored_archive(rest), rng)),
    }
});

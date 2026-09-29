//! Fuzzes the 1PUX importer (ADR 0002 point 2; threat model A16: zip bombs, malicious import
//! files): the zip reader, the DEFLATE decoder with its size cap, and the item mapping of
//! `export.data`. None may panic, and every item that comes out keeps the importer's
//! guarantees ([`import_common::check`]).
//!
//! The first byte picks what the rest is:
//!
//! - `0`: a whole archive, imported as 1PUX; `export.data` is also extracted on its own.
//! - `1`: an `export.data` JSON document, imported without an archive
//!   (`import_1pux_data`), so the mapping is reached without the fuzzer building a zip.
//! - `2`: the same document, wrapped here in a stored zip archive and imported as 1PUX, so
//!   the zip path runs on archives that are valid.
//! - `3`: a raw DEFLATE stream, decoded with an expected size taken from the next two bytes;
//!   a decoded stream must be exactly that size.
//!
//! ```text
//! cargo +nightly fuzz run import_1pux
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::inflate::{crc32, inflate};
use rizzy_import::limits::MAX_EXPANDED_LEN;
use rizzy_import::{Format, import, import_1pux_data, zip};

/// A zip archive holding `data` as its one stored member `export.data`.
fn stored_archive(data: &[u8]) -> Vec<u8> {
    let name = b"export.data";
    let size = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let crc = crc32(data);
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
    match mode % 4 {
        0 => {
            if let Ok(member) = zip::extract(rest, "export.data", MAX_EXPANDED_LEN) {
                assert!(member.len() <= MAX_EXPANDED_LEN);
            }
            import_common::check(import(Format::OnePux, rest, rng));
        }
        1 => import_common::check(import_1pux_data(rest, rng)),
        2 => import_common::check(import(Format::OnePux, &stored_archive(rest), rng)),
        _ => {
            let Some((len, stream)) = rest.split_first_chunk::<2>() else {
                return;
            };
            let expected = usize::from(u16::from_le_bytes(*len));
            if let Ok(out) = inflate(stream, expected) {
                assert_eq!(out.len(), expected);
            }
        }
    }
});

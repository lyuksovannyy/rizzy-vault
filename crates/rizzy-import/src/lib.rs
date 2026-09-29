//! `rizzy-import` — importers for other password managers' export files (roadmap §4.2, M1;
//! [ADR 0002] point 2; [ADR 0016] §3).
//!
//! An import file goes in as bytes, and the create ops of the imported items come out, as
//! field writes of `rizzy-core`'s M1 item schema ([ADR 0018] §6–§8): item types, field keys and
//! values, with per-entry warnings. `rizzy-client` encrypts them under the vault's keys at once
//! and uploads them like any other create op; the server never sees an import file (ADR 0002
//! point 2).
//!
//! # Formats
//!
//! | [`Format`] | Input | Module |
//! |---|---|---|
//! | [`Format::BitwardenJson`] | Bitwarden's unencrypted JSON export | [`bitwarden`] |
//! | [`Format::OnePux`] | 1Password's 1PUX archive | [`onepux`] |
//! | [`Format::KeePassXml`] | `KeePass`'s XML export (`KeePass` 2.x, `KeePassXC`) | [`keepass`] |
//! | [`Format::GenericCsv`] | a CSV file with a header row | [`csv_import`] |
//! | [`Format::ChromeCsv`] | Chrome's (Chromium's) password CSV | [`csv_import`] |
//! | [`Format::FirefoxCsv`] | Firefox's password CSV | [`csv_import`] |
//!
//! Each module's documentation holds its mapping table. **Not imported in M1:** `KeePass` KDBX
//! databases and Bitwarden's encrypted exports, which need the other product's cryptography
//! (ADR 0002 point 2 and owner decision 1: legacy primitives would live here, after ADR 0009's
//! approval procedure, which has not run); they are refused with
//! [`ImportError::KdbxNotSupported`] and [`ImportError::EncryptedExport`].
//!
//! # Contract
//!
//! - **No I/O** ([ADR 0016] R1, threat model INV-58): no filesystem, network, clock,
//!   environment, process, thread or randomness source. Element ids come from the injected
//!   CSPRNG; times come only from the file. `cargo check-wasm` builds the crate for
//!   `wasm32-unknown-unknown`, its `clippy.toml` carries the R1 lists, and
//!   `cargo xtask check-deps` keeps `rizzy-core` its only internal dependency and its closure
//!   on `rizzy-core`'s allow-list (its own list is empty).
//! - **Importers only read** (ADR 0002 point 2). Nothing here decrypts, and no import format
//!   becomes a path into our own data.
//! - **Hostile input** (threat model A16). Every reader is written here, over bytes, with the
//!   caps of [`limits`] checked before the work they bound: input size, nesting depth, node,
//!   entry, column and archive-entry counts, and the decompressed size of 1PUX's
//!   `export.data`, whose buffer is allocated once at its declared size (the zip-bomb cap).
//!   XML document type declarations are refused outright, so no entity is ever expanded.
//!   Nothing panics: the workspace lints warn on `unwrap`, `expect` and `panic!`, this crate
//!   adds `clippy::indexing_slicing` and `clippy::unreachable`, and `cargo lint` makes every
//!   warning an error. One fuzz target per format lives under `fuzz/` (`import_bitwarden`,
//!   `import_1pux`, `import_keepass_xml`, `import_csv`, `import_chrome_csv`,
//!   `import_firefox_csv`).
//! - **Secrets** (CRYPTO.md §12.2). An import file is plaintext passwords. Every string the
//!   readers produce (JSON strings, numbers and names, CSV fields, XML names, attributes and
//!   text, the decompressed archive member) is a zeroizing buffer allocated once, at its final
//!   size or at the size of its raw source, which unescaping only shortens, so no reallocation
//!   leaves a copy behind. Values leave as `rizzy-core`'s zeroizing [`Value`](rizzy_core::item::value::Value)
//!   and [`FieldKey`](rizzy_core::item::key::FieldKey). No `Debug` output, error or warning
//!   carries a byte of the file: errors and warnings are kinds, and a warning names only the
//!   entry's position. The caller owns the input buffer and wipes it.
//! - **The schema's writer rules.** Every item passes `rizzy-core`'s
//!   [`check_create`](rizzy_core::item::schema::check_create) for an import before it is
//!   returned, fits one create op (ADR 0018 §10), and has its writes in canonical key order
//!   (ADR 0018 §4). See [`item`].
//! - **No `unsafe`** (workspace lint and `#![forbid(unsafe_code)]` below).
//!
//! # Readers
//!
//! The format-neutral readers are public so the fuzz targets can reach them: [`json`],
//! [`csv`], [`xml`], [`zip`] and [`inflate`]. Why they are written here rather than taken from
//! crates.io is in each module's documentation; in short, zeroizing buffers of final size and
//! R1's allow-list.
//!
//! [ADR 0002]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0002-own-protocol.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0018]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0018-item-record-encoding.md
#![forbid(unsafe_code)]
#![warn(clippy::indexing_slicing, clippy::unreachable)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod bitwarden;
pub mod csv;
pub mod csv_import;
pub mod inflate;
pub mod item;
pub mod json;
pub mod keepass;
pub mod limits;
pub mod onepux;
pub mod xml;
pub mod zip;

mod error;
mod text;
mod time;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

use rizzy_core::rng::CryptoRng;

pub use crate::error::{ImportError, Warning, WarningKind};
pub use crate::item::{ImportedItem, ImportedWrite};

/// The import formats of roadmap §4.2 (M1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// Bitwarden's unencrypted JSON export.
    BitwardenJson,
    /// 1Password's 1PUX archive.
    OnePux,
    /// `KeePass`'s XML export.
    KeePassXml,
    /// A CSV file with a header row (see [`csv_import`] for its columns).
    GenericCsv,
    /// Chrome's (Chromium's) password CSV export.
    ChromeCsv,
    /// Firefox's password CSV export.
    FirefoxCsv,
}

/// The result of an import: the items, in file order, and the warnings.
#[derive(Debug)]
pub struct Import {
    /// The imported items, one create op each, in file order.
    pub items: Vec<ImportedItem>,
    /// What was not imported as it stood, per entry; at most
    /// [`limits::MAX_WARNINGS`] and one more.
    pub warnings: Vec<Warning>,
}

/// Imports `input` as `format`. Element ids are drawn from `rng`, the leaf crate's CSPRNG
/// (CRYPTO.md §12.1).
///
/// # Errors
/// [`ImportError`] when the file as a whole cannot be imported; then nothing is. Problems with
/// single entries are [`Import::warnings`] instead.
pub fn import<R: CryptoRng + ?Sized>(
    format: Format,
    input: &[u8],
    rng: &mut R,
) -> Result<Import, ImportError> {
    let mut warnings = error::Warnings::default();
    let items = match format {
        Format::BitwardenJson => bitwarden::import(input, rng, &mut warnings)?,
        Format::OnePux => onepux::import(input, rng, &mut warnings)?,
        Format::KeePassXml => keepass::import(input, rng, &mut warnings)?,
        Format::GenericCsv => csv_import::generic(input, rng, &mut warnings)?,
        Format::ChromeCsv => csv_import::chrome(input, rng, &mut warnings)?,
        Format::FirefoxCsv => csv_import::firefox(input, rng, &mut warnings)?,
    };
    Ok(Import {
        items,
        warnings: warnings.into_vec(),
    })
}

/// Imports the `export.data` JSON document of a 1PUX archive, already taken out of the
/// archive: for the `import_1pux` fuzz target, which reaches the item mapping without building
/// a zip first. Applications import the archive with [`import`] and [`Format::OnePux`].
///
/// # Errors
/// As [`import`].
pub fn import_1pux_data<R: CryptoRng + ?Sized>(
    data: &[u8],
    rng: &mut R,
) -> Result<Import, ImportError> {
    let mut warnings = error::Warnings::default();
    let items = onepux::import_data(data, rng, &mut warnings)?;
    Ok(Import {
        items,
        warnings: warnings.into_vec(),
    })
}

// SPDX-License-Identifier: AGPL-3.0-only

//! The embedded identity data file, parsed once per process ([ADR 0079] §5).
//!
//! [ADR 0079]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0079-identity-generator.md

use std::sync::OnceLock;

use super::data::{self, IdentityData, IdentityDataError};

/// The data's name, like `wordlist::NAME` (ADR 0079 §5).
pub const NAME: &str = "identity-data";
/// The data version. A data change is a new version with new known-answer vectors (§4).
pub const VERSION: u32 = 1;

/// `identity-data-v1.txt`, the output of `cargo xtask identity-data` (provenance in
/// `data/identity/SOURCES.md`).
pub(crate) const RAW: &str = include_str!("fixture-placeholder.txt");

/// The parsed embedded data (or its error), built on first use.
static PARSED: OnceLock<Result<IdentityData<'static>, IdentityDataError>> = OnceLock::new();

/// The embedded data, parsed on first use and cached read-only for the process.
///
/// # Errors
/// The parser's error if the embedded file is malformed (a build defect the tests catch).
pub fn embedded_data() -> Result<&'static IdentityData<'static>, IdentityDataError> {
    PARSED
        .get_or_init(|| data::parse(RAW.as_bytes()))
        .as_ref()
        .map_err(|e| *e)
}

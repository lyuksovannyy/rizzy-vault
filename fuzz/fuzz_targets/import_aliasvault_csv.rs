//! Fuzzes `AliasVault`'s CSV importer (roadmap §4.2, M1; threat model A16). It may not panic,
//! and every item that comes out keeps the importer's guarantees ([`import_common::check`]).
//!
//! The fuzzer finds the AliasVault shape from the seed `ServiceName,…,CurrentPassword,…,
//! AliasEmail,…` header (`crates/rizzy-import/src/aliasvault.rs`).
//!
//! ```text
//! cargo +nightly fuzz run import_aliasvault_csv
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::{Format, import};

fuzz_target!(|data: &[u8]| {
    import_common::check(import(
        Format::AliasVaultCsv,
        data,
        &mut import_common::CountingRng(0),
    ));
});

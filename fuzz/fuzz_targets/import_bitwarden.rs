//! Fuzzes the Bitwarden JSON importer (ADR 0002 point 2; threat model A16: malicious import
//! files) and the JSON reader under it. Neither may panic, whatever the input, and every item
//! that comes out keeps the importer's guarantees ([`import_common::check`]): it passes
//! `rizzy-core`'s create-op check for an import, its writes are in canonical key order, and it
//! fits one op.
//!
//! The JSON reader is also run on its own, at the importer's cap, so inputs that are valid
//! JSON but not a Bitwarden export still exercise every JSON path.
//!
//! ```text
//! cargo +nightly fuzz run import_bitwarden
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::limits::MAX_JSON_LEN;
use rizzy_import::{Format, import, json};

fuzz_target!(|data: &[u8]| {
    let _ = json::parse(data, MAX_JSON_LEN);
    import_common::check(import(
        Format::BitwardenJson,
        data,
        &mut import_common::CountingRng(0),
    ));
});

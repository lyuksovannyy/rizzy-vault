//! Fuzzes the Firefox CSV importer (ADR 0002 point 2; threat model A16): row mapping, the
//! host-name extraction for item names, and the `timeCreated` reader. It may not panic, and
//! every item that comes out keeps the importer's guarantees ([`import_common::check`]).
//!
//! ```text
//! cargo +nightly fuzz run import_firefox_csv
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::{Format, import};

fuzz_target!(|data: &[u8]| {
    import_common::check(import(
        Format::FirefoxCsv,
        data,
        &mut import_common::CountingRng(0),
    ));
});

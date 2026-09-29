//! Fuzzes the Chrome CSV importer (ADR 0002 point 2; threat model A16). It may not panic, and
//! every item that comes out keeps the importer's guarantees ([`import_common::check`]).
//!
//! Inputs that start with Chrome's header reach the row mapping; the fuzzer finds it from the
//! seed `name,url,username,password,note`.
//!
//! ```text
//! cargo +nightly fuzz run import_chrome_csv
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::{Format, import};

fuzz_target!(|data: &[u8]| {
    import_common::check(import(
        Format::ChromeCsv,
        data,
        &mut import_common::CountingRng(0),
    ));
});

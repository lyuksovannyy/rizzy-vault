//! Fuzzes the generic CSV importer (ADR 0002 point 2; threat model A16) and the CSV reader
//! under it. Neither may panic, and every item that comes out keeps the importer's guarantees
//! ([`import_common::check`]).
//!
//! The CSV reader is also run on its own, to the end of the input: no record may have more
//! than the column cap.
//!
//! ```text
//! cargo +nightly fuzz run import_csv
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::limits::{MAX_CSV_COLUMNS, MAX_CSV_LEN};
use rizzy_import::{Format, csv, import};

fuzz_target!(|data: &[u8]| {
    if let Ok(mut reader) = csv::Reader::new(data, MAX_CSV_LEN) {
        while let Ok(Some(record)) = reader.next_record() {
            assert!(!record.is_empty() && record.len() <= MAX_CSV_COLUMNS);
        }
    }
    import_common::check(import(
        Format::GenericCsv,
        data,
        &mut import_common::CountingRng(0),
    ));
});

//! Fuzzes the reader of rizzy-vault's own plaintext JSON export (ADR 0027 §6; threat model
//! A16: the file is unauthenticated hostile input) and the JSON reader under it. Neither may
//! panic, whatever the input, and every item that comes out keeps the importer's guarantees
//! ([`import_common::check`]): it passes `rizzy-core`'s create-op check for an import as a
//! carried write (`check_carried`), its writes are in canonical key order, its type is a user
//! item type this client supports, and it fits one item's snapshot.
//!
//! On top of that, the report is consistent with what was imported: nothing is counted as
//! collapsed, dropped or left out unless the file had entries, and the skipped items and the
//! imported ones never exceed the entry cap.
//!
//! The JSON reader is also run on its own, at the importer's cap, so inputs that are valid
//! JSON but not a rizzy-vault export still exercise every JSON path.
//!
//! ```text
//! cargo +nightly fuzz run import_rizzy_json
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_core::item::schema::WriteSource;
use rizzy_import::limits::{MAX_ENTRIES, MAX_JSON_LEN};
use rizzy_import::{Format, import, json};

fuzz_target!(|data: &[u8]| {
    let _ = json::parse(data, MAX_JSON_LEN);
    let result = import(
        Format::RizzyPlaintextJson,
        data,
        &mut import_common::CountingRng(0),
    );
    if let Ok(read) = &result {
        assert!(read.items.len() + read.counts.skipped_items <= MAX_ENTRIES);
        assert!(
            read.items
                .iter()
                .all(|i| i.source() == WriteSource::Carried)
        );
        if read.items.is_empty() {
            assert_eq!(read.counts.collapsed_conflicts, 0);
            assert_eq!(read.counts.dropped_history, 0);
            assert_eq!(read.counts.dropped_fields, 0);
        }
    }
    import_common::check(result);
});

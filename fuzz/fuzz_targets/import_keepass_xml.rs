//! Fuzzes the KeePass XML importer (ADR 0002 point 2; threat model A16: XML entity expansion,
//! malicious import files) and the XML reader under it. Neither may panic, and every item that comes out keeps the importer's
//! guarantees ([`import_common::check`]).
//!
//! The XML reader is also run on its own, at the importer's cap, so documents that are not
//! KeePass exports still exercise every XML path.
//!
//! ```text
//! cargo +nightly fuzz run import_keepass_xml
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::limits::MAX_XML_LEN;
use rizzy_import::{Format, import, xml};

fuzz_target!(|data: &[u8]| {
    if let Ok(root) = xml::parse(data, MAX_XML_LEN) {
        let _ = root.text();
    }
    import_common::check(import(
        Format::KeePassXml,
        data,
        &mut import_common::CountingRng(0),
    ));
});

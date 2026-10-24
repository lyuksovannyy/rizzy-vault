// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the CXF importer (ADR 0074 §3: "fuzz target `import_cxf`"; threat model A16). A CXF
//! file is hostile input whether another product's writer made it or it is the decrypted
//! payload of our own CXF export: one reader serves both, so one target covers both. It may
//! not panic, whatever the input, and every item that comes out keeps the importer's
//! guarantees ([`import_common::check`]): it passes `rizzy-core`'s create-op check for an
//! import, its writes are in canonical key order, and it fits one op. The PKCS#8 reader under
//! it has its own target, `passkey_pkcs8`.
//!
//! ```text
//! cargo +nightly fuzz run import_cxf
//! ```
#![no_main]

#[path = "import_common/mod.rs"]
mod import_common;

use libfuzzer_sys::fuzz_target;
use rizzy_import::{Format, import};

fuzz_target!(|data: &[u8]| {
    import_common::check(import(
        Format::CxfJson,
        data,
        &mut import_common::CountingRng(0),
    ));
});

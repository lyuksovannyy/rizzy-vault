//! Every cap the importers apply (threat model A16: a crafted import file must not exhaust
//! memory or time). Each is checked before the work it bounds.
//!
//! The input caps are far above any real export: 50,000 entries of a typical export are a few
//! tens of MiB of JSON. Memory stays bounded by the input cap times a small constant: every
//! syntax node is at least one input byte and is counted against [`MAX_NODES`], strings are
//! copied once into buffers no larger than their source, and the one decompression (1PUX
//! `export.data`) writes into a buffer allocated once at its declared size, which is capped by
//! [`MAX_EXPANDED_LEN`].
//!
//! The per-item caps come from the record layer (ADR 0018 §10), restated here because this
//! crate may depend on `rizzy-core` only (ADR 0016 §3): an imported item is one create op of at
//! most [`MAX_WRITES`] writes and [`MAX_OP_DATA_LEN`] bytes of op data.

/// Largest JSON input (Bitwarden JSON), in bytes.
pub const MAX_JSON_LEN: usize = 64 << 20;

/// Largest CSV input, in bytes.
pub const MAX_CSV_LEN: usize = 64 << 20;

/// Largest XML input (`KeePass` XML), in bytes. `KeePass` XML carries attachments inline, in
/// Base64, so it is larger than the other formats for the same entries.
pub const MAX_XML_LEN: usize = 128 << 20;

/// Largest 1PUX archive, in bytes. The archive also holds the attached files, which are never
/// decompressed; only the central directory and `export.data` are read.
pub const MAX_ARCHIVE_LEN: usize = 512 << 20;

/// Largest decompressed `export.data` of a 1PUX archive, in bytes: the zip-bomb cap. The
/// output buffer is allocated once at the size the archive declares, which must not exceed
/// this, and decompression stops at that size.
pub const MAX_EXPANDED_LEN: usize = 64 << 20;

/// Most entries of a zip central directory that are read.
pub const MAX_ARCHIVE_ENTRIES: usize = 100_000;

/// Deepest nesting of JSON arrays and objects, or of XML elements.
pub const MAX_DEPTH: usize = 64;

/// Most JSON values, or XML elements and text nodes, in one document.
pub const MAX_NODES: usize = 4_000_000;

/// Most entries (items, `KeePass` entries, CSV data rows) in one import.
pub const MAX_ENTRIES: usize = 100_000;

/// Most CSV fields in one row.
pub const MAX_CSV_COLUMNS: usize = 1_024;

/// Most warnings recorded in one import; one more says the rest were dropped.
pub const MAX_WARNINGS: usize = 10_000;

/// Most URIs imported per item.
pub const MAX_URIS: usize = 100;

/// Most custom fields imported per item.
pub const MAX_CUSTOM_FIELDS: usize = 200;

/// Most password-history entries imported per item. The merge keeps at most 50 history
/// entries per field (ADR 0018 §10), so more would not be kept either.
pub const MAX_HISTORY: usize = 50;

/// Most tags imported per item.
pub const MAX_TAGS: usize = 100;

/// Most field writes in one op (ADR 0018 §10; `rizzy-sync`'s `record::MAX_WRITES`).
pub const MAX_WRITES: usize = 1_024;

/// Largest op data, in bytes (ADR 0018 §10; `rizzy-sync`'s `record::MAX_OP_DATA_LEN`).
pub const MAX_OP_DATA_LEN: usize = 1 << 20;

/// Longest text a Text value holds: 65,536 bytes per value, type byte included (ADR 0018
/// §10).
pub const MAX_TEXT_LEN: usize = rizzy_core::item::value::MAX_VALUE_LEN - 1;

/// Most attributes on one XML element. `KeePass` XML elements carry at most a few (`Protected`,
/// `ProtectInMemory`); the cap keeps the duplicate-attribute check, a scan of the attributes
/// already read, from growing quadratically on a crafted element.
pub const MAX_XML_ATTRIBUTES: usize = 64;

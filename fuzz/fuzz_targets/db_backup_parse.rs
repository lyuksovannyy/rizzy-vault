//! Fuzzes `rizzy-storage`'s logical backup file (`rizzy_storage::backup::file`, ADR 0023):
//! `rizzy-vault restore` reads it from the operator's disk or a pipe, so a damaged or hostile
//! file must be refused without a panic, and an error must never carry a value.
//!
//! For each input:
//! 1. the raw bytes, as a file (almost always refused by the magic or the digest);
//! 2. the bytes with a valid SHA-256 appended, and the magic, format version 1 and a valid
//!    SHA-256 around them, so the table parser behind the digest check is reached;
//! 3. a dump built from the bytes within the ADR 0023 §3 limits, written and parsed back.
//!
//! None may panic; every accepted file re-encodes to exactly its own bytes (the encoding is
//! canonical), and `parse(write(d)) == d` for every generated dump.
//!
//! ```text
//! cargo +nightly fuzz run db_backup_parse
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_storage::backup::file::{FORMAT_VERSION, MAGIC, digest, parse, write};
use rizzy_storage::tables::{Kind, TABLES};
use rizzy_storage::{Dump, TableDump, Value};

/// Parses `bytes`; an accepted file must re-encode to itself.
fn check(bytes: &[u8]) {
    match parse(bytes) {
        Ok(file) => {
            let again = write(&file.dump, file.created_at_ms).expect("an accepted dump writes");
            assert_eq!(again.as_slice(), bytes, "one file per dump");
        }
        Err(e) => {
            // Errors name a place or a rule, never a value.
            assert!(e.to_string().len() < 200);
        }
    }
}

/// `bytes ‖ SHA-256(bytes)`.
fn sealed(body: Vec<u8>) -> Vec<u8> {
    let mut out = body;
    let sum = digest(&out);
    out.extend_from_slice(&sum);
    out
}

/// A byte source that yields zeros once exhausted.
struct Source<'a>(&'a [u8]);

impl Source<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

/// A dump of this release's tables from `data`: up to 3 rows per table, short values.
fn generate(data: &[u8]) -> (Dump, u64) {
    let mut s = Source(data);
    let schema = i64::from_be_bytes(s.bytes(8).try_into().unwrap_or([0; 8])) & i64::MAX;
    let created = u64::from_be_bytes(s.bytes(8).try_into().unwrap_or([0; 8]));
    let tables = TABLES
        .iter()
        .map(|spec| {
            let rows = (0..s.byte() % 4)
                .map(|_| {
                    spec.columns
                        .iter()
                        .map(|c| {
                            let pick = s.byte();
                            if c.nullable && pick & 1 == 1 {
                                return Value::Null;
                            }
                            match c.kind {
                                Kind::Integer => Value::Integer(i64::from_be_bytes(
                                    s.bytes(8).try_into().unwrap_or([0; 8]),
                                )),
                                Kind::Text => Value::Text(
                                    String::from_utf8_lossy(&s.bytes(usize::from(pick % 24)))
                                        .into_owned(),
                                ),
                                Kind::Blob => Value::Blob(s.bytes(usize::from(pick % 64))),
                            }
                        })
                        .collect()
                })
                .collect();
            TableDump {
                table: spec.name.to_owned(),
                rows,
            }
        })
        .collect();
    (
        Dump {
            schema_version: schema.max(1),
            tables,
        },
        created,
    )
}

fuzz_target!(|data: &[u8]| {
    check(data);
    check(&sealed(data.to_vec()));
    let mut framed = MAGIC.to_vec();
    framed.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    framed.extend_from_slice(data);
    check(&sealed(framed));

    let (dump, created) = generate(data);
    let file = write(&dump, created).expect("a dump within the limits writes");
    let parsed = parse(&file).expect("a written file parses");
    assert_eq!(parsed.dump, dump);
    assert_eq!(parsed.created_at_ms, created);
});

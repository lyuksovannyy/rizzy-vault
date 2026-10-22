// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes `rizzy-client`'s `item_index` row parser and the code around it (ADR 0056 §4, §6):
//! the table is read back from a file anyone with the user's rights can change, so every row
//! is untrusted input, and its own failure rule says a bad row rebuilds the table, never fails
//! the load.
//!
//! Each input is a list of raw rows (every column an arbitrary blob or integer) and a query.
//! For each:
//!
//! - [`IndexRow::parse`] never panics; a row that parses has 16-byte ids, UTF-8 columns within
//!   their caps, and writes back ([`IndexRow::new`]) to the same columns it was read from.
//! - [`index::reconcile`] against no vault never panics: it deletes every row of a table that
//!   parses with one row per item, and drops and rebuilds any other table; either way the
//!   reference executor leaves the table empty.
//! - [`index::search`] and [`index::recent`] never panic, return at most their limit, and
//!   only ids of rows that parse.
//!
//! ```text
//! cargo +nightly fuzz run client_item_index
//! ```
#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use rizzy_client::store::index::{self, IndexRow, MAX_DISPLAY_NAME_LEN, MAX_SEARCH_TEXT_LEN};
use rizzy_client::store::rows::{CacheRows, Write};

/// The input, read front to back; a short input reads as zeros.
struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }

    /// A blob of a length the input picks: mostly short, sometimes the caps' neighbourhood.
    fn blob(&mut self) -> Vec<u8> {
        let len = match self.byte() {
            0xFE => MAX_DISPLAY_NAME_LEN + usize::from(self.byte() % 3),
            0xFF => MAX_SEARCH_TEXT_LEN - 1 + usize::from(self.byte() % 3),
            n => usize::from(n % 40),
        };
        let take = len.min(self.0.len());
        let (head, rest) = self.0.split_at(take);
        self.0 = rest;
        let mut out = head.to_vec();
        out.resize(len, b'a');
        out
    }

    fn int(&mut self) -> i64 {
        let mut bytes = [0u8; 8];
        for b in &mut bytes {
            *b = self.byte();
        }
        match bytes[0] % 4 {
            0 => i64::from(bytes[1]),
            1 => -i64::from(bytes[1]),
            2 => i64::from(u16::from_be_bytes([bytes[1], bytes[2]])) + 65_530,
            _ => i64::from_be_bytes(bytes),
        }
    }

    fn row(&mut self) -> IndexRow {
        let flags = self.byte();
        let id = |input: &mut Self, exact: bool| {
            if exact {
                let mut id = vec![0u8; 16];
                id[15] = input.byte() % 4;
                id
            } else {
                input.blob()
            }
        };
        IndexRow {
            item_id: id(self, flags & 1 == 0),
            vault_id: id(self, flags & 2 == 0),
            item_type: if flags & 4 == 0 {
                i64::from(self.byte())
            } else {
                self.int()
            },
            display_name: self.blob().into(),
            search_text: self.blob().into(),
            last_used_ms: match flags >> 4 & 3 {
                0 => None,
                1 => Some(u64::from(self.byte()).to_be_bytes().to_vec()),
                _ => Some(self.blob()),
            },
            use_count: if flags & 8 == 0 {
                i64::from(self.byte())
            } else {
                self.int()
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let count = usize::from(input.byte() % 8);
    let mut rows = CacheRows::default();
    for _ in 0..count {
        rows.item_index.push(input.row());
    }
    let limit = usize::from(input.byte() % 6);
    let query = String::from_utf8_lossy(input.0).into_owned();

    let mut parsed_ids = BTreeSet::new();
    let mut all_parse = true;
    for row in &rows.item_index {
        match row.parse() {
            Ok(stored) => {
                assert_eq!(row.item_id.len(), 16);
                assert_eq!(row.vault_id.len(), 16);
                assert!(stored.entry.display_name.len() <= MAX_DISPLAY_NAME_LEN);
                assert!(stored.entry.search_text.len() <= MAX_SEARCH_TEXT_LEN);
                let back = IndexRow::new(&stored.entry);
                assert_eq!(back.item_id, row.item_id);
                assert_eq!(back.vault_id, row.vault_id);
                assert_eq!(back.item_type, row.item_type);
                assert_eq!(back.display_name, row.display_name);
                assert_eq!(back.search_text, row.search_text);
                all_parse &= parsed_ids.insert(stored.entry.item_id);
            }
            Err(e) => {
                assert_eq!(e, rizzy_client::ClientError::CacheCorrupt);
                all_parse = false;
            }
        }
    }

    for id in index::search(&rows, &query, limit)
        .into_iter()
        .chain(index::recent(&rows, limit))
    {
        assert!(parsed_ids.contains(id.as_bytes()));
    }
    assert!(index::search(&rows, &query, limit).len() <= limit);
    assert!(index::recent(&rows, limit).len() <= limit);
    let pattern = index::like_pattern(&query);
    assert!(pattern.starts_with('%') && pattern.ends_with('%'));

    let writes = index::reconcile(&rows, &mut []);
    if all_parse {
        assert_eq!(writes.writes().len(), rows.item_index.len());
        assert!(
            writes
                .writes()
                .iter()
                .all(|w| matches!(w, Write::IndexDelete { .. }))
        );
    } else {
        assert!(matches!(writes.writes().first(), Some(Write::IndexReset)));
        assert_eq!(writes.writes().len(), 1);
    }
    rows.apply(&writes);
    assert!(rows.item_index.is_empty());
});

//! What every `import_*` fuzz target checks on an import result, and the deterministic RNG
//! they pass for element ids. Shared by `#[path]` inclusion; not a target itself.

use std::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use rizzy_core::item::schema::{WriteMode, WriteSource, check_create};
use rizzy_import::limits::{MAX_OP_DATA_LEN, MAX_WARNINGS, MAX_WRITES};
use rizzy_import::{Import, ImportError};

/// The randomness the importers draw for element ids. It counts upward. It is not a CSPRNG:
/// nothing here depends on unpredictability, and a crash must reproduce from its input alone.
/// Like `rizzy-core`'s test `FixedRng`, it is marked `CryptoRng` only so the API accepts it.
pub struct CountingRng(pub u8);

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for b in dst {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for CountingRng {}

/// Checks the guarantees of an import: every item passes `rizzy-core`'s writer check for an
/// importer's create op, its writes are strictly ascending by key with no duplicate (ADR 0018
/// §4), it fits one op (ADR 0018 §10), items are in file order, and warnings are capped.
pub fn check(result: Result<Import, ImportError>) {
    let Ok(import) = result else {
        return;
    };
    assert!(import.warnings.len() <= MAX_WARNINGS + 1);
    let mut last_entry = None;
    for item in &import.items {
        if let Some(last) = last_entry {
            assert!(item.entry() > last, "items out of file order");
        }
        last_entry = Some(item.entry());
        let writes = item.writes();
        assert!(!writes.is_empty() && writes.len() <= MAX_WRITES);
        for pair in writes.windows(2) {
            assert!(pair[0].key().as_bytes() < pair[1].key().as_bytes());
        }
        let op_len: usize = 4 + writes
            .iter()
            .map(|w| 8 + w.key().as_bytes().len() + w.value().len())
            .sum::<usize>();
        assert!(op_len <= MAX_OP_DATA_LEN);
        check_create(
            item.item_type(),
            WriteMode::Import,
            writes
                .iter()
                .map(|w| (WriteSource::Entered, w.key().as_bytes(), w.value().expose_secret())),
        )
        .expect("an imported item passes the importer's create check");
    }
}

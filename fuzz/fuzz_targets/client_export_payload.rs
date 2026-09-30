//! Fuzzes `rizzy-client`'s export payload reader (ADR 0027 §2 step 2; threat model A16) and
//! the import mapping behind it (ADR 0027 §2 steps 3–4), on arbitrary bytes: the plaintext of
//! an `EXPORT_FILE` envelope is attacker-chosen for anyone who knows or picks the export
//! password.
//!
//! For each input:
//!
//! - [`parse_payload`] never panics. When it accepts, the payload is canonical: encoding the
//!   parsed entries again ([`encode_snapshot`] per entry, then [`encode_payload`]) gives the
//!   input back byte for byte, and entries are strictly ascending by item id.
//! - [`preview_payload`] never panics: it runs the mapping of every entry to a new item
//!   (displayed values, the created time, password history) and the checks the import path
//!   makes before its first op. It accepts exactly what the parser accepts, and its counts
//!   add up to the number of entries.
//!
//! No key is derived and nothing is decrypted: the envelope path is covered by
//! `export_fields` and the file's JSON by `client_export`.
//!
//! ```text
//! cargo +nightly fuzz run client_export_payload
//! ```
#![no_main]

use std::convert::Infallible;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_client::ClientError;
use rizzy_client::export::payload::{
    MAX_PAYLOAD_LEN, PayloadItem, encode_payload, parse_payload, preview_payload,
};
use rizzy_sync::record::{SnapshotData, encode_snapshot};

/// A counting byte source for the element ids the mapping draws. Not a CSPRNG: nothing here
/// depends on unpredictability, and a crash must reproduce from its input alone.
struct CountingRng(u8);

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

fuzz_target!(|data: &[u8]| {
    let parsed = parse_payload(data);
    let preview = preview_payload(data, &mut CountingRng(0));
    match &parsed {
        Ok(entries) => {
            assert!(data.len() <= MAX_PAYLOAD_LEN);
            for pair in entries.windows(2) {
                assert!(pair[0].item_id().to_bytes() < pair[1].item_id().to_bytes());
            }
            let encoded: Vec<_> = entries
                .iter()
                .map(|e| {
                    encode_snapshot(e.covered(), &SnapshotData::Live(e.snapshot().clone()))
                        .expect("a parsed snapshot encodes")
                })
                .collect();
            let items: Vec<PayloadItem<'_>> = entries
                .iter()
                .zip(&encoded)
                .map(|(e, data)| PayloadItem {
                    item_id: e.item_id(),
                    covered: e.covered(),
                    data: data.expose_secret(),
                })
                .collect();
            let again = encode_payload(&items).expect("a parsed payload encodes");
            assert_eq!(again.expose_secret(), data);
            let preview = preview.expect("the preview accepts what the parser accepts");
            assert_eq!(preview.importable + preview.skipped_items, entries.len());
        }
        Err(error) => {
            assert!(matches!(
                error,
                ClientError::InvalidExportFile | ClientError::ExportUpdateRequired
            ));
            assert_eq!(preview, Err(*error));
        }
    }
});

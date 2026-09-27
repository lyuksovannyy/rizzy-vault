//! Fuzzes the op-data parser of the item record (ADR 0018 §5 `parse_op`), which reads the
//! decrypted `data` of every `ITEM_OP` envelope. From M9 a vault member can author that
//! plaintext, and before then any holder of the item key can, so the parser must never panic,
//! never allocate in proportion to a count before checking it against the input, and accept
//! only the one canonical encoding of each op.
//!
//! What runs on each input:
//!
//! - [`parse_op`] on the whole input. When it accepts, [`encode_op`] must give back exactly the
//!   input (one encoding per op, ADR 0018 §1), and the op must hold what §5 promises: data of
//!   at most 1 MiB, at most 1,024 writes, keys strictly ascending, each a key
//!   [`FieldKey::new`] accepts (never `@lifecycle`), values of at most 64 KiB, and writes only
//!   with the `Active` marker.
//! - [`parse_snapshot`] on the same bytes, with an empty covered VV: the purpose picks the
//!   record kind (§5 rule 1), so it must refuse anything [`parse_op`] accepted.
//!
//! Part of CRYPTO.md §15 item 7, "item-record parsers" (ADR 0018 §12: op data).
//!
//! ```text
//! cargo +nightly fuzz run record_op
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_sync::record::{
    FieldKey, Lifecycle, MAX_OP_DATA_LEN, MAX_VALUE_LEN, MAX_WRITES, encode_op, parse_op,
    parse_snapshot,
};
use rizzy_sync::vv::VersionVector;

fuzz_target!(|data: &[u8]| {
    if let Ok(op) = parse_op(data) {
        let again = encode_op(&op).expect("an accepted op encodes");
        assert_eq!(again.expose_secret(), data);
        assert!(data.len() <= MAX_OP_DATA_LEN);
        let writes = op.writes();
        assert!(writes.len() <= MAX_WRITES);
        assert!(writes.is_empty() || op.lifecycle() == Lifecycle::Active);
        for w in writes {
            let key = w.key().expose_secret();
            assert_eq!(FieldKey::new(key).map(|k| k.expose_secret()), Ok(key));
            assert!(w.value().len() <= MAX_VALUE_LEN);
        }
        assert!(writes.windows(2).all(|p| matches!(p, [a, b] if a.key() < b.key())));
        assert!(parse_snapshot(&VersionVector::new(), data).is_err());
    }
});

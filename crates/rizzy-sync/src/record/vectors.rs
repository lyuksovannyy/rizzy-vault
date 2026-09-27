//! Version-1 record vectors (ADR 0018 §12, CRYPTO.md §15 item 1): the layout level.
//!
//! **Where they live.** CRYPTO.md §15 item 1(A) places these vectors under
//! `crates/rizzy-core/tests/vectors/`, in its published JSON schema, which item 8 runs on
//! every target and through the bindings. They are Rust test constants here, which no binding
//! or wasm harness can read: `rizzy-core` cannot depend on this crate, and this crate has no
//! JSON reader. Where they go, and the regeneration of `rizzy-core`'s placeholder
//! `canonical_header` statement vectors over real headers, wait for an owner decision.
//!
//! **Positive vectors.** Each is a record built through this module's types, the same record
//! written field by field by the independent [`Spec`] writer, and the committed hex. The test
//! requires the encoder's output, the spec bytes and the hex to be equal, and the hex to parse
//! back to the record. The records are the §12 list, at the `data` level:
//!
//! - a create of each M1 type (Login, Secure Note, Card, Identity, and the Vault-settings
//!   system type), the Login create writing `login.username`, `login.password` and
//!   `login.totp` to pin the §4 key order;
//! - a list edit (a custom field and a tag added, a URI removed by writing Cleared to its
//!   attributes);
//! - trash, restore and purge;
//! - each value type of §6, and a reserved type under an unknown key, carried verbatim;
//! - a live snapshot with a two-value conflict, history, an unknown key and the tags `tag/61`
//!   and `tag/6162`;
//! - a tombstone with a late value;
//! - a tombstone from two concurrent purges under different item keys, the lower-HLC one
//!   under the newer key, so that `item_key_id` is the older key;
//! - a tombstone recording a purge re-issued under a new key (owner decision 15).
//!
//! The last two pin the layout only: which purge is recorded, and under which key, is the
//! merge's decision (ADR 0018 §3), and the §12 vectors "through real `ITEM_OP` and
//! `ITEM_SNAPSHOT` envelopes" need the merge and the envelope layer.
//!
//! **Negative vectors** (§12): one per rejection rule of §5, each breaking only that rule and
//! given as (purpose, covered VV, `data`), plus the named extras: for rule 3 an odd hex count
//! (`uri/abc/value`), a 33-byte name and uppercase hex; for rule 2 a 161-byte key. Rules 5 and
//! 6 also get a vector on a history group (m = 0; an entry the covered VV does not cover) and
//! rule 6 one on a late value, since §5 applies them to every `register` production and not
//! only to current registers. A vector asserts rejection only. The test also pins the rule
//! each breaks, through [`RecordErrorKind::rule`](super::RecordErrorKind::rule), which is
//! diagnostics, not format.
//!
//! **Mutations.** Every byte change, insertion and short removal of a committed vector that
//! still parses must re-encode to exactly the mutated bytes: one encoding per record (§4).

use rizzy_core::ids::SymmetricKeyId;

use super::testkit::{Spec, dot, hex, hlc, key, key_of_len, to_hex, vv};
use super::{
    Entry, Lifecycle, LiveSnapshot, OpData, Register, SnapshotData, Tombstone, Value, Write,
    encode_op, encode_snapshot, parse_op, parse_snapshot,
};
use crate::hlc::Hlc;
use crate::vv::VersionVector;

// ---------------------------------------------------------------------------------------------
// Values (ADR 0018 §6), written by hand
// ---------------------------------------------------------------------------------------------

/// Text `0x01 ‖ UTF-8`.
fn text(s: &str) -> Vec<u8> {
    [&[0x01][..], s.as_bytes()].concat()
}

/// Bytes `0x02 ‖ raw`.
fn raw(b: &[u8]) -> Vec<u8> {
    [&[0x02][..], b].concat()
}

/// Bool `0x03 ‖ 0x00 | 0x01`.
fn boolean(b: bool) -> Vec<u8> {
    vec![0x03, u8::from(b)]
}

/// U64 `0x04 ‖ u64`.
fn u64v(v: u64) -> Vec<u8> {
    [&[0x04][..], &v.to_be_bytes()].concat()
}

/// Enum `0x05 ‖ u16`.
fn enumv(v: u16) -> Vec<u8> {
    [&[0x05][..], &v.to_be_bytes()].concat()
}

/// `SortKey`: `0x06 ‖ 1–64 bytes`.
fn sort_key(b: &[u8]) -> Vec<u8> {
    [&[0x06][..], b].concat()
}

/// The Cleared value.
fn cleared() -> Vec<u8> {
    Vec::new()
}

/// A URI element id (16 bytes, lowercase hex).
const URI: &str = "00112233445566778899aabbccddeeff";
/// A custom-field element id.
const FIELD_1: &str = "0f0e0d0c0b0a09080706050403020100";
/// A second custom-field element id, above [`FIELD_1`].
const FIELD_2: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
/// A share id.
const SHARE: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// Device A of the vectors.
const A: u8 = 0xaa;
/// Device B.
const B: u8 = 0xbb;

/// Item key id of the older item key in the tombstone vectors.
const KEY_OLD: [u8; 16] = [0x01; 16];
/// The key a re-issued purge was encrypted under.
const KEY_REISSUED: [u8; 16] = [0x03; 16];

// ---------------------------------------------------------------------------------------------
// Op vectors
// ---------------------------------------------------------------------------------------------

/// An op vector: its name, marker and writes (sorted by key, as the ADR requires), and the
/// committed hex.
struct OpVector {
    /// Short name, for failure messages.
    name: &'static str,
    /// The marker.
    lifecycle: Lifecycle,
    /// `(key, value)`, strictly ascending by key.
    writes: Vec<(String, Vec<u8>)>,
    /// The committed `data`.
    hex: &'static str,
}

fn w(k: impl Into<String>, v: Vec<u8>) -> (String, Vec<u8>) {
    (k.into(), v)
}

/// The op vectors of ADR 0018 §12, at the `data` level.
#[expect(
    clippy::too_many_lines,
    reason = "one table of vectors; splitting it would scatter the list ADR 0018 §12 asks for"
)]
fn op_vectors() -> Vec<OpVector> {
    vec![
        OpVector {
            name: "create Login",
            lifecycle: Lifecycle::Active,
            writes: vec![
                w("item.name", text("Example")),
                w("item.type", enumv(0x0001)),
                w("login.password", text("correct horse battery staple")),
                w("login.totp", text("JBSWY3DPEHPK3PXP")),
                w("login.username", text("alice@example.com")),
                w(format!("uri/{URI}/order"), sort_key(&[0x80])),
                w(
                    format!("uri/{URI}/value"),
                    text("https://example.com/login"),
                ),
            ],
            hex: HEX_CREATE_LOGIN,
        },
        OpVector {
            name: "create Secure Note",
            lifecycle: Lifecycle::Active,
            writes: vec![
                w("item.name", text("Wi-Fi at home")),
                w("item.notes", text("SSID: home\nKey: in the drawer")),
                w("item.type", enumv(0x0002)),
            ],
            hex: HEX_CREATE_NOTE,
        },
        OpVector {
            name: "create Card",
            lifecycle: Lifecycle::Active,
            writes: vec![
                w("card.brand", text("Visa")),
                w("card.code", text("123")),
                w("card.exp_month", text("12")),
                w("card.exp_year", text("2030")),
                w("card.holder", text("Alice Example")),
                w("card.number", text("4111111111111111")),
                w("item.name", text("Travel card")),
                w("item.type", enumv(0x0003)),
            ],
            hex: HEX_CREATE_CARD,
        },
        OpVector {
            name: "create Identity",
            lifecycle: Lifecycle::Active,
            writes: vec![
                w("identity.city", text("Springfield")),
                w("identity.email", text("alice@example.com")),
                w("identity.first_name", text("Alice")),
                w("identity.last_name", text("Example")),
                w("item.name", text("Me")),
                w("item.type", enumv(0x0004)),
            ],
            hex: HEX_CREATE_IDENTITY,
        },
        OpVector {
            name: "create Vault settings",
            lifecycle: Lifecycle::Active,
            writes: vec![
                w("item.type", enumv(0xF001)),
                w("vault.icon", text("shield")),
                w("vault.name", text("Personal")),
            ],
            hex: HEX_CREATE_SETTINGS,
        },
        OpVector {
            name: "list edit",
            lifecycle: Lifecycle::Active,
            writes: vec![
                w(format!("field/{FIELD_1}/kind"), enumv(2)),
                w(format!("field/{FIELD_1}/label"), text("PIN")),
                w(format!("field/{FIELD_1}/order"), sort_key(&[0x80])),
                w(format!("field/{FIELD_1}/value"), text("0000")),
                w("tag/776f726b", boolean(true)),
                w(format!("uri/{URI}/order"), cleared()),
                w(format!("uri/{URI}/value"), cleared()),
            ],
            hex: HEX_LIST_EDIT,
        },
        OpVector {
            name: "trash",
            lifecycle: Lifecycle::Trashed,
            writes: vec![],
            hex: "01020000",
        },
        OpVector {
            name: "restore",
            lifecycle: Lifecycle::Active,
            writes: vec![],
            hex: "01010000",
        },
        OpVector {
            name: "purge",
            lifecycle: Lifecycle::Purge,
            writes: vec![],
            hex: "01030000",
        },
        OpVector {
            name: "each value type",
            lifecycle: Lifecycle::Active,
            writes: vec![
                w(format!("field/{FIELD_1}/kind"), enumv(3)),
                w(format!("field/{FIELD_1}/value"), boolean(true)),
                w(format!("field/{FIELD_2}/value"), cleared()),
                w("import.created_ms", u64v(1_700_000_000_000)),
                w("item.name", text("V\u{e4}rde \u{2713}")),
                w(format!("share/{SHARE}/secret"), raw(&[0x5e; 32])),
                w(format!("uri/{URI}/order"), sort_key(&[0x7f, 0xff])),
                // A reserved value type under a key no M1 client knows: carried verbatim.
                w("zz.unknown", vec![0x07, b'x']),
            ],
            hex: HEX_VALUE_TYPES,
        },
    ]
}

impl OpVector {
    /// The record, borrowing from the vector.
    fn record(&self) -> OpData<'_> {
        let writes = self
            .writes
            .iter()
            .map(|(k, v)| Write::new(key(k), Value::new(v)))
            .collect();
        OpData::new(self.lifecycle, writes)
    }

    /// The `data`, written by [`Spec`] from the ADR 0018 §3 layout.
    fn spec(&self) -> Vec<u8> {
        let n = u16::try_from(self.writes.len()).unwrap();
        self.writes
            .iter()
            .fold(
                Spec::new().u8(0x01).u8(self.lifecycle.to_u8()).u16(n),
                |s, (k, v)| s.write(k, v),
            )
            .done()
    }
}

// ---------------------------------------------------------------------------------------------
// Snapshot vectors
// ---------------------------------------------------------------------------------------------

/// A register of a snapshot vector: key and `(device byte, seq, hlc, value)` entries.
type Reg = (&'static str, Vec<(u8, u64, Hlc, Vec<u8>)>);

/// A live-snapshot or tombstone vector.
enum SnapshotBody {
    /// Current registers and history groups.
    Live(Vec<Reg>, Vec<Reg>),
    /// Recorded purge dot and HLC, `c`, `item_key_id` and late registers.
    Tombstone((u8, u64), Hlc, Vec<(u8, u64)>, [u8; 16], Vec<Reg>),
}

/// A snapshot vector.
struct SnapshotVector {
    /// Short name, for failure messages.
    name: &'static str,
    /// The snapshot header's covered VV.
    covered: Vec<(u8, u64)>,
    /// The body.
    body: SnapshotBody,
    /// The committed `data`.
    hex: &'static str,
}

/// Helper: the register `key` with `entries`.
fn reg(key: &'static str, entries: Vec<(u8, u64, Hlc, Vec<u8>)>) -> Reg {
    (key, entries)
}

fn snapshot_vectors() -> Vec<SnapshotVector> {
    let (h1, h2, h3, hb) = (hlc(0, 0), hlc(1_000, 0), hlc(2_000, 0), hlc(1_500, 0));
    let active = || vec![0x01];
    vec![
        // A creates the Login (A:1), then changes the password (A:2). A (A:3) and B (B:1),
        // both from context {A:2}, change the username concurrently; B also adds two tags and
        // a key from a newer client. Every op writes Active, so A:1's and A:2's lifecycle
        // values are in history too.
        SnapshotVector {
            name: "live snapshot",
            covered: vec![(A, 3), (B, 1)],
            body: SnapshotBody::Live(
                vec![
                    reg(
                        "@lifecycle",
                        vec![(A, 3, h3, active()), (B, 1, hb, active())],
                    ),
                    reg("item.name", vec![(A, 1, h1, text("Example"))]),
                    reg("item.type", vec![(A, 1, h1, enumv(1))]),
                    reg("login.password", vec![(A, 2, h2, text("new secret"))]),
                    reg(
                        "login.username",
                        vec![(A, 3, h3, text("alice.a")), (B, 1, hb, text("alice.b"))],
                    ),
                    reg("tag/61", vec![(B, 1, hb, boolean(true))]),
                    reg("tag/6162", vec![(B, 1, hb, boolean(true))]),
                    reg("zz.unknown", vec![(B, 1, hb, text("from a newer client"))]),
                ],
                vec![
                    reg(
                        "@lifecycle",
                        vec![(A, 1, h1, active()), (A, 2, h2, active())],
                    ),
                    reg("login.password", vec![(A, 1, h1, text("old secret"))]),
                    reg("login.username", vec![(A, 1, h1, text("alice"))]),
                ],
            ),
            hex: HEX_LIVE,
        },
        // A purges (A:4, context {A:3}) while B (B:1, context {A:2}) edits the password: B's
        // value is late.
        SnapshotVector {
            name: "tombstone with a late value",
            covered: vec![(A, 4), (B, 1)],
            body: SnapshotBody::Tombstone(
                (A, 4),
                hlc(3_000, 0),
                vec![(A, 3)],
                KEY_OLD,
                vec![reg("login.password", vec![(B, 1, hb, text("late edit"))])],
            ),
            hex: HEX_TOMBSTONE_LATE,
        },
        // Two concurrent purges: A:4 (HLC T0 + 5 s, context {A:3, B:1}, under the newer key)
        // and B:2 (HLC T0 + 6 s, context {A:2, B:1}, under the older key). The recorded purge
        // is B:2, the higher HLC, so item_key_id is the older key; c is the join {A:3, B:1}.
        SnapshotVector {
            name: "tombstone from two concurrent purges",
            covered: vec![(A, 4), (B, 2)],
            body: SnapshotBody::Tombstone(
                (B, 2),
                hlc(6_000, 0),
                vec![(A, 3), (B, 1)],
                KEY_OLD,
                vec![],
            ),
            hex: HEX_TOMBSTONE_TWO_PURGES,
        },
        // A's purge A:4, rejected for a stale epoch and re-issued with the same dot, HLC and
        // context under a fresh item key (owner decision 15): item_key_id is the re-issued key.
        SnapshotVector {
            name: "tombstone of a re-issued purge",
            covered: vec![(A, 4)],
            body: SnapshotBody::Tombstone(
                (A, 4),
                hlc(3_000, 0),
                vec![(A, 3)],
                KEY_REISSUED,
                vec![],
            ),
            hex: HEX_TOMBSTONE_REISSUED,
        },
    ]
}

/// The register `r`, borrowing from it.
fn register_ref(r: &Reg) -> Register<'_> {
    let entries =
        r.1.iter()
            .map(|&(b, seq, h, ref v)| Entry::new(dot(b, seq), h, Value::new(v)))
            .collect();
    Register::new(key(r.0), entries)
}

/// Writes a list of registers with [`Spec`].
fn spec_registers(s: Spec, regs: &[Reg]) -> Spec {
    let n = u16::try_from(regs.len()).unwrap();
    regs.iter().fold(s.u16(n), |s, (k, entries)| {
        let entries: Vec<_> = entries
            .iter()
            .map(|(b, seq, h, v)| (*b, *seq, *h, v.as_slice()))
            .collect();
        s.register(k, &entries)
    })
}

impl SnapshotVector {
    fn covered(&self) -> VersionVector {
        vv(&self.covered)
    }

    /// The record, borrowing from the vector.
    fn record(&self) -> SnapshotData<'_> {
        match &self.body {
            SnapshotBody::Live(regs, hist) => SnapshotData::Live(LiveSnapshot::new(
                regs.iter().map(register_ref).collect(),
                hist.iter().map(register_ref).collect(),
            )),
            SnapshotBody::Tombstone((b, seq), h, c, key_id, late) => {
                SnapshotData::Tombstone(Tombstone::new(
                    dot(*b, *seq),
                    *h,
                    vv(c),
                    SymmetricKeyId::from_bytes(*key_id),
                    late.iter().map(register_ref).collect(),
                ))
            }
        }
    }

    /// The `data`, written by [`Spec`] from the ADR 0018 §3 layout.
    fn spec(&self) -> Vec<u8> {
        match &self.body {
            SnapshotBody::Live(regs, hist) => {
                let s = spec_registers(Spec::new().u8(0x02), regs);
                spec_registers(s, hist).done()
            }
            SnapshotBody::Tombstone((b, seq), h, c, key_id, late) => {
                let s = Spec::new()
                    .u8(0x03)
                    .dot(*b, *seq)
                    .u64(h.to_u64())
                    .vv(c)
                    .raw(key_id);
                spec_registers(s, late).done()
            }
        }
    }
}

#[test]
fn op_vectors_are_byte_exact() {
    for v in op_vectors() {
        let record = v.record();
        let encoded = encode_op(&record).unwrap();
        let spec = v.spec();
        assert_eq!(encoded.expose_secret(), spec.as_slice(), "{}", v.name);
        assert_eq!(to_hex(&spec), v.hex, "{}: committed hex", v.name);
        let committed = hex(v.hex);
        assert_eq!(parse_op(&committed), Ok(record), "{}", v.name);
    }
}

#[test]
fn snapshot_vectors_are_byte_exact() {
    for v in snapshot_vectors() {
        let covered = v.covered();
        let record = v.record();
        let encoded = encode_snapshot(&covered, &record).unwrap();
        let spec = v.spec();
        assert_eq!(encoded.expose_secret(), spec.as_slice(), "{}", v.name);
        assert_eq!(to_hex(&spec), v.hex, "{}: committed hex", v.name);
        let committed = hex(v.hex);
        assert_eq!(
            parse_snapshot(&covered, &committed),
            Ok(record),
            "{}",
            v.name
        );
    }
}

/// ADR 0018 §3: a tombstone without late registers is 53 + 24·c bytes.
#[test]
fn tombstone_sizes() {
    for v in snapshot_vectors() {
        if let SnapshotBody::Tombstone(_, _, c, _, late) = &v.body
            && late.is_empty()
        {
            assert_eq!(hex(v.hex).len(), 53 + 24 * c.len(), "{}", v.name);
        }
    }
}

/// §4 "Order", pinned by the Login create: `login.password` < `login.totp` <
/// `login.username`; and by the live snapshot: `tag/61` < `tag/6162`.
#[test]
fn the_vectors_pin_the_key_order() {
    let keys: Vec<String> = op_vectors()[0]
        .writes
        .iter()
        .map(|(k, _)| k.clone())
        .collect();
    let at = |k: &str| keys.iter().position(|x| x == k).unwrap();
    assert!(at("login.password") < at("login.totp") && at("login.totp") < at("login.username"));
    let snapshots = snapshot_vectors();
    let SnapshotBody::Live(regs, _) = &snapshots[0].body else {
        panic!("the first snapshot vector is live");
    };
    let at = |k: &str| regs.iter().position(|r| r.0 == k).unwrap();
    assert!(at("tag/61") < at("tag/6162"));
}

// ---------------------------------------------------------------------------------------------
// Negative vectors
// ---------------------------------------------------------------------------------------------

/// The purpose a negative vector is parsed under.
#[derive(Clone, Copy, Debug)]
enum Purpose {
    /// `parse_op`.
    ItemOp,
    /// `parse_snapshot` with the covered VV.
    ItemSnapshot,
}

/// A negative vector: (purpose, covered VV, `data`), the §5 rule it breaks, and a name.
struct Negative {
    /// Short name.
    name: &'static str,
    /// The rule broken, 1–8.
    rule: u8,
    /// The purpose.
    purpose: Purpose,
    /// The covered VV (ignored for ops).
    covered: Vec<(u8, u64)>,
    /// The `data`.
    data: Vec<u8>,
}

/// Op data written by [`Spec`]: `lifecycle` and `writes`, verbatim.
fn raw_op(lifecycle: u8, writes: &[(&str, &[u8])]) -> Vec<u8> {
    let n = u16::try_from(writes.len()).unwrap();
    writes
        .iter()
        .fold(Spec::new().u8(0x01).u8(lifecycle).u16(n), |s, (k, v)| {
            s.write(k, v)
        })
        .done()
}

/// A one-value Text write.
const E1: &[u8] = &[0x01, b'x'];

/// An `Active` op writing [`E1`] to `key`.
fn one_write(key: &str) -> Vec<u8> {
    raw_op(0x01, &[(key, E1)])
}

/// Live snapshot data from its register list and its history list, each with its count.
fn raw_live(regs: Spec, hist: Spec) -> Vec<u8> {
    Spec::new()
        .u8(0x02)
        .raw(&regs.done())
        .raw(&hist.done())
        .done()
}

/// Appends the register `@lifecycle` = Active by A:1.
fn lifecycle_a1(s: Spec) -> Spec {
    s.register("@lifecycle", &[(A, 1, hlc(0, 0), &[0x01])])
}

/// Tombstone data up to and including `item_key_id`: the purge dot, an HLC, `c` as given.
fn raw_tomb_head(purge: (u8, u64), c: &[(u8, u64)]) -> Spec {
    Spec::new()
        .u8(0x03)
        .dot(purge.0, purge.1)
        .u64(hlc(0, 0).to_u64())
        .vv(c)
        .raw(&KEY_OLD)
}

/// A negative vector.
fn neg(
    name: &'static str,
    rule: u8,
    purpose: Purpose,
    covered: &[(u8, u64)],
    data: Vec<u8>,
) -> Negative {
    Negative {
        name,
        rule,
        purpose,
        covered: covered.to_vec(),
        data,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one table of vectors; splitting it would scatter the list ADR 0018 §12 asks for"
)]
fn negative_vectors() -> Vec<Negative> {
    use Purpose::{ItemOp as Op, ItemSnapshot as Snap};
    let h = hlc(0, 0).to_u64();
    let (op, one, live, lc, tomb_head, e1) =
        (raw_op, one_write, raw_live, lifecycle_a1, raw_tomb_head, E1);
    vec![
        // Rule 1: a valid live snapshot under ITEM_OP; a valid op under ITEM_SNAPSHOT; the
        // reserved SHARE_SNAPSHOT kind.
        neg(
            "live snapshot data as ITEM_OP",
            1,
            Op,
            &[],
            live(lc(Spec::new().u16(1)), Spec::new().u16(0)),
        ),
        neg(
            "op data as ITEM_SNAPSHOT",
            1,
            Snap,
            &[(A, 1)],
            one("item.name"),
        ),
        neg(
            "record kind 0x04",
            1,
            Snap,
            &[(A, 1)],
            vec![0x04, 0x00, 0x00],
        ),
        neg("record kind 0x00", 1, Op, &[], vec![0x00, 0x01, 0x00, 0x00]),
        // Rule 2.
        neg("161-byte key", 2, Op, &[], one(&key_of_len(161))),
        neg(
            "value of 65,537 bytes",
            2,
            Op,
            &[],
            op(0x01, &[("item.notes", &vec![0x01; 65_537])]),
        ),
        neg("1,025 writes", 2, Op, &[], {
            let keys: Vec<String> = (0..1_025).map(|i| format!("f.k{i:04}")).collect();
            let writes: Vec<(&str, &[u8])> = keys.iter().map(|k| (k.as_str(), e1)).collect();
            op(0x01, &writes)
        }),
        neg(
            "count past the end",
            2,
            Op,
            &[],
            vec![0x01, 0x01, 0x00, 0x01],
        ),
        neg(
            "trailing byte",
            2,
            Op,
            &[],
            [one("item.name"), vec![0x00]].concat(),
        ),
        neg(
            "257 values in a register",
            2,
            Snap,
            &[(A, 257)],
            live(
                (1..=257).fold(Spec::new().u16(1).str("@lifecycle").u16(257), |s, seq| {
                    s.dot(A, seq).u64(h).bytes(&[0x01])
                }),
                Spec::new().u16(0),
            ),
        ),
        // `1 ≤ r` (§3): rule 2, as the merge spike's `validate_snapshot` files it.
        neg(
            "live snapshot with no register",
            2,
            Snap,
            &[(A, 1)],
            live(Spec::new().u16(0), Spec::new().u16(0)),
        ),
        // Rule 3.
        neg("odd hex count", 3, Op, &[], one("uri/abc/value")),
        neg(
            "33-byte name",
            3,
            Op,
            &[],
            one(&format!("{}.x", "a".repeat(33))),
        ),
        neg("uppercase hex", 3, Op, &[], one("tag/6A")),
        neg("a lone name", 3, Op, &[], one("notes")),
        neg(
            "writes out of order",
            3,
            Op,
            &[],
            op(0x01, &[("login.username", e1), ("login.password", e1)]),
        ),
        neg(
            "duplicate write",
            3,
            Op,
            &[],
            op(0x01, &[("item.name", e1), ("item.name", e1)]),
        ),
        neg(
            "dots out of order",
            3,
            Snap,
            &[(A, 2)],
            live(
                Spec::new().u16(1).register(
                    "@lifecycle",
                    &[(A, 2, hlc(0, 0), &[0x01]), (A, 1, hlc(0, 0), &[0x01])],
                ),
                Spec::new().u16(0),
            ),
        ),
        neg(
            "a dot in a register and its history group",
            3,
            Snap,
            &[(A, 1)],
            live(
                lc(Spec::new().u16(1)),
                Spec::new()
                    .u16(1)
                    .register("@lifecycle", &[(A, 1, hlc(0, 0), &[0x01])]),
            ),
        ),
        neg(
            "c not ascending",
            3,
            Snap,
            &[(A, 2), (B, 1)],
            tomb_head((A, 2), &[(B, 1), (A, 1)]).u16(0).done(),
        ),
        // Rule 4.
        neg("lifecycle 0x04", 4, Op, &[], vec![0x01, 0x04, 0x00, 0x00]),
        neg("lifecycle 0x00", 4, Op, &[], vec![0x01, 0x00, 0x00, 0x00]),
        neg(
            "writes with Trashed",
            4,
            Op,
            &[],
            op(0x02, &[("item.name", e1)]),
        ),
        neg(
            "writes with Purge",
            4,
            Op,
            &[],
            op(0x03, &[("item.name", e1)]),
        ),
        // Rule 5.
        neg(
            "live snapshot not starting with @lifecycle",
            5,
            Snap,
            &[(A, 1)],
            live(
                Spec::new()
                    .u16(1)
                    .register("item.name", &[(A, 1, hlc(0, 0), e1)]),
                Spec::new().u16(0),
            ),
        ),
        neg(
            "@lifecycle value 0x03",
            5,
            Snap,
            &[(A, 1)],
            live(
                Spec::new()
                    .u16(1)
                    .register("@lifecycle", &[(A, 1, hlc(0, 0), &[0x03])]),
                Spec::new().u16(0),
            ),
        ),
        neg(
            "@lifecycle value of two bytes",
            5,
            Snap,
            &[(A, 1)],
            live(
                Spec::new()
                    .u16(1)
                    .register("@lifecycle", &[(A, 1, hlc(0, 0), &[0x01, 0x01])]),
                Spec::new().u16(0),
            ),
        ),
        neg(
            "@lifecycle in an op",
            5,
            Op,
            &[],
            op(0x01, &[("@lifecycle", &[0x01])]),
        ),
        neg(
            "@lifecycle in a tombstone",
            5,
            Snap,
            &[(A, 2), (B, 1)],
            tomb_head((A, 2), &[(A, 1)])
                .u16(1)
                .register("@lifecycle", &[(B, 1, hlc(0, 0), &[0x01])])
                .done(),
        ),
        neg(
            "register with m = 0",
            5,
            Snap,
            &[(A, 1)],
            live(
                lc(Spec::new().u16(2)).str("item.name").u16(0),
                Spec::new().u16(0),
            ),
        ),
        neg(
            "history group with m = 0",
            5,
            Snap,
            &[(A, 2)],
            live(
                lc(Spec::new().u16(2)).register("item.name", &[(A, 2, hlc(0, 0), e1)]),
                Spec::new().u16(1).str("item.name").u16(0),
            ),
        ),
        // Rule 6.
        neg(
            "dot with seq 0",
            6,
            Snap,
            &[(A, 1)],
            live(
                Spec::new()
                    .u16(1)
                    .register("@lifecycle", &[(A, 0, hlc(0, 0), &[0x01])]),
                Spec::new().u16(0),
            ),
        ),
        neg(
            "dot not covered",
            6,
            Snap,
            &[(A, 1)],
            live(
                lc(Spec::new().u16(2)).register("item.name", &[(B, 1, hlc(0, 0), e1)]),
                Spec::new().u16(0),
            ),
        ),
        neg(
            "history entry not covered",
            6,
            Snap,
            &[(A, 2)],
            live(
                lc(Spec::new().u16(2)).register("item.name", &[(A, 2, hlc(0, 0), e1)]),
                Spec::new()
                    .u16(1)
                    .register("item.name", &[(B, 1, hlc(0, 0), e1)]),
            ),
        ),
        neg(
            "late value not covered",
            6,
            Snap,
            &[(A, 2)],
            tomb_head((A, 2), &[(A, 1)])
                .u16(1)
                .register("item.name", &[(B, 1, hlc(0, 0), e1)])
                .done(),
        ),
        neg(
            "purge_dot not covered",
            6,
            Snap,
            &[(A, 1)],
            tomb_head((A, 2), &[(A, 1)]).u16(0).done(),
        ),
        neg(
            "entry of c not covered",
            6,
            Snap,
            &[(A, 2)],
            tomb_head((A, 2), &[(A, 1), (B, 1)]).u16(0).done(),
        ),
        neg(
            "entry of c with seq 0",
            6,
            Snap,
            &[(A, 2)],
            tomb_head((A, 2), &[(A, 0)]).u16(0).done(),
        ),
        // Rule 7.
        neg(
            "history group without a current register",
            7,
            Snap,
            &[(A, 2)],
            live(
                Spec::new()
                    .u16(1)
                    .register("@lifecycle", &[(A, 2, hlc(0, 0), &[0x01])]),
                Spec::new()
                    .u16(1)
                    .register("item.name", &[(A, 1, hlc(0, 0), e1)]),
            ),
        ),
        // Rule 8.
        neg(
            "late value covered by c",
            8,
            Snap,
            &[(A, 2), (B, 1)],
            tomb_head((A, 2), &[(A, 1), (B, 1)])
                .u16(1)
                .register("item.name", &[(B, 1, hlc(0, 0), e1)])
                .done(),
        ),
    ]
}

#[test]
fn negative_vectors_are_rejected_for_their_rule() {
    let vectors = negative_vectors();
    for rule in 1..=8 {
        assert!(
            vectors.iter().any(|v| v.rule == rule),
            "no vector for rule {rule}"
        );
    }
    for v in vectors {
        let err = match v.purpose {
            Purpose::ItemOp => parse_op(&v.data).map(drop),
            Purpose::ItemSnapshot => parse_snapshot(&vv(&v.covered), &v.data).map(drop),
        }
        .unwrap_err();
        assert_eq!(err.kind().rule(), v.rule, "{}: {err}", v.name);
    }
}

/// Calls `f` on mutations of `bytes`: each byte changed by each of nine masks, each of three
/// bytes inserted at every position, and 1–4 bytes removed at every position.
fn for_each_mutation(bytes: &[u8], mut f: impl FnMut(&[u8])) {
    const MASKS: [u8; 9] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff];
    let mut m = bytes.to_vec();
    for i in 0..bytes.len() {
        for mask in MASKS {
            m[i] ^= mask;
            f(&m);
            m[i] ^= mask;
        }
    }
    for i in 0..=bytes.len() {
        for byte in [0x00, 0x01, 0xff] {
            let inserted = [&bytes[..i], &[byte], &bytes[i..]].concat();
            f(&inserted);
        }
    }
    for i in 0..bytes.len() {
        for len in 1..=4 {
            if let Some(tail) = bytes.get(i + len..) {
                f(&[&bytes[..i], tail].concat());
            }
        }
    }
}

/// Each record has exactly one encoding (ADR 0018 §4), so every mutation of a committed vector
/// that still parses re-encodes to exactly the mutated bytes, never to other bytes. Changes
/// inside values, HLCs, ids and some dots parse, so this runs on many accepted inputs; the test
/// requires that, so that the check cannot pass vacuously.
#[test]
fn every_accepted_mutation_of_a_vector_is_canonical() {
    let (mut tried, mut accepted) = (0usize, 0usize);
    for v in op_vectors() {
        for_each_mutation(&hex(v.hex), |m| {
            tried += 1;
            if let Ok(op) = parse_op(m) {
                accepted += 1;
                let again = encode_op(&op).unwrap();
                assert_eq!(again.expose_secret(), m, "{}", v.name);
            }
        });
    }
    for v in snapshot_vectors() {
        let covered = v.covered();
        for_each_mutation(&hex(v.hex), |m| {
            tried += 1;
            if let Ok(s) = parse_snapshot(&covered, m) {
                accepted += 1;
                let again = encode_snapshot(&covered, &s).unwrap();
                assert_eq!(again.expose_secret(), m, "{}", v.name);
            }
        });
    }
    assert!(
        accepted > 1_000 && accepted < tried,
        "{accepted} of {tried} mutations parsed"
    );
}

/// The boundary partner of the 161-byte key vector: a 160-byte key parses.
#[test]
fn the_boundaries_parse() {
    let k = key_of_len(160);
    assert_eq!(k.len(), 160);
    let v = [0x01, b'x'];
    let data = Spec::new().u8(0x01).u8(0x01).u16(1).write(&k, &v).done();
    assert!(parse_op(&data).is_ok());
    assert_eq!(key_of_len(161).len(), 161);
}

// Committed hex of the positive vectors, generated by the spec writer on 2026-09-27 and
// checked against the encoder by the tests above.

/// "create Login".
const HEX_CREATE_LOGIN: &str = "\
    01010007000000096974656d2e6e616d6500000008014578616d706c65000000096974656d2e747970650000\
    00030500010000000e6c6f67696e2e70617373776f72640000001d01636f727265637420686f727365206261\
    747465727920737461706c650000000a6c6f67696e2e746f747000000011014a425357593344504548504b33\
    5058500000000e6c6f67696e2e757365726e616d650000001201616c696365406578616d706c652e636f6d00\
    00002a7572692f30303131323233333434353536363737383839396161626263636464656566662f6f726465\
    720000000206800000002a7572692f3030313132323333343435353636373738383939616162626363646465\
    6566662f76616c75650000001a0168747470733a2f2f6578616d706c652e636f6d2f6c6f67696e";
/// "create Secure Note".
const HEX_CREATE_NOTE: &str = "\
    01010003000000096974656d2e6e616d650000000e0157692d466920617420686f6d650000000a6974656d2e\
    6e6f7465730000001e01535349443a20686f6d650a4b65793a20696e20746865206472617765720000000969\
    74656d2e7479706500000003050002";
/// "create Card".
const HEX_CREATE_CARD: &str = "\
    010100080000000a636172642e6272616e6400000005015669736100000009636172642e636f646500000004\
    013132330000000e636172642e6578705f6d6f6e7468000000030131320000000d636172642e6578705f7965\
    61720000000501323033300000000b636172642e686f6c6465720000000e01416c696365204578616d706c65\
    0000000b636172642e6e756d626572000000110134313131313131313131313131313131000000096974656d\
    2e6e616d650000000c0154726176656c2063617264000000096974656d2e7479706500000003050003";
/// "create Identity".
const HEX_CREATE_IDENTITY: &str = "\
    010100060000000d6964656e746974792e636974790000000c01537072696e676669656c640000000e696465\
    6e746974792e656d61696c0000001201616c696365406578616d706c652e636f6d000000136964656e746974\
    792e66697273745f6e616d650000000601416c696365000000126964656e746974792e6c6173745f6e616d65\
    00000008014578616d706c65000000096974656d2e6e616d6500000003014d65000000096974656d2e747970\
    6500000003050004";
/// "create Vault settings".
const HEX_CREATE_SETTINGS: &str = "\
    01010003000000096974656d2e747970650000000305f0010000000a7661756c742e69636f6e000000070173\
    6869656c640000000a7661756c742e6e616d650000000901506572736f6e616c";
/// "list edit".
const HEX_LIST_EDIT: &str = "\
    010100070000002b6669656c642f306630653064306330623061303930383037303630353034303330323031\
    30302f6b696e64000000030500020000002c6669656c642f3066306530643063306230613039303830373036\
    3035303430333032303130302f6c6162656c000000040150494e0000002c6669656c642f3066306530643063\
    3062306130393038303730363035303430333032303130302f6f726465720000000206800000002c6669656c\
    642f30663065306430633062306130393038303730363035303430333032303130302f76616c756500000005\
    01303030300000000c7461672f37373666373236620000000203010000002a7572692f303031313232333334\
    34353536363737383839396161626263636464656566662f6f72646572000000000000002a7572692f303031\
    31323233333434353536363737383839396161626263636464656566662f76616c756500000000";
/// "each value type".
const HEX_VALUE_TYPES: &str = "\
    010100080000002b6669656c642f306630653064306330623061303930383037303630353034303330323031\
    30302f6b696e64000000030500030000002c6669656c642f3066306530643063306230613039303830373036\
    3035303430333032303130302f76616c75650000000203010000002c6669656c642f61306131613261336134\
    613561366137613861396161616261636164616561662f76616c75650000000000000011696d706f72742e63\
    7265617465645f6d7300000009040000018bcfe56800000000096974656d2e6e616d650000000b0156c3a472\
    646520e29c930000002d73686172652f35613561356135613561356135613561356135613561356135613561\
    356135612f73656372657400000021025e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e\
    5e5e5e5e0000002a7572692f3030313132323333343435353636373738383939616162626363646465656666\
    2f6f7264657200000003067fff0000000a7a7a2e756e6b6e6f776e000000020778";
/// "live snapshot".
const HEX_LIVE: &str = "\
    0200080000000a406c6966656379636c650002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000301\
    9e70448fd000000000000101bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000000000001019e70448ddc0000\
    0000000101000000096974656d2e6e616d650001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000001\
    019e70448800000000000008014578616d706c65000000096974656d2e747970650001aaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaa0000000000000001019e704488000000000000030500010000000e6c6f67696e2e70617373\
    776f72640001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000002019e70448be800000000000b016e\
    6577207365637265740000000e6c6f67696e2e757365726e616d650002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aa0000000000000003019e70448fd000000000000801616c6963652e61bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\
    bb0000000000000001019e70448ddc00000000000801616c6963652e62000000067461672f36310001bbbbbb\
    bbbbbbbbbbbbbbbbbbbbbbbbbb0000000000000001019e70448ddc0000000000020301000000087461672f36\
    3136320001bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000000000001019e70448ddc000000000002030100\
    00000a7a7a2e756e6b6e6f776e0001bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000000000001019e70448d\
    dc0000000000140166726f6d2061206e6577657220636c69656e7400030000000a406c6966656379636c6500\
    02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000001019e7044880000000000000101aaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaa0000000000000002019e70448be8000000000001010000000e6c6f67696e2e706173\
    73776f72640001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000001019e7044880000000000000b01\
    6f6c64207365637265740000000e6c6f67696e2e757365726e616d650001aaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaa0000000000000001019e7044880000000000000601616c696365";
/// "tombstone with a late value".
const HEX_TOMBSTONE_LATE: &str = "\
    03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000004019e704493b800000001aaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaa00000000000000030101010101010101010101010101010100010000000e6c6f67696e2e70\
    617373776f72640001bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000000000001019e70448ddc0000000000\
    0a016c6174652065646974";
/// "tombstone from two concurrent purges".
const HEX_TOMBSTONE_TWO_PURGES: &str = "\
    03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000000000002019e70449f7000000002aaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaa0000000000000003bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000000000010101010101\
    01010101010101010101010000";
/// "tombstone of a re-issued purge".
const HEX_TOMBSTONE_REISSUED: &str = "\
    03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000004019e704493b800000001aaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaa0000000000000003030303030303030303030303030303030000";

/// Prints the hex of every positive vector, for regenerating the constants above by hand
/// after a deliberate format change (a new `item_schema_version`, ADR 0018 §11).
#[test]
#[ignore = "prints the committed hex; run by hand with --ignored --nocapture"]
fn print_vector_hex() {
    for v in op_vectors() {
        println!("{}: {}", v.name, to_hex(&v.spec()));
    }
    for v in snapshot_vectors() {
        println!("{}: {}", v.name, to_hex(&v.spec()));
    }
}

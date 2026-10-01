//! The harness's cryptography: real `rizzy-core` keys, signatures and envelopes, under a
//! seeded test RNG (ADR 0012 §12: "real `rizzy-core` crypto with a test RNG").
//!
//! # What is real
//!
//! - **Envelopes.** Every op body is an `ITEM_OP` envelope and every snapshot's data an
//!   `ITEM_SNAPSHOT` envelope, sealed by [`rizzy_core::envelope::seal`] under the item's
//!   [`ItemKey`] with the AAD context the record's header gives
//!   ([`OpHeader::envelope_context`], [`SnapshotHeader::envelope_context`]: the ids, the dot,
//!   the HLC and `SHA-256` of the canonical header, CRYPTO.md §8.4). A device opens an
//!   envelope under the context it rebuilds from the header it verified, so a body moved to
//!   another header, item or covered VV does not open (ADR 0018 owner decision 3).
//! - **Signatures.** Every record travels with its `op` or `snapshot` statement in the signed
//!   wire form (CRYPTO.md §9.6, §10.2), signed with its author's [`DeviceSigningKey`]. The
//!   server and every device verify it under the key of the device the record names, parse
//!   the header from the verified statement, and require that header to name that device
//!   (CRYPTO.md §10.2, INV-22).
//!
//! # The test RNG
//!
//! `rizzy-core` takes randomness only as an injected `rand_core` 0.10 `CryptoRng` and offers
//! no seeded one outside its own tests (ADR 0009 "RNG rules": "Deterministic RNGs are
//! dev-dependencies only"). The harness uses the generator ADR 0009 names for tests,
//! `chacha20`'s `ChaCha20Rng`, as a dev-dependency of this crate, the way `rizzy-core`'s own
//! vectors and `rizzy-import`'s tests do. Nothing is added to `rizzy-core`'s API: the keys
//! come from its public `generate` functions and the nonces from its public `seal`, each
//! given this RNG.
//!
//! - **Keys** ([`KEYS`]) are drawn once per test process from a fixed seed: one signing key
//!   per device id the harness can name and one item key per item id. They are test values
//!   only; a run never sees another run's records, so sharing them between runs shares
//!   nothing.
//! - **Nonces** come from each device's own source ([`Nonces`]), seeded from the run's seed,
//!   the device id and a count of the device's seals, so two devices of a run never draw the
//!   same stream and a history is reproducible from its `(family, seed)`. A device that rolls
//!   its state back (a refused healing request) keeps its count: a real device never reuses a
//!   nonce.
//!
//! # What is not modelled
//!
//! Certificates (the harness's directory of verifying keys stands in for the verified device
//! set), the vault key and the `ITEM_KEY_WRAP` envelope (every device holds every item key
//! from the start, and no statement signs a wrap hash), and key rotation (one vault key epoch,
//! one item key per item).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng as _;
use rizzy_core::envelope::{open, seal};
use rizzy_core::ids::{DeviceId, ItemId, SymmetricKeyId};
use rizzy_core::keys::ItemKey;
use rizzy_core::secret::SecretBytes;
use rizzy_core::sign::{DeviceSigningKey, OpStatement, SnapshotStatement, Verified};

use super::{device_id, item_id};
use crate::header::{OpHeader, SnapshotHeader};

/// How many device ids [`device_id`] and item ids [`item_id`] can name: both keep the low four
/// bits of their index.
const SLOTS: usize = 16;

/// The seed of the harness's keys. Any fixed value does.
const KEY_SEED: u64 = 0x0012_c0de;

/// One item's key and its key id.
struct Item {
    /// The item key every device holds.
    key: ItemKey,
    /// Its key id (CRYPTO.md §4.4): what the envelope header carries and the merge records.
    key_id: SymmetricKeyId,
}

/// The keys of every device and item of the harness.
struct Keys {
    /// Each device's signing key. Its verifying half is what a certificate would carry.
    devices: BTreeMap<DeviceId, DeviceSigningKey>,
    /// Each item's key.
    items: BTreeMap<ItemId, Item>,
}

/// The harness's keys, drawn once from [`KEY_SEED`] through `rizzy-core`'s public `generate`
/// functions.
static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let mut rng = ChaCha20Rng::seed_from_u64(KEY_SEED);
    let devices = (0..SLOTS)
        .map(|d| (device_id(d), DeviceSigningKey::generate(&mut rng)))
        .collect();
    let items = (0..SLOTS)
        .map(|i| {
            let key = ItemKey::generate(&mut rng, 0);
            let key_id = key.key_id().expect("a key id derives");
            (item_id(i), Item { key, key_id })
        })
        .collect();
    Keys { devices, items }
});

/// A device's source of envelope nonces: one fresh `ChaCha20Rng` per seal, keyed by the run's
/// seed, the device id and a count of the seals so far, so every device of every run has its
/// own stream and no seal of a device repeats another's nonce.
///
/// `ChaCha20Rng` is not `Clone`, and a simulated device is (a refused healing request restores
/// a saved copy); this type is, and the device carries the count across that restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Nonces {
    /// The seed the run is scheduled from.
    run: u64,
    /// The device.
    device: DeviceId,
    /// How many generators were handed out.
    drawn: u64,
}

impl Nonces {
    /// The nonce source of device `device` in the run scheduled from `run`.
    pub(super) const fn new(run: u64, device: DeviceId) -> Self {
        Self {
            run,
            device,
            drawn: 0,
        }
    }

    /// The generator of the next seal: `ChaCha20Rng` seeded with
    /// `run (8, little-endian) ‖ device_id (16) ‖ count (8, little-endian)`.
    fn next_rng(&mut self) -> ChaCha20Rng {
        let mut key = [0u8; 32];
        let (run, rest) = key.split_at_mut(8);
        run.copy_from_slice(&self.run.to_le_bytes());
        let (device, count) = rest.split_at_mut(16);
        device.copy_from_slice(self.device.as_bytes());
        count.copy_from_slice(&self.drawn.to_le_bytes());
        self.drawn += 1;
        ChaCha20Rng::from_seed(key)
    }
}

/// The key id of `item`'s key. An item outside the harness's table has no key; its id is then
/// the item id's bytes, which no envelope carries.
pub(super) fn item_key_id(item: ItemId) -> SymmetricKeyId {
    KEYS.items
        .get(&item)
        .map_or_else(|| SymmetricKeyId::from_bytes(item.to_bytes()), |i| i.key_id)
}

/// Seals op `data` as the `ITEM_OP` envelope of the op with `header`, under the item's key,
/// with a nonce from `nonces`. `None` if the item has no key, the header does not encode, or
/// `rizzy-core` refuses the plaintext (above its size limit).
pub(super) fn seal_op(nonces: &mut Nonces, header: &OpHeader, data: &[u8]) -> Option<Vec<u8>> {
    let item = KEYS.items.get(&header.item_id)?;
    let ctx = header.envelope_context().ok()?;
    seal(&mut nonces.next_rng(), item.key.key(), &ctx, data).ok()
}

/// Opens the `ITEM_OP` envelope of the op with `header`: the op `data`. `None` for every
/// failure (another key, header or item, a changed byte).
pub(super) fn open_op(header: &OpHeader, envelope: &[u8]) -> Option<SecretBytes> {
    let item = KEYS.items.get(&header.item_id)?;
    let ctx = header.envelope_context().ok()?;
    open(item.key.key(), &ctx, envelope).ok()
}

/// Seals snapshot `data` as the `ITEM_SNAPSHOT` envelope of the snapshot with `header`. `None`
/// as [`seal_op`].
pub(super) fn seal_snapshot(
    nonces: &mut Nonces,
    header: &SnapshotHeader,
    data: &[u8],
) -> Option<Vec<u8>> {
    let item = KEYS.items.get(&header.item_id)?;
    let ctx = header.envelope_context().ok()?;
    seal(&mut nonces.next_rng(), item.key.key(), &ctx, data).ok()
}

/// Opens the `ITEM_SNAPSHOT` envelope of the snapshot with `header`: the snapshot `data`.
/// `None` for every failure; the covered VV and the author are in the header hash the AAD
/// binds, so data sealed for another covered VV does not open.
pub(super) fn open_snapshot(header: &SnapshotHeader, envelope: &[u8]) -> Option<SecretBytes> {
    let item = KEYS.items.get(&header.item_id)?;
    let ctx = header.envelope_context().ok()?;
    open(item.key.key(), &ctx, envelope).ok()
}

/// The signed `op` statement (wire form) over `header` and `envelope`, by the device the
/// header names. `None` if that device has no key or the header does not encode.
pub(super) fn sign_op(header: &OpHeader, envelope: &[u8]) -> Option<Vec<u8>> {
    let key = KEYS.devices.get(&header.dot.device_id())?;
    let statement = OpStatement::new(&header.to_vec().ok()?, envelope, None).ok()?;
    statement.sign(key).ok()
}

/// The signed `snapshot` statement (wire form) over `header` and `envelope`, by the header's
/// author. `None` as [`sign_op`].
pub(super) fn sign_snapshot(header: &SnapshotHeader, envelope: &[u8]) -> Option<Vec<u8>> {
    let key = KEYS.devices.get(&header.author)?;
    let statement = SnapshotStatement::new(&header.to_vec().ok()?, envelope, None).ok()?;
    statement.sign(key).ok()
}

/// Verifies a signed `op` statement that claims `author` (CRYPTO.md §10.2): the signature
/// under `author`'s key, then the header parsed from the verified statement, which must name
/// `author` (INV-22). `None` for every failure.
pub(super) fn verify_op(
    signed: &[u8],
    author: DeviceId,
) -> Option<(Verified<OpStatement>, OpHeader)> {
    let key = KEYS.devices.get(&author)?;
    let statement = OpStatement::verify(signed, key.verifying_key()).ok()?;
    let header = OpHeader::parse_statement(&statement).ok()?;
    (header.dot.device_id() == author).then_some((statement, header))
}

/// Verifies a signed `snapshot` statement that claims `author`, as [`verify_op`].
pub(super) fn verify_snapshot(
    signed: &[u8],
    author: DeviceId,
) -> Option<(Verified<SnapshotStatement>, SnapshotHeader)> {
    let key = KEYS.devices.get(&author)?;
    let statement = SnapshotStatement::verify(signed, key.verifying_key()).ok()?;
    let header = SnapshotHeader::parse_statement(&statement).ok()?;
    (header.author == author).then_some((statement, header))
}

#[cfg(test)]
mod tests {
    //! The crypto the harness relies on refuses what it must: the generated histories only
    //! ever exchange honest signatures and envelopes, so the refusals are pinned here, on the
    //! records the simulated server and devices check.

    use rizzy_core::ids::{OpId, SnapshotId};

    use super::super::server::{OpAnswer, OpRecord, Server, SnapAnswer, SnapRecord};
    use super::super::{VAULT, text};
    use super::*;
    use crate::dot::Dot;
    use crate::header::ItemSchemaVersion;
    use crate::hlc::Hlc;
    use crate::record::{
        FieldKey, Lifecycle, OpData, Value, Write, encode_op, parse_op, parse_snapshot,
    };
    use crate::vv::VersionVector;

    /// The header of device `d`'s first op, on item `i`.
    fn op_header(d: usize, i: usize) -> OpHeader {
        OpHeader {
            vault_id: VAULT,
            item_id: item_id(i),
            op_id: OpId::from_bytes([0x77; 16]),
            dot: Dot::new(device_id(d), 1).unwrap(),
            vault_prev_seq: 0,
            hlc: Hlc::from_u64(super::super::T0 << 16),
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: 0,
            causal_context: VersionVector::default(),
        }
    }

    /// An op `data` writing `item.name`.
    fn op_data() -> Vec<u8> {
        let key = FieldKey::new("item.name").unwrap();
        let value = text("a name");
        let data = OpData::new(Lifecycle::Active, vec![Write::new(key, Value::new(&value))]);
        encode_op(&data).unwrap().expose_secret().to_vec()
    }

    /// A sealed, signed op record of device `d` on item `i`.
    fn op_record(d: usize, i: usize) -> OpRecord {
        let header = op_header(d, i);
        let mut rng = Nonces::new(1, device_id(d));
        let envelope = seal_op(&mut rng, &header, &op_data()).unwrap();
        OpRecord {
            signed: sign_op(&header, &envelope).unwrap(),
            header,
            body: Some(envelope),
        }
    }

    #[test]
    fn an_op_envelope_opens_only_under_its_own_header() {
        let header = op_header(0, 0);
        let data = op_data();
        let mut rng = Nonces::new(1, device_id(0));
        let envelope = seal_op(&mut rng, &header, &data).unwrap();
        // A real envelope: header, nonce, commitment, the padded frame and the tag, under the
        // item's key id; never the plaintext.
        assert_eq!(envelope.len(), 90 + 256);
        assert_eq!(
            envelope.get(2..18),
            Some(&item_key_id(item_id(0)).as_bytes()[..])
        );
        assert!(!envelope.windows(6).any(|w| w == b"a name"));
        let opened = open_op(&header, &envelope).unwrap();
        assert_eq!(opened.expose_secret(), data);
        assert!(parse_op(opened.expose_secret()).is_ok());

        // Another item (its own key and AAD), another dot, HLC, op id or causal context (the
        // header hash), and a changed byte: none opens.
        let mut other_item = header.clone();
        other_item.item_id = item_id(1);
        assert!(open_op(&other_item, &envelope).is_none());
        let mut other_dot = header.clone();
        other_dot.dot = Dot::new(device_id(0), 2).unwrap();
        assert!(open_op(&other_dot, &envelope).is_none());
        let mut other_hlc = header.clone();
        other_hlc.hlc = Hlc::from_u64(header.hlc.to_u64() + 1);
        assert!(open_op(&other_hlc, &envelope).is_none());
        let mut other_context = header.clone();
        other_context.causal_context = [Dot::new(device_id(1), 1).unwrap()].into_iter().collect();
        assert!(open_op(&other_context, &envelope).is_none());
        let mut other_prev = header.clone();
        other_prev.vault_prev_seq = 7;
        assert!(open_op(&other_prev, &envelope).is_none());
        for at in [0, 17, 18, 60, 100, envelope.len() - 1] {
            let mut changed = envelope.clone();
            if let Some(b) = changed.get_mut(at) {
                *b ^= 1;
            }
            assert!(open_op(&header, &changed).is_none(), "byte {at}");
        }
        // Each seal draws a fresh nonce: the same op sealed again is another envelope.
        let again = seal_op(&mut rng, &header, &data).unwrap();
        assert_ne!(again, envelope);
        assert_eq!(open_op(&header, &again).unwrap().expose_secret(), data);
    }

    #[test]
    fn a_snapshot_envelope_is_bound_to_its_covered_vv_and_author() {
        let covered: VersionVector = [Dot::new(device_id(0), 1).unwrap()].into_iter().collect();
        let header = SnapshotHeader {
            vault_id: VAULT,
            item_id: item_id(0),
            snapshot_id: SnapshotId::from_bytes([0x88; 16]),
            author: device_id(0),
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: 0,
            covered,
        };
        let data = b"snapshot data stand-in";
        let mut rng = Nonces::new(1, device_id(0));
        let envelope = seal_snapshot(&mut rng, &header, data).unwrap();
        assert_eq!(
            open_snapshot(&header, &envelope).unwrap().expose_secret(),
            data
        );
        // ADR 0018 owner decision 3: the item VV is in the header, and the AAD binds it.
        let mut wider = header.clone();
        wider.covered = [
            Dot::new(device_id(0), 1).unwrap(),
            Dot::new(device_id(1), 4).unwrap(),
        ]
        .into_iter()
        .collect();
        assert!(open_snapshot(&wider, &envelope).is_none());
        let mut other_author = header.clone();
        other_author.author = device_id(1);
        assert!(open_snapshot(&other_author, &envelope).is_none());
        let mut other_item = header.clone();
        other_item.item_id = item_id(1);
        assert!(open_snapshot(&other_item, &envelope).is_none());
        // An `ITEM_OP` envelope of the same item is not an `ITEM_SNAPSHOT` envelope.
        let op = op_header(0, 0);
        let op_envelope = seal_op(&mut rng, &op, data).unwrap();
        assert!(open_snapshot(&header, &op_envelope).is_none());

        // The signed statement verifies under its author only, and gives the header back.
        let signed = sign_snapshot(&header, &envelope).unwrap();
        let (statement, parsed) = verify_snapshot(&signed, device_id(0)).unwrap();
        assert_eq!(parsed, header);
        assert!(statement.matches_envelope(&envelope));
        assert!(verify_snapshot(&signed, device_id(1)).is_none());
        assert!(
            verify_op(&signed, device_id(0)).is_none(),
            "not an op statement"
        );
        // The opened bytes of a real snapshot are what the record parser reads; this stand-in
        // is not a snapshot, and the parser says so without a panic.
        assert!(parse_snapshot(&header.covered, data).is_err());
    }

    #[test]
    fn a_statement_verifies_only_under_its_author_and_unchanged() {
        let record = op_record(0, 0);
        let (statement, header) = verify_op(&record.signed, device_id(0)).unwrap();
        assert_eq!(header, record.header);
        assert!(statement.matches_envelope(record.body.as_deref().unwrap()));
        assert!(record.verify().is_some());
        // Another device's key, and any changed byte of the wire form.
        assert!(verify_op(&record.signed, device_id(1)).is_none());
        for at in 0..record.signed.len() {
            let mut changed = record.signed.clone();
            if let Some(b) = changed.get_mut(at) {
                *b ^= 0x40;
            }
            assert!(verify_op(&changed, device_id(0)).is_none(), "byte {at}");
        }
        // A statement signed by a device over a header that names another device (INV-22).
        let header = op_header(1, 0);
        let canonical = header.to_vec().unwrap();
        let body = record.body.as_deref().unwrap();
        let statement = OpStatement::new(&canonical, body, None).unwrap();
        let forged = statement
            .sign(KEYS.devices.get(&device_id(0)).unwrap())
            .unwrap();
        assert!(verify_op(&forged, device_id(0)).is_none());
        assert!(verify_op(&forged, device_id(1)).is_none());
        // A device or an item outside the harness's table has no key.
        let stranger = DeviceId::from_bytes([0xee; 16]);
        assert!(verify_op(&record.signed, stranger).is_none());
        let mut no_key = op_header(0, 0);
        no_key.item_id = ItemId::from_bytes([0xee; 16]);
        let mut rng = Nonces::new(1, device_id(0));
        assert!(seal_op(&mut rng, &no_key, &op_data()).is_none());
    }

    #[test]
    fn the_server_refuses_a_bad_signature_and_a_swapped_body() {
        let record = op_record(0, 0);
        let mut server = Server::new();

        // The signature of another op of the same author: refused.
        let mut other = op_header(0, 0);
        other.op_id = OpId::from_bytes([0x78; 16]);
        let mut rng = Nonces::new(2, device_id(0));
        let other_envelope = seal_op(&mut rng, &other, &op_data()).unwrap();
        let mut wrong_statement = record.clone();
        wrong_statement.signed = sign_op(&other, &other_envelope).unwrap();
        assert_eq!(server.upload_op(&wrong_statement), OpAnswer::BadSignature);
        // A record whose claimed header names another device than its signer: refused.
        let mut wrong_author = record.clone();
        wrong_author.header = op_header(1, 0);
        assert_eq!(server.upload_op(&wrong_author), OpAnswer::BadSignature);
        // A changed signature byte: refused.
        let mut changed = record.clone();
        if let Some(b) = changed.signed.last_mut() {
            *b ^= 1;
        }
        assert_eq!(server.upload_op(&changed), OpAnswer::BadSignature);
        // Another envelope under a valid signature: refused by the signed hash.
        let mut swapped = record.clone();
        swapped.body = Some(other_envelope);
        assert_eq!(server.upload_op(&swapped), OpAnswer::BadBody);
        assert!(server.heads().is_empty(), "nothing was stored");

        // The honest record is stored, and the server never needed a key to do so.
        assert_eq!(server.upload_op(&record), OpAnswer::Stored);
        assert_eq!(server.upload_op(&record), OpAnswer::AlreadyStored);

        // Snapshots: the same two checks.
        let header = SnapshotHeader {
            vault_id: VAULT,
            item_id: item_id(0),
            snapshot_id: SnapshotId::from_bytes([0x88; 16]),
            author: device_id(0),
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: 0,
            covered: [record.header.dot].into_iter().collect(),
        };
        let envelope = seal_snapshot(&mut rng, &header, b"stand-in").unwrap();
        let snapshot = SnapRecord {
            signed: sign_snapshot(&header, &envelope).unwrap(),
            header,
            data: envelope,
            tainted: false,
        };
        let mut bad_signature = snapshot.clone();
        if let Some(b) = bad_signature.signed.last_mut() {
            *b ^= 1;
        }
        assert_eq!(
            server.upload_snapshot(&bad_signature),
            SnapAnswer::BadSignature
        );
        let mut bad_data = snapshot.clone();
        bad_data.data = seal_snapshot(&mut rng, &snapshot.header, b"other").unwrap();
        assert_eq!(server.upload_snapshot(&bad_data), SnapAnswer::BadData);
        assert_eq!(server.upload_snapshot(&snapshot), SnapAnswer::Stored);
    }

    #[test]
    fn nonce_sources_differ_by_run_by_device_and_by_seal() {
        use rand_core::Rng as _;
        let draw = |seed, d| Nonces::new(seed, device_id(d)).next_rng().next_u64();
        assert_eq!(draw(1, 0), draw(1, 0));
        assert_ne!(draw(1, 0), draw(1, 1));
        assert_ne!(draw(1, 0), draw(2, 0));
        // Each seal gets its own generator, and a copy taken earlier does not give the later
        // ones again once the device carries the count over (`Device::heal_headers`).
        let mut nonces = Nonces::new(1, device_id(0));
        let saved = nonces.clone();
        let (first, second) = (nonces.next_rng().next_u64(), nonces.next_rng().next_u64());
        assert_ne!(first, second);
        assert_eq!(saved.clone().next_rng().next_u64(), first);
        assert_ne!(nonces.next_rng().next_u64(), first);
    }
}

//! The device-state record and the encrypted local cache ([ADR 0026] §6) against the fake
//! server of the parent module:
//!
//! - known-answer vectors, round trips and the canonical form of the device-state record;
//! - a persisted device through signup, sync with a second device, a conflict, a compacted
//!   server, a rotation of its own and a rotation it follows: after every committed step the
//!   cache loads to the state the live driver has;
//! - crash injection: the file after each step of §4 (1–3 and 6) and of signup loads; no
//!   `device_seq` is reused or skipped, a sent own row keeps its first `sent_generation`, no
//!   floor moves down, and the stored commit is resent byte for byte;
//! - the floors refuse what must never be written, and the load refuses tampered rows.
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use rizzy_core::item::LIFECYCLE_KEY;
use rizzy_proto::change::CommitChangeRequest;
use rizzy_proto::error::ErrorCode;

use super::*;
use crate::rotation::{RotationLevel, RotationOptions, start_rotation};
use crate::store::floors::Floors;
use crate::store::load::{self, Loaded};
use crate::store::record::{
    DeviceRecord, MAX_DEVICE_STATE_LEN, PendingRecord, RECORD_VERSION, Stage,
};
use crate::store::rows::{Alarm, CacheRows, Changeset, ObjectRow, OpRow, Write, kind, meta, own};
use crate::store::{self};
use crate::unlock::apply_device_grants;

/// The JSON body the tests store as `pending_commit`: opaque bytes to the store.
const COMMIT_JSON: &[u8] = br#"{"commit":"as sent"}"#;

/// A copy of the rows (the type is not `Clone`: it holds the device-state record).
fn copy_rows(rows: &CacheRows) -> CacheRows {
    CacheRows {
        meta: rows.meta.clone(),
        device_state: rows.device_state.clone(),
        pending_commit: rows.pending_commit.clone(),
        objects: rows.objects.clone(),
        vaults: rows.vaults.clone(),
        wraps: rows.wraps.clone(),
        ops: rows.ops.clone(),
        snapshots: rows.snapshots.clone(),
    }
}

/// A cache in memory: the reference executor behind the floors, as a host runs them, with the
/// file after every committed step kept for the crash tests.
struct Cache {
    /// The rows.
    rows: CacheRows,
    /// The floors.
    floors: Floors,
    /// The rows after each commit.
    history: Vec<CacheRows>,
}

impl Cache {
    fn new() -> Self {
        Self {
            rows: CacheRows::default(),
            floors: Floors::empty(),
            history: Vec::new(),
        }
    }

    /// One transaction: the floors first, then the write.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "a changeset is consumed by the step that commits it"
    )]
    fn commit(&mut self, changeset: Changeset) {
        if changeset.is_empty() {
            return;
        }
        self.floors.admit(&changeset).unwrap();
        self.rows.apply(&changeset);
        self.history.push(copy_rows(&self.rows));
    }
}

/// A device that persists: every step's writes are committed before the next request.
struct Dev {
    state: DeviceState,
    unlocked: UnlockedDevice,
    vault: VaultSync,
    authors: Authors,
    cache: Cache,
}

impl Dev {
    /// Signs up, writing the pending cache before the commit and finalising it after.
    fn signed_up(server: &mut Server, rng: &mut ChaCha20Rng) -> (Self, String, String) {
        let input = SignupInput {
            server_origin: ORIGIN,
            login_name: "Alice",
            password: PASSWORD,
            invite: None,
            issue_recovery_code: true,
            device_kind: DeviceKind::DesktopCli,
            now_ms: T0,
        };
        let (started, request) = start_signup(rng, &input).unwrap();
        let account_id = AccountId::from_bytes(request.account_id.to_bytes());
        let mut pending = started
            .finish(rng, &server.register_start(&request))
            .unwrap();
        // Step 2 before step 3: no cache before the kit is confirmed.
        assert_eq!(
            pending.store_writes(COMMIT_JSON).unwrap_err(),
            ClientError::EmergencyKitNotConfirmed
        );
        let kit = pending.emergency_kit();
        let code = kit.recovery_code().unwrap().to_owned();
        let last = kit.secret_key().rsplit('-').next().unwrap().to_owned();
        pending.confirm_kit(&last).unwrap();
        let mut cache = Cache::new();
        cache.commit(pending.store_writes(COMMIT_JSON).unwrap());
        // The file of a crash here: stage 2, with the commit to resend.
        let record = load::open(&cache.rows).unwrap();
        assert_eq!(record.stage(), Stage::SignupPending);
        assert_eq!(
            record.unlock(PASSWORD).unwrap_err(),
            ClientError::SignupPending
        );
        assert_eq!(cache.rows.pending_commit.as_deref(), Some(COMMIT_JSON));
        server.register_finish(account_id, pending.commit_request().unwrap());
        let up = pending.finalize().unwrap();
        let state = up.device.unwrap();
        cache.commit(store::finalize_writes(&state.record(Stage::Committed).unwrap()).unwrap());
        assert!(cache.rows.pending_commit.is_none());
        let sk = secret_key_text(&state);
        let mut vault = VaultSync::new(up.vault_key, &up.unlocked, 1).unwrap();
        vault.persist();
        let authors = Authors::from_statements(&[up.own_certificate], &[]).unwrap();
        let mut dev = Self {
            state,
            unlocked: up.unlocked,
            vault,
            authors,
            cache,
        };
        dev.flush();
        (dev, sk, code)
    }

    /// Enrols a second device by login and creates its cache.
    fn enrolled(server: &mut Server, rng: &mut ChaCha20Rng, sk: &str) -> Self {
        let enrolled = login_and_enrol_any(server, rng, sk);
        let mut cache = Cache::new();
        let record = enrolled.device.record(Stage::Committed).unwrap();
        let mut changeset = store::create_writes(&record).unwrap();
        changeset.append(store::account_writes(&enrolled.account));
        cache.commit(changeset);
        let mut account = enrolled.account;
        let vault_id = account.vault_ids().next().unwrap();
        let mut vault = VaultSync::new(
            account.take_vault_key(vault_id).unwrap(),
            &enrolled.unlocked,
            1,
        )
        .unwrap();
        vault.persist();
        let authors = Authors::from_account(&account).unwrap();
        let mut dev = Self {
            state: enrolled.device,
            unlocked: enrolled.unlocked,
            vault,
            authors,
            cache,
        };
        dev.flush();
        dev
    }

    /// Commits what the driver journaled.
    fn flush(&mut self) {
        let writes = self.vault.take_writes();
        self.cache.commit(writes);
    }

    /// The account answer, verified against the pin and persisted (CRYPTO.md §11.3 step 2).
    fn refresh(&mut self, server: &Server) {
        let view = server.view_since(&account_state_query(&self.state));
        let account = verify_unlock(&mut self.state, &self.unlocked, &view, None).unwrap();
        self.authors = Authors::from_account(&account).unwrap();
        self.cache.commit(store::account_writes(&account));
    }

    /// A complete Fetch, persisted before the next request.
    fn fetch(&mut self, server: &Server) -> crate::sync::FetchOutcome {
        let response = server.fetch(&self.vault.fetch_request().unwrap());
        let outcome = self
            .vault
            .apply_fetch(&self.authors, &response, T0)
            .unwrap();
        self.flush();
        outcome
    }

    /// Uploads everything queued. Each request's rows are committed (`own = 3`) before the
    /// server sees it, and the test checks exactly that.
    fn upload(&mut self, server: &mut Server, rng: &mut ChaCha20Rng) {
        while let Some(up) = self.vault.upload_request(rng, &self.unlocked).unwrap() {
            self.flush();
            self.assert_sent_rows(&up);
            let answer = server.upload(&up);
            let outcome = self.vault.apply_upload_response(&answer).unwrap();
            self.flush();
            assert!(outcome.rejected.is_empty(), "{outcome:?}");
        }
    }

    /// ADR 0026 §4 step 1: every own record of `up` is on disk as `own = 3` with a
    /// `sent_generation`, byte for byte, before the request leaves.
    fn assert_sent_rows(&self, up: &UploadRequest) {
        for record in up.records.as_slice() {
            match record {
                Record::Op(op) => {
                    let row = self
                        .cache
                        .rows
                        .ops
                        .iter()
                        .find(|r| r.statement == op.statement.as_slice())
                        .expect("the own op is on disk before it is sent");
                    assert_eq!(row.own, own::SENT);
                    assert!(row.sent_generation.is_some());
                    assert_eq!(
                        row.body.as_deref(),
                        op.body.as_ref().map(rizzy_proto::wire::Bytes::as_slice)
                    );
                }
                Record::Snapshot(snapshot) => {
                    let row = self
                        .cache
                        .rows
                        .snapshots
                        .iter()
                        .find(|r| r.statement == snapshot.statement.as_slice())
                        .expect("the own snapshot is on disk before it is sent");
                    assert_eq!(row.own, own::SENT);
                    assert_eq!(row.envelope, snapshot.envelope.as_slice());
                }
            }
        }
    }

    fn create(&mut self, rng: &mut ChaCha20Rng, text: &str) -> ItemId {
        let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
        let value = Value::text(text).unwrap();
        let item = self
            .vault
            .create_item(
                rng,
                &self.unlocked,
                ItemType::LOGIN,
                &[FieldEdit {
                    key: &key,
                    value: &value,
                }],
                T0 + 5,
            )
            .unwrap();
        self.flush();
        item
    }

    fn edit(&mut self, rng: &mut ChaCha20Rng, item: ItemId, text: &str) {
        let key = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
        let value = Value::text(text).unwrap();
        self.vault
            .edit_item(
                rng,
                &self.unlocked,
                item,
                &[FieldEdit {
                    key: &key,
                    value: &value,
                }],
                T0 + 9,
            )
            .unwrap();
        self.flush();
    }

    /// Loads the cache as a restarted process does (the keys of the unlock are this device's,
    /// so the Argon2id run is not repeated).
    fn reload(&self) -> Loaded {
        load_rows(&self.cache.rows, &self.unlocked).unwrap()
    }

    /// The loaded cache is the live state: items, values, cursor, counter, queue.
    fn assert_loads(&self) {
        let loaded = self.reload();
        assert_same_vault(&self.vault, &loaded.vaults[0]);
        assert_eq!(loaded.device.account_id(), self.state.account_id());
        assert_eq!(
            loaded.device.pin().state().state_seq,
            self.state.pin().state().state_seq
        );
        assert!(loaded.alarms.is_empty());
    }
}

/// Opens and loads `rows` with the keys `unlocked` holds.
fn load_rows(rows: &CacheRows, unlocked: &UnlockedDevice) -> Result<Loaded, ClientError> {
    let record = load::open(rows)?;
    load::load(rows, &record, unlocked, T0 + 100)
}

/// What a vault shows and would send: the comparison of a live driver with a loaded one.
fn assert_same_vault(live: &VaultSync, loaded: &VaultSync) {
    assert_eq!(loaded.item_ids(), live.item_ids());
    for item in live.item_ids() {
        assert_eq!(loaded.item_lifecycle(item), live.item_lifecycle(item));
        assert_eq!(loaded.item_type(item), live.item_type(item));
        let keys: Vec<String> = live
            .field_keys(item)
            .iter()
            .map(|k| k.to_string())
            .collect();
        let loaded_keys: Vec<String> = loaded
            .field_keys(item)
            .iter()
            .map(|k| k.to_string())
            .collect();
        assert_eq!(loaded_keys, keys);
        for key in keys.iter().filter(|k| k.as_str() != LIFECYCLE_KEY) {
            assert_eq!(
                loaded
                    .field_value(item, key)
                    .map(|v| v.expose_secret().to_vec()),
                live.field_value(item, key)
                    .map(|v| v.expose_secret().to_vec()),
                "{key}"
            );
            assert_eq!(
                loaded.field_conflicts(item, key),
                live.field_conflicts(item, key)
            );
        }
    }
    assert_eq!(
        loaded.fetch_request().unwrap(),
        live.fetch_request().unwrap()
    );
    assert_eq!(loaded.next_device_seq(), live.next_device_seq());
    assert_eq!(loaded.unacknowledged(), live.unacknowledged());
    assert_eq!(loaded.vault_key_epoch(), live.vault_key_epoch());
}

/// Logs in and enrols one more device, whatever the device count.
fn login_and_enrol_any(
    server: &mut Server,
    rng: &mut ChaCha20Rng,
    sk: &str,
) -> crate::login::Enrolled {
    let (pending, enrol) = reauth(server, rng, sk)
        .enrol(rng, DeviceKind::DesktopCli, T0 + 1000)
        .unwrap();
    server.enrol(&enrol);
    pending.finalize()
}

/// A fresh OPAQUE login (the re-authentication of a rotation).
fn reauth(server: &mut Server, rng: &mut ChaCha20Rng, sk: &str) -> crate::login::LoggedIn {
    let input = LoginInput {
        server_origin: ORIGIN,
        login_name: "alice",
        secret_key: sk,
        password: PASSWORD,
    };
    let (started, request) = start_login(rng, &input).unwrap();
    let answer = server.login_start(&request);
    let (awaiting, finish) = started.finish(rng, &answer, None).unwrap();
    awaiting
        .complete(server.login_finish(&finish).unwrap())
        .unwrap()
}

/// A symmetric envelope's bytes, enough for the parser: the header and a minimal body.
fn envelope(fill: u8) -> Vec<u8> {
    let mut out = vec![0x01, 0x01];
    out.extend(core::iter::repeat_n(fill, 88));
    out
}

/// The record of the vectors: fixed fields, no cryptography.
fn vector_record(stage: Stage, has_local: bool, pending: bool) -> DeviceRecord {
    use crate::device::LocalWrap;
    use rizzy_core::kdf::KdfId;
    use rizzy_core::secret_key::SecretKey;
    DeviceRecord {
        stage,
        server_origin: ServerOrigin::parse("https://vault.example.com").unwrap(),
        account_id: AccountId::from_bytes([0xa1; 16]),
        device_id: DeviceId::from_bytes([0xd2; 16]),
        device_kind: DeviceKind::DesktopCli,
        secret_key: SecretKey::from_slice(&[0x11; 16]).unwrap(),
        device_salt: [0x22; 16],
        kdf_id: KdfId::DEFAULT,
        device_keys_wrap: envelope(0x33),
        local_wrap: has_local.then(|| LocalWrap {
            envelope: envelope(0x44),
            account_key_epoch: 7,
            password_epoch: 3,
        }),
        pending: pending.then(|| PendingRecord {
            secret_key: SecretKey::from_slice(&[0x55; 16]).unwrap(),
            device_salt: [0x66; 16],
            kdf_id: KdfId::DEFAULT,
            local_wrap: LocalWrap {
                envelope: envelope(0x77),
                account_key_epoch: 8,
                password_epoch: 4,
            },
            device_keys_wrap: None,
        }),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The vector bytes, written out field by field from ADR 0026 §2.
fn vector_bytes(stage: u8, has_local: bool, pending: bool) -> Vec<u8> {
    let bytes_of = |out: &mut Vec<u8>, x: &[u8]| {
        out.extend_from_slice(&u32::try_from(x.len()).unwrap().to_be_bytes());
        out.extend_from_slice(x);
    };
    let mut out = Vec::new();
    out.extend_from_slice(&[0x00, 0x01, stage]);
    bytes_of(&mut out, b"https://vault.example.com");
    out.extend_from_slice(&[0xa1; 16]);
    out.extend_from_slice(&[0xd2; 16]);
    out.push(1);
    out.extend_from_slice(&[0x11; 16]);
    out.extend_from_slice(&[0x22; 16]);
    out.extend_from_slice(&[0x00, 0x01]);
    bytes_of(&mut out, &envelope(0x33));
    if has_local {
        out.push(1);
        out.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 3]);
        bytes_of(&mut out, &envelope(0x44));
    } else {
        out.push(0);
    }
    if pending {
        out.push(1);
        out.extend_from_slice(&[0x55; 16]);
        out.extend_from_slice(&[0x66; 16]);
        out.extend_from_slice(&[0x00, 0x01]);
        out.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 4]);
        bytes_of(&mut out, &envelope(0x77));
        bytes_of(&mut out, &[]);
    } else {
        out.push(0);
    }
    out
}

/// ADR 0026 §6: known-answer vectors of a committed record with a pending record, of
/// `has_local = 0`, and of `stage = 2`; each parses back to itself (one state, one encoding).
#[test]
fn device_record_vectors() {
    let cases = [
        (Stage::Committed, 1u8, true, true),
        (Stage::Committed, 1, false, false),
        (Stage::SignupPending, 2, true, false),
    ];
    for (stage, stage_byte, has_local, pending) in cases {
        let record = vector_record(stage, has_local, pending);
        let encoded = record.encode().unwrap();
        let expected = vector_bytes(stage_byte, has_local, pending);
        assert_eq!(hex(&encoded), hex(&expected), "{stage:?}");
        let parsed = DeviceRecord::parse(&encoded).unwrap();
        assert_eq!(parsed.stage(), stage);
        assert_eq!(parsed.has_local(), has_local);
        assert_eq!(parsed.has_pending(), pending);
        assert_eq!(parsed.encode().unwrap().as_slice(), encoded.as_slice());
    }
    // The first bytes and the length of the committed vector, fixed here so that a change of
    // the layout cannot pass by changing encoder and test helper together.
    let committed = vector_record(Stage::Committed, true, false)
        .encode()
        .unwrap();
    assert_eq!(
        committed.len(),
        3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + 1 + 8 + 94 + 1
    );
    assert_eq!(
        hex(&committed[..36]),
        "000101000000196874747073 3a2f2f7661756c742e6578616d706c652e636f6da1a1a1a1"
            .replace(' ', "")
    );
    assert_eq!(hex(&committed[committed.len() - 3..]), "444400");
}

/// The parser's refusals (ADR 0026 §2 "Parsing"). None panics.
#[test]
fn device_record_refusals() {
    let good = vector_record(Stage::Committed, true, true)
        .encode()
        .unwrap()
        .to_vec();
    assert!(DeviceRecord::parse(&good).is_ok());
    // A newer record version is "update required"; version 0 and everything else is corrupt.
    let mut newer = good.clone();
    newer[1] = 2;
    assert_eq!(
        DeviceRecord::parse(&newer).unwrap_err(),
        ClientError::CacheUpdateRequired
    );
    assert_eq!(RECORD_VERSION, 1);
    let corrupt = |bytes: &[u8]| {
        assert_eq!(
            DeviceRecord::parse(bytes).unwrap_err(),
            ClientError::CacheCorrupt
        );
    };
    let mut zero = good.clone();
    zero[1] = 0;
    corrupt(&zero);
    // A trailing byte, every truncation, an oversized record.
    let mut trailing = good.clone();
    trailing.push(0);
    corrupt(&trailing);
    for cut in 0..good.len() {
        corrupt(&good[..cut]);
    }
    corrupt(&vec![0u8; MAX_DEVICE_STATE_LEN + 1]);
    // A stage, kind or flag outside its values.
    for (at, value) in [(2usize, 0u8), (2, 3), (64, 0), (64, 4)] {
        let mut bad = good.clone();
        bad[at] = value;
        corrupt(&bad);
    }
    // A `kdf_id` off the allow-list.
    let mut kdf = good.clone();
    kdf[98] = 2;
    corrupt(&kdf);
    // A non-canonical origin (an explicit default port) parses as an origin but is refused.
    let mut origin = vector_record(Stage::Committed, true, false);
    origin.server_origin = ServerOrigin::parse("https://vault.example.com").unwrap();
    let encoded = origin.encode().unwrap();
    let mut spelled = Vec::new();
    spelled.extend_from_slice(&encoded[..3]);
    let text = b"https://vault.example.com:443";
    spelled.extend_from_slice(&u32::try_from(text.len()).unwrap().to_be_bytes());
    spelled.extend_from_slice(text);
    spelled.extend_from_slice(&encoded[3 + 4 + 25..]);
    corrupt(&spelled);
    // An envelope that is not one, and one above 256 bytes.
    let mut not_envelope = good.clone();
    not_envelope[103] = 0x7f;
    corrupt(&not_envelope);
    let mut long = vector_record(Stage::Committed, true, false);
    long.device_keys_wrap = {
        let mut e = envelope(0x33);
        e.extend(core::iter::repeat_n(0u8, 200));
        e
    };
    assert_eq!(long.encode().unwrap_err(), ClientError::Internal);
    // Stage 2 needs `E_local` and no pending record: neither is written, neither is read.
    for (has_local, pending) in [(false, false), (true, true)] {
        let record = vector_record(Stage::SignupPending, has_local, pending);
        assert_eq!(record.encode().unwrap_err(), ClientError::Internal);
        corrupt(&vector_bytes(2, has_local, pending));
    }
    // A state without `E_local` does not unlock.
    let no_local = vector_record(Stage::Committed, false, false);
    assert_eq!(
        no_local.unlock(PASSWORD).unwrap_err(),
        ClientError::LocalUnlockUnavailable
    );
}

mod record_properties {
    //! Round trips and the canonical form of the device-state record (ADR 0026 §6).
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Any record the encoder accepts parses back to the same bytes.
        #[test]
        fn records_round_trip(
            account in any::<[u8; 16]>(),
            device in any::<[u8; 16]>(),
            sk in any::<[u8; 16]>(),
            salt in any::<[u8; 16]>(),
            kind in 1u8..=3,
            epochs in any::<(u32, u32, u32, u32)>(),
            fills in any::<(u8, u8, u8, u8)>(),
            has_local in any::<bool>(),
            pending in any::<bool>(),
            pending_dev in any::<bool>(),
            stage2 in any::<bool>(),
        ) {
            use crate::device::LocalWrap;
            use rizzy_core::secret_key::SecretKey;
            let mut record = vector_record(Stage::Committed, true, true);
            record.account_id = AccountId::from_bytes(account);
            record.device_id = DeviceId::from_bytes(device);
            record.secret_key = SecretKey::from_slice(&sk).unwrap();
            record.device_salt = salt;
            record.device_kind = DeviceKind::from_u8(kind).unwrap();
            record.device_keys_wrap = envelope(fills.0);
            record.local_wrap = has_local.then(|| LocalWrap {
                envelope: envelope(fills.1),
                account_key_epoch: epochs.0,
                password_epoch: epochs.1,
            });
            if let Some(p) = record.pending.as_mut() {
                p.local_wrap.account_key_epoch = epochs.2;
                p.local_wrap.password_epoch = epochs.3;
                p.local_wrap.envelope = envelope(fills.2);
                p.device_keys_wrap = pending_dev.then(|| envelope(fills.3));
            }
            if !pending {
                record.pending = None;
            }
            if stage2 && has_local && !pending {
                record.stage = Stage::SignupPending;
            }
            let encoded = record.encode().unwrap();
            let parsed = DeviceRecord::parse(&encoded).unwrap();
            prop_assert_eq!(parsed.encode().unwrap().to_vec(), encoded.to_vec());
            prop_assert_eq!(parsed.has_local(), has_local);
            prop_assert_eq!(parsed.has_pending(), pending);
        }

        /// Arbitrary bytes never panic the parser, and whatever parses is canonical.
        #[test]
        fn arbitrary_bytes_parse_canonically_or_not_at_all(
            bytes in proptest::collection::vec(any::<u8>(), 0..600),
        ) {
            if let Ok(record) = DeviceRecord::parse(&bytes) {
                prop_assert_eq!(record.encode().unwrap().to_vec(), bytes.clone());
            }
        }

        /// One flipped byte of a valid record either fails or is another canonical record.
        #[test]
        fn mutated_records_stay_canonical(at in 0usize..400, flip in 1u8..=255) {
            let mut bytes = vector_record(Stage::Committed, true, true).encode().unwrap().to_vec();
            let at = at % bytes.len();
            bytes[at] ^= flip;
            if let Ok(record) = DeviceRecord::parse(&bytes) {
                prop_assert_eq!(record.encode().unwrap().to_vec(), bytes.clone());
            }
        }
    }
}

/// The highest own `device_seq` among the rows.
fn max_own_seq(rows: &CacheRows) -> u64 {
    rows.ops
        .iter()
        .filter(|o| o.own != own::SERVED)
        .map(|o| u64::from_be_bytes(o.device_seq.as_slice().try_into().unwrap()))
        .max()
        .unwrap_or(0)
}

fn meta_u64(rows: &CacheRows, key: &str) -> u64 {
    u64::from_be_bytes(rows.meta[key].as_slice().try_into().unwrap())
}

/// The crash-injection assertions of ADR 0026 §6 over the file after each committed step:
/// every file opens; every unlockable file loads; the counter is exactly one past the own
/// dots held (none reused, none skipped); a sent own row keeps its first `sent_generation`
/// unless it was re-issued; the counter, the HLC and `state_seq` never go down; a stored
/// commit never changes while it is outstanding.
fn assert_crash_safe(history: &[CacheRows], unlocked: &[&UnlockedDevice]) {
    let mut previous: Option<&CacheRows> = None;
    let mut last_state_seq = 0;
    for rows in history {
        let record = load::open(rows).unwrap();
        assert_eq!(meta_u64(rows, meta::NEXT_DEVICE_SEQ), max_own_seq(rows) + 1);
        if record.stage() == Stage::Committed {
            // The keys of one of the unlocks open this file (an own rotation changes them).
            let loaded = unlocked
                .iter()
                .find_map(|u| load::load(rows, &record, u, T0 + 100).ok())
                .expect("the file after every step loads");
            assert_eq!(
                loaded.vaults[0].next_device_seq(),
                meta_u64(rows, meta::NEXT_DEVICE_SEQ)
            );
            let state_seq = loaded.device.pin().state().state_seq;
            assert!(state_seq >= last_state_seq);
            last_state_seq = state_seq;
        }
        if let Some(before) = previous {
            assert!(
                meta_u64(rows, meta::NEXT_DEVICE_SEQ) >= meta_u64(before, meta::NEXT_DEVICE_SEQ)
            );
            assert!(meta_u64(rows, meta::HLC) >= meta_u64(before, meta::HLC));
            for old in &before.ops {
                let now = rows
                    .ops
                    .iter()
                    .find(|o| o.device_id == old.device_id && o.device_seq == old.device_seq)
                    .expect("no op row is ever deleted");
                if now.statement == old.statement {
                    // Not re-issued: `own` only moves 1 → 3 → 2, the generation stays.
                    if old.sent_generation.is_some() {
                        assert_eq!(now.sent_generation, old.sent_generation);
                    }
                    let rank = |own: i64| match own {
                        own::UNSENT => 1,
                        own::SENT => 2,
                        own::ACKNOWLEDGED => 3,
                        _ => 0,
                    };
                    assert!(rank(now.own) >= rank(old.own));
                    assert_eq!(now.own == own::SERVED, old.own == own::SERVED);
                } else {
                    // A re-issue: an own row that was never acknowledged, back to unsent with
                    // its generation cleared; or, when the same step sends the new bytes, sent
                    // under the generation of that send.
                    assert_ne!(old.own, own::SERVED);
                    assert_ne!(old.own, own::ACKNOWLEDGED);
                    match now.own {
                        own::UNSENT => assert!(now.sent_generation.is_none()),
                        own::SENT => assert!(now.sent_generation.is_some()),
                        other => panic!("a re-issued row with own = {other}"),
                    }
                }
            }
            if let (Some(a), Some(b)) = (&before.pending_commit, &rows.pending_commit) {
                assert_eq!(a, b, "a stored commit is resent as it is");
            }
        }
        previous = Some(rows);
    }
}

/// ADR 0026 §4 and §6 end to end: a device that persists every step, a second device, a
/// concurrent edit, and a compacted server. After every step the cache loads to the live
/// state, and the file after each step passes the crash assertions.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story of a persisted device, step by step, with a load after each"
)]
fn a_persisted_device_reloads_after_every_step() {
    let mut rng = ChaCha20Rng::seed_from_u64(70);
    let mut server = Server::new(71);
    let (mut a, sk, _code) = Dev::signed_up(&mut server, &mut rng);
    a.assert_loads();
    // The first Fetch (an empty vault), then three items, uploaded.
    a.fetch(&server);
    a.assert_loads();
    let first = a.create(&mut rng, "one");
    let second = a.create(&mut rng, "two");
    a.create(&mut rng, "three");
    // Unsent own rows: `own = 1`, reloaded into the upload queue.
    assert!(a.cache.rows.ops.iter().all(|o| o.own == own::UNSENT));
    a.assert_loads();
    a.upload(&mut server, &mut rng);
    assert!(a.cache.rows.ops.iter().all(|o| o.own == own::ACKNOWLEDGED));
    // The fresh item keys' snapshots went up too and are acknowledged.
    assert!(!a.cache.rows.snapshots.is_empty());
    assert!(
        a.cache
            .rows
            .snapshots
            .iter()
            .all(|s| s.own == own::ACKNOWLEDGED)
    );
    a.fetch(&server);
    a.assert_loads();

    // A second device enrols, persists, reads, and edits an item.
    let mut b = Dev::enrolled(&mut server, &mut rng, &sk);
    b.assert_loads();
    b.fetch(&server);
    b.assert_loads();
    assert_eq!(b.vault.item_ids().len(), 3);
    b.edit(&mut rng, first, "one from b");
    b.assert_loads();

    // A learns of the new device, then both edit the same field before either syncs.
    a.refresh(&server);
    a.assert_loads();
    a.edit(&mut rng, first, "one from a");
    b.upload(&mut server, &mut rng);
    a.upload(&mut server, &mut rng);
    a.fetch(&server);
    b.fetch(&server);
    a.assert_loads();
    b.assert_loads();
    assert!(a.vault.field_conflicts(first, LOGIN_PASSWORD));
    assert!(b.vault.field_conflicts(first, LOGIN_PASSWORD));
    assert_eq!(
        a.vault
            .field_value(first, LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        b.vault
            .field_value(first, LOGIN_PASSWORD)
            .unwrap()
            .expose_secret()
    );
    // The loaded state shows the conflict too.
    assert!(a.reload().vaults[0].field_conflicts(first, LOGIN_PASSWORD));

    // B trashes an item offline; a crash before the upload keeps the unsent op.
    b.vault
        .trash_item(&mut rng, &b.unlocked, second, T0 + 20)
        .unwrap();
    b.flush();
    let restarted = b.reload();
    assert_eq!(restarted.vaults[0].unacknowledged().0, 1);
    assert_eq!(
        restarted.vaults[0].item_lifecycle(second),
        ItemLifecycle::Trashed
    );
    b.upload(&mut server, &mut rng);
    b.fetch(&server);
    b.assert_loads();

    // A third device reads a compacted server: bodiless ops with their covers, kept as rows
    // and replayed at load.
    server.compact = true;
    let mut c = Dev::enrolled(&mut server, &mut rng, &sk);
    let outcome = c.fetch(&server);
    assert!(outcome.absorbed > 0, "{outcome:?}");
    assert!(c.cache.rows.ops.iter().any(|o| o.body.is_none()));
    assert!(c.cache.rows.snapshots.iter().any(|s| s.own == own::SERVED));
    assert_eq!(c.vault.item_ids().len(), 3);
    c.assert_loads();
    c.edit(&mut rng, first, "one from c");
    c.assert_loads();
    a.refresh(&server);
    b.refresh(&server);
    c.upload(&mut server, &mut rng);
    a.fetch(&server);
    a.assert_loads();
    assert_eq!(
        a.vault
            .field_value(first, LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        Value::text("one from c").unwrap().expose_secret()
    );

    for dev in [&a, &b, &c] {
        assert_crash_safe(&dev.cache.history, &[&dev.unlocked]);
    }
    // Every own op the server stored is on disk with the bytes the server holds: no dot was
    // signed twice.
    for dev in [&a, &b, &c] {
        let chain = &server.ops[&dev.state.device_id().to_bytes()];
        for (seq, record) in chain {
            let row = dev
                .cache
                .rows
                .ops
                .iter()
                .find(|o| o.own != own::SERVED && o.device_seq == seq.to_be_bytes())
                .unwrap();
            assert_eq!(row.statement, record.statement.as_slice());
            assert_eq!(row.own, own::ACKNOWLEDGED);
        }
    }
}

/// A signup interrupted between the pending write and the acknowledgement: the file holds
/// stage 2 and the commit; the restart resends the same bytes and finalises (ADR 0026 §2).
#[test]
fn an_interrupted_signup_resends_the_stored_commit() {
    let mut rng = ChaCha20Rng::seed_from_u64(72);
    let mut server = Server::new(73);
    let input = SignupInput {
        server_origin: ORIGIN,
        login_name: "Alice",
        password: PASSWORD,
        invite: None,
        issue_recovery_code: false,
        device_kind: DeviceKind::DesktopCli,
        now_ms: T0,
    };
    let (started, request) = start_signup(&mut rng, &input).unwrap();
    let account_id = AccountId::from_bytes(request.account_id.to_bytes());
    let mut pending = started
        .finish(&mut rng, &server.register_start(&request))
        .unwrap();
    let last = pending
        .emergency_kit()
        .secret_key()
        .rsplit('-')
        .next()
        .unwrap()
        .to_owned();
    pending.confirm_kit(&last).unwrap();
    let mut cache = Cache::new();
    cache.commit(pending.store_writes(COMMIT_JSON).unwrap());
    let commit = pending.commit_request().unwrap();
    // The request reaches the server; the process dies before the answer.
    server.register_finish(account_id, commit);
    drop(pending);

    // Restart: only the file. Stage 2, nothing unlocks, the commit is there to resend.
    let record = load::open(&cache.rows).unwrap();
    assert_eq!(record.stage(), Stage::SignupPending);
    assert_eq!(
        record.unlock(PASSWORD).unwrap_err(),
        ClientError::SignupPending
    );
    assert_eq!(cache.rows.pending_commit.as_deref(), Some(COMMIT_JSON));
    // (The host sends `pending_commit` again; the server answers success for the same bytes.)
    cache.commit(store::finalize_writes(&record.committed()).unwrap());
    let record = load::open(&cache.rows).unwrap();
    assert_eq!(record.stage(), Stage::Committed);
    assert!(cache.rows.pending_commit.is_none());
    let unlocked = record.unlock(PASSWORD).unwrap();
    let loaded = load::load(&cache.rows, &record, &unlocked, T0).unwrap();
    assert_eq!(loaded.vaults.len(), 1);
    assert_eq!(loaded.vaults[0].next_device_seq(), 1);
    // A wrong password is "wrong password", whatever else is in the file.
    assert_eq!(
        record.unlock("not the password").unwrap_err(),
        ClientError::WrongPasswordOrSecretKey
    );
    // The file with the stage-2 record and no stored commit is no state this client writes.
    let mut broken = copy_rows(&cache.history[0]);
    broken.pending_commit = None;
    assert_eq!(load::open(&broken).unwrap_err(), ClientError::CacheCorrupt);
}

impl Server {
    /// The account commit of a rotation, as `tests::rotation` plays it, reduced to what these
    /// tests need: the compare-and-swap, then the new state, wraps and grants.
    fn commit_for_store(&mut self, req: &CommitChangeRequest) -> Result<(), ErrorCode> {
        let s = self.stored();
        if req.account_state.as_slice() == s.state.as_slice() {
            return Ok(());
        }
        let vault = &req.vault_rotation.as_ref().unwrap().vaults()[0];
        if vault.cursor != self.heads() {
            return Err(ErrorCode::StateConflict);
        }
        let s = self.account.as_mut().unwrap();
        s.state = req.account_state.as_slice().to_vec();
        s.e_srv = req.account_key_server_wrap.clone().unwrap();
        s.e_id = req.identity_secret_keys.clone().unwrap();
        s.grants = vec![vault.self_grant.clone()];
        self.wraps = vault.item_key_wraps.as_slice().to_vec();
        for chain in self.ops.values_mut() {
            for record in chain.values_mut() {
                record.key_wrap = None;
            }
        }
        self.device_grants
            .extend(req.device_grants.as_slice().iter().cloned());
        Ok(())
    }
}

/// ADR 0026 §4 step 3 for a rotation, and §4 step 2 for the device that follows it: the
/// pending record and the commit are on disk before the commit is sent; the finalising
/// transaction holds the new record, state, self-grant and wrap set; the follower persists
/// its re-wrapped record, the new state and the Fetch at the new epoch in one transaction. At
/// every step the file loads.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story: a persisted rotation, a crash before its commit, and the follower"
)]
fn a_rotation_is_persisted_and_followed() {
    let mut rng = ChaCha20Rng::seed_from_u64(74);
    let mut server = Server::new(75);
    let (mut a, sk, code) = Dev::signed_up(&mut server, &mut rng);
    a.fetch(&server);
    let item = a.create(&mut rng, "before");
    a.upload(&mut server, &mut rng);
    let mut b = Dev::enrolled(&mut server, &mut rng, &sk);
    b.fetch(&server);
    a.refresh(&server);
    a.fetch(&server);

    let options = RotationOptions {
        level: RotationLevel::Standard,
        revoke: None,
        recovery_code: Some(&code),
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    let mut pending = start_rotation(
        &mut rng,
        login,
        &a.state,
        &a.unlocked,
        &[&a.vault],
        &options,
    )
    .unwrap();
    // Step 3: the pending record and the commit, before the commit is sent.
    let pending_record = pending
        .pending_record(&mut rng, &a.state, &a.unlocked)
        .unwrap();
    let record = a
        .state
        .record(Stage::Committed)
        .unwrap()
        .with_pending(pending_record);
    a.cache
        .commit(store::pending_writes(&record, COMMIT_JSON).unwrap());

    // A crash here: the file still unlocks to the old keys and loads the old state, and it
    // holds the pending record whose keys open once the commit is applied.
    let crashed = load::open(&a.cache.rows).unwrap();
    assert!(crashed.has_pending());
    let old = crashed.unlock(PASSWORD).unwrap();
    assert_eq!(old.account_key.epoch(), 0);
    let loaded = load::load(&a.cache.rows, &crashed, &old, T0).unwrap();
    assert_eq!(loaded.device.pin().state().account_key_epoch, 0);
    let new = crashed.unlock_pending(PASSWORD).unwrap();
    assert_eq!(new.account_key.epoch(), 1);
    // The pending keys do not open the old state: the host knows which side it is on.
    assert_eq!(
        load::load(&a.cache.rows, &crashed, &new, T0).unwrap_err(),
        ClientError::CacheCorrupt
    );
    // A pending record without its commit, or a commit without a pending record, is corrupt.
    let mut broken = copy_rows(&a.cache.rows);
    broken.pending_commit = None;
    assert_eq!(load::open(&broken).unwrap_err(), ClientError::CacheCorrupt);

    // The commit lands; the finalising transaction.
    server.commit_for_store(pending.commit_request()).unwrap();
    let store_writes = pending.store_writes().unwrap();
    let done = {
        let Dev {
            state,
            unlocked,
            vault,
            ..
        } = &mut a;
        pending
            .finalize(&mut rng, state, unlocked, &mut [vault])
            .unwrap()
    };
    a.authors = done.authors;
    let mut changeset = store::finalize_writes(&a.state.record(Stage::Committed).unwrap()).unwrap();
    changeset.append(store_writes);
    changeset.append(a.vault.take_writes());
    a.cache.commit(changeset);
    // The finalised record is the pending one, byte for byte.
    let finalised = load::open(&a.cache.rows).unwrap();
    assert!(!finalised.has_pending());
    assert_eq!(
        finalised.encode().unwrap().as_slice(),
        crashed.promote_pending().encode().unwrap().as_slice()
    );
    assert!(a.cache.rows.pending_commit.is_none());
    // The wraps on disk are at the epoch of the vault key on disk: the file loads, and the
    // item reads, before any Fetch at the new epoch.
    assert!(a.cache.rows.wraps.iter().all(|w| w.vault_key_epoch == 1));
    let unlocked = finalised.unlock(PASSWORD).unwrap();
    assert_eq!(unlocked.account_key.epoch(), 1);
    let loaded = load::load(&a.cache.rows, &finalised, &unlocked, T0).unwrap();
    assert_eq!(loaded.vaults[0].vault_key_epoch(), 1);
    assert_eq!(
        loaded.vaults[0]
            .field_value(item, LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        Value::text("before").unwrap().expose_secret()
    );
    a.fetch(&server);
    a.assert_loads();
    a.edit(&mut rng, item, "after");
    a.upload(&mut server, &mut rng);
    a.assert_loads();

    // B follows: grants, the re-wrapped record, the new state and vault key, and the Fetch at
    // the new epoch, persisted in one transaction; only then the acknowledgement.
    let view = server.view();
    assert_eq!(
        verify_unlock(&mut b.state, &b.unlocked, &view, None).unwrap_err(),
        ClientError::AccountKeyRotated
    );
    let before_follow = copy_rows(&b.cache.rows);
    let grants = rizzy_proto::account::DeviceGrantsResponse {
        grants: List::new(
            server
                .device_grants
                .iter()
                .filter(|g| g.recipient_device_id.to_bytes() == b.state.device_id().to_bytes())
                .cloned()
                .collect(),
        )
        .unwrap(),
    };
    let mut b_unlocked = b.state.unlock(PASSWORD).unwrap();
    apply_device_grants(
        &mut rng,
        &mut b.state,
        &mut b_unlocked,
        &view,
        &grants,
        None,
    )
    .unwrap();
    let mut account = verify_unlock(&mut b.state, &b_unlocked, &view, None).unwrap();
    b.unlocked = b_unlocked;
    b.authors = Authors::from_account(&account).unwrap();
    let mut changeset: Changeset =
        [store::record_write(&b.state.record(Stage::Committed).unwrap()).unwrap()]
            .into_iter()
            .collect();
    changeset.append(store::account_writes(&account));
    let vault_id = account.vault_ids().next().unwrap();
    b.vault
        .adopt_vault_key(account.take_vault_key(vault_id).unwrap())
        .unwrap();
    let response = server.fetch(&b.vault.fetch_request().unwrap());
    b.vault.apply_fetch(&b.authors, &response, T0).unwrap();
    changeset.append(b.vault.take_writes());
    b.cache.commit(changeset);
    b.assert_loads();
    assert_eq!(b.vault.vault_key_epoch(), 1);
    assert_eq!(
        b.reload().vaults[0]
            .field_value(item, LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        Value::text("after").unwrap().expose_secret()
    );
    // A crash before that transaction left the old file, which still loads with the old keys.
    let old_record = load::open(&before_follow).unwrap();
    let old_unlocked = old_record.unlock(PASSWORD).unwrap();
    assert!(load::load(&before_follow, &old_record, &old_unlocked, T0).is_ok());

    assert_crash_safe(&a.cache.history, &[&old, &a.unlocked]);
    assert_crash_safe(&b.cache.history, &[&old_unlocked, &b.unlocked]);
}

/// ADR 0026 §4 step 6: a stale answer changes no row; the re-issue replaces the row under the
/// same `device_seq` in a transaction committed before the new bytes are sent; a crash before
/// it resends the old bytes. And §4 step 7 with the owner's decision on open question 5: a
/// file older than this device's own history raises the alarm and never moves the counter.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story: a stale answer, the re-issue, and an older copy of the file"
)]
fn a_stale_answer_reissues_and_an_older_file_raises_the_alarm() {
    let mut rng = ChaCha20Rng::seed_from_u64(76);
    let mut server = Server::new(77);
    let (mut a, sk, code) = Dev::signed_up(&mut server, &mut rng);
    a.fetch(&server);
    let item = a.create(&mut rng, "v0");
    a.upload(&mut server, &mut rng);
    let mut b = Dev::enrolled(&mut server, &mut rng, &sk);
    b.fetch(&server);
    a.refresh(&server);
    a.fetch(&server);

    // B writes at the old epoch while A rotates.
    b.edit(&mut rng, item, "from b, old epoch");
    let options = RotationOptions {
        level: RotationLevel::Standard,
        revoke: None,
        recovery_code: Some(&code),
        now_ms: T0 + 10_000,
    };
    let login = reauth(&mut server, &mut rng, &sk);
    let pending = start_rotation(
        &mut rng,
        login,
        &a.state,
        &a.unlocked,
        &[&a.vault],
        &options,
    )
    .unwrap();
    server.commit_for_store(pending.commit_request()).unwrap();
    let store_writes = pending.store_writes().unwrap();
    {
        let Dev {
            state,
            unlocked,
            vault,
            ..
        } = &mut a;
        pending
            .finalize(&mut rng, state, unlocked, &mut [vault])
            .unwrap();
    }
    let mut changeset = store::finalize_writes(&a.state.record(Stage::Committed).unwrap()).unwrap();
    changeset.append(store_writes);
    changeset.append(a.vault.take_writes());
    a.cache.commit(changeset);

    // B's upload is answered `stale_epoch`: the row was sent (`own = 3`) and stays as it is.
    let up = b
        .vault
        .upload_request(&mut rng, &b.unlocked)
        .unwrap()
        .unwrap();
    b.flush();
    let sent_row = b
        .cache
        .rows
        .ops
        .iter()
        .find(|o| o.own == own::SENT)
        .unwrap()
        .clone();
    let stale = UploadResponse {
        restore_generation: Fixed::from_bytes(server.generation),
        results: List::new(
            up.records
                .as_slice()
                .iter()
                .map(|_| UploadResult::Rejected {
                    error: ErrorCode::StaleEpoch,
                })
                .collect(),
        )
        .unwrap(),
    };
    b.vault.apply_upload_response(&stale).unwrap();
    b.flush();
    let after_stale = b
        .cache
        .rows
        .ops
        .iter()
        .find(|o| o.own == own::SENT)
        .unwrap();
    assert_eq!(*after_stale, sent_row, "a stale answer changes no row");
    // A crash here: the same bytes are in the queue again.
    let crashed = b.reload();
    assert_eq!(crashed.vaults[0].unacknowledged().0, 1);
    let mut crashed_vault = crashed.vaults.into_iter().next().unwrap();
    let again = crashed_vault.unsent_upload_request().unwrap().unwrap();
    assert_eq!(again.records.as_slice()[0], up.records.as_slice()[0]);

    // B follows the rotation, then re-issues under the new epoch with the same `device_seq`.
    let view = server.view();
    let grants = rizzy_proto::account::DeviceGrantsResponse {
        grants: List::new(server.device_grants.clone()).unwrap(),
    };
    let mut b_unlocked = b.state.unlock(PASSWORD).unwrap();
    apply_device_grants(
        &mut rng,
        &mut b.state,
        &mut b_unlocked,
        &view,
        &grants,
        None,
    )
    .unwrap();
    let mut account = verify_unlock(&mut b.state, &b_unlocked, &view, None).unwrap();
    b.unlocked = b_unlocked;
    b.authors = Authors::from_account(&account).unwrap();
    let mut changeset: Changeset =
        [store::record_write(&b.state.record(Stage::Committed).unwrap()).unwrap()]
            .into_iter()
            .collect();
    changeset.append(store::account_writes(&account));
    let vault_id = account.vault_ids().next().unwrap();
    b.vault
        .adopt_vault_key(account.take_vault_key(vault_id).unwrap())
        .unwrap();
    let response = server.fetch(&b.vault.fetch_request().unwrap());
    b.vault.apply_fetch(&b.authors, &response, T0).unwrap();
    changeset.append(b.vault.take_writes());
    b.cache.commit(changeset);
    b.assert_loads();

    let reissue = b
        .vault
        .upload_request(&mut rng, &b.unlocked)
        .unwrap()
        .unwrap();
    b.flush();
    let Record::Op(reissued) = &reissue.records.as_slice()[0] else {
        panic!("the re-issued op first");
    };
    let row = b
        .cache
        .rows
        .ops
        .iter()
        .find(|o| o.device_seq == sent_row.device_seq && o.own != own::SERVED)
        .unwrap();
    assert_eq!(row.statement, reissued.statement.as_slice());
    assert_ne!(row.statement, sent_row.statement);
    // Re-issued and sent in the same step: the row is `own = 3` again, under the generation
    // of this send.
    assert_eq!(row.own, own::SENT);
    let answer = server.upload(&reissue);
    b.vault.apply_upload_response(&answer).unwrap();
    b.flush();
    b.upload(&mut server, &mut rng);
    b.fetch(&server);
    b.assert_loads();
    assert_crash_safe(
        &b.cache.history[..],
        &[&b.unlocked, &crashed.device.unlock(PASSWORD).unwrap()],
    );

    // An older copy of B's file: the server holds an own dot the file lacks. The Fetch says
    // so; the counter does not move to the server's unsigned head.
    let old_rows = b
        .cache
        .history
        .iter()
        .rev()
        .find(|rows| max_own_seq(rows) == 0 && load::open(rows).is_ok_and(|r| !r.has_pending()))
        .expect("a file from before B's first op");
    let old_record = load::open(old_rows).unwrap();
    let Ok(old_unlocked) = old_record.unlock(PASSWORD) else {
        panic!("the old file unlocks");
    };
    let mut old = load::load(old_rows, &old_record, &old_unlocked, T0).unwrap();
    let vault = &mut old.vaults[0];
    assert_eq!(vault.next_device_seq(), 1);
    let response = server.fetch(&vault.fetch_request().unwrap());
    let outcome = vault.apply_fetch(&old.authors, &response, T0).unwrap();
    assert!(outcome.own_history_ahead, "{outcome:?}");
    assert_eq!(
        vault.next_device_seq(),
        1,
        "the unsigned head moves nothing"
    );
    // The host writes the alarm in the transaction that detects it and goes read-only; a
    // restart finds it.
    let mut rows = copy_rows(old_rows);
    let mut floors = old.floors.clone();
    let mut changeset = vault.take_writes();
    changeset.push(store::alarm_write(Alarm::DeviceStateOutdated, &[]).unwrap());
    floors.admit(&changeset).unwrap();
    rows.apply(&changeset);
    let alarmed = load::load(&rows, &old_record, &old_unlocked, T0).unwrap();
    assert!(alarmed.alarms.contains(&Alarm::DeviceStateOutdated));
    assert!(alarmed.vaults[0].is_read_only());
}

/// The floors (ADR 0026 §4 "What never goes backwards"): each refused changeset leaves the
/// index unchanged, so the host writes nothing.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one refusal per rule of the floors, on one cache"
)]
fn the_floors_refuse_what_must_never_be_written() {
    let mut rng = ChaCha20Rng::seed_from_u64(78);
    let mut server = Server::new(79);
    let (mut a, _sk, _code) = Dev::signed_up(&mut server, &mut rng);
    a.fetch(&server);
    a.create(&mut rng, "x");
    a.create(&mut rng, "y");
    a.upload(&mut server, &mut rng);
    a.create(&mut rng, "z");

    let refused = |floors: &Floors, write: Write| {
        let mut probe = floors.clone();
        let changeset: Changeset = [write].into_iter().collect();
        assert_eq!(probe.admit(&changeset).unwrap_err(), ClientError::Internal);
    };
    let floors = &a.cache.floors;
    let vault_id = a.vault.vault_id().to_bytes();
    let device_id = a.state.device_id().to_bytes();
    let state_row = a
        .cache
        .rows
        .objects
        .iter()
        .find(|o| o.kind == kind::ACCOUNT_STATE)
        .unwrap();
    // The counters never go down; the set-once rows never change.
    refused(
        floors,
        Write::Meta {
            key: meta::NEXT_DEVICE_SEQ,
            value: 1u64.to_be_bytes().to_vec(),
        },
    );
    let hlc = meta_u64(&a.cache.rows, meta::HLC);
    assert!(hlc > 0);
    refused(
        floors,
        Write::Meta {
            key: meta::HLC,
            value: (hlc - 1).to_be_bytes().to_vec(),
        },
    );
    for key in [meta::ACCOUNT_ID, meta::DEVICE_ID] {
        refused(
            floors,
            Write::Meta {
                key,
                value: vec![0xee; 16],
            },
        );
    }
    refused(
        floors,
        Write::Meta {
            key: meta::FORMAT,
            value: 2u16.to_be_bytes().to_vec(),
        },
    );
    // Another body at the pinned `state_seq` (a fork), and a lower `state_seq` (a rollback).
    let mut other = state_row.bytes.clone();
    other[10] ^= 1;
    refused(
        floors,
        Write::AccountState {
            wire: other,
            state_seq: 0,
            settings_seq: 0,
        },
    );
    a.refresh(&server);
    let floors = &a.cache.floors;
    // Other bytes at a held bundle, `E_id` or alarm-free object kind; an unknown kind.
    let bundle = a
        .cache
        .rows
        .objects
        .iter()
        .find(|o| o.kind == kind::BUNDLE)
        .unwrap();
    refused(
        floors,
        Write::PutObject(ObjectRow {
            bytes: vec![1, 2, 3],
            ..bundle.clone()
        }),
    );
    for kind in [kind::ACCOUNT_STATE, kind::CERTIFICATE, 9] {
        refused(
            floors,
            Write::PutObject(ObjectRow {
                kind,
                key: vec![0; 16],
                bytes: vec![1],
            }),
        );
    }
    // An op row never changes its statement, and `own` never goes back.
    let acked = a
        .cache
        .rows
        .ops
        .iter()
        .find(|o| o.own == own::ACKNOWLEDGED)
        .unwrap();
    let unsent = a
        .cache
        .rows
        .ops
        .iter()
        .find(|o| o.own == own::UNSENT)
        .unwrap();
    refused(
        floors,
        Write::PutOp(OpRow {
            statement: vec![9; 40],
            ..acked.clone()
        }),
    );
    let acked_seq = u64::from_be_bytes(acked.device_seq.as_slice().try_into().unwrap());
    for own in [own::UNSENT, own::SENT, own::SERVED] {
        refused(
            floors,
            Write::OpOwn {
                vault_id,
                device_id,
                device_seq: acked_seq,
                own,
                sent_generation: Some([1; 16]),
            },
        );
    }
    // Only a served row's body is pruned: never an own row's, never a row the file lacks.
    for (seq, device) in [
        (acked_seq, device_id),
        (
            u64::from_be_bytes(unsent.device_seq.as_slice().try_into().unwrap()),
            device_id,
        ),
        (1, [0x42; 16]),
    ] {
        refused(
            floors,
            Write::PruneOpBody {
                vault_id,
                device_id: device,
                device_seq: seq,
            },
        );
    }
    // An acknowledged row is never re-issued; a sent one only under its own generation.
    refused(
        floors,
        Write::ReissueOp {
            row: OpRow {
                own: own::UNSENT,
                ..acked.clone()
            },
            stale_generation: Some([0; 16]),
        },
    );
    // A new own op below the stored counter is a reused dot; one that leaves the counter at
    // or below it is a counter that did not advance.
    refused(
        floors,
        Write::PutOp(OpRow {
            device_seq: 9u64.to_be_bytes().to_vec(),
            ..unsent.clone()
        }),
    );
    // A served row under this device's id, and an own row under another's.
    refused(
        floors,
        Write::PutOp(OpRow {
            device_seq: 50u64.to_be_bytes().to_vec(),
            own: own::SERVED,
            ..unsent.clone()
        }),
    );
    refused(
        floors,
        Write::PutOp(OpRow {
            device_id: vec![0x77; 16],
            device_seq: 50u64.to_be_bytes().to_vec(),
            ..unsent.clone()
        }),
    );
    // A self-grant of another key at the held epoch (the fork alarm of ADR 0025 §4).
    let grant = a.cache.rows.vaults[0].self_grant.clone();
    refused(
        floors,
        Write::VaultGrant {
            grant,
            vault_key_id: [0xab; 16],
        },
    );
    // An acknowledged or served snapshot is never deleted; an unknown vault takes no rows.
    let snapshot = a
        .cache
        .rows
        .snapshots
        .iter()
        .find(|s| s.own == own::ACKNOWLEDGED)
        .unwrap();
    refused(
        floors,
        Write::DeleteSnapshot {
            vault_id,
            snapshot_id: snapshot.snapshot_id.as_slice().try_into().unwrap(),
        },
    );
    refused(
        floors,
        Write::VaultGeneration {
            vault_id: [0x99; 16],
            generation: [0; 16],
        },
    );
    // A device-state record that does not parse, or of another device.
    refused(
        floors,
        Write::DeviceState(zeroize::Zeroizing::new(vec![1, 2, 3])),
    );
    refused(
        floors,
        Write::DeviceState(
            vector_record(Stage::Committed, true, false)
                .encode()
                .unwrap(),
        ),
    );
    refused(floors, Write::PendingCommit(Some(Vec::new())));
    // The cache itself was never touched by the probes, and still loads.
    a.assert_loads();
}

/// The load refuses what a tampered file holds (ADR 0026 §3 "Columns are indexes, never
/// facts", §5): (d) fails the load as a whole; (e) a damaged body or wrap under a verified
/// statement is missing data, and the load stands.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one tampering per rule of the load, on one cache"
)]
fn the_load_refuses_tampered_rows() {
    let mut rng = ChaCha20Rng::seed_from_u64(80);
    let mut server = Server::new(81);
    let (mut a, sk, _code) = Dev::signed_up(&mut server, &mut rng);
    a.fetch(&server);
    let item = a.create(&mut rng, "mine");
    a.upload(&mut server, &mut rng);
    let mut b = Dev::enrolled(&mut server, &mut rng, &sk);
    b.fetch(&server);
    b.edit(&mut rng, item, "theirs");
    b.upload(&mut server, &mut rng);
    a.refresh(&server);
    a.fetch(&server);
    a.create(&mut rng, "unsent");
    a.assert_loads();

    let corrupt = |rows: &CacheRows| {
        assert_eq!(
            load_rows(rows, &a.unlocked).unwrap_err(),
            ClientError::CacheCorrupt
        );
    };
    let rows = || copy_rows(&a.cache.rows);
    let own_device = a.state.device_id().to_bytes();
    let served_at = a
        .cache
        .rows
        .ops
        .iter()
        .position(|o| o.own == own::SERVED)
        .unwrap();
    let own_at = a
        .cache
        .rows
        .ops
        .iter()
        .position(|o| o.own == own::ACKNOWLEDGED)
        .unwrap();
    let unsent_at = a
        .cache
        .rows
        .ops
        .iter()
        .position(|o| o.own == own::UNSENT)
        .unwrap();

    // (a) The format and the meta rows.
    let mut t = rows();
    t.meta
        .insert(meta::FORMAT.to_owned(), 2u16.to_be_bytes().to_vec());
    assert_eq!(
        load::open(&t).unwrap_err(),
        ClientError::CacheUpdateRequired
    );
    for key in meta::ALL {
        let mut t = rows();
        t.meta.remove(key);
        assert_eq!(load::open(&t).unwrap_err(), ClientError::CacheCorrupt);
    }
    let mut t = rows();
    t.meta.insert("extra".to_owned(), vec![1]);
    corrupt(&t);
    let mut t = rows();
    t.meta.insert(meta::DEVICE_ID.to_owned(), vec![7; 16]);
    corrupt(&t);
    // (b) The record.
    let mut t = rows();
    t.device_state = None;
    corrupt(&t);
    // (d) An account object: a flipped state, a missing certificate, a foreign revocation row,
    // a bundle under the wrong key, an unknown kind, an alarm of an unknown kind.
    let mut t = rows();
    let state = t
        .objects
        .iter_mut()
        .find(|o| o.kind == kind::ACCOUNT_STATE)
        .unwrap();
    state.bytes[12] ^= 1;
    corrupt(&t);
    let mut t = rows();
    let at = t
        .objects
        .iter()
        .position(|o| o.kind == kind::CERTIFICATE)
        .unwrap();
    t.objects.remove(at);
    corrupt(&t);
    let mut t = rows();
    let cert = t
        .objects
        .iter_mut()
        .find(|o| o.kind == kind::CERTIFICATE)
        .unwrap();
    cert.key = vec![0x42; 16];
    corrupt(&t);
    let mut t = rows();
    let bundle = t
        .objects
        .iter_mut()
        .find(|o| o.kind == kind::BUNDLE)
        .unwrap();
    bundle.key = 5u64.to_be_bytes().to_vec();
    corrupt(&t);
    for (kind, key) in [
        (8, vec![1]),
        (kind::ALARM, vec![9]),
        (kind::ALARM, vec![1, 2]),
    ] {
        let mut t = rows();
        t.objects.push(ObjectRow {
            kind,
            key,
            bytes: Vec::new(),
        });
        corrupt(&t);
    }
    // (d) A statement: a served op with a flipped signature; a column that disagrees with
    // the statement (the item, the `device_seq`, the author).
    let mut t = rows();
    let last = t.ops[served_at].statement.len() - 1;
    t.ops[served_at].statement[last] ^= 1;
    corrupt(&t);
    let mut t = rows();
    t.ops[served_at].item_id = vec![0x31; 16];
    corrupt(&t);
    let mut t = rows();
    t.ops[served_at].device_seq = 77u64.to_be_bytes().to_vec();
    corrupt(&t);
    let mut t = rows();
    t.ops[served_at].device_seq = vec![1, 2, 3];
    corrupt(&t);
    // (d) `own` and `sent_generation` against the author: a served row claimed as own, an own
    // row claimed as served, a generation on a row that was never sent, a sent row without one.
    let mut t = rows();
    t.ops[served_at].own = own::ACKNOWLEDGED;
    corrupt(&t);
    let mut t = rows();
    t.ops[own_at].own = own::SERVED;
    corrupt(&t);
    let mut t = rows();
    t.ops[own_at].own = 5;
    corrupt(&t);
    let mut t = rows();
    t.ops[unsent_at].sent_generation = Some(vec![0; 16]);
    corrupt(&t);
    let mut t = rows();
    t.ops[unsent_at].own = own::SENT;
    corrupt(&t);
    // (d) The own chain (§4 step 7): an own row removed from the middle; a counter not above
    // every own `device_seq` held; an acknowledged row after an unacknowledged one.
    let mut t = rows();
    t.ops.remove(own_at);
    corrupt(&t);
    let mut t = rows();
    t.meta.insert(
        meta::NEXT_DEVICE_SEQ.to_owned(),
        1u64.to_be_bytes().to_vec(),
    );
    corrupt(&t);
    let mut t = rows();
    t.ops[own_at].own = own::UNSENT;
    t.ops[own_at].sent_generation = None;
    t.ops[unsent_at].own = own::ACKNOWLEDGED;
    corrupt(&t);
    // (d) A row of a vault the account has no self-grant for; a wrap row of a bad length.
    let mut t = rows();
    t.ops[served_at].vault_id = vec![0x55; 16];
    corrupt(&t);
    let mut t = rows();
    t.wraps[0].item_id = vec![1];
    corrupt(&t);
    let mut t = rows();
    t.vaults[0].restore_generation = Some(vec![1, 2]);
    corrupt(&t);
    // (d) A snapshot row whose statement or column is off.
    let mut t = rows();
    let last = t.snapshots[0].statement.len() - 1;
    t.snapshots[0].statement[last] ^= 1;
    corrupt(&t);
    let mut t = rows();
    t.snapshots[0].snapshot_id = vec![0x66; 16];
    corrupt(&t);

    // (e) A damaged body of a served op under a statement that verifies: the load stands, the
    // op is missing data, and the field shows what the rest of the log gives.
    let mut t = rows();
    let body = t.ops[served_at].body.as_mut().unwrap();
    let mid = body.len() / 2;
    body[mid] ^= 1;
    let loaded = load_rows(&t, &a.unlocked).unwrap();
    assert_eq!(
        loaded.vaults[0]
            .field_value(item, LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        Value::text("mine").unwrap().expose_secret()
    );
    // (e) A damaged wrap-set row: the item's bodies wait for their key; the load stands.
    let mut t = rows();
    for wrap in &mut t.wraps {
        let mid = wrap.envelope.len() / 2;
        wrap.envelope[mid] ^= 1;
    }
    assert!(load_rows(&t, &a.unlocked).is_ok());
    // Another device's keys do not load this file.
    assert_eq!(
        load::load(
            &a.cache.rows,
            &load::open(&a.cache.rows).unwrap(),
            &b.unlocked,
            T0
        )
        .unwrap_err(),
        ClientError::InvalidInput
    );
    let _ = own_device;
}

/// An alarm is written in the transaction that detects it and keeps the device read-only
/// across a restart (ADR 0026 §4 step 4); the evidence is the conflicting signed statements.
#[test]
fn an_alarm_survives_a_restart() {
    let mut rng = ChaCha20Rng::seed_from_u64(82);
    let mut server = Server::new(83);
    let (mut a, _sk, _code) = Dev::signed_up(&mut server, &mut rng);
    a.fetch(&server);
    a.create(&mut rng, "x");
    let pinned = a.state.pin().state_wire.clone();
    // The host saw a fork: it writes the alarm with both statements and goes read-only.
    let other = vec![0xfe; 8];
    let changeset: Changeset = [store::alarm_write(Alarm::Fork, &[&pinned, &other]).unwrap()]
        .into_iter()
        .collect();
    a.cache.commit(changeset);
    let loaded = a.reload();
    assert_eq!(loaded.alarms.into_iter().collect::<Vec<_>>(), [Alarm::Fork]);
    assert!(loaded.vaults[0].is_read_only());
    let row = a
        .cache
        .rows
        .objects
        .iter()
        .find(|o| o.kind == kind::ALARM)
        .unwrap();
    assert_eq!(row.key, [2]);
    let mut expected = Vec::new();
    for statement in [&pinned, &other] {
        expected.extend_from_slice(&u32::try_from(statement.len()).unwrap().to_be_bytes());
        expected.extend_from_slice(statement);
    }
    assert_eq!(row.bytes, expected);
    // The journal still persists what the read-only device receives.
    let mut loaded = a.reload();
    assert_eq!(
        loaded.vaults[0]
            .create_item(&mut rng, &a.unlocked, ItemType::LOGIN, &[], T0)
            .unwrap_err(),
        ClientError::ReadOnly
    );
}

/// ADR 0026 §1, §4 step 2 ("pruning of bodies ADR 0018 §10 no longer needs"): once a snapshot
/// of its own is acknowledged, a device drops the bodies of the served ops it covers, keeps
/// every statement and its own bodies, and the file loads to the same state after every step.
/// After a restore lost everything, its healing request (ADR 0021 §9) sends those headers
/// bodiless behind that snapshot, verbatim, and a fresh replica reads the item again.
#[test]
fn bodies_behind_an_acknowledged_own_snapshot_are_pruned_and_healed_bodiless() {
    let mut rng = ChaCha20Rng::seed_from_u64(90);
    let mut server = Server::new(91);
    let (mut a, sk, _) = Dev::signed_up(&mut server, &mut rng);
    a.fetch(&server);
    let mut b = Dev::enrolled(&mut server, &mut rng, &sk);
    b.fetch(&server);
    let backup = (
        server.ops.clone(),
        server.wraps.clone(),
        server.snapshots.clone(),
        server.op_items.clone(),
    );
    let item = a.create(&mut rng, "v0");
    for i in 0..34 {
        a.edit(&mut rng, item, &format!("a{i}"));
    }
    a.upload(&mut server, &mut rng);
    b.fetch(&server);
    assert!(b.cache.rows.ops.iter().all(|o| o.body.is_some()));
    // B's write makes its own snapshot due; once the server acknowledged it, the bodies it
    // covers go.
    b.edit(&mut rng, item, "from b");
    b.upload(&mut server, &mut rng);
    let pruned_flags = |rows: &CacheRows| {
        rows.ops
            .iter()
            .filter(|o| o.own == own::SERVED)
            .map(|o| o.body.is_none())
            .collect::<Vec<bool>>()
    };
    let pruned = pruned_flags(&b.cache.rows).iter().filter(|p| **p).count();
    assert!(pruned > 0, "some served body is pruned");
    assert!(
        b.cache
            .rows
            .ops
            .iter()
            .filter(|o| o.own != own::SERVED)
            .all(|o| o.body.is_some()),
        "own rows keep their bodies"
    );
    assert!(
        b.cache
            .rows
            .snapshots
            .iter()
            .any(|s| s.own == own::ACKNOWLEDGED)
    );
    b.assert_loads();
    assert_crash_safe(&b.cache.history, &[&b.unlocked]);
    // A reload has nothing more to prune.
    let mut loaded = b.reload();
    let writes = loaded.vaults[0].take_writes();
    assert!(
        !writes
            .writes()
            .iter()
            .any(|w| matches!(w, Write::PruneOpBody { .. }))
    );

    // The restore loses every op; B heals it.
    (server.ops, server.wraps, server.snapshots, server.op_items) = backup;
    server.generation = [0x77; 16];
    let out = b.fetch(&server);
    assert!(out.server_behind);
    let heal = b.vault.healing_request().unwrap().unwrap();
    let records = heal.records.as_slice();
    let bodiless = records
        .iter()
        .filter(|r| matches!(r, Record::Op(op) if op.body.is_none()))
        .count();
    assert_eq!(bodiless, pruned);
    assert!(matches!(records.last(), Some(Record::Snapshot(_))));
    let answer = server.heal(&heal).unwrap();
    b.vault.apply_healing_response(&answer).unwrap();
    b.flush();
    assert!(!b.fetch(&server).server_behind);
    b.assert_loads();

    // A new device, through a compacting server, reads the item again.
    server.compact = true;
    let mut c = Dev::enrolled(&mut server, &mut rng, &sk);
    let out = c.fetch(&server);
    assert!(out.reports.is_empty(), "{:?}", out.reports);
    assert_eq!(
        c.vault
            .field_value(item, LOGIN_PASSWORD)
            .unwrap()
            .expose_secret(),
        Value::text("from b").unwrap().expose_secret()
    );
    c.assert_loads();
}

/// ADR 0021 §9 "Healing request" and ADR 0026 §4 step 6: two own ops are sent and stored, but
/// the answer is lost; the restored backup holds the first and not the second, and lost
/// another device's later ops. The healing request skips the stored own op (its range starts
/// above the server's head) and re-publishes the second; the answer acknowledges both, both
/// rows move to `own = 2`, and the file loads again.
#[test]
fn a_heal_acknowledges_the_own_ops_the_restored_server_holds() {
    let mut rng = ChaCha20Rng::seed_from_u64(92);
    let mut server = Server::new(93);
    let (mut a, sk, _) = Dev::signed_up(&mut server, &mut rng);
    a.fetch(&server);
    let item = a.create(&mut rng, "v0");
    a.upload(&mut server, &mut rng);
    let mut b = Dev::enrolled(&mut server, &mut rng, &sk);
    b.fetch(&server);

    // B sends two edits; the server stores both, and the answer is lost.
    b.edit(&mut rng, item, "b1");
    b.edit(&mut rng, item, "b2");
    let up = b
        .vault
        .upload_request(&mut rng, &b.unlocked)
        .unwrap()
        .unwrap();
    b.flush();
    b.assert_sent_rows(&up);
    let own_seqs: Vec<u64> = up
        .records
        .as_slice()
        .iter()
        .filter_map(|r| match r {
            Record::Op(op) => b
                .cache
                .rows
                .ops
                .iter()
                .find(|row| row.statement == op.statement.as_slice())
                .map(|row| u64::from_be_bytes(row.device_seq.clone().try_into().unwrap())),
            Record::Snapshot(_) => None,
        })
        .collect();
    assert_eq!(own_seqs.len(), 2);
    let b_device: [u8; 16] = b
        .cache
        .rows
        .ops
        .iter()
        .find(|row| row.own == own::SENT)
        .unwrap()
        .device_id
        .clone()
        .try_into()
        .unwrap();
    server.upload(&up);
    // The backup holds B's first op, not its second.
    let mut backup = (
        server.ops.clone(),
        server.wraps.clone(),
        server.snapshots.clone(),
        server.op_items.clone(),
    );
    backup.0.get_mut(&b_device).unwrap().remove(&own_seqs[1]);
    backup.3.remove(&(b_device, own_seqs[1]));
    // A writes after the backup, and B reads it.
    a.fetch(&server);
    a.edit(&mut rng, item, "a1");
    a.upload(&mut server, &mut rng);
    b.fetch(&server);

    // The restore: B finds the server behind on A's chain and heals it.
    (server.ops, server.wraps, server.snapshots, server.op_items) = backup;
    server.generation = [0x79; 16];
    let out = b.fetch(&server);
    assert!(out.server_behind);
    let heal = b.vault.healing_request().unwrap().unwrap();
    let republished: Vec<&OpRecord> = heal
        .records
        .as_slice()
        .iter()
        .filter_map(|r| match r {
            Record::Op(op) => Some(op),
            Record::Snapshot(_) => None,
        })
        .filter(|op| up.records.as_slice().contains(&Record::Op((*op).clone())))
        .collect();
    assert_eq!(
        republished,
        vec![match &up.records.as_slice()[1] {
            Record::Op(op) => op,
            Record::Snapshot(_) => panic!("an op"),
        }],
        "the stored own op is outside the range; the other is re-published verbatim"
    );
    let answer = server.heal(&heal).unwrap();
    let outcome = b.vault.apply_healing_response(&answer).unwrap();
    assert_eq!(outcome.own_acknowledged, 1);
    b.flush();
    assert!(
        b.cache
            .rows
            .ops
            .iter()
            .filter(|row| row.own != own::SERVED)
            .all(|row| row.own == own::ACKNOWLEDGED),
        "every own row up to the re-published one is acknowledged"
    );
    b.assert_loads();
    assert!(!b.fetch(&server).server_behind);
    b.upload(&mut server, &mut rng);
    b.assert_loads();
    assert_crash_safe(&b.cache.history, &[&b.unlocked]);
}

//! Fuzzes `rizzy-client`'s cache loader (ADR 0026 §3 "Columns are indexes, never facts", §4
//! steps 5 and 7, §5, §6): the rows of the local cache are read back from a file anyone with
//! the user's rights can change, so every row is untrusted input.
//!
//! A valid cache is built once per process with the real flows: a signup, a second device
//! enrolled by login, ops of both devices, a Fetch and an upload answer, so the rows hold
//! served ops with bodies and carried wraps, the wrap set, own ops that are acknowledged, sent
//! and unsent, and own snapshots. The device's keys come from the signup itself; no input
//! costs an Argon2id run.
//!
//! Each input is a list of mutations of those rows: a byte flipped or a blob replaced,
//! truncated or emptied in any column of any table, an `own` or an epoch set to an arbitrary
//! value, a `sent_generation` set or cleared, a row removed or duplicated, a meta row changed.
//! For each mutated cache:
//!
//! - [`open`] and [`load`] never panic; a failure is one of the errors the load documents.
//! - A cache that loads is coherent: one driver per vault row, `next_device_seq` is the stored
//!   counter and above every own `device_seq` held, the driver builds its Fetch request, and
//!   an alarm row makes it read-only.
//! - The unmutated cache always loads.
//! - A further own op of a loaded driver never panics; its writes are admitted by the floors
//!   of the unmutated cache, and the reference executor takes whatever the floors admit.
//!
//! ```text
//! cargo +nightly fuzz run client_cache_load
//! ```
#![no_main]

use std::convert::Infallible;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::items::{FieldEdit, FieldKey, ItemType, Value};
use rizzy_client::login::{LoginInput, start_login};
use rizzy_client::signup::{DeviceKind, SignupInput, start_signup};
use rizzy_client::store::floors::Floors;
use rizzy_client::store::load::{load, open};
use rizzy_client::store::record::Stage;
use rizzy_client::store::rows::{CacheRows, Changeset, Write, kind, meta, own};
use rizzy_client::store::{account_writes, finalize_writes};
use rizzy_client::sync::{Authors, VaultSync};
use rizzy_client::unlock::{account_state_query, verify_unlock};
use rizzy_core::ids::AccountId;
use rizzy_core::kdf::KdfId;
use rizzy_core::normalize::{LoginName, ServerOrigin};
use rizzy_core::opaque::{
    CredentialIdentifier, OpaqueContext, PasswordFile, RegisteredCredential, ServerSetup,
    server_login_finish, server_login_start, server_registration_finish, server_registration_start,
};
use rizzy_proto::account::AccountView;
use rizzy_proto::auth::{LoginFinishResponse, LoginStartResponse, RegisterStartResponse};
use rizzy_proto::objects::ItemKeyWrap;
use rizzy_proto::vault::{
    FetchResponse, Record, SeqEntry, SeqVector, UploadRequest, UploadResponse, UploadResult,
};
use rizzy_proto::wire::{Bytes, Fixed, Id, List, SessionToken, Text};

/// The origin of the fixture's server.
const ORIGIN: &str = "https://vault.example.com";
/// The fixture account's master password.
const PASSWORD: &str = "correct horse battery staple";
/// The fixture's clock.
const NOW: u64 = 1_790_000_000_000;
/// The restore generation every fixture answer carries.
const GENERATION: [u8; 16] = [0x47; 16];

/// A deterministic byte source for the fixture's keys and ids (SplitMix64). Not a CSPRNG:
/// the fixture's secrets protect nothing, and a crash must reproduce from its input alone.
struct FixtureRng(u64);

impl TryRng for FixtureRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.try_next_u64()?.to_le_bytes()[..4]
            .try_into()
            .map(u32::from_le_bytes)
            .unwrap_or(0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for FixtureRng {}

/// What every input runs against, built once per process.
struct Fixture {
    /// The rows of the valid cache.
    rows: CacheRows,
    /// The keys of the device the cache belongs to.
    unlocked: UnlockedDevice,
}

/// A copy of the rows (the type is not `Clone`: it holds the device-state record).
fn copy(rows: &CacheRows) -> CacheRows {
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

/// A bounded wire byte string.
fn bytes<const N: usize>(v: &[u8]) -> Bytes<N> {
    Bytes::from_slice(v).expect("within the wire bound")
}

/// The wrap-set rows a server holds after it stored `records`: each carried wrap, under the
/// item its op names. The item comes from the uploading device's own cache row of that op
/// (`rows`), whose `item_id` column the driver wrote from the header it signed.
fn wrap_set(rows: &CacheRows, records: &[Record]) -> Vec<ItemKeyWrap> {
    let mut wraps = Vec::new();
    for record in records {
        let Record::Op(op) = record else { continue };
        let Some(wrap) = &op.key_wrap else { continue };
        let row = rows
            .ops
            .iter()
            .find(|r| r.statement == op.statement.as_slice())
            .expect("an uploaded op is an own row");
        wraps.push(ItemKeyWrap {
            item_id: Id::from_bytes(row.item_id.as_slice().try_into().expect("an item id")),
            item_key_id: wrap.item_key_id,
            vault_key_epoch: 0,
            envelope: wrap.envelope.clone(),
        });
    }
    wraps
}

/// The Fetch answer of a server that serves the ops of `records`, holds the chains of `heads`
/// (device and head), and holds the wrap set `wraps`.
fn fetch_answer(
    records: &[Record],
    heads: &[([u8; 16], u64)],
    wraps: &[ItemKeyWrap],
) -> FetchResponse {
    let mut heads: Vec<SeqEntry> = heads
        .iter()
        .filter(|(_, seq)| *seq > 0)
        .map(|(device, seq)| SeqEntry {
            device_id: Id::from_bytes(*device),
            seq: *seq,
        })
        .collect();
    heads.sort_by_key(|e| e.device_id);
    let ops: Vec<_> = records
        .iter()
        .filter_map(|r| match r {
            Record::Op(op) => Some(op.clone()),
            Record::Snapshot(_) => None,
        })
        .collect();
    FetchResponse {
        restore_generation: Fixed::from_bytes(GENERATION),
        heads: SeqVector::new(heads).expect("ascending heads"),
        ops: List::new(ops).expect("a few ops"),
        covers: List::empty(),
        item_key_wraps: List::new(wraps.to_vec()).expect("a few wraps"),
        complete: true,
    }
}

/// An upload answer that stores everything.
fn stored(request: &UploadRequest) -> UploadResponse {
    UploadResponse {
        restore_generation: Fixed::from_bytes(GENERATION),
        results: List::new(vec![UploadResult::Stored; request.records.len()]).expect("results"),
    }
}

/// One committed step of the fixture device: the floors, then the reference executor.
fn commit(rows: &mut CacheRows, floors: &mut Floors, changeset: &Changeset) {
    floors
        .admit(changeset)
        .expect("the fixture's own steps are admitted");
    rows.apply(changeset);
}

/// A login field write.
fn password_edit(text: &str) -> (FieldKey, Value) {
    (
        FieldKey::parse(b"login.password").expect("a schema key"),
        Value::text(text).expect("a short text"),
    )
}

/// Builds the fixture (module docs). Every `expect` is on a step of the real flows with
/// well-formed inputs; a failure here is a bug in the fixture, found at the first input.
fn build() -> Fixture {
    let mut rng = FixtureRng(1);
    let origin = ServerOrigin::parse(ORIGIN).expect("origin");
    let setup = ServerSetup::generate(&mut rng);

    // Signup of the device whose cache is fuzzed.
    let (started, request) = start_signup(
        &mut rng,
        &SignupInput {
            server_origin: ORIGIN,
            login_name: "alice",
            password: PASSWORD,
            invite: None,
            issue_recovery_code: true,
            device_kind: DeviceKind::DesktopCli,
            now_ms: NOW,
        },
    )
    .expect("signup starts");
    let account_id = AccountId::from_bytes(request.account_id.to_bytes());
    let credential = CredentialIdentifier::for_account(account_id);
    let m2 =
        server_registration_start(&setup, request.registration_request.as_slice(), &credential)
            .expect("registration starts");
    let mut pending = started
        .finish(
            &mut rng,
            &RegisterStartResponse {
                registration_response: bytes(&m2),
            },
        )
        .expect("signup finishes");
    let last = pending
        .emergency_kit()
        .secret_key()
        .rsplit('-')
        .next()
        .expect("groups")
        .to_owned();
    let secret_key = pending.emergency_kit().secret_key().to_owned();
    pending.confirm_kit(&last).expect("the kit confirms");
    let mut rows = CacheRows::default();
    let mut floors = Floors::empty();
    commit(
        &mut rows,
        &mut floors,
        &pending.store_writes(b"{}").expect("the pending cache"),
    );
    let commit_request = pending.commit_request().expect("confirmed");
    let password_file = server_registration_finish(commit_request.registration_upload.as_slice())
        .expect("registration finishes")
        .to_bytes();
    let mut view = AccountView {
        account_state: commit_request.account_state.clone(),
        bundles: List::new(vec![commit_request.bundle.clone()]).expect("one bundle"),
        device_certificates: List::new(vec![commit_request.device_certificate.clone()])
            .expect("one certificate"),
        device_revocations: List::empty(),
        account_settings: None,
        identity_secret_keys: commit_request.identity_secret_keys.clone(),
        vault_self_grants: List::new(vec![commit_request.vault_self_grant.clone()])
            .expect("one grant"),
    };
    let e_srv = commit_request.account_key_server_wrap.clone();
    let signed_up = pending.finalize().expect("finalised");
    let mut state = signed_up.device.expect("a durable device");
    let unlocked = signed_up.unlocked;
    commit(
        &mut rows,
        &mut floors,
        &finalize_writes(&state.record(Stage::Committed).expect("record")).expect("writes"),
    );
    let own_device = state.device_id().to_bytes();
    let mut authors = Authors::from_statements(&[signed_up.own_certificate], &[]).expect("authors");
    let mut vault = VaultSync::new(signed_up.vault_key, &unlocked, 1).expect("the driver");
    vault.persist();
    vault
        .apply_fetch(&authors, &fetch_answer(&[], &[], &[]), NOW)
        .expect("the first Fetch");
    commit(&mut rows, &mut floors, &vault.take_writes());

    // Two items, uploaded and acknowledged (their snapshots too).
    let (key, value) = password_edit("first");
    let mut items = Vec::new();
    for _ in 0..2 {
        items.push(
            vault
                .create_item(
                    &mut rng,
                    &unlocked,
                    ItemType::LOGIN,
                    &[FieldEdit {
                        key: &key,
                        value: &value,
                    }],
                    NOW + 1,
                )
                .expect("an item"),
        );
        commit(&mut rows, &mut floors, &vault.take_writes());
    }
    let mut uploaded: Vec<Record> = Vec::new();
    while let Some(request) = vault
        .upload_request(&mut rng, &unlocked)
        .expect("an upload")
    {
        commit(&mut rows, &mut floors, &vault.take_writes());
        uploaded.extend(request.records.as_slice().iter().cloned());
        vault
            .apply_upload_response(&stored(&request))
            .expect("the answer applies");
        commit(&mut rows, &mut floors, &vault.take_writes());
    }

    // A second device logs in, enrols, reads the two items and edits one.
    let (login, ke1) = start_login(
        &mut rng,
        &LoginInput {
            server_origin: ORIGIN,
            login_name: "alice",
            secret_key: &secret_key,
            password: PASSWORD,
        },
    )
    .expect("login starts");
    let context = OpaqueContext::new(KdfId::DEFAULT, &origin);
    let server_login = server_login_start(
        &mut rng,
        &setup,
        &LoginName::parse("alice").expect("name"),
        Some(RegisteredCredential {
            account_id,
            password_file: PasswordFile::from_bytes(&password_file).expect("the record"),
            kdf_id: KdfId::DEFAULT,
        }),
        ke1.ke1.as_slice(),
        &context,
    )
    .expect("the server answers KE1");
    let (awaiting, ke3) = login
        .finish(
            &mut rng,
            &LoginStartResponse {
                login_id: Id::from_bytes([1; 16]),
                ke2: bytes(&server_login.ke2),
                kdf_id: 1,
                server_origin: Text::from_str(ORIGIN).expect("origin"),
            },
            None,
        )
        .expect("login finishes");
    server_login_finish(server_login.state, ke3.ke3.as_slice(), &context)
        .expect("the server accepts KE3");
    let logged_in = awaiting
        .complete(LoginFinishResponse {
            session_token: SessionToken::from_b64url(&"A".repeat(43)).expect("a token"),
            account_id: Id::from_bytes(account_id.to_bytes()),
            account_key_server_wrap: e_srv,
            account: view.clone(),
        })
        .expect("the login answer verifies");
    let (enrolment, enrol_request) = logged_in
        .enrol(&mut rng, DeviceKind::DesktopCli, NOW + 2)
        .expect("the enrolment");
    view.account_state = enrol_request.account_state.clone();
    view.device_certificates = List::new(vec![
        view.device_certificates.as_slice()[0].clone(),
        enrol_request.device_certificate.clone(),
    ])
    .expect("two certificates");
    let enrolled = enrolment.finalize();
    let other_device = enrolled.device.device_id().to_bytes();
    let mut other_account: VerifiedAccount = enrolled.account;
    let other_authors = Authors::from_account(&other_account).expect("authors");
    let vault_id = other_account.vault_ids().next().expect("one vault");
    let mut other = VaultSync::new(
        other_account.take_vault_key(vault_id).expect("the key"),
        &enrolled.unlocked,
        1,
    )
    .expect("the other driver");
    let wraps = wrap_set(&rows, &uploaded);
    let own_head = u64::try_from(
        uploaded
            .iter()
            .filter(|r| matches!(r, Record::Op(_)))
            .count(),
    )
    .expect("small");
    other
        .apply_fetch(
            &other_authors,
            &fetch_answer(&uploaded, &[(own_device, own_head)], &wraps),
            NOW + 3,
        )
        .expect("the other device's Fetch");
    let (key, value) = password_edit("from the other device");
    other
        .edit_item(
            &mut rng,
            &enrolled.unlocked,
            items[0],
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            NOW + 4,
        )
        .expect("the other device's edit");
    let other_upload = other
        .upload_request(&mut rng, &enrolled.unlocked)
        .expect("upload")
        .expect("one op");

    // The fuzzed device learns of the new device and fetches its op: a served row.
    let verified = verify_unlock(&mut state, &unlocked, &view, None).expect("the state verifies");
    let _ = account_state_query(&state);
    authors = Authors::from_account(&verified).expect("authors");
    commit(&mut rows, &mut floors, &account_writes(&verified));
    vault
        .apply_fetch(
            &authors,
            &fetch_answer(
                other_upload.records.as_slice(),
                &[(own_device, own_head), (other_device, 1)],
                &wraps,
            ),
            NOW + 5,
        )
        .expect("the Fetch of the other device's op");
    commit(&mut rows, &mut floors, &vault.take_writes());

    // One own op sent and unanswered, one written and never sent.
    let (key, value) = password_edit("sent, no answer");
    vault
        .edit_item(
            &mut rng,
            &unlocked,
            items[1],
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            NOW + 6,
        )
        .expect("an edit");
    commit(&mut rows, &mut floors, &vault.take_writes());
    vault
        .upload_request(&mut rng, &unlocked)
        .expect("upload")
        .expect("the edit");
    commit(&mut rows, &mut floors, &vault.take_writes());
    let (key, value) = password_edit("never sent");
    vault
        .create_item(
            &mut rng,
            &unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            NOW + 7,
        )
        .expect("an item");
    commit(&mut rows, &mut floors, &vault.take_writes());
    rows.sort();
    Fixture { rows, unlocked }
}

/// The fixture, built on first use.
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let fixture = build();
        // The unmutated cache loads, and holds what the module docs say.
        assert!(fixture.rows.ops.iter().any(|o| o.own == own::SERVED));
        assert!(fixture.rows.ops.iter().any(|o| o.own == own::UNSENT));
        assert!(fixture.rows.ops.iter().any(|o| o.own == own::SENT));
        assert!(fixture.rows.ops.iter().any(|o| o.own == own::ACKNOWLEDGED));
        assert!(!fixture.rows.snapshots.is_empty() && !fixture.rows.wraps.is_empty());
        run(&fixture.rows, &fixture.unlocked, true).expect("the valid cache loads");
        fixture
    })
}

/// Opens and loads `rows`; checks what a loaded cache must satisfy (module docs). `valid`
/// says the rows are the unmutated fixture, whose further own op must be admitted.
fn run(rows: &CacheRows, unlocked: &UnlockedDevice, valid: bool) -> Result<(), ClientError> {
    let record = open(rows)?;
    let mut loaded = load(rows, &record, unlocked, NOW + 100)?;
    assert_eq!(loaded.vaults.len(), rows.vaults.len());
    let counter = rows
        .meta
        .get(meta::NEXT_DEVICE_SEQ)
        .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
        .map(u64::from_be_bytes)
        .expect("a loaded cache has its counter");
    let alarmed = rows.objects.iter().any(|o| o.kind == kind::ALARM);
    assert_eq!(loaded.alarms.is_empty(), !alarmed);
    let mut rng = FixtureRng(2);
    let (key, value) = password_edit("further");
    for vault in &mut loaded.vaults {
        assert_eq!(vault.next_device_seq(), counter);
        vault
            .fetch_request()
            .expect("a loaded driver builds its Fetch");
        assert!(!alarmed || vault.is_read_only());
        for row in rows.ops.iter().filter(|o| o.own != own::SERVED) {
            let seq = <[u8; 8]>::try_from(row.device_seq.as_slice())
                .map(u64::from_be_bytes)
                .expect("a loaded own row has a well-formed seq");
            assert!(seq < counter, "the counter is above every own dot held");
        }
        // The load journals no row: at most the HLC, which the replay may have moved on.
        assert!(
            vault
                .take_writes()
                .writes()
                .iter()
                .all(|w| matches!(w, Write::Meta { key, .. } if *key == meta::HLC))
        );
        // A further own op: its writes pass the floors of the valid cache, and whatever the
        // floors of a mutated one admit, the reference executor takes and the result opens.
        let created = vault.create_item(
            &mut rng,
            unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            NOW + 200,
        );
        assert!(
            created.is_ok() || !valid,
            "the valid cache takes a further op"
        );
        let changeset = vault.take_writes();
        let admitted = loaded.floors.admit(&changeset);
        assert!(
            admitted.is_ok() || !valid,
            "the valid cache admits its own op"
        );
        if created.is_ok() && admitted.is_ok() {
            let mut next = copy(rows);
            next.apply(&changeset);
            open(&next).expect("the record is untouched by an op");
        }
    }
    Ok(())
}

/// A blob mutated by one instruction: a flipped byte, a truncation, emptied, or replaced by
/// the instruction's payload.
fn mutate_blob(blob: &mut Vec<u8>, how: u8, at: u8, payload: &[u8]) {
    match how % 4 {
        0 => {
            if !blob.is_empty() {
                let index = usize::from(at) * blob.len() / 256;
                blob[index] ^= 1 << (at % 8);
            }
        }
        1 => blob.truncate(usize::from(at) * blob.len() / 256),
        2 => blob.clear(),
        _ => *blob = payload.to_vec(),
    }
}

/// An optional blob mutated: cleared to `NULL`, set from the payload, or mutated in place.
fn mutate_optional(blob: &mut Option<Vec<u8>>, how: u8, at: u8, payload: &[u8]) {
    match (how % 6, blob.as_mut()) {
        (4, _) => *blob = None,
        (5, _) | (_, None) => *blob = Some(payload.to_vec()),
        (_, Some(held)) => mutate_blob(held, how, at, payload),
    }
}

/// Applies one mutation instruction to the rows.
fn mutate(rows: &mut CacheRows, instruction: &[u8; 5], payload: &[u8]) {
    let [table, row, column, how, at] = *instruction;
    let pick = |len: usize| usize::from(row) % len.max(1);
    match table % 8 {
        0 => {
            let keys: Vec<String> = rows.meta.keys().cloned().collect();
            match (how % 3, keys.get(pick(keys.len()))) {
                (0, Some(key)) => {
                    rows.meta.remove(key);
                }
                (1, Some(key)) => {
                    if let Some(value) = rows.meta.get_mut(key) {
                        mutate_blob(value, column, at, payload);
                    }
                }
                _ => {
                    rows.meta.insert(format!("k{column}"), payload.to_vec());
                }
            }
        }
        1 => match how % 3 {
            0 => rows.device_state = None,
            1 => {
                if let Some(record) = rows.device_state.as_mut() {
                    mutate_blob(record, column, at, payload);
                }
            }
            _ => rows.pending_commit = Some(payload.to_vec()),
        },
        2 if !rows.objects.is_empty() => {
            let index = pick(rows.objects.len());
            match column % 5 {
                0 => rows.objects[index].kind = i64::from(at) - 2,
                1 => mutate_blob(&mut rows.objects[index].key, how, at, payload),
                2 => mutate_blob(&mut rows.objects[index].bytes, how, at, payload),
                3 => {
                    rows.objects.remove(index);
                }
                _ => {
                    let copy = rows.objects[index].clone();
                    rows.objects.push(copy);
                }
            }
        }
        3 if !rows.vaults.is_empty() => {
            let index = pick(rows.vaults.len());
            let vault = &mut rows.vaults[index];
            match column % 6 {
                0 => mutate_blob(&mut vault.vault_id, how, at, payload),
                1 => vault.self_grant.vault_key_epoch = u32::from(at),
                2 => vault.self_grant.account_key_epoch = u32::from(at),
                3 => mutate_optional(&mut vault.restore_generation, how, at, payload),
                4 => vault.wraps_after_epoch = Some(i64::from(at)),
                _ => {
                    rows.vaults.remove(index);
                }
            }
        }
        4 if !rows.wraps.is_empty() => {
            let index = pick(rows.wraps.len());
            let wrap = &mut rows.wraps[index];
            match column % 6 {
                0 => mutate_blob(&mut wrap.vault_id, how, at, payload),
                1 => mutate_blob(&mut wrap.item_id, how, at, payload),
                2 => mutate_blob(&mut wrap.item_key_id, how, at, payload),
                3 => wrap.vault_key_epoch = i64::from(at) - 2,
                4 => mutate_blob(&mut wrap.envelope, how, at, payload),
                _ => {
                    rows.wraps.remove(index);
                }
            }
        }
        5 | 6 if !rows.ops.is_empty() => {
            let index = pick(rows.ops.len());
            let op = &mut rows.ops[index];
            match column % 11 {
                0 => mutate_blob(&mut op.vault_id, how, at, payload),
                1 => mutate_blob(&mut op.device_id, how, at, payload),
                2 => mutate_blob(&mut op.device_seq, how, at, payload),
                3 => mutate_blob(&mut op.item_id, how, at, payload),
                4 => mutate_blob(&mut op.statement, how, at, payload),
                5 => mutate_optional(&mut op.body, how, at, payload),
                6 => mutate_optional(&mut op.key_wrap, how, at, payload),
                7 => op.own = i64::from(at % 6) - 1,
                8 => mutate_optional(&mut op.sent_generation, how, at, payload),
                9 => {
                    rows.ops.remove(index);
                }
                _ => {
                    // Another row's statement under this row's key: a column/statement
                    // mismatch.
                    let other = usize::from(at) % rows.ops.len();
                    let statement = rows.ops[other].statement.clone();
                    rows.ops[index].statement = statement;
                }
            }
        }
        7 if !rows.snapshots.is_empty() => {
            let index = pick(rows.snapshots.len());
            let snapshot = &mut rows.snapshots[index];
            match column % 9 {
                0 => mutate_blob(&mut snapshot.vault_id, how, at, payload),
                1 => mutate_blob(&mut snapshot.snapshot_id, how, at, payload),
                2 => mutate_blob(&mut snapshot.item_id, how, at, payload),
                3 => mutate_blob(&mut snapshot.statement, how, at, payload),
                4 => mutate_blob(&mut snapshot.envelope, how, at, payload),
                5 => mutate_optional(&mut snapshot.key_wrap, how, at, payload),
                6 => snapshot.own = i64::from(at % 6) - 1,
                7 => mutate_optional(&mut snapshot.sent_generation, how, at, payload),
                _ => {
                    rows.snapshots.remove(index);
                }
            }
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let mut rows = copy(&fixture.rows);
    // Instructions of five bytes, each followed by a payload of up to 40 bytes taken from
    // what is left.
    let mut rest = data;
    let mut steps = 0;
    while let Some((instruction, tail)) = rest.split_first_chunk::<5>() {
        let take = usize::from(instruction[4] % 41).min(tail.len());
        let (payload, tail) = tail.split_at(take);
        mutate(&mut rows, instruction, payload);
        rest = tail;
        steps += 1;
        if steps == 16 {
            break;
        }
    }
    if let Err(e) = run(&rows, &fixture.unlocked, false) {
        assert!(
            matches!(
                e,
                ClientError::CacheCorrupt
                    | ClientError::CacheUpdateRequired
                    | ClientError::SignupPending
                    | ClientError::LocalUnlockUnavailable
                    | ClientError::InvalidInput
            ),
            "{e:?}"
        );
    }
});

// SPDX-License-Identifier: AGPL-3.0-only

//! Several vaults per account against the fake server (ADR 0081 Part A):
//!
//! - a vault is created by one atomic account change, named, written to, and seen by another
//!   session; the Personal vault refuses a rename and a delete (INV-101);
//! - a malicious server that withholds a listed vault, serves an unlisted one, or rolls the
//!   directory back is detected (INV-102);
//! - the same `item_id` in two vaults never crosses, in the merges or the local index (INV-103);
//! - a move purges the source only after the target is acknowledged, resumes from its row, and
//!   a deleted vault is dropped by the other session;
//! - a late edit on a moved and purged item names the target vault when this session recorded
//!   the move (§A6 step 2);
//! - property: random ops over 1–4 vaults on two sessions, delivered per vault in any
//!   interleaving, converge per vault, with `device_seq` gap-free per device across vaults and
//!   `vault_prev_seq` chained per vault (ADR 0081 §A7);
//! - property: a move with a failure injected at every step leaves every field value in at least
//!   one vault, and completes when resumed (INV-104).
//!
//! The server's own checks of `vault_create` and `vault_delete` are `rizzy-domain-auth`'s and
//! `rizzy-domain-vault`'s tests (`tests/auth/vaults.rs`, `tests/vault/vaults.rs`).

use std::cell::RefCell;

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestRng, TestRunner};
use rizzy_core::envelope::purpose::VaultKeySelfGrantCtx;
use rizzy_core::ids::VaultId;
use rizzy_core::item::schema::ITEM_NAME;
use rizzy_core::keys::VaultKey;
use rizzy_proto::change::CommitChangeRequest;
use rizzy_proto::error::ErrorCode;
use rizzy_proto::objects::{KeyEnvelope, VaultSelfGrant};
use rizzy_sync::merge::ItemLifecycle;

use super::settings::{refresh, web_account};
use super::*;
use crate::login::WebSession;
use crate::store::index;
use crate::store::rows::CacheRows;
use crate::sync::DeviceCounters;
use crate::vaults::{
    LateEdit, MoveStep, PendingMove, VaultAlarm, VaultCatalog, VaultStatus, create_vault,
    delete_vault, late_edit, rename_vault, vault_name,
};

impl Server {
    /// `account/commit` of a settings change that may carry `vault_create` or `vault_delete`
    /// (ADR 0081 §A3, §A5), as the real server applies it: the settings change, then the vault
    /// row and self-grant created or the vault and its rows deleted.
    fn commit_vault_change(&mut self, req: &CommitChangeRequest) -> Result<(), ErrorCode> {
        if req.vault_create.is_some() && req.vault_delete.is_some() {
            return Err(ErrorCode::InvalidRequest);
        }
        self.commit_settings(req)?;
        let s = self.account.as_mut().unwrap();
        if let Some(grant) = &req.vault_create
            && !s.grants.iter().any(|g| g.vault_id == grant.vault_id)
        {
            s.grants.push(grant.clone());
            s.grants.sort_by_key(|g| g.vault_id);
        }
        if let Some(vault) = req.vault_delete {
            s.grants.retain(|g| g.vault_id != vault);
            let gone: Vec<([u8; 16], u64)> = self
                .op_vaults
                .iter()
                .filter(|(_, v)| **v == vault.to_bytes())
                .map(|(k, _)| *k)
                .collect();
            for (device, seq) in gone {
                if let Some(chain) = self.ops.get_mut(&device) {
                    chain.remove(&seq);
                }
            }
        }
        Ok(())
    }
}

/// A text value.
fn text(s: &str) -> Value {
    Value::text(s).unwrap()
}

/// A login item named `name` in `vault`.
fn new_item(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    name: &str,
    now: u64,
) -> ItemId {
    let key = SchemaKey::parse(ITEM_NAME.as_bytes()).unwrap();
    let value = text(name);
    vault
        .create_item(
            rng,
            unlocked,
            ItemType::LOGIN,
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            now,
        )
        .unwrap()
}

/// Renames item `item` of `vault`.
fn rename_item(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    name: &str,
    now: u64,
) {
    let key = SchemaKey::parse(ITEM_NAME.as_bytes()).unwrap();
    let value = text(name);
    vault
        .edit_item(
            rng,
            unlocked,
            item,
            &[FieldEdit {
                key: &key,
                value: &value,
            }],
            now,
        )
        .unwrap();
}

/// The name of `item` in `vault`, if it is there and live.
fn name_of(vault: &VaultSync, item: ItemId) -> Option<String> {
    if !matches!(
        vault.item_lifecycle(item),
        ItemLifecycle::Active | ItemLifecycle::Trashed
    ) {
        return None;
    }
    match vault.field_value(item, ITEM_NAME)?.decode() {
        Ok(ValueRef::Text(t)) => Some(t.to_owned()),
        _ => None,
    }
}

/// Uploads everything `vault` holds; `deliver` false loses the server's answer after it stored
/// the records (a broken connection): the records stay unacknowledged and the next upload
/// sends them again.
fn upload(
    server: &mut Server,
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    deliver: bool,
) {
    while let Some(up) = vault.upload_request(rng, unlocked).unwrap() {
        let answer = server.upload(&up);
        if !deliver {
            return;
        }
        let outcome = vault.apply_upload_response(&answer).unwrap();
        assert!(outcome.rejected.is_empty(), "{:?}", outcome.rejected);
    }
}

/// Fetches `vault` until complete.
fn fetch(server: &Server, vault: &mut VaultSync, now: u64) {
    let authors = server.authors();
    loop {
        let response = server.fetch(&vault.fetch_request().unwrap());
        let complete = response.complete;
        vault.apply_fetch(&authors, &response, now).unwrap();
        if complete {
            break;
        }
    }
}

/// Commits a vault change on `web` and adopts it; a creation answers the new vault's driver.
fn commit_change(
    server: &mut Server,
    web: &mut WebSession,
    pending: crate::vaults::PendingVaultChange,
    counters: &DeviceCounters,
) -> Option<VaultSync> {
    server
        .commit_vault_change(pending.commit_request())
        .unwrap();
    let created = pending.finalize(&mut web.account).unwrap();
    refresh(server, web);
    created.map(|c| {
        let mut vault = VaultSync::new(c.key, &web.unlocked, 1).unwrap();
        vault.share_counters(counters);
        fetch(server, &mut vault, T0 + 5);
        vault
    })
}

/// The drivers of every open vault of `web`, sharing one set of counters, fetched.
fn open_all(server: &Server, web: &mut WebSession, now: u64) -> (DeviceCounters, Vec<VaultSync>) {
    let catalog = VaultCatalog::of_account(&web.account, &web.unlocked).unwrap();
    assert!(catalog.alarms().is_empty(), "{:?}", catalog.alarms());
    let counters = DeviceCounters::new();
    let mut vaults = Vec::new();
    for id in catalog.open_vaults().collect::<Vec<_>>() {
        let mut vault =
            VaultSync::new(web.account.take_vault_key(id).unwrap(), &web.unlocked, 1).unwrap();
        vault.share_counters(&counters);
        fetch(server, &mut vault, now);
        vaults.push(vault);
    }
    (counters, vaults)
}

/// The vault `id` among `vaults`.
fn find(vaults: &mut [VaultSync], id: VaultId) -> &mut VaultSync {
    vaults.iter_mut().find(|v| v.vault_id() == id).unwrap()
}

/// The own `device_seq` values the server holds for `device`, ascending, and per vault the
/// `vault_prev_seq` of each in order: the allocator's two properties (ADR 0081 §A7).
fn assert_allocator(server: &Server, device: DeviceId) {
    let authors = server.authors();
    let Some(chain) = server.ops.get(&device.to_bytes()) else {
        return;
    };
    let seqs: Vec<u64> = chain.keys().copied().collect();
    let expected: Vec<u64> = (1..=seqs.len() as u64).collect();
    assert_eq!(
        seqs, expected,
        "device_seq is gap-free per device across vaults"
    );
    let mut last: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    for (seq, record) in chain {
        let wire = record.statement.as_slice();
        let author = authors.signer(wire).unwrap();
        let verified = OpStatement::verify(wire, &author.verifying_key).unwrap();
        let header = rizzy_sync::header::OpHeader::parse_statement(&verified).unwrap();
        let vault = header.vault_id.to_bytes();
        let prev = last.get(&vault).copied().unwrap_or(0);
        assert_eq!(
            header.vault_prev_seq, prev,
            "vault_prev_seq chains per vault"
        );
        last.insert(vault, *seq);
    }
}

#[test]
fn a_vault_is_created_named_used_and_seen_by_another_session() {
    let mut rng = ChaCha20Rng::seed_from_u64(810);
    let mut server = Server::new(811);
    let (mut web, sk) = web_account(&mut server, &mut rng);
    // ADR 0081 §A10: before any write, the legacy rule names the one vault Personal.
    let before = VaultCatalog::of_account(&web.account, &web.unlocked).unwrap();
    assert!(!before.has_directory());
    let personal = before.personal().unwrap();
    // INV-101 on the client: the Personal vault is not deleted.
    assert_eq!(
        delete_vault(&mut rng, &web.account, &web.unlocked, personal).unwrap_err(),
        ClientError::PersonalVaultProtected
    );

    let (counters, mut vaults) = open_all(&server, &mut web, T0 + 10);
    let pending = create_vault(&mut rng, &web.account, &web.unlocked).unwrap();
    let owned_id = pending.vault_id();
    assert!(pending.commit_request().vault_create.is_some());
    let mut owned = commit_change(&mut server, &mut web, pending, &counters).unwrap();
    let catalog = VaultCatalog::of_account(&web.account, &web.unlocked).unwrap();
    assert!(catalog.has_directory() && catalog.alarms().is_empty());
    assert_eq!(catalog.personal(), Some(personal));
    assert!(catalog.is_open(owned_id) && catalog.is_open(personal));

    // §A3 step 3, §A4: the name is the vault's first op; the Personal vault has none.
    assert_eq!(vault_name(&owned), None);
    rename_vault(
        &mut rng,
        &web.unlocked,
        &catalog,
        &mut owned,
        "  Work ",
        T0 + 20,
    )
    .unwrap();
    assert_eq!(vault_name(&owned).unwrap().as_str(), "Work");
    assert!(matches!(
        crate::vaults::vault_label(&catalog, &owned),
        crate::vaults::VaultLabel::Named(n) if n.as_str() == "Work"
    ));
    assert_eq!(
        crate::vaults::vault_label(&catalog, find(&mut vaults, personal)),
        crate::vaults::VaultLabel::Personal
    );
    let p = find(&mut vaults, personal);
    assert_eq!(
        rename_vault(&mut rng, &web.unlocked, &catalog, p, "Mine", T0 + 21).unwrap_err(),
        ClientError::PersonalVaultProtected
    );
    let a = new_item(p, &mut rng, &web.unlocked, "in personal", T0 + 22);
    let b = new_item(&mut owned, &mut rng, &web.unlocked, "in work", T0 + 23);
    let p = find(&mut vaults, personal);
    upload(&mut server, p, &mut rng, &web.unlocked, true);
    upload(&mut server, &mut owned, &mut rng, &web.unlocked, true);
    // One device_seq allocator across both drivers (§A7).
    assert_allocator(&server, web.unlocked.device_id);

    let mut other = web_login(&mut server, &mut rng, &sk);
    let (_, mut theirs) = open_all(&server, &mut other, T0 + 30);
    assert_eq!(theirs.len(), 2);
    let o = find(&mut theirs, owned_id);
    assert_eq!(vault_name(o).unwrap().as_str(), "Work");
    assert_eq!(name_of(o, b).as_deref(), Some("in work"));
    assert_eq!(
        name_of(o, a),
        None,
        "an item of one vault is not in another"
    );
    let p = find(&mut theirs, personal);
    assert_eq!(name_of(p, a).as_deref(), Some("in personal"));
    assert_eq!(name_of(p, b), None);
}

#[test]
fn a_malicious_server_hiding_or_adding_a_vault_is_detected() {
    let mut rng = ChaCha20Rng::seed_from_u64(820);
    let mut server = Server::new(821);
    let (mut web, _) = web_account(&mut server, &mut rng);
    let counters = DeviceCounters::new();
    let before_state = server.stored().state.clone();
    let before_settings = server.stored().settings.clone();
    let pending = create_vault(&mut rng, &web.account, &web.unlocked).unwrap();
    let owned = pending.vault_id();
    commit_change(&mut server, &mut web, pending, &counters).unwrap();
    let honest = server.stored().grants.clone();

    // A listed vault withheld: an alarm, the vault not opened.
    server
        .account
        .as_mut()
        .unwrap()
        .grants
        .retain(|g| g.vault_id.to_bytes() != owned.to_bytes());
    refresh(&server, &mut web);
    let catalog = VaultCatalog::of_account(&web.account, &web.unlocked).unwrap();
    assert_eq!(catalog.alarms(), &[VaultAlarm::Withheld(owned)]);
    assert!(!catalog.is_open(owned));
    assert!(
        catalog
            .entries()
            .iter()
            .any(|e| e.vault_id == owned && e.status == VaultStatus::Withheld)
    );
    // No vault change is built on a vault set served inconsistently.
    assert_eq!(
        create_vault(&mut rng, &web.account, &web.unlocked).unwrap_err(),
        ClientError::VaultSetMismatch
    );

    // An unlisted vault served with a real self-grant: an alarm, never opened.
    let stranger = VaultId::generate(&mut rng);
    let key = VaultKey::generate(&mut rng, stranger, 0);
    let epoch = web.account.state().account_key_epoch;
    let envelope = web
        .unlocked
        .account_key
        .wrap_vault_key(
            &mut rng,
            &VaultKeySelfGrantCtx {
                account_id: web.account.account_id(),
                vault_id: stranger,
                account_key_epoch: epoch,
                vault_key_epoch: 0,
            },
            &key,
        )
        .unwrap();
    let mut grants = honest.clone();
    grants.push(VaultSelfGrant {
        vault_id: rizzy_proto::wire::Id::from_bytes(stranger.to_bytes()),
        account_key_epoch: epoch,
        vault_key_epoch: 0,
        envelope: KeyEnvelope::new(envelope).unwrap(),
    });
    grants.sort_by_key(|g| g.vault_id);
    server.account.as_mut().unwrap().grants = grants;
    refresh(&server, &mut web);
    let catalog = VaultCatalog::of_account(&web.account, &web.unlocked).unwrap();
    assert_eq!(catalog.alarms(), &[VaultAlarm::Unlisted(stranger)]);
    assert!(!catalog.is_open(stranger));
    assert!(catalog.is_open(owned));

    // The directory rolled back with the state that committed to it: the existing rollback
    // check refuses the answer (the server cannot rewrite the directory alone).
    let s = server.account.as_mut().unwrap();
    s.grants = honest;
    s.state = before_state;
    s.settings = before_settings;
    let view = server.view_since(&crate::login::web_account_query(&web.account));
    assert!(crate::login::verify_web_refresh(&web.account, &web.unlocked, &view).is_err());
}

#[test]
fn the_same_item_id_in_two_vaults_never_crosses() {
    let mut rng = ChaCha20Rng::seed_from_u64(830);
    let mut server = Server::new(831);
    let (mut web, _) = web_account(&mut server, &mut rng);
    let (counters, mut vaults) = open_all(&server, &mut web, T0 + 10);
    let personal = vaults[0].vault_id();
    let pending = create_vault(&mut rng, &web.account, &web.unlocked).unwrap();
    let owned_id = pending.vault_id();
    let mut owned = commit_change(&mut server, &mut web, pending, &counters).unwrap();
    owned.persist();
    index::track_new(&mut owned);
    let p = find(&mut vaults, personal);
    p.persist();
    index::track_new(p);

    let item = new_item(p, &mut rng, &web.unlocked, "alpha", T0 + 20);
    // The same id in the other vault, through the importer path.
    let key = SchemaKey::parse(ITEM_NAME.as_bytes()).unwrap();
    let value = text("bravo");
    let writes = [crate::items::ImportWrite {
        source: crate::items::WriteSource::Entered,
        key: &key,
        value: &value,
    }];
    owned
        .import_item_writes_as(
            &mut rng,
            &web.unlocked,
            item,
            ItemType::LOGIN,
            &writes,
            false,
            T0 + 21,
        )
        .unwrap();
    rename_item(
        &mut owned,
        &mut rng,
        &web.unlocked,
        item,
        "charlie",
        T0 + 22,
    );
    let p = find(&mut vaults, personal);
    assert_eq!(name_of(p, item).as_deref(), Some("alpha"));
    assert_eq!(name_of(&owned, item).as_deref(), Some("charlie"));

    // The local index keeps one row per (vault_id, item_id).
    let mut rows = CacheRows::default();
    rows.apply(&find(&mut vaults, personal).take_writes());
    rows.apply(&owned.take_writes());
    assert_eq!(rows.item_index.len(), 2);
    assert_eq!(index::search(&rows, "alpha", 10), vec![(personal, item)]);
    assert_eq!(index::search(&rows, "charlie", 10), vec![(owned_id, item)]);
    assert!(index::search(&rows, "bravo", 10).is_empty());
    let used = index::record_use(&owned, item, T0 + 30).unwrap();
    rows.apply(&[used].into_iter().collect());
    assert_eq!(index::recent(&rows, 10), vec![(owned_id, item)]);
    // Both vaults upload and fetch back their own item.
    upload(
        &mut server,
        find(&mut vaults, personal),
        &mut rng,
        &web.unlocked,
        true,
    );
    upload(&mut server, &mut owned, &mut rng, &web.unlocked, true);
    fetch(&server, &mut owned, T0 + 40);
    fetch(&server, find(&mut vaults, personal), T0 + 40);
    assert_eq!(
        name_of(find(&mut vaults, personal), item).as_deref(),
        Some("alpha")
    );
    assert_eq!(name_of(&owned, item).as_deref(), Some("charlie"));
}

#[test]
fn a_move_waits_for_the_target_and_a_deleted_vault_is_dropped_elsewhere() {
    let mut rng = ChaCha20Rng::seed_from_u64(840);
    let mut server = Server::new(841);
    let (mut web, sk) = web_account(&mut server, &mut rng);
    let (counters, mut vaults) = open_all(&server, &mut web, T0 + 10);
    let personal = vaults[0].vault_id();
    let pending = create_vault(&mut rng, &web.account, &web.unlocked).unwrap();
    let owned_id = pending.vault_id();
    let mut owned = commit_change(&mut server, &mut web, pending, &counters).unwrap();
    let item = new_item(&mut owned, &mut rng, &web.unlocked, "to move", T0 + 20);
    upload(&mut server, &mut owned, &mut rng, &web.unlocked, true);
    let mut other = web_login(&mut server, &mut rng, &sk);
    let other_before = VaultCatalog::of_account(&other.account, &other.unlocked).unwrap();

    let mv = PendingMove::new(&mut rng, &owned, item, personal).unwrap();
    let mut rows = CacheRows::default();
    rows.apply(&[mv.row_write()].into_iter().collect());
    assert_eq!(rows.pending_moves.len(), 1);
    let p = find(&mut vaults, personal);
    let copy = mv
        .copy(&mut rng, &web.unlocked, &owned, p, T0 + 30)
        .unwrap();
    assert!(copy.created && copy.item_id == mv.target_item);
    // Not acknowledged yet: the source is not touched (INV-104).
    assert_eq!(
        mv.finish(&mut rng, &web.unlocked, &mut owned, p, true, T0 + 31)
            .unwrap(),
        MoveStep::AwaitTarget
    );
    assert_eq!(owned.item_lifecycle(item), ItemLifecycle::Active);
    // Resumed after a restart, the copy is not written again.
    let again = mv
        .copy(&mut rng, &web.unlocked, &owned, p, T0 + 32)
        .unwrap();
    assert!(!again.created);
    upload(&mut server, p, &mut rng, &web.unlocked, true);
    // The host says an attachment upload is still running: still waiting.
    assert_eq!(
        mv.finish(&mut rng, &web.unlocked, &mut owned, p, false, T0 + 33)
            .unwrap(),
        MoveStep::AwaitTarget
    );
    assert_eq!(
        mv.finish(&mut rng, &web.unlocked, &mut owned, p, true, T0 + 34)
            .unwrap(),
        MoveStep::SourcePurged
    );
    assert_eq!(owned.item_lifecycle(item), ItemLifecycle::Purged);
    upload(&mut server, &mut owned, &mut rng, &web.unlocked, true);
    rows.apply(&[mv.done_write()].into_iter().collect());
    assert!(rows.pending_moves.is_empty());
    assert_eq!(name_of(p, mv.target_item).as_deref(), Some("to move"));

    // The vault goes; the other session drops it from its new directory (§A5).
    let pending = delete_vault(&mut rng, &web.account, &web.unlocked, owned_id).unwrap();
    assert!(pending.commit_request().vault_delete.is_some());
    assert!(commit_change(&mut server, &mut web, pending, &counters).is_none());
    let catalog = VaultCatalog::of_account(&web.account, &web.unlocked).unwrap();
    assert!(!catalog.is_open(owned_id) && catalog.alarms().is_empty());
    refresh(&server, &mut other);
    let other_after = VaultCatalog::of_account(&other.account, &other.unlocked).unwrap();
    assert_eq!(other_after.dropped_since(&other_before), vec![owned_id]);
    let (_, theirs) = open_all(&server, &mut other, T0 + 50);
    assert_eq!(theirs.len(), 1);
    assert_eq!(
        name_of(&theirs[0], mv.target_item).as_deref(),
        Some("to move")
    );
}

/// ADR 0081 §A6 step 2: an edit made offline on another session arrives after this session
/// moved the item and purged its source. It is a late op (ADR 0012 §5), surfaced once, and the
/// prompt names the vault the item went to, because this session recorded the move. Without
/// that record (another device, or a move of an item with the same id in another vault,
/// INV-103), the prompt is the plain "deleted permanently" one.
#[test]
fn late_ops_after_a_move_and_purge_name_the_target_vault() {
    let mut rng = ChaCha20Rng::seed_from_u64(850);
    let mut server = Server::new(851);
    let (mut web, sk) = web_account(&mut server, &mut rng);
    let (counters, mut vaults) = open_all(&server, &mut web, T0 + 10);
    let personal = vaults[0].vault_id();
    let pending = create_vault(&mut rng, &web.account, &web.unlocked).unwrap();
    let owned_id = pending.vault_id();
    let mut owned = commit_change(&mut server, &mut web, pending, &counters).unwrap();
    let item = new_item(&mut owned, &mut rng, &web.unlocked, "to move", T0 + 20);
    upload(&mut server, &mut owned, &mut rng, &web.unlocked, true);
    // The other session holds the item, then goes offline.
    let mut other = web_login(&mut server, &mut rng, &sk);
    let (_, mut theirs) = open_all(&server, &mut other, T0 + 25);
    assert_eq!(
        name_of(find(&mut theirs, owned_id), item).as_deref(),
        Some("to move")
    );

    // This session moves the item to the Personal vault: copy, acknowledged, source purged.
    let mv = PendingMove::new(&mut rng, &owned, item, personal).unwrap();
    let p = find(&mut vaults, personal);
    mv.copy(&mut rng, &web.unlocked, &owned, p, T0 + 30)
        .unwrap();
    upload(&mut server, p, &mut rng, &web.unlocked, true);
    assert_eq!(
        mv.finish(&mut rng, &web.unlocked, &mut owned, p, true, T0 + 31)
            .unwrap(),
        MoveStep::SourcePurged
    );
    upload(&mut server, &mut owned, &mut rng, &web.unlocked, true);
    assert_eq!(owned.item_lifecycle(item), ItemLifecycle::Purged);
    assert_eq!(late_edit(&owned, item, &[mv]), None, "nothing late yet");

    // The offline edit is injected after the move and the purge: concurrent with the purge.
    let o = find(&mut theirs, owned_id);
    rename_item(
        o,
        &mut rng,
        &other.unlocked,
        item,
        "edited offline",
        T0 + 40,
    );
    upload(&mut server, o, &mut rng, &other.unlocked, true);
    fetch(&server, &mut owned, T0 + 50);

    // It does not resurrect the item (ADR 0012 §5) and is surfaced naming the target vault.
    assert_eq!(owned.item_lifecycle(item), ItemLifecycle::Purged);
    assert_eq!(
        late_edit(&owned, item, &[mv]),
        Some(LateEdit {
            devices: vec![other.unlocked.device_id],
            moved_to: Some(personal),
        })
    );
    // Without this device's record of the move: the plain prompt.
    assert_eq!(late_edit(&owned, item, &[]).map(|l| l.moved_to), Some(None));
    // A record of a move of the same item id out of another vault names nothing (INV-103).
    let elsewhere = PendingMove {
        source_vault: personal,
        ..mv
    };
    assert_eq!(
        late_edit(&owned, item, &[elsewhere]).map(|l| l.moved_to),
        Some(None)
    );
    // The copy in the target is untouched by the late edit.
    let p = find(&mut vaults, personal);
    fetch(&server, p, T0 + 51);
    assert_eq!(name_of(p, mv.target_item).as_deref(), Some("to move"));
    // Surfaced once.
    owned.mark_late_edits_surfaced(item);
    assert_eq!(late_edit(&owned, item, &[mv]), None);
}

// --- Property tests ----------------------------------------------------------------------------

/// Two sessions of one account with four vaults (the Personal vault and three owned), shared
/// by every case: each session's drivers share its counters.
struct Fleet {
    server: Server,
    rng: ChaCha20Rng,
    /// The account's Secret Key, for more sessions.
    sk: String,
    sessions: Vec<(WebSession, Vec<VaultSync>)>,
    now: u64,
    /// Every item created, with its vault.
    items: Vec<(VaultId, ItemId)>,
}

impl Fleet {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut server = Server::new(seed + 1);
        let (mut web, sk) = web_account(&mut server, &mut rng);
        let counters = DeviceCounters::new();
        for _ in 0..3 {
            let pending = create_vault(&mut rng, &web.account, &web.unlocked).unwrap();
            commit_change(&mut server, &mut web, pending, &counters);
        }
        let mut first = web;
        let (_, a) = open_all(&server, &mut first, T0 + 10);
        let mut second = web_login(&mut server, &mut rng, &sk);
        let sk = sk.clone();
        let (_, b) = open_all(&server, &mut second, T0 + 10);
        assert_eq!(a.len(), 4);
        Self {
            server,
            rng,
            sk,
            sessions: vec![(first, a), (second, b)],
            now: T0 + 1_000,
            items: Vec::new(),
        }
    }

    fn tick(&mut self) -> u64 {
        self.now += 10;
        self.now
    }
}

/// One step of a session on one vault.
#[derive(Clone, Debug)]
enum Step {
    /// Create an item in vault `vault % n` on session `session`.
    Create { session: usize, vault: usize },
    /// Rename the item picked by `pick`.
    Rename {
        session: usize,
        pick: usize,
        name: u8,
    },
    /// Upload one vault of one session.
    Upload { session: usize, vault: usize },
    /// Fetch one vault of one session.
    Fetch { session: usize, vault: usize },
}

fn step_strategy(vaults: usize) -> impl Strategy<Value = Step> {
    prop_oneof![
        (0..2usize, 0..vaults).prop_map(|(session, vault)| Step::Create { session, vault }),
        (0..2usize, 0..64usize, any::<u8>()).prop_map(|(session, pick, name)| Step::Rename {
            session,
            pick,
            name
        }),
        (0..2usize, 0..vaults).prop_map(|(session, vault)| Step::Upload { session, vault }),
        (0..2usize, 0..vaults).prop_map(|(session, vault)| Step::Fetch { session, vault }),
    ]
}

fn runner(cases: u32) -> TestRunner {
    let config = ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    TestRunner::new_with_rng(
        config.clone(),
        TestRng::deterministic_rng(config.rng_algorithm),
    )
}

/// Runs `steps` over the first `n` vaults, then syncs everything and checks convergence per
/// vault and the allocator.
fn convergence_case(fleet: &mut Fleet, n: usize, steps: &[Step]) -> Result<(), TestCaseError> {
    for step in steps {
        let now = fleet.tick();
        match *step {
            Step::Create { session, vault } => {
                let (web, vaults) = &mut fleet.sessions[session];
                let v = &mut vaults[vault % n];
                let id = new_item(v, &mut fleet.rng, &web.unlocked, "new", now);
                fleet.items.push((v.vault_id(), id));
            }
            Step::Rename {
                session,
                pick,
                name,
            } => {
                if fleet.items.is_empty() {
                    continue;
                }
                let (vault_id, item) = fleet.items[pick % fleet.items.len()];
                let (web, vaults) = &mut fleet.sessions[session];
                let v = find(vaults, vault_id);
                if v.merge(item).is_some() {
                    rename_item(
                        v,
                        &mut fleet.rng,
                        &web.unlocked,
                        item,
                        &format!("n{name}"),
                        now,
                    );
                }
            }
            Step::Upload { session, vault } => {
                let (web, vaults) = &mut fleet.sessions[session];
                upload(
                    &mut fleet.server,
                    &mut vaults[vault % n],
                    &mut fleet.rng,
                    &web.unlocked,
                    true,
                );
            }
            Step::Fetch { session, vault } => {
                let (_, vaults) = &mut fleet.sessions[session];
                fetch(&fleet.server, &mut vaults[vault % n], now);
            }
        }
    }
    for _ in 0..2 {
        for s in 0..2 {
            let (web, vaults) = &mut fleet.sessions[s];
            for v in vaults.iter_mut() {
                upload(&mut fleet.server, v, &mut fleet.rng, &web.unlocked, true);
            }
        }
        let now = fleet.tick();
        for s in 0..2 {
            for v in &mut fleet.sessions[s].1 {
                fetch(&fleet.server, v, now);
            }
        }
    }
    for (vault_id, item) in &fleet.items {
        let names: Vec<Option<String>> = (0..2)
            .map(|s| {
                let v = fleet.sessions[s]
                    .1
                    .iter()
                    .find(|v| v.vault_id() == *vault_id)
                    .unwrap();
                name_of(v, *item)
            })
            .collect();
        prop_assert_eq!(&names[0], &names[1], "vault {:?} converges", vault_id);
        prop_assert!(names[0].is_some());
        // INV-103: the item lives only in its own vault.
        for s in 0..2 {
            for v in &fleet.sessions[s].1 {
                if v.vault_id() != *vault_id {
                    prop_assert!(v.merge(*item).is_none());
                }
            }
        }
    }
    for s in 0..2 {
        assert_allocator(&fleet.server, fleet.sessions[s].0.unlocked.device_id);
    }
    Ok(())
}

#[test]
fn ops_over_several_vaults_converge_per_vault_with_one_allocator() {
    let fleet = RefCell::new(Fleet::new(850));
    runner(12)
        .run(
            &(1..=4usize)
                .prop_flat_map(|n| (Just(n), proptest::collection::vec(step_strategy(n), 1..24))),
            |(n, steps)| convergence_case(&mut fleet.borrow_mut(), n, &steps),
        )
        .unwrap();
}

/// How the injected failure hits the step it stops at.
#[derive(Clone, Copy, Debug)]
enum Failure {
    /// The request never reaches the server.
    Unsent,
    /// The server stores it, but the answer is lost.
    AnswerLost,
}

/// Two distinct drivers of `vaults`, by index.
fn two_mut(vaults: &mut [VaultSync], a: usize, b: usize) -> (&mut VaultSync, &mut VaultSync) {
    assert_ne!(a, b);
    if a < b {
        let (l, r) = vaults.split_at_mut(b);
        (&mut l[a], &mut r[0])
    } else {
        let (l, r) = vaults.split_at_mut(a);
        (&mut r[0], &mut l[b])
    }
}

/// One move of a fresh item from an owned vault to the Personal vault, stopped by `failure`
/// at step `stop` (0: after the row; 1: after the copy; 2: at the target's upload; 3: after
/// the target was acknowledged; 4: at the source's upload of its trash and purge), checked from
/// a fresh session's view, then resumed from the row and completed.
#[expect(
    clippy::too_many_lines,
    reason = "one move through every step, the failure, the check and the resume, in order"
)]
fn move_case(
    fleet: &mut Fleet,
    name: &str,
    stop: usize,
    failure: Failure,
) -> Result<(), TestCaseError> {
    let now = fleet.tick();
    let (web, vaults) = &mut fleet.sessions[0];
    let personal = VaultCatalog::of_account(&web.account, &web.unlocked)
        .unwrap()
        .personal()
        .unwrap();
    let source_id = vaults
        .iter()
        .map(VaultSync::vault_id)
        .find(|v| *v != personal)
        .unwrap();
    let s = vaults
        .iter()
        .position(|v| v.vault_id() == source_id)
        .unwrap();
    let t = vaults
        .iter()
        .position(|v| v.vault_id() == personal)
        .unwrap();
    let (source, target) = two_mut(vaults, s, t);
    let item = new_item(source, &mut fleet.rng, &web.unlocked, name, now);
    upload(
        &mut fleet.server,
        source,
        &mut fleet.rng,
        &web.unlocked,
        true,
    );
    let mv = PendingMove::new(&mut fleet.rng, source, item, personal).unwrap();
    let mut rows = CacheRows::default();
    rows.apply(&[mv.row_write()].into_iter().collect());

    // The steps, up to the injected failure.
    let deliver = matches!(failure, Failure::AnswerLost);
    if stop > 0 {
        mv.copy(&mut fleet.rng, &web.unlocked, source, target, now)
            .unwrap();
    }
    if stop > 1 {
        if stop == 2 {
            if deliver {
                upload(
                    &mut fleet.server,
                    target,
                    &mut fleet.rng,
                    &web.unlocked,
                    false,
                );
            }
        } else {
            upload(
                &mut fleet.server,
                target,
                &mut fleet.rng,
                &web.unlocked,
                true,
            );
        }
    }
    if stop > 3 {
        let purged = mv
            .finish(&mut fleet.rng, &web.unlocked, source, target, true, now)
            .unwrap();
        prop_assert_eq!(purged, MoveStep::SourcePurged);
        if deliver {
            upload(
                &mut fleet.server,
                source,
                &mut fleet.rng,
                &web.unlocked,
                false,
            );
        }
    }

    // Whatever happened, the value is in at least one vault the server holds (INV-104).
    let mut watcher = web_login(&mut fleet.server, &mut fleet.rng, &fleet.sk);
    let (_, seen) = open_all(&fleet.server, &mut watcher, now);
    let held = seen
        .iter()
        .filter(|v| {
            name_of(v, item).as_deref() == Some(name)
                || name_of(v, mv.target_item).as_deref() == Some(name)
        })
        .count();
    prop_assert!(held >= 1, "the value survives a failure at step {stop}");

    // Resumed from the row: copy (no second copy), upload, finish, upload, drop the row.
    let row = PendingMove::of_row(&rows.pending_moves[0]);
    prop_assert_eq!(row, mv);
    if source.item_lifecycle(item) != ItemLifecycle::Purged {
        let copy = row
            .copy(&mut fleet.rng, &web.unlocked, source, target, now)
            .unwrap();
        prop_assert_eq!(copy.created, stop == 0);
    }
    upload(
        &mut fleet.server,
        target,
        &mut fleet.rng,
        &web.unlocked,
        true,
    );
    let resumed = row
        .finish(&mut fleet.rng, &web.unlocked, source, target, true, now)
        .unwrap();
    prop_assert_eq!(resumed, MoveStep::SourcePurged);
    upload(
        &mut fleet.server,
        source,
        &mut fleet.rng,
        &web.unlocked,
        true,
    );
    rows.apply(&[row.done_write()].into_iter().collect());
    prop_assert!(rows.pending_moves.is_empty());
    let moved = name_of(target, mv.target_item);
    prop_assert_eq!(moved.as_deref(), Some(name));
    prop_assert_eq!(name_of(source, item), None);
    Ok(())
}

#[test]
fn a_move_survives_a_failure_at_every_step() {
    let fleet = RefCell::new(Fleet::new(860));
    runner(4)
        .run(
            &("[a-z]{1,12}", 0..5usize, any::<bool>()),
            |(name, stop, lost)| {
                let failure = if lost {
                    Failure::AnswerLost
                } else {
                    Failure::Unsent
                };
                move_case(&mut fleet.borrow_mut(), &name, stop, failure)
            },
        )
        .unwrap();
    // And every step deterministically, both failure kinds.
    let mut fleet = fleet.into_inner();
    for stop in 0..5 {
        for failure in [Failure::Unsent, Failure::AnswerLost] {
            move_case(&mut fleet, &format!("fixed{stop}"), stop, failure).unwrap();
        }
    }
}

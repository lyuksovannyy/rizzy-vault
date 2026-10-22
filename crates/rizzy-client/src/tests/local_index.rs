// SPDX-License-Identifier: AGPL-3.0-only

//! The M3 local index ([ADR 0056] §6) against the fake server of the parent module:
//!
//! - the allow-list property (INV-80): for any item type and any mix of allow-listed and other
//!   field keys and values, the row holds exactly the allow-listed values of that type and
//!   nothing else, no other key's value or name included; the vault-settings item has no row;
//! - for any sequence of creates, edits, trashes, restores, purges, uses, uploads and fetches
//!   on two devices, the rows a device reaches by the incremental writes of each step equal the
//!   rebuild from its full merge after every step, a load-time reconcile of them writes nothing,
//!   the counters are kept by every edit, and both devices end with the same rows;
//! - the reference search: a Cyrillic query matches whatever its case, through Rust's
//!   `to_lowercase`; `LIKE` wildcards in a query are literal; the empty query is the recently
//!   used order;
//! - the format 2 → 3 migration and the table's own failure rule.
//!
//! The property tests share one pair of devices across their cases, as `conflicts.rs` does:
//! every signup and login runs a 64 MiB Argon2id.
//!
//! [ADR 0056]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0056-local-index-recently-used-search.md

use std::cell::RefCell;

use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::{Config as ProptestConfig, TestRng, TestRunner};
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_MS, ATTR_VALUE, CARD_BRAND, CARD_CODE, CARD_HOLDER, CARD_NUMBER,
    CARD_PIN, CUSTOM_KIND_BOOLEAN, CUSTOM_KIND_HIDDEN, CUSTOM_KIND_TEXT, IDENTITY_COMPANY,
    IDENTITY_EMAIL, IDENTITY_FIRST_NAME, IDENTITY_LAST_NAME, IDENTITY_MIDDLE_NAME, IDENTITY_TITLE,
    ITEM_NAME, ITEM_NOTES, ITEM_TYPE, LIST_FIELD, LIST_PWHIST, LIST_URI, LOGIN_TOTP,
};
use rizzy_core::item::tag::tag_key;
use rizzy_sync::record::Lifecycle;

use super::late_edits::enrol_another_device;
use super::*;
use crate::store::index::{self, IndexEntry, IndexRow, SEPARATOR};
use crate::store::load::migration_writes;
use crate::store::rows::{CACHE_FORMAT, CacheRows, Changeset, Write, meta};
use crate::sync::OwnChange;

/// One device: its driver, its keys, and its cache rows (the reference executor).
struct Device {
    vault: VaultSync,
    unlocked: UnlockedDevice,
    rows: CacheRows,
}

/// Two devices of one account on one fake server.
struct Fleet {
    server: Server,
    rng: ChaCha20Rng,
    devices: Vec<Device>,
    now: u64,
    /// Every item created, by any case, for the actions to pick from.
    items: Vec<ItemId>,
    /// The uses each device recorded, per item: what its counters must say.
    uses: Vec<BTreeMap<[u8; 16], (u64, u64)>>,
}

impl Fleet {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut server = Server::new(seed + 1);
        let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
        let sk = secret_key_text(a.device.as_ref().unwrap());
        let vault_id = a.vault_key.vault_id();
        let mut first = VaultSync::new(a.vault_key, &a.unlocked, 1).unwrap();
        first.persist();
        index::track_new(&mut first);
        let mut devices = vec![Device {
            vault: first,
            unlocked: a.unlocked,
            rows: CacheRows::default(),
        }];
        let e = enrol_another_device(&mut server, &mut rng, &sk);
        let mut account = e.account;
        let mut second =
            VaultSync::new(account.take_vault_key(vault_id).unwrap(), &e.unlocked, 1).unwrap();
        second.persist();
        index::track_new(&mut second);
        devices.push(Device {
            vault: second,
            unlocked: e.unlocked,
            rows: CacheRows::default(),
        });
        let mut fleet = Self {
            server,
            rng,
            devices,
            now: T0 + 2000,
            items: Vec::new(),
            uses: vec![BTreeMap::new(), BTreeMap::new()],
        };
        for i in 0..2 {
            fleet.fetch(i);
        }
        fleet
    }

    fn tick(&mut self) -> u64 {
        self.now += 10;
        self.now
    }

    /// Commits what device `i` journaled, then checks its index against its merge.
    fn flush(&mut self, i: usize) {
        let d = &mut self.devices[i];
        let writes = d.vault.take_writes();
        d.rows.apply(&writes);
        assert_consistent(d);
    }

    fn upload(&mut self, i: usize) {
        let d = &mut self.devices[i];
        if let Some(up) = d.vault.upload_request(&mut self.rng, &d.unlocked).unwrap() {
            let answer = self.server.upload(&up);
            let outcome = d.vault.apply_upload_response(&answer).unwrap();
            assert!(outcome.rejected.is_empty(), "{:?}", outcome.rejected);
        }
        self.flush(i);
    }

    fn fetch(&mut self, i: usize) {
        let now = self.tick();
        let authors = self.server.authors();
        let d = &mut self.devices[i];
        let response = self.server.fetch(&d.vault.fetch_request().unwrap());
        d.vault.apply_fetch(&authors, &response, now).unwrap();
        self.flush(i);
    }

    fn sync_all(&mut self) {
        for _ in 0..2 {
            for i in 0..2 {
                self.upload(i);
            }
            for i in 0..2 {
                self.fetch(i);
            }
        }
    }

    /// One raw own op on device `i`: any keys, past the schema checks, as a hostile or newer
    /// client could write them.
    fn raw(&mut self, i: usize, item: ItemId, writes: &[(String, Value)]) {
        let now = self.tick();
        let d = &mut self.devices[i];
        let pairs: Vec<(&str, &[u8])> = writes
            .iter()
            .map(|(k, v)| (k.as_str(), v.expose_secret()))
            .collect();
        d.vault
            .write_op(
                &mut self.rng,
                &d.unlocked,
                item,
                &OwnChange {
                    lifecycle: Lifecycle::Active,
                    writes: &pairs,
                },
                now,
            )
            .unwrap();
        self.flush(i);
    }

    /// Records one use of `item` on device `i`, as a host does when the user views it.
    fn record_use(&mut self, i: usize, item: ItemId) {
        let now = self.tick();
        let d = &mut self.devices[i];
        if let Some(write) = index::record_use(&d.vault, item, now) {
            d.rows.apply(&std::iter::once(write).collect::<Changeset>());
            let entry = self.uses[i].entry(item.to_bytes()).or_insert((0, 0));
            *entry = (now, entry.1 + 1);
        }
        assert_consistent(&self.devices[i]);
    }
}

/// The stored rows of `d`, parsed, without their counters.
fn stored(rows: &CacheRows) -> BTreeMap<[u8; 16], IndexEntry> {
    rows.item_index
        .iter()
        .map(|r| {
            let parsed = r.parse().unwrap();
            (parsed.entry.item_id, parsed.entry)
        })
        .collect()
}

/// The rows the incremental writes reached are the rebuild from the full merge, and a
/// load-time reconcile of them changes nothing (ADR 0056 §6).
fn assert_consistent(d: &Device) {
    let rebuilt = index::project_vault(&d.vault);
    let held = stored(&d.rows);
    assert!(held == rebuilt, "incremental rows differ from the rebuild");
    let mut seen = std::collections::BTreeSet::new();
    for row in &d.rows.item_index {
        assert!(seen.insert(row.item_id.clone()), "one row per item");
    }
}

/// A random 16-byte element id, as lowercase hex.
fn element(rng: &mut ChaCha20Rng) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    hex_of(&bytes)
}

fn text(s: &str) -> Value {
    Value::text(s).unwrap()
}

/// Cyrillic text, upper and lower case: the only alphabet the allow-listed values of the
/// INV-80 property use, so an ASCII letter in a row can only be a leak.
fn cyrillic() -> impl Strategy<Value = String> {
    "[А-Яа-яЁё]{1,6}"
}

/// The allow-listed and the other content of one item of the INV-80 property.
#[derive(Clone, Debug)]
struct Spec {
    /// `item.type`; `None` writes none.
    item_type: Option<u16>,
    name: Option<String>,
    /// Values of the type-specific allow-listed keys, by key.
    fixed: Vec<(&'static str, String)>,
    uris: Vec<String>,
    tags: Vec<String>,
    /// Text custom fields: label and value.
    custom: Vec<(Option<String>, Option<String>)>,
    /// How many of the never-indexed fields to write (each with an ASCII marker value).
    others: usize,
}

fn spec_strategy() -> impl Strategy<Value = Spec> {
    let fixed_keys = proptest::sample::subsequence(
        vec![
            LOGIN_USERNAME,
            CARD_HOLDER,
            CARD_BRAND,
            IDENTITY_TITLE,
            IDENTITY_FIRST_NAME,
            IDENTITY_MIDDLE_NAME,
            IDENTITY_LAST_NAME,
            IDENTITY_COMPANY,
            IDENTITY_EMAIL,
        ],
        0..=9,
    );
    (
        prop_oneof![
            Just(None),
            (1u16..=9).prop_map(Some),
            Just(Some(0x0123)),
            Just(Some(0)),
        ],
        proptest::option::of(cyrillic()),
        fixed_keys.prop_flat_map(|keys| {
            let n = keys.len();
            (Just(keys), proptest::collection::vec(cyrillic(), n))
        }),
        proptest::collection::vec(cyrillic(), 0..3),
        proptest::collection::vec(cyrillic(), 0..3),
        proptest::collection::vec(
            (
                proptest::option::of(cyrillic()),
                proptest::option::of(cyrillic()),
            ),
            0..3,
        ),
        0usize..=OTHER_FIELDS,
    )
        .prop_map(
            |(item_type, name, (keys, values), uris, tags, custom, others)| Spec {
                item_type,
                name,
                fixed: keys.into_iter().zip(values).collect(),
                uris,
                tags,
                custom,
                others,
            },
        )
}

/// How many never-indexed fields [`other_writes`] knows.
const OTHER_FIELDS: usize = 16;

/// The first `n` never-indexed writes: concealed fields, imported password history,
/// `identity.drivers_license`, `item.notes`, custom fields of every kind but text (label
/// included), one without a kind, a key no schema knows, and keys of the ADR 0055 types. Every
/// value is an ASCII marker.
fn other_writes(rng: &mut ChaCha20Rng, n: usize) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = Vec::new();
    let marker = |i: usize| text(&format!("Secret{i}Marker"));
    let field = |rng: &mut ChaCha20Rng, kind: Option<u16>, i: usize| {
        let e = element(rng);
        let mut w = vec![
            (format!("{LIST_FIELD}/{e}/{ATTR_LABEL}"), marker(i)),
            (format!("{LIST_FIELD}/{e}/{ATTR_VALUE}"), marker(i + 100)),
        ];
        if let Some(kind) = kind {
            w.push((
                format!("{LIST_FIELD}/{e}/{ATTR_KIND}"),
                Value::enumeration(kind),
            ));
        }
        w
    };
    for i in 0..n {
        match i {
            0 => out.push((LOGIN_PASSWORD.to_owned(), marker(i))),
            1 => out.push((LOGIN_TOTP.to_owned(), marker(i))),
            2 => {
                let e = element(rng);
                out.push((format!("{LIST_PWHIST}/{e}/{ATTR_VALUE}"), marker(i)));
                out.push((format!("{LIST_PWHIST}/{e}/{ATTR_MS}"), Value::u64(7)));
            }
            3 => out.push(("identity.drivers_license".to_owned(), marker(i))),
            4 => out.push(("identity.ssn".to_owned(), marker(i))),
            5 => out.push(("identity.passport_number".to_owned(), marker(i))),
            6 => out.push((ITEM_NOTES.to_owned(), marker(i))),
            7 => out.push((CARD_NUMBER.to_owned(), marker(i))),
            8 => out.push((CARD_CODE.to_owned(), marker(i))),
            9 => out.push((CARD_PIN.to_owned(), marker(i))),
            10 => out.extend(field(rng, Some(CUSTOM_KIND_HIDDEN), i)),
            11 => {
                let e = element(rng);
                out.push((format!("{LIST_FIELD}/{e}/{ATTR_LABEL}"), marker(i)));
                out.push((format!("{LIST_FIELD}/{e}/{ATTR_VALUE}"), Value::bool(true)));
                out.push((
                    format!("{LIST_FIELD}/{e}/{ATTR_KIND}"),
                    Value::enumeration(CUSTOM_KIND_BOOLEAN),
                ));
            }
            12 => out.extend(field(rng, Some(7), i)),
            13 => out.extend(field(rng, None, i)),
            14 => out.push(("zzunlisted.qq".to_owned(), marker(i))),
            _ => {
                out.push(("ssh.private_key".to_owned(), marker(i)));
                out.push(("bank.account_number".to_owned(), marker(i + 1)));
            }
        }
    }
    out
}

/// What the row of `spec` must hold (module docs of `store::index`): the name, and the
/// allow-listed values its type indexes, lower-cased; sorted, as the order is the list order.
fn expected(spec: &Spec) -> (String, Vec<String>) {
    let display = spec.name.as_deref().unwrap_or("").to_lowercase();
    let mut parts: Vec<String> = Vec::new();
    let keys: &[&str] = match spec.item_type {
        Some(1) => &[LOGIN_USERNAME],
        Some(3) => &[CARD_HOLDER, CARD_BRAND],
        Some(4) => &[
            IDENTITY_TITLE,
            IDENTITY_FIRST_NAME,
            IDENTITY_MIDDLE_NAME,
            IDENTITY_LAST_NAME,
            IDENTITY_COMPANY,
            IDENTITY_EMAIL,
        ],
        _ => &[],
    };
    for (key, value) in &spec.fixed {
        if keys.contains(key) {
            parts.push(value.to_lowercase());
        }
    }
    if spec.item_type == Some(1) {
        parts.extend(spec.uris.iter().map(|u| u.to_lowercase()));
    }
    if matches!(spec.item_type, Some(1..=4)) {
        let mut tags: Vec<String> = spec.tags.clone();
        tags.sort();
        tags.dedup();
        parts.extend(tags.iter().map(|t| t.to_lowercase()));
        for (label, value) in &spec.custom {
            parts.extend(label.iter().map(|l| l.to_lowercase()));
            parts.extend(value.iter().map(|v| v.to_lowercase()));
        }
    }
    parts.sort();
    (display, parts)
}

/// Writes `spec` as one new item on device 0 and returns it.
fn write_spec(fleet: &mut Fleet, spec: &Spec) -> ItemId {
    let item = ItemId::generate(&mut fleet.rng);
    let mut writes: Vec<(String, Value)> = Vec::new();
    if let Some(t) = spec.item_type {
        writes.push((ITEM_TYPE.to_owned(), Value::enumeration(t)));
    }
    if let Some(name) = &spec.name {
        writes.push((ITEM_NAME.to_owned(), text(name)));
    }
    for (key, value) in &spec.fixed {
        writes.push(((*key).to_owned(), text(value)));
    }
    for uri in &spec.uris {
        let e = element(&mut fleet.rng);
        writes.push((format!("{LIST_URI}/{e}/{ATTR_VALUE}"), text(uri)));
    }
    let mut tags = spec.tags.clone();
    tags.sort();
    tags.dedup();
    for tag in &tags {
        let key = tag_key(tag).unwrap();
        writes.push((key.as_str().to_owned(), Value::bool(true)));
    }
    for (label, value) in &spec.custom {
        let e = element(&mut fleet.rng);
        writes.push((
            format!("{LIST_FIELD}/{e}/{ATTR_KIND}"),
            Value::enumeration(CUSTOM_KIND_TEXT),
        ));
        if let Some(label) = label {
            writes.push((format!("{LIST_FIELD}/{e}/{ATTR_LABEL}"), text(label)));
        }
        if let Some(value) = value {
            writes.push((format!("{LIST_FIELD}/{e}/{ATTR_VALUE}"), text(value)));
        }
    }
    let others = other_writes(&mut fleet.rng, spec.others);
    writes.extend(others);
    writes.sort_by(|a, b| a.0.cmp(&b.0));
    writes.dedup_by(|a, b| a.0 == b.0);
    fleet.raw(0, item, &writes);
    item
}

fn inv80_case(fleet: &mut Fleet, spec: &Spec) -> Result<(), TestCaseError> {
    let item = write_spec(fleet, spec);
    let entry = index::project(&fleet.devices[0].vault, item).unwrap();
    let (display, parts) = expected(spec);
    prop_assert_eq!(entry.display_name.as_str(), display.as_str());
    let mut got: Vec<String> = if entry.search_text.is_empty() {
        Vec::new()
    } else {
        entry
            .search_text
            .split(SEPARATOR)
            .map(str::to_owned)
            .collect()
    };
    got.sort();
    prop_assert_eq!(&got, &parts);
    // No marker value and no key's name, ASCII all of them, ever reaches the row.
    for column in [entry.display_name.as_str(), entry.search_text.as_str()] {
        prop_assert!(
            !column
                .bytes()
                .any(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
        );
    }
    prop_assert_eq!(entry.item_type, spec.item_type.unwrap_or(0));
    // The committed row is that entry.
    let rows = stored(&fleet.devices[0].rows);
    prop_assert!(rows.get(&item.to_bytes()) == Some(&entry));
    Ok(())
}

fn runner(cases: u32, fixed: bool) -> TestRunner {
    let config = ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    if fixed {
        TestRunner::new_with_rng(
            config.clone(),
            TestRng::deterministic_rng(config.rng_algorithm),
        )
    } else {
        TestRunner::new(config)
    }
}

fn run_inv80(cases: u32, fixed: bool) {
    let fleet = RefCell::new(Fleet::new(5600));
    let result = runner(cases, fixed).run(&spec_strategy(), |spec| {
        inv80_case(&mut fleet.borrow_mut(), &spec)
    });
    if let Err(e) = result {
        panic!("{e}");
    }
}

/// INV-80 (ADR 0056 §2): a row holds the allow-listed values of its item's type and nothing
/// else; an M3 type, an unknown type and an item without a valid type are indexed by
/// `item.name` only (owner answer 5). PR budget, deterministic seeds.
#[test]
fn the_index_holds_only_the_allow_list() {
    run_inv80(96, true);
}

#[test]
#[ignore = "nightly budget: 10x the PR cases on fresh seeds"]
fn nightly_the_index_holds_only_the_allow_list() {
    run_inv80(960, false);
}

/// One action of the sequence property.
#[derive(Clone, Debug)]
enum Action {
    Create {
        device: usize,
        kind: u8,
        name: String,
    },
    Edit {
        device: usize,
        pick: Index,
        what: u8,
        value: String,
    },
    Trash {
        device: usize,
        pick: Index,
    },
    Restore {
        device: usize,
        pick: Index,
    },
    Purge {
        device: usize,
        pick: Index,
    },
    Use {
        device: usize,
        pick: Index,
    },
    Upload {
        device: usize,
    },
    Fetch {
        device: usize,
    },
}

fn action_strategy() -> impl Strategy<Value = Action> {
    let device = || 0usize..2;
    prop_oneof![
        3 => (device(), 0u8..6, cyrillic()).prop_map(|(device, kind, name)| Action::Create { device, kind, name }),
        4 => (device(), any::<Index>(), 0u8..6, cyrillic())
            .prop_map(|(device, pick, what, value)| Action::Edit { device, pick, what, value }),
        1 => (device(), any::<Index>()).prop_map(|(device, pick)| Action::Trash { device, pick }),
        1 => (device(), any::<Index>()).prop_map(|(device, pick)| Action::Restore { device, pick }),
        1 => (device(), any::<Index>()).prop_map(|(device, pick)| Action::Purge { device, pick }),
        2 => (device(), any::<Index>()).prop_map(|(device, pick)| Action::Use { device, pick }),
        2 => device().prop_map(|device| Action::Upload { device }),
        2 => device().prop_map(|device| Action::Fetch { device }),
    ]
}

/// The item an action picks, if any exists.
fn pick(fleet: &Fleet, pick: Index) -> Option<ItemId> {
    (!fleet.items.is_empty()).then(|| fleet.items[pick.index(fleet.items.len())])
}

/// Runs one edit, ignoring a refusal (an edit of a trashed item, a field another type does not
/// have): a refused write writes nothing.
fn edit(fleet: &mut Fleet, device: usize, item: ItemId, what: u8, value: &str) {
    let now = fleet.tick();
    let e = element(&mut fleet.rng);
    let edits: Vec<(String, Value)> = match what {
        0 => vec![(ITEM_NAME.to_owned(), text(value))],
        1 => vec![(LOGIN_USERNAME.to_owned(), text(value))],
        2 => vec![(
            tag_key(value).unwrap().as_str().to_owned(),
            Value::bool(true),
        )],
        3 => vec![
            (
                format!("{LIST_FIELD}/{e}/{ATTR_KIND}"),
                Value::enumeration(CUSTOM_KIND_TEXT),
            ),
            (format!("{LIST_FIELD}/{e}/{ATTR_LABEL}"), text(value)),
        ],
        4 => vec![(format!("{LIST_URI}/{e}/{ATTR_VALUE}"), text(value))],
        _ => vec![(LOGIN_PASSWORD.to_owned(), text("Hunter2"))],
    };
    let keys: Vec<SchemaKey> = edits
        .iter()
        .map(|(k, _)| SchemaKey::parse(k.as_bytes()).unwrap())
        .collect();
    let fields: Vec<FieldEdit<'_>> = keys
        .iter()
        .zip(&edits)
        .map(|(key, (_, value))| FieldEdit { key, value })
        .collect();
    let d = &mut fleet.devices[device];
    let _ = d
        .vault
        .edit_item(&mut fleet.rng, &d.unlocked, item, &fields, now);
}

fn apply_action(fleet: &mut Fleet, action: &Action) {
    match action {
        Action::Create { device, kind, name } => {
            let device = *device;
            let item = if *kind < 4 {
                let item_type = ItemType::from_id(u16::from(*kind) + 1);
                let now = fleet.tick();
                let key = SchemaKey::parse(ITEM_NAME.as_bytes()).unwrap();
                let value = text(name);
                let d = &mut fleet.devices[device];
                d.vault
                    .create_item(
                        &mut fleet.rng,
                        &d.unlocked,
                        item_type,
                        &[FieldEdit {
                            key: &key,
                            value: &value,
                        }],
                        now,
                    )
                    .unwrap()
            } else {
                // An ADR 0055 type (or an unassigned one), written raw: indexed by name only.
                let item = ItemId::generate(&mut fleet.rng);
                let id = if *kind == 4 { 0x0005 } else { 0x0123 };
                fleet.raw(
                    device,
                    item,
                    &[
                        (ITEM_NAME.to_owned(), text(name)),
                        (ITEM_TYPE.to_owned(), Value::enumeration(id)),
                        (LOGIN_USERNAME.to_owned(), text("Hidden")),
                    ],
                );
                item
            };
            fleet.items.push(item);
            fleet.flush(device);
        }
        Action::Edit {
            device,
            pick: p,
            what,
            value,
        } => {
            if let Some(item) = pick(fleet, *p) {
                edit(fleet, *device, item, *what, value);
                fleet.flush(*device);
            }
        }
        Action::Trash { device, pick: p }
        | Action::Restore { device, pick: p }
        | Action::Purge { device, pick: p } => {
            let Some(item) = pick(fleet, *p) else {
                return;
            };
            let now = fleet.tick();
            let d = &mut fleet.devices[*device];
            let _ = match action {
                Action::Trash { .. } => d.vault.trash_item(&mut fleet.rng, &d.unlocked, item, now),
                Action::Restore { .. } => {
                    d.vault.restore_item(&mut fleet.rng, &d.unlocked, item, now)
                }
                _ => d.vault.purge_item(&mut fleet.rng, &d.unlocked, item, now),
            };
            fleet.flush(*device);
        }
        Action::Use { device, pick: p } => {
            if let Some(item) = pick(fleet, *p) {
                fleet.record_use(*device, item);
            }
        }
        Action::Upload { device } => fleet.upload(*device),
        Action::Fetch { device } => fleet.fetch(*device),
    }
}

fn sequence_case(fleet: &mut Fleet, actions: &[Action]) -> Result<(), TestCaseError> {
    for action in actions {
        apply_action(fleet, action);
    }
    fleet.sync_all();
    let a = stored(&fleet.devices[0].rows);
    let b = stored(&fleet.devices[1].rows);
    prop_assert!(a == b, "both devices hold the same rows after a full sync");
    for (i, d) in fleet.devices.iter_mut().enumerate() {
        // A load-time reconcile of these rows writes nothing.
        let writes = index::reconcile(&d.rows, core::slice::from_mut(&mut d.vault));
        prop_assert!(writes.is_empty());
        // The counters are the uses this device recorded, kept through every edit, sync and
        // trash; gone with a purged item's row; never another device's.
        for row in &d.rows.item_index {
            let parsed = row.parse().unwrap();
            let want = fleet.uses[i].get(&parsed.entry.item_id).copied();
            prop_assert_eq!(
                (parsed.last_used_ms, parsed.use_count),
                want.map_or((None, 0), |(at, n)| (Some(at), n))
            );
        }
    }
    Ok(())
}

fn run_sequences(cases: u32, fixed: bool) {
    let fleet = RefCell::new(Fleet::new(5610));
    let result = runner(cases, fixed).run(
        &proptest::collection::vec(action_strategy(), 1..14),
        |actions| sequence_case(&mut fleet.borrow_mut(), &actions),
    );
    if let Err(e) = result {
        panic!("{e}");
    }
}

/// ADR 0056 §4, §6: the incremental rows equal the rebuild from the full merge after every
/// step, for any sequence of edits, deletes and syncs on two devices (so for every op order a
/// device can see), and both devices converge to the same rows. PR budget, deterministic seeds.
#[test]
fn the_index_follows_the_vault_through_any_sequence() {
    run_sequences(32, true);
}

#[test]
#[ignore = "nightly budget: 10x the PR cases on fresh seeds"]
fn nightly_the_index_follows_the_vault_through_any_sequence() {
    run_sequences(320, false);
}

/// ADR 0018 §8, ADR 0056 §2: the vault-settings item never has a row.
#[test]
fn the_vault_settings_item_is_never_a_row() {
    let mut fleet = Fleet::new(5620);
    let item = ItemId::generate(&mut fleet.rng);
    fleet.raw(
        0,
        item,
        &[
            (ITEM_TYPE.to_owned(), Value::enumeration(0xF001)),
            ("vault.name".to_owned(), text("Personal")),
        ],
    );
    assert!(index::project(&fleet.devices[0].vault, item).is_none());
    assert!(fleet.devices[0].rows.item_index.is_empty());
    assert!(index::record_use(&fleet.devices[0].vault, item, T0).is_none());
}

/// Rows for the reference search, with counters: `(name, search_text, last_used_ms)`.
fn search_rows(rows: &[(&str, &str, Option<u64>)]) -> (CacheRows, Vec<ItemId>) {
    let mut cache = CacheRows::default();
    let mut ids = Vec::new();
    for (i, (name, search, used)) in rows.iter().enumerate() {
        let mut id = [0u8; 16];
        id[15] = u8::try_from(i).unwrap() + 1;
        ids.push(ItemId::from_bytes(id));
        let entry = IndexEntry {
            item_id: id,
            vault_id: [9; 16],
            item_type: 1,
            display_name: Zeroizing::new(name.to_lowercase()),
            search_text: Zeroizing::new(search.to_lowercase()),
        };
        let mut row = IndexRow::new(&entry);
        row.last_used_ms = used.map(|u| u.to_be_bytes().to_vec());
        row.use_count = i64::from(used.is_some());
        cache.item_index.push(row);
    }
    (cache, ids)
}

/// ADR 0056 §5, §6: the Cyrillic lower-casing vector — a query matches whatever its case, through
/// Rust's Unicode `to_lowercase`, which `SQLite`'s ASCII-only `lower()` would not do.
#[test]
fn a_cyrillic_query_matches_in_any_case() {
    let (rows, ids) = search_rows(&[
        ("Почта Иван", "ivan@example.com", None),
        ("Банк", "ПЁТР", Some(T0)),
        ("ascii Name", "", None),
    ]);
    assert_eq!(index::normalize_query("  ИВАН ").as_str(), "иван");
    for query in ["иван", "ИВАН", "Иван", "иВаН"] {
        assert_eq!(index::search(&rows, query, 10), [ids[0]], "{query}");
    }
    for query in ["пётр", "ПЁТР", "Пётр"] {
        assert_eq!(index::search(&rows, query, 10), [ids[1]], "{query}");
    }
    assert_eq!(index::search(&rows, "NAME", 10), [ids[2]]);
    assert!(index::search(&rows, "петр", 10).is_empty(), "ё is not е");
}

/// ADR 0056 §5: `%`, `_` and `\` in a query are literal; the empty query matches every row,
/// most recently used first; `recent` lists only used rows.
#[test]
fn wildcards_are_literal_and_the_empty_query_is_recently_used() {
    assert_eq!(index::like_pattern("a%b_c\\d").as_str(), "%a\\%b\\_c\\\\d%");
    assert_eq!(index::like_pattern("").as_str(), "%%");
    let (rows, ids) = search_rows(&[
        ("b", "100% sure", Some(T0 + 1)),
        ("a", "x_y", None),
        ("c", "", Some(T0 + 5)),
        ("d", "", None),
    ]);
    assert_eq!(index::search(&rows, "%", 10), [ids[0]]);
    assert_eq!(index::search(&rows, "_", 10), [ids[1]]);
    assert!(index::search(&rows, "x%y", 10).is_empty());
    assert_eq!(
        index::search(&rows, "", 10),
        [ids[2], ids[0], ids[1], ids[3]]
    );
    assert_eq!(index::search(&rows, "", 2), [ids[2], ids[0]]);
    assert_eq!(index::recent(&rows, 10), [ids[2], ids[0]]);
}

/// Format 2 → 3 (ADR 0056 §3, §6): one write, the format bump, and nothing else — no other row
/// is touched and the new table is empty; 1 → 3 runs both steps; a format-2 cache that already
/// holds index rows is corrupt.
#[test]
fn the_format_2_to_3_migration_only_adds_the_table() {
    let mut rows = CacheRows::default();
    rows.meta
        .insert(meta::FORMAT.to_owned(), 2u16.to_be_bytes().to_vec());
    rows.meta.insert(
        meta::HIGHEST_EQUIVALENCE_LIST_VERSION.to_owned(),
        5u64.to_be_bytes().to_vec(),
    );
    let migration = migration_writes(&rows).unwrap();
    assert_eq!(migration.writes().len(), 1);
    assert!(matches!(
        migration.writes()[0],
        Write::Meta { key: meta::FORMAT, ref value } if value == &CACHE_FORMAT.to_be_bytes()
    ));
    rows.apply(&migration);
    assert_eq!(rows.meta.len(), 2);
    assert_eq!(
        rows.meta[meta::HIGHEST_EQUIVALENCE_LIST_VERSION],
        5u64.to_be_bytes()
    );
    assert!(rows.item_index.is_empty());
    assert!(migration_writes(&rows).unwrap().is_empty());

    let mut old = CacheRows::default();
    old.meta
        .insert(meta::FORMAT.to_owned(), 1u16.to_be_bytes().to_vec());
    let migration = migration_writes(&old).unwrap();
    old.apply(&migration);
    assert_eq!(old.meta[meta::FORMAT], CACHE_FORMAT.to_be_bytes());
    assert_eq!(
        old.meta[meta::HIGHEST_EQUIVALENCE_LIST_VERSION],
        0u64.to_be_bytes()
    );

    let mut odd = CacheRows::default();
    odd.meta
        .insert(meta::FORMAT.to_owned(), 2u16.to_be_bytes().to_vec());
    odd.item_index.push(IndexRow::default());
    assert_eq!(
        migration_writes(&odd).unwrap_err(),
        ClientError::CacheCorrupt
    );
}

/// ADR 0056 §4: a row that does not parse, two rows of one item, or a table the host could not
/// read rebuilds the table alone from the merge (the counters go with it); a stored row that
/// parses keeps its counters, and a row of an item the vault does not hold is deleted.
#[test]
fn a_corrupt_index_is_rebuilt_alone() {
    let mut fleet = Fleet::new(5630);
    for name in ["Один", "Два"] {
        apply_action(
            &mut fleet,
            &Action::Create {
                device: 0,
                kind: 0,
                name: name.to_owned(),
            },
        );
    }
    let first = fleet.items[0];
    fleet.record_use(0, first);
    let good = fleet.devices[0].rows.item_index.clone();
    let rebuilt_from = |rows: &CacheRows, fleet: &mut Fleet| -> Changeset {
        index::reconcile(rows, core::slice::from_mut(&mut fleet.devices[0].vault))
    };

    // A stray row of an unknown item is deleted, the others keep their counters.
    let mut rows = CacheRows::default();
    rows.item_index.clone_from(&good);
    let mut stray = good[0].clone();
    stray.item_id = vec![0xEE; 16];
    rows.item_index.push(stray);
    let writes = rebuilt_from(&rows, &mut fleet);
    assert_eq!(writes.writes().len(), 1);
    assert!(matches!(writes.writes()[0], Write::IndexDelete { item_id } if item_id == [0xEE; 16]));
    rows.apply(&writes);
    assert_eq!(rows.item_index.len(), 2);
    let used = rows
        .item_index
        .iter()
        .find(|r| r.item_id == first.to_bytes())
        .unwrap();
    assert_eq!(used.use_count, 1);

    let corruptions: [fn(&mut IndexRow); 6] = [
        |r| r.item_id.truncate(15),
        |r| r.vault_id.push(0),
        |r| r.display_name = Zeroizing::new(vec![0xFF, 0xFE]),
        |r| r.search_text = Zeroizing::new(vec![0xC0]),
        |r| r.last_used_ms = Some(vec![1, 2, 3]),
        |r| r.use_count = -1,
    ];
    for corrupt in corruptions {
        let mut rows = CacheRows::default();
        rows.item_index.clone_from(&good);
        corrupt(&mut rows.item_index[0]);
        let writes = rebuilt_from(&rows, &mut fleet);
        assert!(matches!(writes.writes()[0], Write::IndexReset));
        rows.apply(&writes);
        assert!(stored(&rows) == index::project_vault(&fleet.devices[0].vault));
        assert!(rows.item_index.iter().all(|r| r.use_count == 0));
    }
    let mut rows = CacheRows::default();
    rows.item_index.clone_from(&good);
    rows.item_index.push(good[0].clone());
    assert!(matches!(
        rebuilt_from(&rows, &mut fleet).writes()[0],
        Write::IndexReset
    ));
    let mut rows = CacheRows {
        item_index_unreadable: true,
        ..CacheRows::default()
    };
    let writes = rebuilt_from(&rows, &mut fleet);
    assert!(matches!(writes.writes()[0], Write::IndexReset));
    rows.apply(&writes);
    assert!(!rows.item_index_unreadable);
    assert_eq!(rows.item_index.len(), 2);

    // `cache reindex`: the same rebuild, on demand.
    let writes = index::reindex(core::slice::from_mut(&mut fleet.devices[0].vault));
    assert!(matches!(writes.writes()[0], Write::IndexReset));
    assert_eq!(writes.writes().len(), 3);
}

/// Neither column, nor the user content of a write, reaches `Debug` (ADR 0056 §2).
#[test]
fn index_types_redact_their_debug() {
    let (rows, _) = search_rows(&[("Секрет", "tajna", Some(T0))]);
    let row = &rows.item_index[0];
    let parsed = row.parse().unwrap();
    let write = Write::IndexPut(parsed.entry.clone());
    for shown in [
        format!("{row:?}"),
        format!("{parsed:?}"),
        format!("{:?}", parsed.entry),
        format!("{write:?}"),
        format!("{rows:?}"),
    ] {
        assert!(
            !shown.contains("секрет") && !shown.contains("tajna"),
            "{shown}"
        );
    }
}

/// A raw row with any columns, ids mostly of the right length.
fn raw_row() -> impl Strategy<Value = IndexRow> {
    let id = || {
        prop_oneof![
            4 => (0u8..4).prop_map(|n| {
                let mut id = vec![0u8; 16];
                id[15] = n;
                id
            }),
            1 => proptest::collection::vec(any::<u8>(), 0..20),
        ]
    };
    (
        id(),
        id(),
        prop_oneof![4 => 0i64..10, 1 => any::<i64>()],
        proptest::collection::vec(any::<u8>(), 0..12),
        prop_oneof![3 => "[a-zА-я]{0,8}".prop_map(String::into_bytes), 1 => proptest::collection::vec(any::<u8>(), 0..12)],
        proptest::option::of(proptest::collection::vec(any::<u8>(), 7..10)),
        prop_oneof![4 => 0i64..5, 1 => any::<i64>()],
    )
        .prop_map(
            |(item_id, vault_id, item_type, display_name, search_text, last_used_ms, use_count)| {
                IndexRow {
                    item_id,
                    vault_id,
                    item_type,
                    display_name: Zeroizing::new(display_name),
                    search_text: Zeroizing::new(search_text),
                    last_used_ms,
                    use_count,
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// The `client_item_index` fuzz target's properties, on the PR budget: any stored rows
    /// parse or are refused without a panic, a parsed row writes back to its own columns, the
    /// searches return only parsed ids within their limit, and a reconcile against no vault
    /// always empties the table (rows deleted, or the table dropped when any row is bad).
    #[test]
    fn any_stored_rows_are_parsed_or_rebuilt(
        rows in proptest::collection::vec(raw_row(), 0..6),
        query in "[a-zА-я%_ ]{0,4}",
        limit in 0usize..6,
    ) {
        let mut cache = CacheRows {
            item_index: rows,
            ..CacheRows::default()
        };
        let mut ids = std::collections::BTreeSet::new();
        let mut all_parse = true;
        for row in &cache.item_index {
            match row.parse() {
                Ok(stored) => {
                    let back = IndexRow::new(&stored.entry);
                    prop_assert_eq!(&back.item_id, &row.item_id);
                    prop_assert_eq!(&back.display_name, &row.display_name);
                    prop_assert_eq!(&back.search_text, &row.search_text);
                    prop_assert_eq!(back.item_type, row.item_type);
                    all_parse &= ids.insert(stored.entry.item_id);
                }
                Err(e) => {
                    prop_assert_eq!(e, ClientError::CacheCorrupt);
                    all_parse = false;
                }
            }
        }
        let found = index::search(&cache, &query, limit);
        prop_assert!(found.len() <= limit);
        prop_assert!(found.iter().all(|id| ids.contains(id.as_bytes())));
        let used = index::recent(&cache, limit);
        prop_assert!(used.len() <= limit);
        prop_assert!(used.iter().all(|id| ids.contains(id.as_bytes())));
        let writes = index::reconcile(&cache, &mut []);
        if all_parse {
            let deletes = writes
                .writes()
                .iter()
                .all(|w| matches!(w, Write::IndexDelete { .. }));
            prop_assert!(deletes, "only deletes");
        } else {
            prop_assert!(matches!(writes.writes(), [Write::IndexReset]));
        }
        cache.apply(&writes);
        prop_assert!(cache.item_index.is_empty());
    }
}

// SPDX-License-Identifier: AGPL-3.0-only

//! `VaultSync::field_conflict`, `VaultSync::resolve_conflict_pick` and
//! `VaultSync::resolve_conflict_keep_both` (ROADMAP §4.5 "keep both / pick one", M3; ADR 0012
//! §4 step 5; ADR 0018 §6 "Display"): real concurrent edits on several devices through the fake
//! server, a resolution on one of them, and the checks that every device ends in the same state
//! (convergence), that the resolution ends the conflict there, and that repeating it, or
//! delivering it twice, changes nothing (idempotence).
//!
//! The property test shares one fleet of devices across its cases, as `mutation.rs` shares
//! its fixture: every signup and login runs a 64 MiB Argon2id, so one fleet per case would not
//! fit a PR budget. Each case works on an item of its own, so cases do not see each other's
//! data; they do share the devices' op chains, which is what real devices do.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::{Config as ProptestConfig, TestRng, TestRunner};
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_MATCH, ATTR_VALUE, CUSTOM_KIND_HIDDEN, CUSTOM_KIND_TEXT,
    ITEM_FAVORITE, ITEM_NAME, LIST_FIELD, LIST_URI,
};

use super::late_edits::enrol_another_device;
use super::*;
use crate::conflicts::ConflictValue;

/// One device of a [`Fleet`].
struct Device {
    /// Its vault driver.
    vault: VaultSync,
    /// Its unlocked keys.
    unlocked: UnlockedDevice,
}

/// Devices of one account on one fake server.
struct Fleet {
    /// The server.
    server: Server,
    /// The test RNG.
    rng: ChaCha20Rng,
    /// The devices; 0 signed up, the others logged in and enrolled.
    devices: Vec<Device>,
    /// The host clock, advanced by every call that takes one.
    now: u64,
    /// Cases of the property test that resolved by "pick one", by "keep both", and with a
    /// write racing the resolution: the generator must reach all three.
    reached: [u32; 3],
}

impl Fleet {
    /// Signs up one device and enrols `n - 1` more; every device has fetched.
    fn new(seed: u64, n: usize) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut server = Server::new(seed + 1);
        let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
        let sk = secret_key_text(a.device.as_ref().unwrap());
        let vault_id = a.vault_key.vault_id();
        let vault = VaultSync::new(a.vault_key, &a.unlocked, 1).unwrap();
        let mut devices = vec![Device {
            vault,
            unlocked: a.unlocked,
        }];
        for _ in 1..n {
            let e = enrol_another_device(&mut server, &mut rng, &sk);
            let mut account = e.account;
            let vault =
                VaultSync::new(account.take_vault_key(vault_id).unwrap(), &e.unlocked, 1).unwrap();
            devices.push(Device {
                vault,
                unlocked: e.unlocked,
            });
        }
        let mut fleet = Self {
            server,
            rng,
            devices,
            now: T0 + 2000,
            reached: [0; 3],
        };
        for i in 0..n {
            fleet.fetch(i);
        }
        fleet
    }

    /// The next host time.
    fn tick(&mut self) -> u64 {
        self.now += 10;
        self.now
    }

    /// Uploads device `i`'s unsent ops and applies the answer; nothing when none wait.
    fn upload(&mut self, i: usize) {
        let d = &mut self.devices[i];
        if let Some(up) = d.vault.upload_request(&mut self.rng, &d.unlocked).unwrap() {
            let answer = self.server.upload(&up);
            let outcome = d.vault.apply_upload_response(&answer).unwrap();
            assert!(outcome.rejected.is_empty(), "{:?}", outcome.rejected);
        }
    }

    /// Fetches and applies everything new for device `i`; returns the response, for a
    /// duplicate delivery.
    fn fetch(&mut self, i: usize) -> FetchResponse {
        let now = self.tick();
        let authors = self.server.authors();
        let d = &mut self.devices[i];
        let response = self.server.fetch(&d.vault.fetch_request().unwrap());
        d.vault.apply_fetch(&authors, &response, now).unwrap();
        response
    }

    /// Uploads then fetches on every device, twice, so everyone holds everything.
    fn sync_all(&mut self) {
        for _ in 0..2 {
            for i in 0..self.devices.len() {
                self.upload(i);
            }
            for i in 0..self.devices.len() {
                self.fetch(i);
            }
        }
    }

    /// Device `i` writes `value` to `key` of `item`.
    fn write(&mut self, i: usize, item: ItemId, key: &str, value: &Value) {
        let now = self.tick();
        let d = &mut self.devices[i];
        let key = SchemaKey::parse(key.as_bytes()).unwrap();
        d.vault
            .edit_item(
                &mut self.rng,
                &d.unlocked,
                item,
                &[FieldEdit { key: &key, value }],
                now,
            )
            .unwrap();
    }

    /// Own ops of device `i` not yet acknowledged: what a resolution wrote.
    fn unsent(&self, i: usize) -> usize {
        self.devices[i].vault.unacknowledged().0
    }

    /// Device `i`'s "pick one".
    fn pick(&mut self, i: usize, item: ItemId, key: &str, dot: Dot) -> Result<(), ClientError> {
        let now = self.tick();
        let d = &mut self.devices[i];
        d.vault
            .resolve_conflict_pick(&mut self.rng, &d.unlocked, item, key, dot, now)
    }

    /// Device `i`'s "keep both".
    fn keep_both(
        &mut self,
        i: usize,
        item: ItemId,
        key: &str,
        keep: Dot,
        label: Option<&str>,
    ) -> Result<Vec<String>, ClientError> {
        let now = self.tick();
        let d = &mut self.devices[i];
        d.vault
            .resolve_conflict_keep_both(&mut self.rng, &d.unlocked, item, key, keep, label, now)
            .map(|ids| ids.iter().map(|e| e.as_str().to_owned()).collect())
    }

    /// A Login created on device 0 with a password, a name, a text custom field labelled
    /// "Note" and a website, synced to every device. Returns the item and the custom field's
    /// and website's element ids.
    fn login(&mut self) -> (ItemId, String, String) {
        let now = self.tick();
        let d = &mut self.devices[0];
        let password = SchemaKey::parse(LOGIN_PASSWORD.as_bytes()).unwrap();
        let name = SchemaKey::parse(ITEM_NAME.as_bytes()).unwrap();
        let base = Value::text("base").unwrap();
        let title = Value::text("Example").unwrap();
        let item = d
            .vault
            .create_item(
                &mut self.rng,
                &d.unlocked,
                ItemType::LOGIN,
                &[
                    FieldEdit {
                        key: &password,
                        value: &base,
                    },
                    FieldEdit {
                        key: &name,
                        value: &title,
                    },
                ],
                now,
            )
            .unwrap();
        let field_order = d.vault.append_orders(Some(item), LIST_FIELD, 1).unwrap();
        let (field, mut writes) = VaultSync::new_element_writes(
            &mut self.rng,
            LIST_FIELD,
            vec![
                (ATTR_LABEL, Value::text("Note").unwrap()),
                (ATTR_KIND, Value::enumeration(CUSTOM_KIND_TEXT)),
                (ATTR_VALUE, Value::text("base-f").unwrap()),
            ],
            Some(&field_order[0]),
        )
        .unwrap();
        let uri_order = d.vault.append_orders(Some(item), LIST_URI, 1).unwrap();
        let (uri, mut uri_writes) = VaultSync::new_element_writes(
            &mut self.rng,
            LIST_URI,
            vec![
                (ATTR_VALUE, Value::text("https://base.example").unwrap()),
                (ATTR_MATCH, Value::enumeration(2)),
            ],
            Some(&uri_order[0]),
        )
        .unwrap();
        writes.append(&mut uri_writes);
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        let now = self.tick();
        let d = &mut self.devices[0];
        d.vault
            .edit_item(&mut self.rng, &d.unlocked, item, &edits, now)
            .unwrap();
        self.sync_all();
        let hex = |e: rizzy_core::item::key::ElementId| {
            e.key(LIST_FIELD, ATTR_VALUE)
                .unwrap()
                .as_key()
                .element()
                .unwrap()
                .to_owned()
        };
        (item, hex(field), hex(uri))
    }
}

/// What a device shows of `item`: every field's displayed bytes and conflict flag, and the
/// bytes and dots of every conflicting field's listing. Equal on two devices means they show
/// the same item.
type Shown = BTreeMap<String, (Vec<u8>, bool, Vec<(Dot, Vec<u8>)>)>;

fn shown(vault: &VaultSync, item: ItemId) -> Shown {
    vault
        .field_keys(item)
        .iter()
        .map(|key| {
            let value = vault
                .field_value(item, key)
                .map(|v| v.expose_secret().to_vec())
                .unwrap_or_default();
            let listing = vault
                .field_conflict(item, key)
                .into_iter()
                .map(|v| (v.dot, v.value.expose_secret().to_vec()))
                .collect();
            (
                key.as_str().to_owned(),
                (value, vault.field_conflicts(item, key), listing),
            )
        })
        .collect()
}

/// Every device shows the same item; returns what they show.
fn assert_converged(fleet: &Fleet, item: ItemId) -> Shown {
    let first = shown(&fleet.devices[0].vault, item);
    for (i, d) in fleet.devices.iter().enumerate().skip(1) {
        assert_eq!(
            shown(&d.vault, item),
            first,
            "device {i} differs from device 0"
        );
    }
    first
}

/// The encoded bytes of a Text value.
fn text(t: &str) -> Vec<u8> {
    Value::text(t).unwrap().expose_secret().to_vec()
}

/// The displayed bytes of `key` on device `i`.
fn shown_bytes(fleet: &Fleet, i: usize, item: ItemId, key: &str) -> Vec<u8> {
    fleet.devices[i]
        .vault
        .field_value(item, key)
        .unwrap()
        .expose_secret()
        .to_vec()
}

/// The device id of fleet device `i`.
fn device_id(fleet: &Fleet, i: usize) -> DeviceId {
    fleet.devices[i].unlocked.device_id
}

#[test]
fn pick_one_resolves_the_conflict_on_every_device() {
    let mut fleet = Fleet::new(700, 2);
    let (item, _, _) = fleet.login();
    fleet.write(0, item, LOGIN_PASSWORD, &Value::text("from-a").unwrap());
    fleet.write(1, item, LOGIN_PASSWORD, &Value::text("from-b").unwrap());
    fleet.sync_all();

    // Both devices list the same two values, the displayed one first.
    let before = assert_converged(&fleet, item);
    let (_, conflict, listing) = &before[LOGIN_PASSWORD];
    assert!(conflict);
    assert_eq!(listing.len(), 2);
    let values = fleet.devices[0].vault.field_conflict(item, LOGIN_PASSWORD);
    assert!(values[0].displayed && !values[1].displayed);
    assert_eq!(
        values[0].value.expose_secret(),
        shown_bytes(&fleet, 0, item, LOGIN_PASSWORD)
    );
    assert!(values.iter().all(|v| v.written_ms >= T0));
    let b_value = values
        .iter()
        .find(|v| v.dot.device_id() == device_id(&fleet, 1))
        .unwrap();
    assert_eq!(b_value.value.expose_secret(), text("from-b"));
    let b_dot = b_value.dot;
    // Debug never shows a value.
    assert_eq!(format!("{b_value:?}"), "ConflictValue([REDACTED])");

    // A picks B's value: one ordinary op.
    fleet.pick(0, item, LOGIN_PASSWORD, b_dot).unwrap();
    assert_eq!(fleet.unsent(0), 1);
    assert!(!fleet.devices[0].vault.field_conflicts(item, LOGIN_PASSWORD));
    // Idempotent: the conflict is gone, so a second pick writes nothing.
    assert_eq!(
        fleet.pick(0, item, LOGIN_PASSWORD, b_dot).unwrap_err(),
        ClientError::UnknownItem
    );
    assert_eq!(fleet.unsent(0), 1);

    fleet.upload(0);
    let response = fleet.fetch(1);
    // A duplicate delivery of the same page changes nothing (ADR 0012 §4 step 3).
    let once = shown(&fleet.devices[1].vault, item);
    let now = fleet.tick();
    let authors = fleet.server.authors();
    fleet.devices[1]
        .vault
        .apply_fetch(&authors, &response, now)
        .unwrap();
    assert_eq!(shown(&fleet.devices[1].vault, item), once);
    fleet.sync_all();

    let after = assert_converged(&fleet, item);
    assert_eq!(after[LOGIN_PASSWORD], (text("from-b"), false, Vec::new()));
    // The value not picked is history, not lost (ADR 0012 §5).
    let history = fleet.devices[1].vault.field_history(item, LOGIN_PASSWORD);
    assert!(
        history
            .iter()
            .any(|e| e.value.expose_secret() == text("from-a"))
    );
}

#[test]
fn keep_both_moves_the_other_values_into_new_fields() {
    let mut fleet = Fleet::new(710, 3);
    let (item, _, _) = fleet.login();
    for (i, t) in ["one", "two", "three"].into_iter().enumerate() {
        fleet.write(i, item, LOGIN_PASSWORD, &Value::text(t).unwrap());
    }
    fleet.sync_all();
    let values = fleet.devices[2].vault.field_conflict(item, LOGIN_PASSWORD);
    assert_eq!(values.len(), 3);
    let keep = values.iter().find(|v| v.displayed).unwrap();
    let kept = keep.value.expose_secret().to_vec();
    let keep_dot = keep.dot;
    let moved: BTreeSet<Vec<u8>> = values
        .iter()
        .filter(|v| !v.displayed)
        .map(|v| v.value.expose_secret().to_vec())
        .collect();

    // A fixed field has no label of its own to give the copies.
    assert_eq!(
        fleet
            .keep_both(2, item, LOGIN_PASSWORD, keep_dot, None)
            .unwrap_err(),
        ClientError::InvalidInput
    );
    assert_eq!(fleet.unsent(2), 0);

    let elements = fleet
        .keep_both(2, item, LOGIN_PASSWORD, keep_dot, Some("Password (copy)"))
        .unwrap();
    assert_eq!(elements.len(), 2);
    // One op, and a second call writes nothing.
    assert_eq!(fleet.unsent(2), 1);
    assert_eq!(
        fleet
            .keep_both(2, item, LOGIN_PASSWORD, keep_dot, Some("Password (copy)"))
            .unwrap_err(),
        ClientError::UnknownItem
    );
    assert_eq!(fleet.unsent(2), 1);
    fleet.sync_all();

    let after = assert_converged(&fleet, item);
    assert_eq!(after[LOGIN_PASSWORD], (kept, false, Vec::new()));
    let mut copies = BTreeSet::new();
    for e in &elements {
        let value = format!("{LIST_FIELD}/{e}/{ATTR_VALUE}");
        let (bytes, conflict, _) = &after[&value];
        assert!(!conflict);
        copies.insert(bytes.clone());
        // A password is concealed, so its copies are hidden custom fields.
        assert_eq!(
            after[&format!("{LIST_FIELD}/{e}/{ATTR_KIND}")].0,
            Value::enumeration(CUSTOM_KIND_HIDDEN).expose_secret()
        );
        assert_eq!(
            after[&format!("{LIST_FIELD}/{e}/{ATTR_LABEL}")].0,
            text("Password (copy)")
        );
    }
    assert_eq!(copies, moved);
    // Nothing conflicts any more.
    assert!(after.values().all(|(_, conflict, _)| !conflict));
}

#[test]
fn keep_both_on_a_website_or_custom_field_adds_one_of_the_same_kind() {
    let mut fleet = Fleet::new(720, 2);
    let (item, field, uri) = fleet.login();
    let uri_key = format!("{LIST_URI}/{uri}/{ATTR_VALUE}");
    let field_key = format!("{LIST_FIELD}/{field}/{ATTR_VALUE}");
    fleet.write(
        0,
        item,
        &uri_key,
        &Value::text("https://a.example").unwrap(),
    );
    fleet.write(
        1,
        item,
        &uri_key,
        &Value::text("https://b.example").unwrap(),
    );
    fleet.write(0, item, &field_key, &Value::text("fa").unwrap());
    fleet.write(1, item, &field_key, &Value::text("fb").unwrap());
    fleet.sync_all();

    for key in [&uri_key, &field_key] {
        let values = fleet.devices[1].vault.field_conflict(item, key);
        assert_eq!(values.len(), 2);
        let keep = values[1].dot;
        let ids = fleet.keep_both(1, item, key, keep, None).unwrap();
        assert_eq!(ids.len(), 1);
    }
    fleet.sync_all();
    let after = assert_converged(&fleet, item);
    assert!(after.values().all(|(_, conflict, _)| !conflict));
    let websites = fleet.devices[0].vault.list_elements(item, LIST_URI);
    assert_eq!(websites.len(), 2);
    let urls: BTreeSet<Vec<u8>> = websites
        .iter()
        .map(|e| {
            after[&format!("{LIST_URI}/{}/{ATTR_VALUE}", e.element.as_str())]
                .0
                .clone()
        })
        .collect();
    assert_eq!(
        urls,
        BTreeSet::from([text("https://a.example"), text("https://b.example")])
    );
    // The new website keeps the source website's match mode.
    for e in &websites {
        assert_eq!(
            after[&format!("{LIST_URI}/{}/{ATTR_MATCH}", e.element.as_str())].0,
            Value::enumeration(2).expose_secret()
        );
    }
    // The new custom field copies the source's kind and label.
    let fields = fleet.devices[0].vault.list_elements(item, LIST_FIELD);
    assert_eq!(fields.len(), 2);
    let mut values = BTreeSet::new();
    for e in &fields {
        let e = e.element.as_str();
        assert_eq!(
            after[&format!("{LIST_FIELD}/{e}/{ATTR_LABEL}")].0,
            text("Note")
        );
        assert_eq!(
            after[&format!("{LIST_FIELD}/{e}/{ATTR_KIND}")].0,
            Value::enumeration(CUSTOM_KIND_TEXT).expose_secret()
        );
        values.insert(after[&format!("{LIST_FIELD}/{e}/{ATTR_VALUE}")].0.clone());
    }
    assert_eq!(values, BTreeSet::from([text("fa"), text("fb")]));
}

#[test]
fn what_keep_both_refuses_and_pick_accepts() {
    let mut fleet = Fleet::new(730, 2);
    let (item, _, _) = fleet.login();
    // A Bool conflict: only "pick one" resolves it.
    fleet.write(0, item, ITEM_FAVORITE, &Value::bool(true));
    fleet.write(1, item, ITEM_FAVORITE, &Value::bool(false));
    // Cleared on A while edited on B.
    fleet.write(0, item, ITEM_NAME, &Value::cleared());
    fleet.write(1, item, ITEM_NAME, &Value::text("Edited").unwrap());
    fleet.sync_all();

    let favorite = fleet.devices[0].vault.field_conflict(item, ITEM_FAVORITE);
    assert_eq!(favorite.len(), 2);
    assert_eq!(
        fleet
            .keep_both(0, item, ITEM_FAVORITE, favorite[0].dot, Some("x"))
            .unwrap_err(),
        ClientError::InvalidEdit
    );

    let name = fleet.devices[0].vault.field_conflict(item, ITEM_NAME);
    assert_eq!(name.len(), 2);
    // The non-empty value displays over the concurrent Cleared one (ADR 0018 §6).
    assert!(name[0].displayed && !name[0].value.is_cleared());
    assert!(name[1].value.is_cleared());
    // Nothing to keep besides the displayed value, and a Cleared value is never "kept".
    for keep in [name[0].dot, name[1].dot] {
        assert_eq!(
            fleet
                .keep_both(0, item, ITEM_NAME, keep, Some("x"))
                .unwrap_err(),
            ClientError::InvalidEdit
        );
    }
    // A dot that is not one of the listed values, or a field without a conflict.
    assert_eq!(
        fleet.pick(0, item, ITEM_NAME, favorite[0].dot).unwrap_err(),
        ClientError::UnknownItem
    );
    let password = fleet.devices[0].vault.field_conflict(item, LOGIN_PASSWORD);
    assert!(password.is_empty());
    assert_eq!(fleet.unsent(0), 0);

    // Picking resolves both, the Cleared value included: it accepts the deletion.
    fleet.pick(0, item, ITEM_FAVORITE, favorite[1].dot).unwrap();
    fleet.pick(1, item, ITEM_NAME, name[1].dot).unwrap();
    fleet.sync_all();
    let after = assert_converged(&fleet, item);
    assert_eq!(after[ITEM_NAME], (Vec::new(), false, Vec::new()));
    assert_eq!(
        after[ITEM_FAVORITE].0,
        favorite[1].value.expose_secret().to_vec()
    );
    assert!(!after[ITEM_FAVORITE].1);
}

#[test]
fn concurrent_resolutions_converge() {
    let mut fleet = Fleet::new(740, 2);
    let (item, _, _) = fleet.login();
    fleet.write(0, item, LOGIN_PASSWORD, &Value::text("a").unwrap());
    fleet.write(1, item, LOGIN_PASSWORD, &Value::text("b").unwrap());
    fleet.sync_all();
    let values = fleet.devices[0].vault.field_conflict(item, LOGIN_PASSWORD);
    // Both devices pick the same value at once: byte-identical values are one value.
    fleet.pick(0, item, LOGIN_PASSWORD, values[1].dot).unwrap();
    fleet.pick(1, item, LOGIN_PASSWORD, values[1].dot).unwrap();
    fleet.sync_all();
    let after = assert_converged(&fleet, item);
    assert_eq!(
        after[LOGIN_PASSWORD],
        (values[1].value.expose_secret().to_vec(), false, Vec::new())
    );

    // Different choices at once conflict again, the same way on both devices.
    fleet.write(0, item, ITEM_NAME, &Value::text("x").unwrap());
    fleet.write(1, item, ITEM_NAME, &Value::text("y").unwrap());
    fleet.sync_all();
    let values = fleet.devices[1].vault.field_conflict(item, ITEM_NAME);
    fleet.pick(0, item, ITEM_NAME, values[0].dot).unwrap();
    fleet.pick(1, item, ITEM_NAME, values[1].dot).unwrap();
    fleet.sync_all();
    let after = assert_converged(&fleet, item);
    assert!(after[ITEM_NAME].1);
    let again: BTreeSet<Vec<u8>> = after[ITEM_NAME].2.iter().map(|(_, b)| b.clone()).collect();
    assert_eq!(again, BTreeSet::from([text("x"), text("y")]));
}

// -------------------------------------------------------------------------------------------
// Property: convergence and idempotence under any delivery order
// -------------------------------------------------------------------------------------------

/// Devices in the property fleet.
const DEVICES: usize = 3;

/// One generated scenario.
#[derive(Clone, Debug)]
struct Case {
    /// Which field conflicts: 0 `login.password`, 1 the custom field, 2 the website.
    target: u8,
    /// Per device: 0 no write, 1 Cleared, 2–4 one of three texts (so values coincide).
    writes: [u8; DEVICES],
    /// The order the devices upload their writes in.
    upload_order: Vec<usize>,
    /// The order the devices fetch in.
    fetch_order: Vec<usize>,
    /// The resolving device.
    resolver: usize,
    /// "Keep both" (or "pick one") and which listed value.
    keep_both: bool,
    /// The value picked or kept.
    choice: Index,
    /// Another device's concurrent write of a new value, before it sees the resolution.
    concurrent: Option<usize>,
    /// Which device gets the resolution's fetch page twice.
    duplicate: usize,
}

fn case_strategy() -> impl Strategy<Value = Case> {
    let order = || Just((0..DEVICES).collect::<Vec<usize>>()).prop_shuffle();
    (
        0u8..3,
        [0u8..5, 0u8..5, 0u8..5],
        order(),
        order(),
        0..DEVICES,
        any::<bool>(),
        any::<Index>(),
        proptest::option::of(1..DEVICES),
        0..DEVICES,
    )
        .prop_map(
            |(
                target,
                writes,
                upload_order,
                fetch_order,
                resolver,
                keep_both,
                choice,
                other,
                duplicate,
            )| {
                Case {
                    target,
                    writes,
                    upload_order,
                    fetch_order,
                    resolver,
                    keep_both,
                    choice,
                    // Another device than the resolver.
                    concurrent: other.map(|o| (resolver + o) % DEVICES),
                    duplicate,
                }
            },
        )
}

/// The value device writes code `w` stands for; `None` for no write.
fn written(w: u8) -> Option<Value> {
    match w {
        0 => None,
        1 => Some(Value::cleared()),
        n => Some(Value::text(&format!("v{n}")).unwrap()),
    }
}

/// Runs one case on the shared fleet.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario in order: conflict, resolution, delivery, checks"
)]
fn run_case(fleet: &mut Fleet, case: &Case) -> Result<(), TestCaseError> {
    let (item, field, uri) = fleet.login();
    let key = match case.target {
        0 => LOGIN_PASSWORD.to_owned(),
        1 => format!("{LIST_FIELD}/{field}/{ATTR_VALUE}"),
        _ => format!("{LIST_URI}/{uri}/{ATTR_VALUE}"),
    };
    // Concurrent writes: no device sees another's before all are written.
    let mut distinct: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut writers = 0;
    for (i, w) in case.writes.iter().enumerate() {
        if let Some(value) = written(*w) {
            fleet.write(i, item, &key, &value);
            distinct.insert(value.expose_secret().to_vec());
            writers += 1;
        }
    }
    for &i in &case.upload_order {
        fleet.upload(i);
    }
    for &i in &case.fetch_order {
        fleet.fetch(i);
    }
    let before = assert_converged(fleet, item);
    let expect_conflict = writers >= 2 && distinct.len() >= 2;
    prop_assert_eq!(before[&key].1, expect_conflict);
    let listed: BTreeSet<Vec<u8>> = before[&key].2.iter().map(|(_, b)| b.clone()).collect();
    if expect_conflict {
        prop_assert_eq!(&listed, &distinct);
    } else {
        prop_assert!(listed.is_empty());
    }

    let r = case.resolver;
    let listing = fleet.devices[r].vault.field_conflict(item, &key);
    if listing.is_empty() {
        // Nothing to resolve: refused, nothing written.
        let dot = Dot::new(device_id(fleet, r), 1).unwrap();
        prop_assert_eq!(
            fleet.pick(r, item, &key, dot),
            Err(ClientError::UnknownItem)
        );
        prop_assert_eq!(fleet.unsent(r), 0);
        return Ok(());
    }

    // The resolution, and what the field and the new elements must show after it.
    let label = (case.target == 0).then_some("Copy");
    let (chosen, dot, moved, elements): (Vec<u8>, Dot, BTreeSet<Vec<u8>>, Vec<String>) =
        if case.keep_both {
            let non_empty: Vec<&ConflictValue> =
                listing.iter().filter(|v| !v.value.is_cleared()).collect();
            let keep = non_empty[case
                .choice
                .index(non_empty.len().max(1))
                .min(non_empty.len() - 1)];
            let result = fleet.keep_both(r, item, &key, keep.dot, label);
            if non_empty.len() < 2 {
                prop_assert_eq!(result, Err(ClientError::InvalidEdit));
                prop_assert_eq!(fleet.unsent(r), 0);
                return Ok(());
            }
            let moved: BTreeSet<Vec<u8>> = non_empty
                .iter()
                .filter(|v| v.dot != keep.dot)
                .map(|v| v.value.expose_secret().to_vec())
                .collect();
            let elements = result.unwrap();
            prop_assert_eq!(elements.len(), moved.len());
            (
                keep.value.expose_secret().to_vec(),
                keep.dot,
                moved,
                elements,
            )
        } else {
            let pick = &listing[case.choice.index(listing.len())];
            fleet.pick(r, item, &key, pick.dot).unwrap();
            (
                pick.value.expose_secret().to_vec(),
                pick.dot,
                BTreeSet::new(),
                Vec::new(),
            )
        };
    // Resolved at once on the resolving device; a repeat writes nothing.
    prop_assert!(!fleet.devices[r].vault.field_conflicts(item, &key));
    let sent = fleet.unsent(r);
    prop_assert!(sent >= 1);
    prop_assert_eq!(
        fleet.pick(r, item, &key, dot),
        Err(ClientError::UnknownItem)
    );
    prop_assert_eq!(fleet.unsent(r), sent);
    fleet.reached[usize::from(case.keep_both)] += 1;
    if case.concurrent.is_some() {
        fleet.reached[2] += 1;
    }

    // A write concurrent with the resolution, on a device that has not seen it.
    let late = text("late");
    if let Some(c) = case.concurrent {
        fleet.write(c, item, &key, &Value::text("late").unwrap());
    }

    // Delivery in the generated order, one page delivered twice.
    for &i in &case.upload_order {
        fleet.upload(i);
    }
    for &i in &case.fetch_order {
        let page = fleet.fetch(i);
        if i == case.duplicate {
            let once = shown(&fleet.devices[i].vault, item);
            let now = fleet.tick();
            let authors = fleet.server.authors();
            fleet.devices[i]
                .vault
                .apply_fetch(&authors, &page, now)
                .unwrap();
            prop_assert_eq!(shown(&fleet.devices[i].vault, item), once);
        }
    }
    fleet.sync_all();
    let after = assert_converged(fleet, item);

    // The field: the resolution's value alone, or with the concurrent write beside it.
    let (shown_value, conflict, listing) = &after[&key];
    if case.concurrent.is_none() {
        prop_assert!(!conflict);
        prop_assert_eq!(shown_value, &chosen);
    } else {
        let values: BTreeSet<Vec<u8>> = listing.iter().map(|(_, b)| b.clone()).collect();
        let expected: BTreeSet<Vec<u8>> = [chosen.clone(), late.clone()].into();
        prop_assert_eq!(*conflict, chosen != late);
        if chosen != late {
            prop_assert_eq!(values, expected);
        }
    }
    // "Keep both": every other value sits in a new element, on every device.
    let list = if case.target == 2 {
        LIST_URI
    } else {
        LIST_FIELD
    };
    let copies: BTreeSet<Vec<u8>> = elements
        .iter()
        .map(|e| after[&format!("{list}/{e}/{ATTR_VALUE}")].0.clone())
        .collect();
    prop_assert_eq!(copies, moved);
    // Nothing but the field under test (and only with a concurrent write) conflicts.
    for (k, (_, conflict, _)) in &after {
        prop_assert!(
            !conflict || (k == &key && case.concurrent.is_some()),
            "{}",
            k
        );
    }
    Ok(())
}

/// Cases per PR run: each one runs a few dozen signed ops through the fake server.
const PR_CASES: u32 = 48;

fn run_cases(cases: u32, fixed: bool) {
    let fleet = RefCell::new(Fleet::new(750, DEVICES));
    let config = ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let mut runner = if fixed {
        TestRunner::new_with_rng(
            config.clone(),
            TestRng::deterministic_rng(config.rng_algorithm),
        )
    } else {
        TestRunner::new(config)
    };
    let result = runner.run(&case_strategy(), |case| {
        run_case(&mut fleet.borrow_mut(), &case)
    });
    if let Err(e) = result {
        panic!("{e}");
    }
    let reached = fleet.borrow().reached;
    assert!(reached.iter().all(|n| *n > 0), "{reached:?}");
}

/// Convergence and idempotence of both resolutions, for any concurrent writes, any upload
/// and fetch order, a concurrent write racing the resolution, and a duplicated page (CLAUDE.md:
/// "The sync engine needs property tests for convergence"). PR budget, deterministic seeds.
#[test]
fn resolutions_converge_and_are_idempotent() {
    run_cases(PR_CASES, true);
}

/// Nightly budget on fresh seeds (see `mutation.rs` for the job it needs).
#[test]
#[ignore = "nightly budget: 10x the PR cases on fresh seeds"]
fn nightly_resolutions_converge_and_are_idempotent() {
    run_cases(PR_CASES * 10, false);
}

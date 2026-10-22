// SPDX-License-Identifier: AGPL-3.0-only

//! Custom-field autocomplete ids and autocomplete-driven autofill through a real vault
//! ([ADR 0076] §2–§5, §10 "`rizzy-client`"): W1–W5 on every write path (create, edit, conflict
//! "pick one" and "keep both", history restore, import), the merge-made duplicate (an unrelated
//! edit still succeeds; two replicas converge on the same winner and the warning names it), an
//! old-client simulation, the fill plan (exact match only, the fields that never fill, the
//! 4096 limit, role precedence, narrowing, TOTP vectors, the secret never in the result) and the
//! save plan.
//!
//! [ADR 0076]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0076-autocomplete-driven-autofill.md

use std::cell::RefCell;

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestRng, TestRunner};
use rizzy_core::item::schema::{
    ATTR_AUTOCOMPLETE, ATTR_KIND, ATTR_LABEL, ATTR_VALUE, CUSTOM_KIND_BOOLEAN, CUSTOM_KIND_HIDDEN,
    CUSTOM_KIND_TEXT, ITEM_NAME, LIST_FIELD, LOGIN_TOTP,
};

use super::late_edits::enrol_another_device;
use super::lists::one_item;
use super::*;
use crate::autofill::{
    AutofillState, CapturedField, CustomChoice, FillOnly, FillRequest, SaveRowKind,
};

/// The Text value of `s`.
fn t(s: &str) -> Value {
    Value::text(s).unwrap()
}

/// A custom-field kind.
fn kind(n: u16) -> Value {
    Value::enumeration(n)
}

/// `field/<element>/<attribute>`.
fn k(element: &str, attribute: &str) -> String {
    format!("{LIST_FIELD}/{element}/{attribute}")
}

/// Writes `writes` to `item` in one edit op through the client's checks.
fn edit(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    writes: &[(String, Value)],
    now: u64,
) -> Result<(), ClientError> {
    let keys: Vec<SchemaKey> = writes
        .iter()
        .map(|(key, _)| SchemaKey::parse(key.as_bytes()).unwrap())
        .collect();
    let edits: Vec<FieldEdit<'_>> = keys
        .iter()
        .zip(writes)
        .map(|(key, (_, value))| FieldEdit { key, value })
        .collect();
    vault.edit_item(rng, unlocked, item, &edits, now)
}

/// Adds a custom field with `attributes` after the last one; returns its element id (hex).
fn add_field(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    attributes: Vec<(&str, Value)>,
    now: u64,
) -> Result<String, ClientError> {
    let orders = vault.append_orders(Some(item), LIST_FIELD, 1).unwrap();
    let (element, writes) =
        VaultSync::new_element_writes(rng, LIST_FIELD, attributes, Some(&orders[0])).unwrap();
    let writes: Vec<(String, Value)> = writes
        .into_iter()
        .map(|(key, value)| (key.as_str().to_owned(), value))
        .collect();
    edit(vault, rng, unlocked, item, &writes, now)?;
    Ok(hex_of(element.as_bytes()))
}

/// A labelled text field with `id` and `value`.
fn text_field<'a>(label: &str, id: &str, value: &str) -> Vec<(&'a str, Value)> {
    vec![
        (ATTR_LABEL, t(label)),
        (ATTR_KIND, kind(CUSTOM_KIND_TEXT)),
        (ATTR_VALUE, t(value)),
        (ATTR_AUTOCOMPLETE, t(id)),
    ]
}

/// Writes `writes` with no client check at all: another client, an old one or a hostile one.
fn raw_write(
    vault: &mut VaultSync,
    rng: &mut ChaCha20Rng,
    unlocked: &UnlockedDevice,
    item: ItemId,
    writes: &[(String, Value)],
    now: u64,
) {
    let pairs: Vec<(&str, &[u8])> = writes
        .iter()
        .map(|(key, value)| (key.as_str(), value.expose_secret()))
        .collect();
    vault
        .write_op(
            rng,
            unlocked,
            item,
            &crate::sync::OwnChange {
                lifecycle: rizzy_sync::record::Lifecycle::Active,
                writes: &pairs,
            },
            now,
        )
        .unwrap();
}

/// A fresh element id (hex) for a raw write.
fn raw_element(rng: &mut ChaCha20Rng) -> String {
    hex_of(rizzy_core::item::key::ElementId::generate(rng).as_bytes())
}

/// W1–W5 on edit and create.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of W1–W5 cases, in order, on one item"
)]
fn writer_checks_on_edit_and_create() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(7601);
    let mut now = T0 + 10;
    let mut tick = || {
        now += 10;
        now
    };
    let member = add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        text_field("Member no.", "member", "M-1"),
        tick(),
    )
    .unwrap();

    // W1: grammar, never normalised.
    for bad in ["Member", "a b", "", "caf\u{e9}", &"a".repeat(65)] {
        let attrs = if bad.is_empty() {
            // An empty Text is the schema's own refusal (writers write Cleared).
            continue;
        } else {
            text_field("X", bad, "v")
        };
        assert_eq!(
            add_field(&mut vault, &mut rng, &unlocked, item, attrs, tick()),
            Err(ClientError::AutocompleteInvalid),
            "{bad:?}"
        );
    }
    // W2: reserved, incl. email/tel and the section- prefix.
    for reserved in [
        "username",
        "email",
        "tel",
        "totp",
        "2fa",
        "section-a",
        "cc-csc",
    ] {
        assert_eq!(
            add_field(
                &mut vault,
                &mut rng,
                &unlocked,
                item,
                text_field("X", reserved, "v"),
                tick()
            ),
            Err(ClientError::AutocompleteReserved),
            "{reserved}"
        );
    }
    // W3: a second field with the same id, or an edit that moves it onto another field.
    assert_eq!(
        add_field(
            &mut vault,
            &mut rng,
            &unlocked,
            item,
            text_field("Other", "member", "v"),
            tick()
        ),
        Err(ClientError::AutocompleteDuplicate)
    );
    let other = add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        text_field("Other", "branch", "B"),
        tick(),
    )
    .unwrap();
    assert_eq!(
        edit(
            &mut vault,
            &mut rng,
            &unlocked,
            item,
            &[(k(&other, ATTR_AUTOCOMPLETE), t("member"))],
            tick()
        ),
        Err(ClientError::AutocompleteDuplicate)
    );
    // Swapping two ids in one op is fine: after the write no two fields share one.
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[
            (k(&other, ATTR_AUTOCOMPLETE), t("member")),
            (k(&member, ATTR_AUTOCOMPLETE), t("branch")),
        ],
        tick(),
    )
    .unwrap();
    // W4: an id on a boolean field, or a field with an id turned boolean.
    assert_eq!(
        add_field(
            &mut vault,
            &mut rng,
            &unlocked,
            item,
            vec![
                (ATTR_LABEL, t("Flag")),
                (ATTR_KIND, kind(CUSTOM_KIND_BOOLEAN)),
                (ATTR_VALUE, Value::bool(true)),
                (ATTR_AUTOCOMPLETE, t("flag")),
            ],
            tick()
        ),
        Err(ClientError::AutocompleteKind)
    );
    assert_eq!(
        edit(
            &mut vault,
            &mut rng,
            &unlocked,
            item,
            &[
                (k(&member, ATTR_KIND), kind(CUSTOM_KIND_BOOLEAN)),
                (k(&member, ATTR_VALUE), Value::bool(true)),
            ],
            tick()
        ),
        Err(ClientError::AutocompleteKind)
    );
    // ...unless the same op clears the id.
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[
            (k(&member, ATTR_KIND), kind(CUSTOM_KIND_BOOLEAN)),
            (k(&member, ATTR_VALUE), Value::bool(true)),
            (k(&member, ATTR_AUTOCOMPLETE), Value::cleared()),
        ],
        tick(),
    )
    .unwrap();
    // W5: no Display Name, or a blank one, on add or edit.
    for label in [None, Some("   ")] {
        let mut attrs = vec![(ATTR_KIND, kind(CUSTOM_KIND_TEXT)), (ATTR_VALUE, t("v"))];
        if let Some(label) = label {
            attrs.push((ATTR_LABEL, t(label)));
        }
        assert_eq!(
            add_field(&mut vault, &mut rng, &unlocked, item, attrs, tick()),
            Err(ClientError::LabelRequired)
        );
    }
    assert_eq!(
        edit(
            &mut vault,
            &mut rng,
            &unlocked,
            item,
            &[(k(&other, ATTR_LABEL), Value::cleared())],
            tick()
        ),
        Err(ClientError::LabelRequired)
    );
    // Removing a field is not an edit of it.
    let removal = vault
        .element_removal_writes(item, LIST_FIELD, &other)
        .unwrap();
    let removal: Vec<(String, Value)> = removal
        .into_iter()
        .map(|(key, value)| (key.as_str().to_owned(), value))
        .collect();
    edit(&mut vault, &mut rng, &unlocked, item, &removal, tick()).unwrap();

    // create_item runs the same checks.
    let create = |vault: &mut VaultSync, rng: &mut ChaCha20Rng, attrs: Vec<(&str, Value)>| {
        let element = raw_element(rng);
        let writes: Vec<(String, Value)> = attrs
            .into_iter()
            .map(|(a, v)| (k(&element, a), v))
            .collect();
        let keys: Vec<SchemaKey> = writes
            .iter()
            .map(|(key, _)| SchemaKey::parse(key.as_bytes()).unwrap())
            .collect();
        let edits: Vec<FieldEdit<'_>> = keys
            .iter()
            .zip(&writes)
            .map(|(key, (_, value))| FieldEdit { key, value })
            .collect();
        vault.create_item(rng, &unlocked, ItemType::LOGIN, &edits, T0 + 5_000)
    };
    assert_eq!(
        create(&mut vault, &mut rng, text_field("A", "Bad", "v")).unwrap_err(),
        ClientError::AutocompleteInvalid
    );
    assert_eq!(
        create(&mut vault, &mut rng, text_field("A", "password", "v")).unwrap_err(),
        ClientError::AutocompleteReserved
    );
    assert_eq!(
        create(
            &mut vault,
            &mut rng,
            vec![(ATTR_KIND, kind(CUSTOM_KIND_TEXT)), (ATTR_VALUE, t("v"))]
        )
        .unwrap_err(),
        ClientError::LabelRequired
    );
    create(&mut vault, &mut rng, text_field("A", "acct", "v")).unwrap();
}

/// A label-less field another client wrote stays valid data: an unrelated edit of the item
/// succeeds, an edit of the field asks for a name (W5), and removing it works (§2.4). It never
/// fills and cannot take an id until named.
#[test]
fn label_less_fields_stay_and_never_fill() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(7602);
    let element = raw_element(&mut rng);
    raw_write(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[
            (k(&element, ATTR_KIND), kind(CUSTOM_KIND_TEXT)),
            (k(&element, ATTR_VALUE), t("v")),
        ],
        T0 + 10,
    );
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(ITEM_NAME.to_owned(), t("renamed"))],
        T0 + 20,
    )
    .unwrap();
    for writes in [
        vec![(k(&element, ATTR_VALUE), t("w"))],
        vec![(k(&element, ATTR_AUTOCOMPLETE), t("acct"))],
    ] {
        assert_eq!(
            edit(&mut vault, &mut rng, &unlocked, item, &writes, T0 + 30),
            Err(ClientError::LabelRequired)
        );
    }
    // Named, it may take an id and fills.
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[
            (k(&element, ATTR_LABEL), t("Account")),
            (k(&element, ATTR_AUTOCOMPLETE), t("acct")),
        ],
        T0 + 40,
    )
    .unwrap();
    assert_eq!(vault.custom_fill_offer(item, &["acct"]).len(), 1);
}

/// §2.5: a merge-made duplicate (two fields with one id, written by a raw writer here) does
/// not lock the item; the first in list order fills and the other is shadowed and names it;
/// changing one id resolves it.
#[test]
fn merge_made_duplicates_do_not_lock_the_item() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(7603);
    let first = add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        text_field("First", "acct", "one"),
        T0 + 10,
    )
    .unwrap();
    let second = add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        text_field("Second", "other", "two"),
        T0 + 20,
    )
    .unwrap();
    raw_write(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(k(&second, ATTR_AUTOCOMPLETE), t("acct"))],
        T0 + 30,
    );
    // An unrelated edit, and an edit of the shadowed field's value, still succeed.
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(ITEM_NAME.to_owned(), t("x"))],
        T0 + 40,
    )
    .unwrap();
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(k(&second, ATTR_VALUE), t("two!"))],
        T0 + 50,
    )
    .unwrap();
    let states = vault.custom_field_autofill(item);
    assert_eq!(states.len(), 2);
    assert_eq!(states[0].element.as_str(), first);
    assert_eq!(states[0].state, AutofillState::Fills);
    assert_eq!(
        states[1].state,
        AutofillState::Shadowed(Zeroizing::new(first.clone()))
    );
    let offer = vault.custom_fill_offer(item, &["acct"]);
    assert_eq!(offer.len(), 1);
    assert_eq!(offer[0].element.as_str(), first);
    assert_eq!(offer[0].label.as_str(), "First");
    // Resolving it is an ordinary edit.
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(k(&second, ATTR_AUTOCOMPLETE), t("acct2"))],
        T0 + 60,
    )
    .unwrap();
    assert!(
        vault
            .custom_field_autofill(item)
            .iter()
            .all(|s| s.state == AutofillState::Fills)
    );
}

/// Two devices of one account, synced through the fake server.
struct Pair {
    /// The server.
    server: Server,
    /// The test RNG.
    rng: ChaCha20Rng,
    /// The devices' vaults and keys.
    devices: [(VaultSync, UnlockedDevice); 2],
    /// The host clock.
    now: u64,
}

impl Pair {
    /// Signs up one device and enrols a second.
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut server = Server::new(seed + 1);
        let a = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
        let sk = secret_key_text(a.device.as_ref().unwrap());
        let vault_id = a.vault_key.vault_id();
        let first = VaultSync::new(a.vault_key, &a.unlocked, 1).unwrap();
        let e = enrol_another_device(&mut server, &mut rng, &sk);
        let mut account = e.account;
        let second =
            VaultSync::new(account.take_vault_key(vault_id).unwrap(), &e.unlocked, 1).unwrap();
        let mut pair = Self {
            server,
            rng,
            devices: [(first, a.unlocked), (second, e.unlocked)],
            now: T0 + 2_000,
        };
        for i in 0..2 {
            pair.fetch(i);
        }
        pair.sync();
        pair
    }

    /// Fetches and applies everything new for device `i`.
    fn fetch(&mut self, i: usize) {
        self.now += 10;
        let authors = self.server.authors();
        let (vault, _) = &mut self.devices[i];
        let response = self.server.fetch(&vault.fetch_request().unwrap());
        vault.apply_fetch(&authors, &response, self.now).unwrap();
    }

    /// The next host time.
    fn tick(&mut self) -> u64 {
        self.now += 10;
        self.now
    }

    /// Uploads, then fetches, on both devices, twice.
    fn sync(&mut self) {
        for _ in 0..2 {
            for i in 0..2 {
                let (vault, unlocked) = &mut self.devices[i];
                if let Some(up) = vault.upload_request(&mut self.rng, unlocked).unwrap() {
                    let answer = self.server.upload(&up);
                    vault.apply_upload_response(&answer).unwrap();
                }
            }
            for i in 0..2 {
                self.fetch(i);
            }
        }
    }

    /// Device `i` edits through the client's checks.
    fn edit(
        &mut self,
        i: usize,
        item: ItemId,
        writes: &[(String, Value)],
    ) -> Result<(), ClientError> {
        let now = self.tick();
        let (vault, unlocked) = &mut self.devices[i];
        edit(vault, &mut self.rng, unlocked, item, writes, now)
    }

    /// Device 0 creates a Login item with two labelled text fields without ids; returns the
    /// item and the fields' element ids, in list order.
    fn item_with_two_fields(&mut self) -> (ItemId, [String; 2]) {
        let now = self.tick();
        let (vault, unlocked) = &mut self.devices[0];
        let name = SchemaKey::parse(ITEM_NAME.as_bytes()).unwrap();
        let value = t("item");
        let item = vault
            .create_item(
                &mut self.rng,
                unlocked,
                ItemType::LOGIN,
                &[FieldEdit {
                    key: &name,
                    value: &value,
                }],
                now,
            )
            .unwrap();
        let a = add_field(
            vault,
            &mut self.rng,
            unlocked,
            item,
            vec![
                (ATTR_LABEL, t("Alpha")),
                (ATTR_KIND, kind(CUSTOM_KIND_TEXT)),
                (ATTR_VALUE, t("a")),
            ],
            now + 1,
        )
        .unwrap();
        let b = add_field(
            vault,
            &mut self.rng,
            unlocked,
            item,
            vec![
                (ATTR_LABEL, t("Beta")),
                (ATTR_KIND, kind(CUSTOM_KIND_HIDDEN)),
                (ATTR_VALUE, t("b")),
            ],
            now + 2,
        )
        .unwrap();
        self.sync();
        (item, [a, b])
    }
}

/// §10: two replicas concurrently set the same id on two different fields; after the merge
/// both converge, the same field (the first in list order) wins on both, and the warning names
/// it. A property test over which device tags which field, which writes first and the id; the
/// cases share one pair of devices (each signup or login runs a 64 MiB Argon2id), each on an
/// item of its own.
#[test]
fn concurrent_duplicate_ids_converge_on_one_winner() {
    let pair = RefCell::new(Pair::new(7604));
    let config = ProptestConfig {
        cases: 6,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let mut runner = TestRunner::new_with_rng(
        config.clone(),
        TestRng::deterministic_rng(config.rng_algorithm),
    );
    let result = runner.run(
        &(any::<bool>(), any::<bool>(), "[a-z][a-z0-9_.-]{0,10}"),
        |(swap_fields, swap_devices, id)| {
            prop_assume!(check_autocomplete_id_ok(&id));
            let mut p = pair.borrow_mut();
            let (item, fields) = p.item_with_two_fields();
            let (x, y) = if swap_fields { (1, 0) } else { (0, 1) };
            let (d0, d1) = if swap_devices { (1, 0) } else { (0, 1) };
            p.edit(d0, item, &[(k(&fields[x], ATTR_AUTOCOMPLETE), t(&id))])
                .unwrap();
            p.edit(d1, item, &[(k(&fields[y], ATTR_AUTOCOMPLETE), t(&id))])
                .unwrap();
            p.sync();
            let views: Vec<Vec<(String, AutofillState)>> = p
                .devices
                .iter()
                .map(|(vault, _)| {
                    vault
                        .custom_field_autofill(item)
                        .into_iter()
                        .map(|s| (s.element.as_str().to_owned(), s.state))
                        .collect()
                })
                .collect();
            prop_assert_eq!(&views[0], &views[1]);
            // List order is creation order here: the first field wins and names nobody; the
            // second is shadowed and names the first.
            prop_assert_eq!(&views[0][0].0, &fields[0]);
            prop_assert_eq!(&views[0][0].1, &AutofillState::Fills);
            prop_assert_eq!(
                &views[0][1].1,
                &AutofillState::Shadowed(Zeroizing::new(fields[0].clone()))
            );
            for (vault, _) in &p.devices {
                let offer = vault.custom_fill_offer(item, &[id.as_str()]);
                prop_assert_eq!(offer.len(), 1);
                prop_assert_eq!(offer[0].element.as_str(), fields[0].as_str());
            }
            // An unrelated edit on either device still succeeds.
            p.edit(d1, item, &[(ITEM_NAME.to_owned(), t("renamed"))])
                .unwrap();
            Ok(())
        },
    );
    if let Err(e) = result {
        panic!("{e}");
    }
}

/// The id grammar and reserved set, for the property test's assumption.
fn check_autocomplete_id_ok(id: &str) -> bool {
    rizzy_core::item::autocomplete::check_autocomplete_id(id.as_bytes()).is_ok()
}

/// W1–W5 on conflict "pick one" and "keep both", and on history restore.
#[test]
fn writer_checks_on_conflicts_and_history() {
    let mut p = Pair::new(7605);
    let (item, [alpha, beta]) = p.item_with_two_fields();
    // Device 0 tags Alpha "acct" and Beta "x"; device 1, concurrently and later, tags Beta
    // "acct". Beta's id conflicts: "acct" (device 1, displayed) against "x".
    p.edit(
        0,
        item,
        &[
            (k(&alpha, ATTR_AUTOCOMPLETE), t("acct")),
            (k(&beta, ATTR_AUTOCOMPLETE), t("x")),
        ],
    )
    .unwrap();
    p.edit(1, item, &[(k(&beta, ATTR_AUTOCOMPLETE), t("acct"))])
        .unwrap();
    p.sync();
    let key = k(&beta, ATTR_AUTOCOMPLETE);
    let values = p.devices[0].0.field_conflict(item, &key);
    assert_eq!(values.len(), 2);
    let displayed = values[0].value.decode().unwrap();
    let ValueRef::Text(shown) = displayed else {
        panic!("text")
    };
    let (acct_dot, x_dot) = if shown == "acct" {
        (values[0].dot, values[1].dot)
    } else {
        (values[1].dot, values[0].dot)
    };
    let now = p.tick();
    let (vault, unlocked) = &mut p.devices[0];
    if shown == "acct" {
        // Picking the displayed duplicate changes nothing and is allowed; picking "x" ends both
        // the conflict and the duplicate.
        vault
            .resolve_conflict_pick(&mut p.rng, unlocked, item, &key, x_dot, now)
            .unwrap();
    } else {
        // Picking "acct" would set an id Alpha already displays (W3).
        assert_eq!(
            vault.resolve_conflict_pick(&mut p.rng, unlocked, item, &key, acct_dot, now),
            Err(ClientError::AutocompleteDuplicate)
        );
        vault
            .resolve_conflict_pick(&mut p.rng, unlocked, item, &key, x_dot, now)
            .unwrap();
    }
    assert!(
        vault
            .custom_field_autofill(item)
            .iter()
            .all(|s| s.state == AutofillState::Fills)
    );

    // History restore: Beta's old id "acct" comes back only if no other field shows it.
    let history = vault.field_history(item, &key);
    let old = history
        .iter()
        .find(|h| matches!(h.value.decode(), Ok(ValueRef::Text("acct"))))
        .map(|h| h.dot);
    if let Some(dot) = old {
        assert_eq!(
            vault.restore_field_history(&mut p.rng, unlocked, item, &key, dot, now + 1),
            Err(ClientError::AutocompleteDuplicate)
        );
    }

    // Keep both on a value conflict: the copies are new fields that take the source's Display
    // Name (W5 passes); an explicit blank one is refused.
    p.edit(0, item, &[(k(&alpha, ATTR_VALUE), t("a0"))])
        .unwrap();
    p.edit(1, item, &[(k(&alpha, ATTR_VALUE), t("a1"))])
        .unwrap();
    p.sync();
    let label_key = k(&alpha, ATTR_VALUE);
    let values = p.devices[0].0.field_conflict(item, &label_key);
    assert_eq!(values.len(), 2);
    let now = p.tick();
    let (vault, unlocked) = &mut p.devices[0];
    assert_eq!(
        vault.resolve_conflict_keep_both(
            &mut p.rng,
            unlocked,
            item,
            &label_key,
            values[0].dot,
            Some(" "),
            now
        ),
        Err(ClientError::LabelRequired)
    );
    vault
        .resolve_conflict_keep_both(
            &mut p.rng,
            unlocked,
            item,
            &label_key,
            values[0].dot,
            None,
            now,
        )
        .unwrap();
}

/// Import: W1–W4 skip the item; an empty label is kept unless the field has an id (§2.4).
#[test]
fn writer_checks_on_import() {
    let (_server, mut rng, mut vault, unlocked, _) = one_item(7606);
    let import = |vault: &mut VaultSync, rng: &mut ChaCha20Rng, attrs: Vec<(&str, Value)>| {
        let element = raw_element(rng);
        let writes: Vec<(String, Value)> = attrs
            .into_iter()
            .map(|(a, v)| (k(&element, a), v))
            .collect();
        let keys: Vec<SchemaKey> = writes
            .iter()
            .map(|(key, _)| SchemaKey::parse(key.as_bytes()).unwrap())
            .collect();
        let edits: Vec<FieldEdit<'_>> = keys
            .iter()
            .zip(&writes)
            .map(|(key, (_, value))| FieldEdit { key, value })
            .collect();
        vault.import_item(rng, &unlocked, ItemType::LOGIN, &edits, T0 + 100)
    };
    let kept = import(
        &mut vault,
        &mut rng,
        vec![(ATTR_KIND, kind(CUSTOM_KIND_TEXT)), (ATTR_VALUE, t("v"))],
    )
    .unwrap();
    assert_eq!(vault.custom_field_autofill(kept).len(), 1);
    for attrs in [
        text_field("A", "Bad", "v"),
        text_field("A", "username", "v"),
        vec![
            (ATTR_KIND, kind(CUSTOM_KIND_TEXT)),
            (ATTR_VALUE, t("v")),
            (ATTR_AUTOCOMPLETE, t("acct")),
        ],
        vec![
            (ATTR_LABEL, t("A")),
            (ATTR_KIND, kind(CUSTOM_KIND_BOOLEAN)),
            (ATTR_VALUE, Value::bool(true)),
            (ATTR_AUTOCOMPLETE, t("acct")),
        ],
    ] {
        assert_eq!(
            import(&mut vault, &mut rng, attrs).unwrap_err(),
            ClientError::InvalidEdit
        );
    }
    import(&mut vault, &mut rng, text_field("A", "acct", "v")).unwrap();
}

/// §2.6 with this client standing in for an old one: the key syncs to another device byte for
/// byte, a label edit keeps it, and removing the field clears it with every other attribute.
#[test]
fn the_key_is_carried_kept_and_cleared_on_removal() {
    let mut p = Pair::new(7607);
    let (item, [alpha, _]) = p.item_with_two_fields();
    p.edit(0, item, &[(k(&alpha, ATTR_AUTOCOMPLETE), t("acct"))])
        .unwrap();
    p.sync();
    let key = k(&alpha, ATTR_AUTOCOMPLETE);
    assert_eq!(
        p.devices[1]
            .0
            .field_value(item, &key)
            .unwrap()
            .expose_secret(),
        t("acct").expose_secret()
    );
    p.edit(1, item, &[(k(&alpha, ATTR_LABEL), t("Renamed"))])
        .unwrap();
    p.sync();
    assert_eq!(
        p.devices[0]
            .0
            .field_value(item, &key)
            .unwrap()
            .expose_secret(),
        t("acct").expose_secret()
    );
    let removal = p.devices[1]
        .0
        .element_removal_writes(item, LIST_FIELD, &alpha)
        .unwrap();
    let removal: Vec<(String, Value)> = removal
        .into_iter()
        .map(|(key, value)| (key.as_str().to_owned(), value))
        .collect();
    assert!(removal.iter().any(|(k, _)| *k == key));
    p.edit(1, item, &removal).unwrap();
    p.sync();
    assert!(p.devices[0].0.field_value(item, &key).unwrap().is_cleared());
}

/// RFC 6238 Appendix B, through the fill plan (CRYPTO.md §15 reuses them for `rizzy-core`'s
/// TOTP): (`otpauth` URI, Unix seconds, code).
const TOTP_VECTORS: [(&str, u64, &str); 6] = [
    (
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
        59,
        "94287082",
    ),
    (
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
        1_111_111_109,
        "07081804",
    ),
    (
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
        1_234_567_890,
        "89005924",
    ),
    (
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
        20_000_000_000,
        "65353130",
    ),
    (
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&digits=8&algorithm=SHA256",
        59,
        "46119246",
    ),
    (
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&digits=8&algorithm=SHA512",
        59,
        "90693936",
    ),
];

/// A request with no custom tokens.
fn plain(only: Option<FillOnly>, totp: bool) -> FillRequest<'static> {
    FillRequest {
        only,
        totp,
        custom: &[],
        username_token: None,
        password_token: None,
    }
}

/// §4.2: the TOTP code through the fill plan, current step only, never the secret; HOTP and
/// a missing secret give nothing; narrowing by `only`.
#[test]
fn fill_plan_totp_and_narrowing() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(7608);
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(LOGIN_USERNAME.to_owned(), t("alice"))],
        T0 + 10,
    )
    .unwrap();
    // No secret: a TOTP-only request sends nothing.
    assert!(!vault.has_time_based_totp(item));
    assert!(
        vault
            .fill_plan(item, &plain(Some(FillOnly::Totp), false), T0)
            .unwrap()
            .is_empty()
    );
    for (i, (uri, seconds, code)) in TOTP_VECTORS.iter().enumerate() {
        edit(
            &mut vault,
            &mut rng,
            &unlocked,
            item,
            &[(LOGIN_TOTP.to_owned(), t(uri))],
            T0 + 20 + u64::try_from(i).unwrap(),
        )
        .unwrap();
        assert!(vault.has_time_based_totp(item));
        let plan = vault
            .fill_plan(item, &plain(Some(FillOnly::Totp), false), seconds * 1000)
            .unwrap();
        assert_eq!(
            plan.totp.as_deref().map(String::as_str),
            Some(*code),
            "{uri}"
        );
        assert!(plan.username.is_none() && plan.password.is_none());
        let debug = format!("{plan:?}");
        assert!(!debug.contains(code) && !debug.contains("GEZDGNBV"));
        // The current step only: one millisecond later in the same step, the same code.
        let again = vault
            .fill_plan(
                item,
                &plain(Some(FillOnly::Totp), false),
                seconds * 1000 + 1,
            )
            .unwrap();
        assert_eq!(again.totp, plan.totp);
    }
    // Narrowing.
    let all = vault.fill_plan(item, &plain(None, false), 59_000).unwrap();
    assert_eq!(all.username.as_deref().map(String::as_str), Some("alice"));
    assert_eq!(all.password.as_deref().map(String::as_str), Some("p"));
    assert!(all.totp.is_none());
    let with_totp = vault.fill_plan(item, &plain(None, true), 59_000).unwrap();
    assert!(with_totp.totp.is_some());
    let user = vault
        .fill_plan(item, &plain(Some(FillOnly::Username), false), 59_000)
        .unwrap();
    assert!(user.username.is_some() && user.password.is_none() && user.totp.is_none());
    let pass = vault
        .fill_plan(item, &plain(Some(FillOnly::Password), true), 59_000)
        .unwrap();
    assert!(pass.username.is_none() && pass.password.is_some() && pass.totp.is_some());
    // HOTP is not time-based.
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(
            LOGIN_TOTP.to_owned(),
            t("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1"),
        )],
        T0 + 100,
    )
    .unwrap();
    assert!(!vault.has_time_based_totp(item));
    assert!(
        vault
            .fill_plan(item, &plain(Some(FillOnly::Totp), false), 59_000)
            .unwrap()
            .totp
            .is_none()
    );
    // Only Active Logins fill.
    vault
        .trash_item(&mut rng, &unlocked, item, T0 + 200)
        .unwrap();
    assert_eq!(
        vault
            .fill_plan(item, &plain(None, false), 59_000)
            .unwrap_err(),
        ClientError::UnknownItem
    );
}

/// The choices an offer recorded, as the long-lived context keeps them.
fn choices(offer: &[crate::autofill::CustomOffer]) -> Vec<CustomChoice> {
    offer
        .iter()
        .map(|o| CustomChoice {
            token: o.token.clone(),
            element: o.element.clone(),
        })
        .collect()
}

/// §4.3: exact match only; reserved, invalid, boolean, unknown-kind and label-less fields
/// never fill; values over 4096 UTF-16 units are left out; role precedence; a field edited
/// since the offer is re-checked.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one item with every kind of field that does and does not fill, then the plan"
)]
fn fill_plan_custom_fields() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(7609);
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(LOGIN_USERNAME.to_owned(), t("alice"))],
        T0 + 5,
    )
    .unwrap();
    let member = add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        text_field("Member no.", "member", "M-1"),
        T0 + 10,
    )
    .unwrap();
    let pin = add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        vec![
            (ATTR_LABEL, t("PIN")),
            (ATTR_KIND, kind(CUSTOM_KIND_HIDDEN)),
            (ATTR_VALUE, t("4242")),
            (ATTR_AUTOCOMPLETE, t("pin.code")),
        ],
        T0 + 20,
    )
    .unwrap();
    let long = add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        text_field("Long", "long", &"x".repeat(4097)),
        T0 + 30,
    )
    .unwrap();
    // Fields no checked writer would make, written raw.
    let mut raw = |attrs: Vec<(&str, Value)>, now: u64| {
        let element = raw_element(&mut rng);
        let writes: Vec<(String, Value)> = attrs
            .into_iter()
            .map(|(a, v)| (k(&element, a), v))
            .collect();
        raw_write(&mut vault, &mut rng, &unlocked, item, &writes, now);
        element
    };
    raw(text_field("Reserved", "username", "r"), T0 + 40);
    raw(text_field("Invalid", "Upper", "i"), T0 + 41);
    raw(
        vec![
            (ATTR_LABEL, t("Bool")),
            (ATTR_KIND, kind(CUSTOM_KIND_BOOLEAN)),
            (ATTR_VALUE, Value::bool(true)),
            (ATTR_AUTOCOMPLETE, t("boolean")),
        ],
        T0 + 42,
    );
    raw(
        vec![
            (ATTR_LABEL, t("Unknown")),
            (ATTR_KIND, kind(9)),
            (ATTR_VALUE, t("u")),
            (ATTR_AUTOCOMPLETE, t("unknown")),
        ],
        T0 + 43,
    );
    raw(
        vec![
            (ATTR_KIND, kind(CUSTOM_KIND_TEXT)),
            (ATTR_VALUE, t("n")),
            (ATTR_AUTOCOMPLETE, t("nameless")),
        ],
        T0 + 44,
    );
    let tokens = [
        "member", "member2", "membe", "pin.code", "long", "username", "upper", "Upper", "boolean",
        "unknown", "nameless", "member",
    ];
    let offer = vault.custom_fill_offer(item, &tokens);
    let offered: Vec<(&str, &str, bool)> = offer
        .iter()
        .map(|o| (o.token.as_str(), o.label.as_str(), o.concealed))
        .collect();
    assert_eq!(
        offered,
        [("member", "Member no.", false), ("pin.code", "PIN", true)]
    );
    assert_eq!(offer[0].element.as_str(), member);
    assert_eq!(offer[1].element.as_str(), pin);
    let _ = long;

    let recorded = choices(&offer);
    let request = FillRequest {
        only: None,
        totp: false,
        custom: &recorded,
        username_token: Some("member"),
        password_token: None,
    };
    let plan = vault.fill_plan(item, &request, T0).unwrap();
    let custom: Vec<(&str, &str)> = plan
        .custom
        .iter()
        .map(|(t, v)| (t.as_str(), v.as_str()))
        .collect();
    assert_eq!(custom, [("member", "M-1"), ("pin.code", "4242")]);
    // Role precedence: the username target carries "member", which resolved.
    assert!(plan.username.is_none());
    assert_eq!(plan.password.as_deref().map(String::as_str), Some("p"));
    // A token that did not resolve leaves the role value.
    let request = FillRequest {
        username_token: Some("other"),
        ..request
    };
    let plan = vault.fill_plan(item, &request, T0).unwrap();
    assert_eq!(plan.username.as_deref().map(String::as_str), Some("alice"));

    // Edited since the offer: a field that lost its id, or became boolean, is dropped.
    edit(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[(k(&member, ATTR_AUTOCOMPLETE), t("member-no"))],
        T0 + 50,
    )
    .unwrap();
    let plan = vault.fill_plan(item, &request, T0).unwrap();
    let custom: Vec<&str> = plan.custom.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(custom, ["pin.code"]);
    // A recorded element that is no longer the one filling the token is dropped too.
    let forged = [CustomChoice {
        token: Zeroizing::new("pin.code".to_owned()),
        element: Zeroizing::new(member.clone()),
    }];
    let request = FillRequest {
        custom: &forged,
        ..request
    };
    assert!(
        vault
            .fill_plan(item, &request, T0)
            .unwrap()
            .custom
            .is_empty()
    );
}

/// §5.3: the save plan's rows and defaults, for a new item and an update.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the new-item rows, then the update rows, then the cap"
)]
fn save_plan_rows_and_defaults() {
    let (_server, mut rng, mut vault, unlocked, item) = one_item(7610);
    let captured = [
        CapturedField {
            token: "member",
            value: "M-1",
            masked: false,
        },
        CapturedField {
            token: "pin.code",
            value: "4242",
            masked: true,
        },
        CapturedField {
            token: "username",
            value: "x",
            masked: false,
        },
        CapturedField {
            token: "Upper",
            value: "x",
            masked: false,
        },
        CapturedField {
            token: "empty",
            value: "",
            masked: false,
        },
        CapturedField {
            token: "member",
            value: "again",
            masked: false,
        },
    ];
    let rows = vault.custom_save_plan(None, &captured);
    let summary: Vec<(usize, SaveRowKind, &str, bool, bool)> = rows
        .iter()
        .map(|r| {
            (
                r.index,
                r.kind.clone(),
                r.label.as_str(),
                r.concealed,
                r.checked,
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (0, SaveRowKind::Add, "member", false, true),
            (1, SaveRowKind::Add, "pin.code", true, false),
        ]
    );

    // Update: "member" exists with another value (unchecked update row), "pin.code" holds the
    // same value (no row), "branch" does not exist (add row), "flag" is held by a field that
    // cannot fill (no row: adding would duplicate the id, and a save never changes an id).
    let member = add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        text_field("Member no.", "member", "M-0"),
        T0 + 10,
    )
    .unwrap();
    add_field(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        vec![
            (ATTR_LABEL, t("PIN")),
            (ATTR_KIND, kind(CUSTOM_KIND_HIDDEN)),
            (ATTR_VALUE, t("4242")),
            (ATTR_AUTOCOMPLETE, t("pin.code")),
        ],
        T0 + 20,
    )
    .unwrap();
    let element = raw_element(&mut rng);
    raw_write(
        &mut vault,
        &mut rng,
        &unlocked,
        item,
        &[
            (k(&element, ATTR_KIND), kind(CUSTOM_KIND_TEXT)),
            (k(&element, ATTR_VALUE), t("f")),
            (k(&element, ATTR_AUTOCOMPLETE), t("flag")),
        ],
        T0 + 30,
    );
    let captured = [
        CapturedField {
            token: "member",
            value: "M-1",
            masked: false,
        },
        CapturedField {
            token: "pin.code",
            value: "4242",
            masked: true,
        },
        CapturedField {
            token: "branch",
            value: "B",
            masked: false,
        },
        CapturedField {
            token: "flag",
            value: "g",
            masked: false,
        },
    ];
    let rows = vault.custom_save_plan(Some(item), &captured);
    let summary: Vec<(usize, SaveRowKind, &str, bool, bool)> = rows
        .iter()
        .map(|r| {
            (
                r.index,
                r.kind.clone(),
                r.label.as_str(),
                r.concealed,
                r.checked,
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (
                0,
                SaveRowKind::Update(Zeroizing::new(member)),
                "Member no.",
                false,
                false
            ),
            (2, SaveRowKind::Add, "branch", false, true),
        ]
    );
    // At most 8 captured fields are read.
    let many: Vec<String> = (0..10).map(|i| format!("f{i}")).collect();
    let captured: Vec<CapturedField<'_>> = many
        .iter()
        .map(|token| CapturedField {
            token,
            value: "v",
            masked: false,
        })
        .collect();
    assert_eq!(vault.custom_save_plan(None, &captured).len(), 8);
}

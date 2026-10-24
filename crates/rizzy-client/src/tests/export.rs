// SPDX-License-Identifier: AGPL-3.0-only

//! Export and import tests (ADR 0027): the payload's known answer and refusal vectors, the
//! round trips vault → encrypted file → new vault and vault → plaintext JSON → new vault, the
//! import path's splitting and limits, trashed items, carried unknown keys, the plaintext
//! acknowledgement and the CSV form. The vaults are real [`VaultSync`] drivers of signed-up
//! devices of the parent module's fake server.

use std::collections::BTreeMap;

use rizzy_core::item::key::ElementId;
use rizzy_core::item::schema::{
    API_ENDPOINT, API_KEY, API_NAME, API_SECRET, ATTR_KIND, ATTR_LABEL, ATTR_ORDER, ATTR_VALUE,
    CARD_NUMBER, IMPORT_CREATED_MS, ITEM_FAVORITE, ITEM_NAME, ITEM_NOTES, ITEM_TYPE,
    LICENSE_EXPIRES, LICENSE_KEY, LICENSE_NAME, LICENSE_SEATS, LIST_FIELD, LIST_URI, LOGIN_TOTP,
    SSH_HOST, SSH_PASSPHRASE, SSH_PORT, SSH_PRIVATE_KEY, SSH_PUBLIC_KEY, SSH_USERNAME, VAULT_NAME,
    WIFI_PASSWORD, WIFI_SECURITY_TYPE, WIFI_SSID, WriteSource,
};
use rizzy_core::item::tag::tag_key;
use rizzy_core::item::value::SortKey;
use rizzy_import::{Format, import};
use rizzy_sync::hlc::Hlc;
use rizzy_sync::record::{
    Entry, FieldKey as RecordKey, LiveSnapshot, MAX_SNAPSHOT_DATA_LEN, Register, SnapshotData,
    Value as RecordValue, encode_snapshot,
};
use rizzy_sync::vv::VersionVector;

use super::*;
use crate::export::detect::{DetectedFormat, detect_format};
use crate::export::gate::test_auth;
use crate::export::payload::{
    MAX_PAYLOAD_ENTRIES, MAX_PAYLOAD_LEN, PayloadImport, PayloadItem, PayloadPreview,
    encode_payload, parse_payload, preview_payload,
};
use crate::export::plaintext::{
    CSV_EXPORT_WARNING_AFTER_COUNT, CSV_EXPORT_WARNING_BEFORE_COUNT, CsvLoss,
    PLAINTEXT_EXPORT_PHRASE, PLAINTEXT_EXPORT_WARNING, PlaintextExportAck, csv_columns,
    csv_export_warning,
};
use crate::export::{read_export, write_export};
use crate::items::ImportWrite;
use proptest::prelude::*;

/// A signed-up device and the driver of its personal vault.
struct Fixture {
    /// The fake server of the account.
    server: Server,
    /// The device's randomness.
    rng: ChaCha20Rng,
    /// The vault.
    vault: VaultSync,
    /// The unlocked device.
    unlocked: UnlockedDevice,
}

/// A new account with one device and an empty vault.
fn fixture(seed: u64) -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut server = Server::new(seed + 1000);
    let signed = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let vault = VaultSync::new(signed.vault_key, &signed.unlocked, 1).unwrap();
    Fixture {
        server,
        rng,
        vault,
        unlocked: signed.unlocked,
    }
}

impl Fixture {
    /// Creates an item from `(key, value)` pairs.
    fn create(&mut self, item_type: ItemType, fields: &[(&SchemaKey, &Value)], at: u64) -> ItemId {
        let edits: Vec<FieldEdit<'_>> = fields
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        self.vault
            .create_item(&mut self.rng, &self.unlocked, item_type, &edits, at)
            .unwrap()
    }

    /// Edits one field.
    fn edit(&mut self, item: ItemId, key: &SchemaKey, value: &Value, at: u64) {
        self.vault
            .edit_item(
                &mut self.rng,
                &self.unlocked,
                item,
                &[FieldEdit { key, value }],
                at,
            )
            .unwrap();
    }

    /// Fetches, uploads every own record and checks the fake server stored them all.
    fn sync(&mut self) -> usize {
        let authors = self.server.authors();
        let fetch = self.server.fetch(&self.vault.fetch_request().unwrap());
        self.vault.apply_fetch(&authors, &fetch, T0).unwrap();
        let mut stored = 0;
        while let Some(up) = self
            .vault
            .upload_request(&mut self.rng, &self.unlocked)
            .unwrap()
        {
            let answer = self.server.upload(&up);
            assert!(
                answer
                    .results
                    .as_slice()
                    .iter()
                    .all(|r| matches!(r, UploadResult::Stored | UploadResult::AlreadyStored))
            );
            let outcome = self.vault.apply_upload_response(&answer).unwrap();
            assert!(outcome.rejected.is_empty());
            stored += outcome.acknowledged;
        }
        stored
    }
}

/// A fixed key.
fn k(key: &str) -> SchemaKey {
    SchemaKey::parse(key.as_bytes()).unwrap()
}

/// A Text value.
fn text(s: &str) -> Value {
    Value::text(s).unwrap()
}

/// What a vault displays: per live item, by its `item.name` (the tests give every item one),
/// its lifecycle and every field's displayed value bytes, cleared fields left out.
fn displayed(vault: &VaultSync) -> BTreeMap<String, (ItemLifecycle, BTreeMap<String, Vec<u8>>)> {
    let mut out = BTreeMap::new();
    for item in vault.item_ids() {
        let lifecycle = vault.item_lifecycle(item);
        if !matches!(lifecycle, ItemLifecycle::Active | ItemLifecycle::Trashed) {
            continue;
        }
        let mut fields = BTreeMap::new();
        for key in vault.field_keys(item) {
            let value = vault.field_value(item, &key).unwrap();
            if !value.is_cleared() {
                fields.insert(key.to_string(), value.expose_secret().to_vec());
            }
        }
        let name = match fields.get(ITEM_NAME).map(|v| ValueRef::decode(v).unwrap()) {
            Some(ValueRef::Text(name)) => name.to_owned(),
            _ => "(unnamed)".to_owned(),
        };
        assert!(out.insert(name, (lifecycle, fields)).is_none());
    }
    out
}

/// The `pwhist` entries of displayed fields as `(password, ms)`, newest first.
fn pwhist(fields: &BTreeMap<String, Vec<u8>>) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    for (key, value) in fields {
        if let Some(id) = key
            .strip_prefix("pwhist/")
            .and_then(|k| k.strip_suffix("/value"))
        {
            let ValueRef::Text(password) = ValueRef::decode(value).unwrap() else {
                panic!("history value is not a text");
            };
            let ValueRef::U64(ms) = ValueRef::decode(&fields[&format!("pwhist/{id}/ms")]).unwrap()
            else {
                panic!("history time is not a u64");
            };
            entries.push((password.to_owned(), ms));
        }
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    entries
}

/// `fields` without what an import adds: `import.created_ms` and `pwhist/…`.
fn without_import_keys(fields: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    fields
        .iter()
        .filter(|(key, _)| *key != IMPORT_CREATED_MS && !key.starts_with("pwhist/"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// The vault every round trip exports: a login with a password history, a URI, a tag, a
/// hidden custom field and a favourite flag; a trashed note; a card with an unknown key, a
/// reserved key and an unsupported value (as a newer client would leave them); an identity;
/// one item of each M3 type of ADR 0055, every key of its type set; a Bank account of the type
/// ADR 0078 retired, as an older build wrote it ([`create_retired_bank_account`]); the
/// vault-settings item and a purged item, neither of which is exported.
fn populated(seed: u64) -> (Fixture, ItemId) {
    let mut f = fixture(seed);
    let uri = ElementId::generate(&mut f.rng);
    let field = ElementId::generate(&mut f.rng);
    let bank = f.create(
        ItemType::LOGIN,
        &[
            (&k(ITEM_NAME), &text("Bank \"main\"")),
            (&k(LOGIN_USERNAME), &text("alice")),
            (&k(LOGIN_PASSWORD), &text("p1")),
            (&k(LOGIN_TOTP), &text("JBSWY3DPEHPK3PXP")),
            (&k(ITEM_FAVORITE), &Value::bool(true)),
            (
                &uri.key(LIST_URI, ATTR_VALUE).unwrap(),
                &text("https://bank.example"),
            ),
            (
                &uri.key(LIST_URI, ATTR_ORDER).unwrap(),
                &Value::sort_key(&SortKey::from_slice(&[0x80]).unwrap()),
            ),
            (&tag_key("work").unwrap(), &Value::bool(true)),
            (&field.key(LIST_FIELD, ATTR_LABEL).unwrap(), &text("PIN")),
            (
                &field.key(LIST_FIELD, ATTR_KIND).unwrap(),
                &Value::enumeration(2),
            ),
            (&field.key(LIST_FIELD, ATTR_VALUE).unwrap(), &text("=1+1")),
        ],
        T0 + 1,
    );
    f.edit(bank, &k(LOGIN_PASSWORD), &text("p2"), T0 + 2_000);
    f.edit(bank, &k(LOGIN_PASSWORD), &text("p3,\r\n\"q\""), T0 + 3_000);

    let note = f.create(
        ItemType::SECURE_NOTE,
        &[
            (&k(ITEM_NAME), &text("Old note")),
            (&k(ITEM_NOTES), &text("line one\nline two\ttab \u{1} é")),
        ],
        T0 + 10,
    );
    f.vault
        .trash_item(&mut f.rng, &f.unlocked, note, T0 + 11)
        .unwrap();

    // A newer client's keys and an unsupported value, carried into the vault as they are.
    let newer = k("newer.thing");
    // Still reserved after ADR 0055, which assigns `ssh.private_key` but not this one (§2).
    let reserved = k("ssh.key_type");
    let raw = Value::copy_from_encoded(&[0x7f, 0x01, 0x02]).unwrap();
    let bad_text = Value::copy_from_encoded(&[0x01, 0xff, 0xfe]).unwrap();
    let name = k(ITEM_NAME);
    let number = k(CARD_NUMBER);
    let (card_name, card_number, key_text) = (text("Visa"), text("4111111111111111"), text("x"));
    let carried = |key, value| ImportWrite {
        source: WriteSource::Carried,
        key,
        value,
    };
    f.vault
        .import_item_writes(
            &mut f.rng,
            &f.unlocked,
            ItemType::CARD,
            &[
                carried(&name, &card_name),
                carried(&number, &card_number),
                carried(&newer, &raw),
                carried(&reserved, &key_text),
                carried(&k("newer.text"), &bad_text),
            ],
            false,
            T0 + 20,
        )
        .unwrap();

    f.create(
        ItemType::IDENTITY,
        &[
            (&k(ITEM_NAME), &text("Me")),
            (&k("identity.first_name"), &text("Alice")),
            (&k("identity.ssn"), &text("000-00-0000")),
        ],
        T0 + 30,
    );
    create_m3_items(&mut f);
    create_retired_bank_account(&mut f, T0 + 36);
    f.create(
        ItemType::VAULT_SETTINGS,
        &[(&k(VAULT_NAME), &text("Personal"))],
        T0 + 40,
    );
    let gone = f.create(ItemType::LOGIN, &[(&k(ITEM_NAME), &text("Gone"))], T0 + 50);
    f.vault
        .trash_item(&mut f.rng, &f.unlocked, gone, T0 + 51)
        .unwrap();
    f.vault
        .purge_item(&mut f.rng, &f.unlocked, gone, T0 + 52)
        .unwrap();
    (f, bank)
}

/// An M3 item of [`m3_items`]: its type, title, and `(key, text)` of each field.
type M3Item = (ItemType, &'static str, Vec<(&'static str, &'static str)>);

/// Creates the items of [`m3_items`] in `f`'s vault.
fn create_m3_items(f: &mut Fixture) {
    for (at, (item_type, name, keys)) in (T0 + 31..).zip(m3_items()) {
        let keys: Vec<(SchemaKey, Value)> = keys
            .iter()
            .map(|(key, value)| (k(key), text(value)))
            .collect();
        let mut fields: Vec<(&SchemaKey, &Value)> = keys.iter().map(|(k, v)| (k, v)).collect();
        let title = (k(ITEM_NAME), text(name));
        fields.push((&title.0, &title.1));
        f.create(item_type, &fields, at);
    }
}

/// One item of each M3 type (ADR 0055 §1, as ADR 0078 §7 amends it): its type, title, and every
/// key of the type with a value, the concealed ones included.
fn m3_items() -> [M3Item; 4] {
    [
        (
            ItemType::SSH_KEY,
            "SSH",
            vec![
                (SSH_HOST, "git.example.com"),
                (SSH_PORT, "2222"),
                (SSH_USERNAME, "git"),
                (
                    SSH_PRIVATE_KEY,
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n",
                ),
                (SSH_PUBLIC_KEY, "ssh-ed25519 AAAA alice@example.com"),
                (SSH_PASSPHRASE, "hunter2"),
            ],
        ),
        (
            ItemType::API_CREDENTIAL,
            "API",
            vec![
                (API_NAME, "Example API"),
                (API_KEY, "AKIAEXAMPLE"),
                (API_SECRET, "s3cr3t"),
                (API_ENDPOINT, "https://api.example.com"),
            ],
        ),
        (
            ItemType::SOFTWARE_LICENSE,
            "License",
            vec![
                (LICENSE_NAME, "Editor"),
                (LICENSE_KEY, "ABCD-EFGH"),
                (LICENSE_SEATS, "5"),
                (LICENSE_EXPIRES, "2027-12-31"),
            ],
        ),
        (
            ItemType::WIFI,
            "WiFi",
            vec![
                (WIFI_SSID, "home-net"),
                (WIFI_PASSWORD, "correct horse"),
                (WIFI_SECURITY_TYPE, "WPA2"),
            ],
        ),
    ]
}

/// The title of the item [`create_retired_bank_account`] writes.
const RETIRED_BANK_TITLE: &str = "Bank account";

/// The five `bank.` keys ADR 0055 §1 assigned and ADR 0078 §2 retired, each with a value.
const RETIRED_BANK_FIELDS: [(&str, &str); 5] = [
    ("bank.bank_name", "Example Bank"),
    ("bank.account_holder", "Alice"),
    ("bank.account_number", "DE89370400440532013000"),
    ("bank.routing_number", "COBADEFFXXX"),
    ("bank.account_type", "Checking"),
];

/// Writes a Bank account (`0x0009`) with its five `bank.` keys, as an integration build between
/// ADR 0055 and ADR 0078 did. This client never creates one (ADR 0078 §1: `create_item` refuses
/// the type), so the op is written past its schema checks, as an older client's would be.
fn create_retired_bank_account(f: &mut Fixture, at: u64) -> ItemId {
    let item_type = Value::enumeration(ItemType::RETIRED_BANK_ACCOUNT.id());
    let name = text(RETIRED_BANK_TITLE);
    let values: Vec<(&str, Value)> = RETIRED_BANK_FIELDS
        .iter()
        .map(|(key, value)| (*key, text(value)))
        .collect();
    let mut writes: Vec<(&str, &[u8])> = vec![
        (ITEM_TYPE, item_type.expose_secret()),
        (ITEM_NAME, name.expose_secret()),
    ];
    writes.extend(
        values
            .iter()
            .map(|(key, value)| (*key, value.expose_secret())),
    );
    // `create_item` refuses it, before anything is written.
    let edits: Vec<(SchemaKey, Value)> = RETIRED_BANK_FIELDS
        .iter()
        .map(|(key, value)| (k(key), text(value)))
        .collect();
    let edits: Vec<FieldEdit<'_>> = edits
        .iter()
        .map(|(key, value)| FieldEdit { key, value })
        .collect();
    let before = f.vault.next_device_seq();
    assert_eq!(
        f.vault
            .create_item(
                &mut f.rng,
                &f.unlocked,
                ItemType::RETIRED_BANK_ACCOUNT,
                &edits,
                at
            )
            .unwrap_err(),
        ClientError::InvalidEdit
    );
    assert_eq!(f.vault.next_device_seq(), before);
    let item = ItemId::generate(&mut f.rng);
    f.vault
        .write_op(
            &mut f.rng,
            &f.unlocked,
            item,
            &crate::sync::OwnChange {
                lifecycle: rizzy_sync::record::Lifecycle::Active,
                writes: &writes,
            },
            at,
        )
        .unwrap();
    item
}

/// Checks that `fields` are the retired Bank account's, byte for byte.
fn assert_retired_bank_account(fields: &BTreeMap<String, Vec<u8>>) {
    assert_eq!(
        fields[ITEM_TYPE],
        Value::enumeration(0x0009).expose_secret()
    );
    for (key, value) in RETIRED_BANK_FIELDS {
        assert_eq!(fields[key], text(value).expose_secret(), "{key}");
    }
}

/// ADR 0078 §1, §3 with ADR 0018 §8 "Unknown type": a retired Bank account an older build wrote
/// is shown with its fields, refuses every field edit, and can be trashed, restored and purged.
#[test]
fn a_retired_bank_account_is_unsupported_but_trashable() {
    let mut f = fixture(61);
    let item = create_retired_bank_account(&mut f, T0 + 1);
    assert_eq!(
        f.vault.item_type(item),
        Some(ItemType::RETIRED_BANK_ACCOUNT)
    );
    assert_eq!(f.vault.item_type(item).and_then(ItemType::supported), None);
    // Its fields stay displayed (concealment is the clients' display rule, ADR 0078 §2).
    assert_retired_bank_account(&displayed(&f.vault)[RETIRED_BANK_TITLE].1);
    // No field edit, not even of `item.name` or a Cleared `bank.` key.
    let before = f.vault.next_device_seq();
    for (key, value) in [
        (k(ITEM_NAME), text("Renamed")),
        (k("bank.account_number"), text("1")),
        (k("bank.account_number"), Value::cleared()),
    ] {
        assert_eq!(
            f.vault
                .edit_item(
                    &mut f.rng,
                    &f.unlocked,
                    item,
                    &[FieldEdit {
                        key: &key,
                        value: &value
                    }],
                    T0 + 2
                )
                .unwrap_err(),
            ClientError::InvalidEdit
        );
    }
    assert_eq!(f.vault.next_device_seq(), before);
    // Trash, restore and purge work.
    f.vault
        .trash_item(&mut f.rng, &f.unlocked, item, T0 + 3)
        .unwrap();
    assert_eq!(f.vault.item_lifecycle(item), ItemLifecycle::Trashed);
    f.vault
        .restore_item(&mut f.rng, &f.unlocked, item, T0 + 4)
        .unwrap();
    assert_eq!(f.vault.item_lifecycle(item), ItemLifecycle::Active);
    f.vault
        .trash_item(&mut f.rng, &f.unlocked, item, T0 + 5)
        .unwrap();
    f.vault
        .purge_item(&mut f.rng, &f.unlocked, item, T0 + 6)
        .unwrap();
    assert_eq!(f.vault.item_lifecycle(item), ItemLifecycle::Purged);
    assert_eq!(f.sync(), 5);
}

/// Checks that vault `b`, which imported an export of vault `a`, displays what `a` displays.
fn assert_same_vault(a: &Fixture, b: &Fixture, bank: ItemId) {
    let mut exported = displayed(&a.vault);
    // Neither the vault settings nor the purged item is exported.
    let settings = exported.remove("(unnamed)").unwrap();
    assert!(settings.1.contains_key(VAULT_NAME));
    // The retired Bank account is exported, and skipped on import (ADR 0078 §3).
    let retired = exported.remove(RETIRED_BANK_TITLE).unwrap();
    assert_retired_bank_account(&retired.1);
    let imported = displayed(&b.vault);
    assert!(!imported.contains_key(RETIRED_BANK_TITLE));
    assert_eq!(
        exported.keys().collect::<Vec<_>>(),
        [
            "API",
            "Bank \"main\"",
            "License",
            "Me",
            "Old note",
            "SSH",
            "Visa",
            "WiFi"
        ]
    );
    assert_eq!(
        imported.keys().collect::<Vec<_>>(),
        exported.keys().collect::<Vec<_>>()
    );
    for (name, (lifecycle, fields)) in &exported {
        let (new_lifecycle, new_fields) = &imported[name];
        assert_eq!(new_lifecycle, lifecycle, "{name}");
        assert_eq!(
            &without_import_keys(new_fields),
            &without_import_keys(fields),
            "{name}"
        );
        assert!(new_fields.contains_key(IMPORT_CREATED_MS), "{name}");
    }
    assert_eq!(imported["Old note"].0, ItemLifecycle::Trashed);
    // The unknown and reserved keys and the unsupported values, byte for byte.
    let visa = &imported["Visa"].1;
    assert_eq!(visa["newer.thing"], [0x7f, 0x01, 0x02]);
    assert_eq!(visa["newer.text"], [0x01, 0xff, 0xfe]);
    assert_eq!(visa["ssh.key_type"], [0x01, b'x']);
    // Each M3 item, of its own type, with every key of its type (ADR 0055).
    for (item_type, name, keys) in m3_items() {
        let fields = &imported[name].1;
        assert_eq!(
            fields[ITEM_TYPE],
            Value::enumeration(item_type.id()).expose_secret()
        );
        for (key, value) in keys {
            assert_eq!(fields[key], text(value).expose_secret(), "{name}: {key}");
        }
    }
    // The created time of the exported state, and the password history, newest first.
    let bank_fields = &imported["Bank \"main\""].1;
    let created = a.vault.merge(bank).unwrap().times().created_ms.unwrap();
    assert_eq!(created, T0 + 1);
    assert_eq!(
        bank_fields[IMPORT_CREATED_MS],
        Value::u64(created).expose_secret()
    );
    assert_eq!(
        pwhist(bank_fields),
        [("p2".to_owned(), T0 + 2_000), ("p1".to_owned(), T0 + 1)]
    );
    // Element ids are kept.
    let kept = |fields: &BTreeMap<String, Vec<u8>>| -> Vec<String> {
        fields
            .keys()
            .filter(|key| key.starts_with("uri/") || key.starts_with("field/"))
            .cloned()
            .collect()
    };
    assert_eq!(kept(bank_fields), kept(&exported["Bank \"main\""].1));
    assert_eq!(kept(bank_fields).len(), 5);
}

#[test]
fn encrypted_export_round_trips_into_a_new_vault() {
    let (mut a, bank) = populated(31);
    assert!(a.vault.export_blockers().is_empty());
    let export = a
        .vault
        .export_encrypted(&mut a.rng, test_auth().0, "export pw", T0 + 100)
        .unwrap();
    // The four M1 items, the four M3 items of ADR 0055 and the retired Bank account.
    assert_eq!(export.items, 9);
    assert!(export.unresolved.is_empty());
    // The payload carries the retired Bank account byte for byte (ADR 0078 §3, ADR 0027 §1).
    let payload = a.vault.export_payload().unwrap();
    let entries = parse_payload(payload.expose_secret()).unwrap();
    assert_eq!(entries.len(), 9);
    let retired: Vec<BTreeMap<String, Vec<u8>>> = entries
        .iter()
        .map(|e| {
            e.snapshot()
                .registers()
                .iter()
                .filter(|r| !r.key().is_lifecycle())
                .map(|r| {
                    assert_eq!(r.entries().len(), 1);
                    (
                        r.key().expose_secret().to_owned(),
                        r.entries()[0].value().expose_secret().to_vec(),
                    )
                })
                .collect()
        })
        .filter(|fields: &BTreeMap<String, Vec<u8>>| {
            fields.get(ITEM_TYPE).map(Vec::as_slice) == Some(&[0x05, 0x00, 0x09])
        })
        .collect();
    assert_eq!(retired.len(), 1);
    assert_retired_bank_account(&retired[0]);
    assert_eq!(retired[0].len(), 7);
    // One vault state gives one payload.
    assert_eq!(
        a.vault.export_payload().unwrap().expose_secret(),
        a.vault.export_payload().unwrap().expose_secret()
    );
    // No plaintext in the file.
    let file = String::from_utf8(export.file.clone()).unwrap();
    for secret in ["Bank", "alice", "4111111111111111"] {
        assert!(!file.contains(secret));
    }

    let mut b = fixture(32);
    // The vault's own refusals come before the key derivation.
    b.vault.set_read_only(true);
    assert_eq!(
        b.vault
            .import_encrypted(&mut b.rng, &b.unlocked, &export.file, "export pw", T0 + 200)
            .unwrap_err(),
        ClientError::ReadOnly
    );
    b.vault.set_read_only(false);
    assert_eq!(
        b.vault
            .import_encrypted(&mut b.rng, &b.unlocked, &export.file, "wrong", T0 + 200)
            .unwrap_err(),
        ClientError::ExportDecryptionFailed
    );
    assert!(b.vault.item_ids().is_empty());
    let report = b
        .vault
        .import_encrypted(&mut b.rng, &b.unlocked, &export.file, "export pw", T0 + 200)
        .unwrap();
    // The retired Bank account is skipped and counted, like any unsupported type (ADR 0078 §3,
    // ADR 0027 §2 step 4).
    assert_eq!(report.imported.len(), 8);
    assert_eq!(
        report,
        PayloadImport {
            imported: report.imported.clone(),
            skipped_items: 1,
            ..PayloadImport::default()
        }
    );
    // New item ids, and ops of the importing device only.
    let old: Vec<ItemId> = a.vault.item_ids();
    assert!(report.imported.iter().all(|id| !old.contains(id)));
    assert_eq!(b.vault.item_ids().len(), 8);
    assert_same_vault(&a, &b, bank);
    // Eight create ops and the trash op, all stored by the server.
    assert_eq!(b.vault.next_device_seq(), 10);
    assert_eq!(b.sync(), 9);
    // Exporting the importing vault again gives the same displayed values.
    let again = b
        .vault
        .export_encrypted(&mut b.rng, test_auth().0, "second pw", T0 + 300)
        .unwrap();
    let mut c = fixture(33);
    c.vault
        .import_encrypted(&mut c.rng, &c.unlocked, &again.file, "second pw", T0 + 400)
        .unwrap();
    let (shown_b, shown_c) = (displayed(&b.vault), displayed(&c.vault));
    for (name, (lifecycle, fields)) in &shown_b {
        assert_eq!(&shown_c[name].0, lifecycle);
        assert_eq!(&shown_c[name].1, fields, "{name}");
    }
}

#[test]
fn plaintext_json_round_trips_into_a_new_vault() {
    let (a, bank) = populated(41);
    for wrong in [
        "",
        "export plaintext",
        "EXPORT PLAINTEXT\n",
        " EXPORT PLAINTEXT",
        "EXPORT  PLAINTEXT",
        "yes",
    ] {
        assert_eq!(
            PlaintextExportAck::from_typed_phrase(wrong).unwrap_err(),
            ClientError::PlaintextExportNotAcknowledged
        );
    }
    let ack = PlaintextExportAck::from_typed_phrase(PLAINTEXT_EXPORT_PHRASE).unwrap();
    let json = a
        .vault
        .export_plaintext_json(test_auth().1, ack, T0 + 100)
        .unwrap();
    let doc = core::str::from_utf8(json.expose_secret()).unwrap();
    // The shape of ADR 0027 §3: no BOM, LF only, members in order, one item per line.
    assert!(doc.starts_with(&format!(
        "{{\"format\":\"rizzy-vault-plaintext-export\",\"version\":1,\"exported_at\":{},\"items\":[\n{{\"id\":\"",
        T0 + 100
    )));
    assert!(doc.ends_with("]}\n]}\n"));
    assert!(!doc.contains('\r'));
    // The head, nine items (four M1, four M3, the retired Bank account) and the tail.
    assert_eq!(doc.lines().count(), 11);
    for piece in [
        r#""type":5,"#,
        r#"{"key":"ssh.private_key","value":{"text":"-----BEGIN OPENSSH PRIVATE KEY-----\u000aAAAA\u000a"}}"#,
        r#""type":6,"#,
        r#"{"key":"api.secret","value":{"text":"s3cr3t"}}"#,
        r#""type":7,"#,
        r#""type":8,"#,
        r#"{"key":"wifi.password","value":{"text":"correct horse"}}"#,
        // The retired Bank account, every key as an older build wrote it (ADR 0078 §3).
        r#""type":9,"#,
        r#"{"key":"bank.bank_name","value":{"text":"Example Bank"}}"#,
        r#"{"key":"bank.account_holder","value":{"text":"Alice"}}"#,
        r#"{"key":"bank.account_number","value":{"text":"DE89370400440532013000"}}"#,
        r#"{"key":"bank.routing_number","value":{"text":"COBADEFFXXX"}}"#,
        r#"{"key":"bank.account_type","value":{"text":"Checking"}}"#,
    ] {
        assert!(doc.contains(piece), "{piece}");
    }
    for piece in [
        r#"{"key":"item.name","value":{"text":"Bank \"main\""}}"#,
        r#"{"key":"item.favorite","value":{"bool":true}}"#,
        r#"{"key":"item.type","value":{"enum":1}}"#,
        r#""type":1,"trashed":false,"created_ms":1790000000001,"modified_ms":1790000003000,"fields":["#,
        r#"{"key":"login.password","value":{"text":"p3,\u000d\u000a\"q\""},"history":[{"value":{"text":"p2"},"ms":1790000002000},{"value":{"text":"p1"},"ms":1790000000001}]}"#,
        r#""type":2,"trashed":true,"#,
        r#"{"key":"item.notes","value":{"text":"line one\u000aline two\u0009tab \u0001 é"}}"#,
        r#"{"key":"newer.thing","value":{"raw":"fwEC"}}"#,
        r#"{"key":"newer.text","value":{"raw":"Af_-"}}"#,
        r#"/order","value":{"sort_key":"gA"}}"#,
    ] {
        assert!(doc.contains(piece), "{piece}");
    }
    // Neither the vault settings nor the purged item is in it.
    assert!(!doc.contains("Personal") && !doc.contains("Gone") && !doc.contains("61441"));

    let mut b = fixture(42);
    let read = import(Format::RizzyPlaintextJson, json.expose_secret(), &mut b.rng).unwrap();
    // The retired Bank account is skipped and counted on read-back (ADR 0078 §3).
    assert_eq!(read.warnings.len(), 1);
    assert_eq!(
        read.warnings[0].kind,
        rizzy_import::WarningKind::UnsupportedItemType
    );
    assert_eq!(
        read.counts,
        rizzy_import::Counts {
            skipped_items: 1,
            ..rizzy_import::Counts::default()
        }
    );
    assert_eq!(read.items.len(), 8);
    let done = b
        .vault
        .import_items(&mut b.rng, &b.unlocked, &read.items, T0 + 200)
        .unwrap();
    assert_eq!(done.imported.len(), 8);
    assert!(done.skipped.is_empty());
    assert_same_vault(&a, &b, bank);
    assert_eq!(b.sync(), 9);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the column list and both frozen warning texts are spelled out in full"
)]
fn plaintext_csv_is_rfc_4180_and_counts_its_losses() {
    let (a, _) = populated(51);
    assert_eq!(
        csv_columns(),
        [
            "type",
            "name",
            "notes",
            "favorite",
            "tags",
            "uris",
            "login.username",
            "login.password",
            "login.totp",
            "card.holder",
            "card.number",
            "card.brand",
            "card.exp_month",
            "card.exp_year",
            "card.code",
            "card.pin",
            "identity.title",
            "identity.first_name",
            "identity.middle_name",
            "identity.last_name",
            "identity.company",
            "identity.email",
            "identity.phone",
            "identity.username",
            "identity.address1",
            "identity.address2",
            "identity.address3",
            "identity.city",
            "identity.state",
            "identity.postal_code",
            "identity.country",
            "identity.ssn",
            "identity.passport_number",
            "identity.drivers_license",
            // ADR 0079 §1, added under ADR 0018 §7, so ADR 0027 §4 lists them in table order.
            "identity.sex",
            "identity.birthday",
        ]
    );
    // The login (custom field, password history) and the card (unknown keys, unsupported
    // values) lose data; the trashed note, the four M3 items (ADR 0027 §4: "other types are
    // left out of CSV") and the retired Bank account (ADR 0078 §3) are left out; the identity
    // is complete.
    let loss = a.vault.csv_export_loss().unwrap();
    assert_eq!(
        loss,
        CsvLoss {
            rows: 3,
            lossy_rows: 2,
            left_out: 6,
        }
    );
    assert_eq!(loss.items_losing_data(), 8);
    assert_eq!(
        csv_export_warning(loss.items_losing_data()),
        "Do not open this file in a spreadsheet program: a cell that begins with =, +, - or @ \
         can run as a formula, and saving from a spreadsheet can change your passwords. CSV \
         leaves out custom fields, password history, conflicting values and trashed items; 8 \
         items lose data. The JSON export is complete."
    );
    assert_eq!(
        format!("{CSV_EXPORT_WARNING_BEFORE_COUNT}3{CSV_EXPORT_WARNING_AFTER_COUNT}"),
        csv_export_warning(3)
    );
    assert_eq!(
        PLAINTEXT_EXPORT_WARNING,
        "This file will hold every password, one-time-code secret, card number and note of \
         this vault, unencrypted. Anyone and any program that can read the file can read them \
         all, including backup and cloud-sync tools and other users of this computer. \
         rizzy-vault cannot protect, track or erase the file once it is written. Delete it as \
         soon as you have used it. To keep a copy of your vault, use the encrypted export \
         instead."
    );
    let ack = PlaintextExportAck::from_typed_phrase("EXPORT PLAINTEXT").unwrap();
    let csv = a.vault.export_plaintext_csv(test_auth().1, ack).unwrap();
    let doc = core::str::from_utf8(csv.expose_secret()).unwrap();
    let empty = |n: usize| vec!["\"\""; n].join(",");
    let header = csv_columns()
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(",");
    // Rows in item-id order; sort them by their first cells for a stable comparison.
    let mut rows: Vec<&str> = doc
        .strip_suffix("\"\r\n")
        .unwrap()
        .split("\"\r\n\"")
        .collect();
    assert_eq!(format!("{}\"", rows.remove(0)), header);
    rows.sort_unstable();
    assert_eq!(
        rows,
        [
            format!(
                "card\",\"Visa\",{},\"4111111111111111\",{}",
                empty(8),
                empty(25).strip_suffix('"').unwrap()
            ),
            format!(
                "identity\",\"Me\",{},\"Alice\",{},\"000-00-0000\",{}",
                empty(15),
                empty(13),
                empty(4).strip_suffix('"').unwrap()
            ),
            // Every field quoted, `"` doubled, the CRLF inside the password kept, and the
            // formula-like custom field not in CSV at all.
            format!(
                "login\",\"Bank \"\"main\"\"\",\"\",\"true\",\"work\",\"https://bank.example\",\
                 \"alice\",\"p3,\r\n\"\"q\"\"\",\"JBSWY3DPEHPK3PXP\",{}",
                empty(27).strip_suffix('"').unwrap()
            ),
        ]
    );
    assert!(!doc.contains("=1+1") && !doc.contains("Old note"));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one import story on one vault: splits by count and by size, then every refusal"
)]
fn import_splits_an_item_over_consecutive_ops_and_keeps_the_limits() {
    let mut f = fixture(61);
    f.sync();
    // 2,500 writes: three ops by count. `item.type` and `import.created_ms` are in the first.
    let keys: Vec<SchemaKey> = (0..2_498).map(|i| k(&format!("aaa.f{i}"))).collect();
    let flag = Value::bool(true);
    let created = k(IMPORT_CREATED_MS);
    let created_value = Value::u64(1_234);
    let mut writes: Vec<ImportWrite<'_>> = keys
        .iter()
        .map(|key| ImportWrite {
            source: WriteSource::Carried,
            key,
            value: &flag,
        })
        .collect();
    writes.push(ImportWrite {
        source: WriteSource::Entered,
        key: &created,
        value: &created_value,
    });
    let item = f
        .vault
        .import_item_writes(
            &mut f.rng,
            &f.unlocked,
            ItemType::SECURE_NOTE,
            &writes,
            true,
            T0 + 5,
        )
        .unwrap();
    // Three `Active` ops and the `Trashed` one.
    assert_eq!(f.vault.next_device_seq(), 5);
    assert_eq!(f.vault.item_lifecycle(item), ItemLifecycle::Trashed);
    assert_eq!(f.vault.item_type(item), Some(ItemType::SECURE_NOTE));
    assert_eq!(f.vault.field_keys(item).len(), 2_500);
    assert_eq!(f.vault.merge(item).unwrap().times().created_ms, Some(1_234));
    // The create op holds `item.type` and `import.created_ms`: its dot is the first.
    let merge = f.vault.merge(item).unwrap();
    for key in [ITEM_TYPE, IMPORT_CREATED_MS] {
        assert_eq!(merge.field(key).unwrap().current[0].dot().seq(), 1, "{key}");
    }
    let seqs: std::collections::BTreeSet<u64> = keys
        .iter()
        .map(|key| merge.field(key.as_str()).unwrap().current[0].dot().seq())
        .collect();
    assert_eq!(seqs.into_iter().collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(f.sync(), 4);

    // 40 values of 60,000 bytes are 2.4 MiB: three ops by size.
    let big = Value::bytes(&vec![7u8; 60_000]).unwrap();
    let writes: Vec<ImportWrite<'_>> = keys
        .iter()
        .take(40)
        .map(|key| ImportWrite {
            source: WriteSource::Carried,
            key,
            value: &big,
        })
        .collect();
    let before = f.vault.next_device_seq();
    let fat = f
        .vault
        .import_item_writes(
            &mut f.rng,
            &f.unlocked,
            ItemType::LOGIN,
            &writes,
            false,
            T0 + 6,
        )
        .unwrap();
    assert_eq!(f.vault.next_device_seq(), before + 3);
    assert_eq!(f.vault.field_keys(fat).len(), 41);
    assert!(!f.vault.merge(fat).unwrap().is_oversize());
    assert_eq!(f.sync(), 3);

    // Refusals, each before anything is written.
    let before = f.vault.next_device_seq();
    let items = f.vault.item_ids().len();
    let too_many: Vec<SchemaKey> = (0..4_095).map(|i| k(&format!("bbb.f{i}"))).collect();
    let refuse = |f: &mut Fixture, item_type, writes: &[ImportWrite<'_>]| {
        f.vault
            .import_item_writes(&mut f.rng, &f.unlocked, item_type, writes, false, T0 + 7)
            .unwrap_err()
    };
    let carried = |key, value| ImportWrite {
        source: WriteSource::Carried,
        key,
        value,
    };
    // 4,095 fields and `item.type` are 4,096 writes: one more than an item's snapshot holds.
    let all: Vec<ImportWrite<'_>> = too_many.iter().map(|key| carried(key, &flag)).collect();
    assert_eq!(
        refuse(&mut f, ItemType::LOGIN, &all),
        ClientError::InvalidEdit
    );
    // More value bytes than one snapshot holds.
    let huge = Value::bytes(&vec![7u8; 65_535]).unwrap();
    let heavy: Vec<ImportWrite<'_>> = too_many
        .iter()
        .take(MAX_SNAPSHOT_DATA_LEN / 65_536 + 1)
        .map(|key| carried(key, &huge))
        .collect();
    assert_eq!(
        refuse(&mut f, ItemType::LOGIN, &heavy),
        ClientError::InvalidEdit
    );
    let name = k(ITEM_NAME);
    let number = k(CARD_NUMBER);
    let kind = k(ITEM_TYPE);
    let ssh_host = k(SSH_HOST);
    let (a, login_type, cleared) = (text("a"), Value::enumeration(1), Value::cleared());
    for (item_type, writes) in [
        // The vault-settings type and an unsupported type are never imported as an item.
        (ItemType::VAULT_SETTINGS, vec![carried(&name, &a)]),
        (ItemType::from_id(0x000B), vec![carried(&name, &a)]),
        // A key twice; a key of another item type (an M1 key on an M3 type and an M3 key on
        // an M1 type, ADR 0055 §1); a blank field; another type's `item.type`.
        (ItemType::SSH_KEY, vec![carried(&number, &a)]),
        (ItemType::LOGIN, vec![carried(&ssh_host, &a)]),
        (
            ItemType::LOGIN,
            vec![carried(&name, &a), carried(&name, &a)],
        ),
        (ItemType::LOGIN, vec![carried(&number, &a)]),
        (ItemType::LOGIN, vec![carried(&name, &cleared)]),
        (ItemType::CARD, vec![carried(&kind, &login_type)]),
    ] {
        assert_eq!(refuse(&mut f, item_type, &writes), ClientError::InvalidEdit);
    }
    f.vault.set_read_only(true);
    assert_eq!(
        refuse(&mut f, ItemType::LOGIN, &[carried(&name, &a)]),
        ClientError::ReadOnly
    );
    f.vault.set_read_only(false);
    assert_eq!(f.vault.next_device_seq(), before);
    assert_eq!(f.vault.item_ids().len(), items);

    // The importers' entry point: an item of another product's file still imports.
    let bitwarden =
        br#"{"items":[{"type":1,"name":"Site","login":{"username":"u","password":"p"}}]}"#;
    let read = import(Format::BitwardenJson, bitwarden, &mut f.rng).unwrap();
    let done = f
        .vault
        .import_items(&mut f.rng, &f.unlocked, &read.items, T0 + 8)
        .unwrap();
    assert_eq!(done.imported.len(), 1);
    assert_eq!(
        f.vault
            .field_value(done.imported[0], LOGIN_USERNAME)
            .unwrap()
            .expose_secret(),
        [0x01, b'u']
    );
    assert_eq!(f.sync(), 1);
}

/// Hex digits to bytes.
fn unhex(hex: &str) -> Vec<u8> {
    let digits: Vec<u8> = hex
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| u8::try_from(char::from(b).to_digit(16).unwrap()).unwrap())
        .collect();
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// A device id of one repeated byte.
fn device(byte: u8) -> DeviceId {
    DeviceId::from_bytes([byte; 16])
}

/// One register entry.
fn entry(dev: u8, seq: u64, ms: u64, value: &[u8]) -> Entry<'_> {
    Entry::new(
        Dot::new(device(dev), seq).unwrap(),
        Hlc::from_parts(ms, 0).unwrap(),
        RecordValue::new(value),
    )
}

/// A register of a grammar key.
fn register<'a>(key: &'a str, entries: Vec<Entry<'a>>) -> Register<'a> {
    Register::new(RecordKey::new(key).unwrap(), entries)
}

/// The `@lifecycle` register with one value.
fn lifecycle(value: &[u8]) -> Register<'_> {
    Register::new(RecordKey::LIFECYCLE, vec![entry(1, 1, 5_000, value)])
}

/// A covered VV.
fn covered(entries: &[(u8, u64)]) -> VersionVector {
    let mut vv = VersionVector::new();
    for (dev, seq) in entries {
        vv.add(Dot::new(device(*dev), *seq).unwrap());
    }
    vv
}

/// The smallest payload: one Login that holds nothing but its lifecycle and type.
fn small_payload() -> Vec<u8> {
    let vv = covered(&[(1, 1)]);
    let data = encode_snapshot(
        &vv,
        &SnapshotData::Live(LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x01])]),
            ],
            Vec::new(),
        )),
    )
    .unwrap();
    encode_payload(&[PayloadItem {
        item_id: ItemId::from_bytes([0x11; 16]),
        covered: &vv,
        data: data.expose_secret(),
    }])
    .unwrap()
    .expose_secret()
    .to_vec()
}

#[test]
fn payload_known_answer_through_a_real_envelope() {
    // ADR 0027 §1, byte by byte. 5,000 ms is HLC 0x0000_0000_1388_0000.
    let expected = unhex(
        "0001 00000001
         11111111111111111111111111111111 0001
         0001 01010101010101010101010101010101 0000000000000001
         00000070
         02 0002
         0000000a 406c6966656379636c65 0001
           01010101010101010101010101010101 0000000000000001 0000000013880000 00000001 01
         00000009 6974656d2e74797065 0001
           01010101010101010101010101010101 0000000000000001 0000000013880000 00000003 050001
         0000",
    );
    let payload = small_payload();
    assert_eq!(payload, expected);
    let entries = parse_payload(&payload).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].item_id(), ItemId::from_bytes([0x11; 16]));
    assert_eq!(entries[0].covered(), &covered(&[(1, 1)]));
    assert_eq!(entries[0].snapshot().registers().len(), 2);
    assert!(!format!("{entries:?}").contains("item.type"));
    // An empty vault's payload.
    assert_eq!(
        encode_payload(&[]).unwrap().expose_secret(),
        [0, 1, 0, 0, 0, 0]
    );
    assert!(parse_payload(&[0, 1, 0, 0, 0, 0]).unwrap().is_empty());

    // Through a real `EXPORT_FILE` envelope, with a fixed RNG: the file is a known answer.
    let mut rng = ChaCha20Rng::seed_from_u64(27);
    let file = write_export(&mut rng, "export pw", &payload, 1_790_000_000_000).unwrap();
    assert_eq!(String::from_utf8(file.clone()).unwrap(), KNOWN_FILE);
    assert_eq!(
        read_export(&file, "export pw").unwrap().expose_secret(),
        expected
    );
    // The payload imports as one new item.
    let mut b = fixture(71);
    let report = b
        .vault
        .import_encrypted(&mut b.rng, &b.unlocked, &file, "export pw", T0 + 9)
        .unwrap();
    assert_eq!(report.imported.len(), 1);
    assert_ne!(report.imported[0], ItemId::from_bytes([0x11; 16]));
    assert_eq!(b.vault.item_type(report.imported[0]), Some(ItemType::LOGIN));
    assert_eq!(
        b.vault
            .field_value(report.imported[0], IMPORT_CREATED_MS)
            .unwrap()
            .expose_secret(),
        Value::u64(5_000).expose_secret()
    );
}

/// The export file of [`small_payload`] under "export pw" with `ChaCha20Rng` seed 27 at
/// 1,790,000,000,000 ms.
const KNOWN_FILE: &str = "{\"format\":\"rizzy-vault-export\",\"version\":1,\"kdf_id\":1,\"export_salt\":\"ncu_NvguphM-UMj4SncCmw\",\"export_id\":\"e8z1LCuac95Q8tI8ExnlfA\",\"created_at\":1790000000000,\"data\":\"AQGeegF-HdOmnRM5MRveKqe4fzjjsCq6zJ5SckAwnaAmXUFGZDI4z1xOVv5qoenLV6_79efFJS1nlYSE4TMZjmm4UH18Ar8j3fOkpEWna5F3boUCa1c80L5vug7qSpyI4KqcBZKtgBHtjRYRUZpFMmrkocj-D29WYZGK0cHVhKodTxuur94FeKYHdpTtsW8jtUM0NXq-tw9DsdnQrcwJ5hHu6i2GocXdn1HJHcsCJDUZkTQIKh8pGEvxX6-i-NxO-objWVcpP_FQ3XKvFaeVPP9GLUVxY3YDhmcjUFPEG0myYuW9lYcNs1btFllmgbupyqXz89d5sPNrGfy8B2Ilpg\"}";

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one refusal vector per rule of ADR 0027 §2 step 2, in the ADR's order"
)]
fn payload_refusal_vectors() {
    const BAD: ClientError = ClientError::InvalidExportFile;
    let ok = small_payload();
    assert!(parse_payload(&ok).is_ok());
    let with = |at: usize, bytes: &[u8]| {
        let mut changed = ok.clone();
        changed[at..at + bytes.len()].copy_from_slice(bytes);
        changed
    };
    // Offsets: version 0, n 2, item_id 6, schema version 22, c 24, VV entry 26, data length
    // 50, data 54.
    assert_eq!(ok.len(), 54 + 0x70);
    // `len ≤ 16 MiB`, before anything is read.
    assert_eq!(
        parse_payload(&vec![0u8; MAX_PAYLOAD_LEN + 1]).unwrap_err(),
        BAD
    );
    // `payload_version` = 1; 2 is a CXF payload under the wrong tag, refused at dispatch
    // (ADR 0074 §2); any other is "update required".
    for version in [[0, 0], [1, 1], [0xff, 0xff]] {
        assert_eq!(
            parse_payload(&with(0, &version)).unwrap_err(),
            ClientError::ExportUpdateRequired
        );
    }
    assert_eq!(parse_payload(&with(0, &[0, 2])).unwrap_err(), BAD);
    // Too short for the version or the count.
    for len in 0..6 {
        assert_eq!(parse_payload(&ok[..len]).unwrap_err(), BAD, "{len}");
    }
    // `n ≤ 1,048,576`, and `n × 24 ≤ remaining`.
    let mut many = vec![0u8, 1];
    many.extend(
        u32::try_from(MAX_PAYLOAD_ENTRIES + 1)
            .unwrap()
            .to_be_bytes(),
    );
    many.resize(6 + (MAX_PAYLOAD_ENTRIES + 1) * 24, 0);
    assert_eq!(parse_payload(&many).unwrap_err(), BAD);
    assert_eq!(parse_payload(&with(2, &[0, 0, 0, 2])).unwrap_err(), BAD);
    assert_eq!(parse_payload(&with(2, &[0, 0, 0, 0])).unwrap_err(), BAD);
    assert_eq!(parse_payload(&with(2, &[0xff; 4])).unwrap_err(), BAD);
    // Ascending `item_id`, no duplicates.
    let two = |first: u8, second: u8| {
        let mut out = vec![0u8, 1, 0, 0, 0, 2];
        for id in [first, second] {
            out.extend_from_slice(&[id; 16]);
            out.extend_from_slice(&ok[22..]);
        }
        out
    };
    assert_eq!(parse_payload(&two(1, 2)).unwrap().len(), 2);
    assert_eq!(parse_payload(&two(2, 2)).unwrap_err(), BAD);
    assert_eq!(parse_payload(&two(2, 1)).unwrap_err(), BAD);
    // `item_schema_version` = 1.
    for version in [[0, 0], [0, 2], [0xff, 0xff]] {
        assert_eq!(parse_payload(&with(22, &version)).unwrap_err(), BAD);
    }
    // The covered VV: `c × 24 ≤ remaining`, canonical, no `seq` 0.
    assert_eq!(parse_payload(&with(24, &[0xff, 0xff])).unwrap_err(), BAD);
    assert_eq!(parse_payload(&with(24, &[0, 9])).unwrap_err(), BAD);
    assert_eq!(parse_payload(&with(42, &[0; 8])).unwrap_err(), BAD);
    // `bytes(data)` ≤ 12 MiB, and within the input.
    let over = u32::try_from(MAX_SNAPSHOT_DATA_LEN + 1)
        .unwrap()
        .to_be_bytes();
    let mut long = with(50, &over);
    long.resize(54 + MAX_SNAPSHOT_DATA_LEN + 1, 0);
    assert_eq!(parse_payload(&long).unwrap_err(), BAD);
    assert_eq!(parse_payload(&with(50, &[0, 0, 0, 0x71])).unwrap_err(), BAD);
    // `parse_snapshot(covered_vv, data)`: every ADR 0018 §5 rule.
    assert_eq!(parse_payload(&with(54, &[0x01])).unwrap_err(), BAD);
    assert_eq!(parse_payload(&with(54, &[0x04])).unwrap_err(), BAD);
    // A dot the covered VV does not cover (the VV's device changed).
    assert_eq!(parse_payload(&with(26, &[2; 16])).unwrap_err(), BAD);
    // A key outside the grammar, and `@lifecycle` not first.
    assert_eq!(parse_payload(&with(54 + 3 + 4, b"!")).unwrap_err(), BAD);
    // A tombstone is not live snapshot data.
    let vv = covered(&[(1, 1)]);
    let tomb = encode_snapshot(
        &vv,
        &SnapshotData::Tombstone(rizzy_sync::record::Tombstone::new(
            Dot::new(device(1), 1).unwrap(),
            Hlc::from_parts(5_000, 0).unwrap(),
            VersionVector::new(),
            rizzy_core::ids::SymmetricKeyId::from_bytes([9; 16]),
            Vec::new(),
        )),
    )
    .unwrap();
    let mut purged = ok[..50].to_vec();
    purged.extend(u32::try_from(tomb.len()).unwrap().to_be_bytes());
    purged.extend_from_slice(tomb.expose_secret());
    assert_eq!(parse_payload(&purged).unwrap_err(), BAD);
    assert_eq!(
        encode_payload(&[PayloadItem {
            item_id: ItemId::from_bytes([1; 16]),
            covered: &vv,
            data: tomb.expose_secret(),
        }])
        .unwrap_err(),
        ClientError::InvalidInput
    );
    // No trailing bytes, no truncation.
    let mut trailing = ok.clone();
    trailing.push(0);
    assert_eq!(parse_payload(&trailing).unwrap_err(), BAD);
    for len in 6..ok.len() {
        assert_eq!(parse_payload(&ok[..len]).unwrap_err(), BAD, "{len}");
    }
    // Any failure refuses the whole payload: nothing is imported from a malformed one.
    let mut b = fixture(81);
    let mut second_bad = two(1, 2);
    let last = second_bad.len() - 1;
    second_bad[last] ^= 1;
    assert_eq!(
        b.vault
            .import_payload(&mut b.rng, &b.unlocked, &second_bad, T0)
            .unwrap_err(),
        BAD
    );
    assert!(b.vault.item_ids().is_empty());
    assert_eq!(b.vault.next_device_seq(), 1);
    // The writer's own refusals.
    let unordered = [[2u8; 16], [1u8; 16]].map(|id| PayloadItem {
        item_id: ItemId::from_bytes(id),
        covered: &vv,
        data: &ok[54..],
    });
    assert_eq!(
        encode_payload(&unordered).unwrap_err(),
        ClientError::InvalidInput
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "hand-built exported states, then what the import makes of each"
)]
fn payload_import_flattens_conflicts_and_reports_what_it_left() {
    let vv = covered(&[(1, 4), (2, 2)]);
    let text = |s: &str| [&[0x01], s.as_bytes()].concat();
    let (a, b, new, old1, old2, x) = (
        text("A"),
        text("B"),
        text("new"),
        text("old1"),
        text("old2"),
        text("x"),
    );
    let card = text("4111");
    let wifi = text("Home");
    let share_secret = [[0x02].as_slice(), &[0x5a; 32]].concat();
    let entries = [
        // A Login: a conflict on `item.name`, a password history with a cleared entry, the
        // history of another field, a share secret (M5's: never written), `match`, an unknown
        // key.
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(
                    ITEM_NAME,
                    vec![entry(1, 2, 6_000, &a), entry(2, 1, 9_000, &b)],
                ),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x01])]),
                register(LOGIN_PASSWORD, vec![entry(1, 4, 8_000, &new)]),
                register(LOGIN_USERNAME, vec![entry(1, 4, 8_000, &[])]),
                register("newer.key", vec![entry(1, 1, 5_000, &[0x7f, 0x09])]),
                register(
                    "share/5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a/secret",
                    vec![entry(1, 1, 5_000, &share_secret)],
                ),
                register(
                    "uri/00112233445566778899aabbccddeeff/match",
                    vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x02])],
                ),
            ],
            vec![
                register(ITEM_NAME, vec![entry(1, 1, 5_000, &x)]),
                register(
                    LOGIN_PASSWORD,
                    vec![
                        entry(1, 1, 5_000, &old1),
                        entry(1, 3, 7_000, &old2),
                        entry(2, 2, 7_500, &[]),
                    ],
                ),
            ],
        ),
        // A trashed note.
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x02]),
                register(ITEM_NAME, vec![entry(1, 1, 5_000, &x)]),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x02])]),
            ],
            Vec::new(),
        ),
        // The vault-settings type, an unassigned type, and an item without a valid type.
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0xf0, 0x01])]),
            ],
            Vec::new(),
        ),
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x0b])]),
            ],
            Vec::new(),
        ),
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(ITEM_NAME, vec![entry(1, 1, 5_000, &x)]),
            ],
            Vec::new(),
        ),
        // A key of another item type skips the whole item (ADR 0055 owner answer 4): an M3
        // key on a Login, and an M1 key on an Identity.
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(ITEM_NAME, vec![entry(1, 1, 5_000, &x)]),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x01])]),
                register("ssh.host", vec![entry(1, 1, 5_000, &x)]),
            ],
            Vec::new(),
        ),
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(CARD_NUMBER, vec![entry(1, 1, 5_000, &card)]),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x04])]),
            ],
            Vec::new(),
        ),
        // A Wi-Fi item (ADR 0055): imported with its concealed field.
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(ITEM_NAME, vec![entry(1, 1, 5_000, &wifi)]),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x08])]),
                register(WIFI_PASSWORD, vec![entry(1, 1, 5_000, &card)]),
            ],
            Vec::new(),
        ),
        // A Bank account (`0x0009`) an older build wrote: the type ADR 0078 §1 retired is
        // skipped and counted like any unsupported type (ADR 0078 §3).
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register("bank.account_number", vec![entry(1, 1, 5_000, &card)]),
                register(ITEM_NAME, vec![entry(1, 1, 5_000, &x)]),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x09])]),
            ],
            Vec::new(),
        ),
    ];
    let data: Vec<_> = entries
        .into_iter()
        .map(|live| encode_snapshot(&vv, &SnapshotData::Live(live)).unwrap())
        .collect();
    let items: Vec<PayloadItem<'_>> = data
        .iter()
        .zip(1u8..)
        .map(|(data, id)| PayloadItem {
            item_id: ItemId::from_bytes([id; 16]),
            covered: &vv,
            data: data.expose_secret(),
        })
        .collect();
    let payload = encode_payload(&items).unwrap();

    // The preview says what the import will do, without a vault.
    assert_eq!(
        preview_payload(payload.expose_secret(), &mut ChaCha20Rng::seed_from_u64(1)).unwrap(),
        PayloadPreview {
            importable: 3,
            skipped_items: 6,
            collapsed_fields: 1,
            history_not_carried: 2,
            fields_not_carried: 1,
        }
    );

    let mut f = fixture(91);
    let report = f
        .vault
        .import_payload(&mut f.rng, &f.unlocked, payload.expose_secret(), T0 + 1)
        .unwrap();
    assert_eq!(
        report,
        PayloadImport {
            imported: report.imported.clone(),
            skipped_items: 6,
            collapsed_fields: 1,
            // The history of `item.name`, and the cleared password entry.
            history_not_carried: 2,
            // `share/<id>/secret`; `uri/<id>/match` now carries (ADR 0037, Accepted, M2), and
            // a key of another item type skips its item instead (ADR 0055 owner answer 4).
            fields_not_carried: 1,
        }
    );
    assert_eq!(report.imported.len(), 3);
    assert!(!format!("{report:?}").contains("old1"));
    let shown = displayed(&f.vault);
    // The displayed value of the conflict: the higher HLC.
    let (lifecycle, fields) = &shown["B"];
    assert_eq!(*lifecycle, ItemLifecycle::Active);
    assert_eq!(
        without_import_keys(fields).keys().collect::<Vec<_>>(),
        [
            "item.name",
            "item.type",
            "login.password",
            "newer.key",
            "uri/00112233445566778899aabbccddeeff/match",
        ]
    );
    assert_eq!(fields["newer.key"], [0x7f, 0x09]);
    assert_eq!(fields[LOGIN_PASSWORD], new);
    assert_eq!(fields[IMPORT_CREATED_MS], Value::u64(5_000).expose_secret());
    assert_eq!(
        pwhist(fields),
        [("old2".to_owned(), 7_000), ("old1".to_owned(), 5_000)]
    );
    assert_eq!(shown["x"].0, ItemLifecycle::Trashed);
    assert_eq!(shown["Home"].1[WIFI_PASSWORD], card);
    assert_eq!(f.vault.item_type(report.imported[2]), Some(ItemType::WIFI));
    // The new item has no conflict: one create op of this device.
    assert!(!f.vault.field_conflicts(report.imported[0], ITEM_NAME));
    assert_eq!(f.vault.next_device_seq(), 5);
}

#[test]
fn exports_refuse_oversize_vaults_and_oversize_items() {
    // Too large: a payload over 16 MiB is refused from its length alone, before anything is
    // allocated, encoded or derived (the data here is never looked at).
    let vv = covered(&[(1, 1)]);
    let item = |id: u8, data| PayloadItem {
        item_id: ItemId::from_bytes([id; 16]),
        covered: &vv,
        data,
    };
    // An entry is 16 + 2 + 26 + 4 bytes around its data; the payload's head is 6.
    let exact = vec![0u8; (MAX_PAYLOAD_LEN - 6) / 2 - 48];
    assert_eq!(6 + 2 * (48 + exact.len()), MAX_PAYLOAD_LEN);
    let longer = vec![0u8; exact.len() + 1];
    assert_eq!(
        encode_payload(&[item(1, &longer), item(2, &longer)]).unwrap_err(),
        ClientError::ExportTooLarge
    );
    // At the limit the length check passes, and the data is what is refused.
    assert_eq!(
        encode_payload(&[item(1, &exact), item(2, &exact)]).unwrap_err(),
        ClientError::InvalidInput
    );
    // More entries than a reader accepts are over 16 MiB whatever they hold (24 bytes each
    // at least), so the writer's answer is "too large" (ADR 0027 §1), not an input error.
    let empty = VersionVector::new();
    let tiny = PayloadItem {
        item_id: ItemId::from_bytes([1; 16]),
        covered: &empty,
        data: &[],
    };
    assert_eq!(
        encode_payload(&vec![tiny; MAX_PAYLOAD_ENTRIES + 1]).unwrap_err(),
        ClientError::ExportTooLarge
    );

    // Oversize items: edits grow an item past what one snapshot holds, and every export
    // names it and refuses.
    let mut f = fixture(101);
    let fine = f.create(ItemType::LOGIN, &[(&k(ITEM_NAME), &text("fine"))], T0 + 1);
    let grown = f.create(ItemType::LOGIN, &[(&k(ITEM_NAME), &text("grown"))], T0 + 2);
    assert!(f.vault.export_blockers().is_empty());
    assert_eq!(f.vault.export_payload().unwrap().items, 2);
    // 4,096 website values, in four ops of 1,024 writes: over the register cap. (Websites,
    // not custom fields: a custom field needs a Display Name too, ADR 0076 §2.3 W5.)
    let value = text("v");
    for op in 0..4u32 {
        let field_keys: Vec<SchemaKey> = (0..1_024u32)
            .map(|i| {
                let mut id = [0u8; 16];
                id[..4].copy_from_slice(&(op * 1_024 + i).to_be_bytes());
                ElementId::from_bytes(id).key(LIST_URI, ATTR_VALUE).unwrap()
            })
            .collect();
        let edits: Vec<FieldEdit<'_>> = field_keys
            .iter()
            .map(|key| FieldEdit { key, value: &value })
            .collect();
        f.vault
            .edit_item(
                &mut f.rng,
                &f.unlocked,
                grown,
                &edits,
                T0 + 100 + u64::from(op),
            )
            .unwrap();
    }
    assert!(f.vault.merge(grown).unwrap().is_oversize());
    assert!(!f.vault.merge(fine).unwrap().is_oversize());
    assert_eq!(f.vault.export_blockers(), [grown]);
    assert_eq!(
        f.vault.export_payload().unwrap_err(),
        ClientError::ExportOversizeItems
    );
    // Refused before any key derivation: the export password is not even looked at.
    assert_eq!(
        f.vault
            .export_encrypted(&mut f.rng, test_auth().0, "", T0 + 200)
            .unwrap_err(),
        ClientError::ExportOversizeItems
    );
    let ack = || PlaintextExportAck::from_typed_phrase(PLAINTEXT_EXPORT_PHRASE).unwrap();
    assert_eq!(
        f.vault
            .export_plaintext_json(test_auth().1, ack(), T0)
            .unwrap_err(),
        ClientError::ExportOversizeItems
    );
    assert_eq!(
        f.vault
            .export_plaintext_csv(test_auth().1, ack())
            .unwrap_err(),
        ClientError::ExportOversizeItems
    );
    assert_eq!(
        f.vault.csv_export_loss().unwrap_err(),
        ClientError::ExportOversizeItems
    );
    // Trashing the item does not take it out of the export; purging it does.
    f.vault
        .trash_item(&mut f.rng, &f.unlocked, grown, T0 + 300)
        .unwrap();
    assert_eq!(f.vault.export_blockers(), [grown]);
    f.vault
        .purge_item(&mut f.rng, &f.unlocked, grown, T0 + 301)
        .unwrap();
    assert!(f.vault.export_blockers().is_empty());
    assert_eq!(f.vault.export_payload().unwrap().items, 1);
}

#[test]
fn gated_exports_are_recognised_on_import() {
    use crate::export::detect::{DetectedFormat, detect_format};
    use crate::export::gate::{ExportGate, PLAINTEXT_EXPORT_HOLD_MS};

    let (mut a, _) = populated(36);
    let me = rizzy_core::ids::AccountId::from_bytes([7; 16]);
    let mut gate = ExportGate::new();
    assert_eq!(
        gate.authorize_encrypted(T0).unwrap_err(),
        ClientError::ReauthRequired
    );
    gate.accept_reauth(me, me, T0).unwrap();
    let auth = gate.authorize_encrypted(T0 + 1).unwrap();
    let export = a
        .vault
        .export_encrypted(&mut a.rng, auth, "file pw", T0 + 1)
        .unwrap();
    assert_eq!(
        detect_format(&export.file),
        Some(DetectedFormat::RizzyEncrypted)
    );

    let ack = || PlaintextExportAck::from_typed_phrase(PLAINTEXT_EXPORT_PHRASE).unwrap();
    gate.accept_reauth(me, me, T0).unwrap();
    gate.plaintext_warning_shown(T0);
    assert_eq!(
        gate.authorize_plaintext(T0 + PLAINTEXT_EXPORT_HOLD_MS - 1)
            .unwrap_err(),
        ClientError::PlaintextExportHold
    );
    let auth = gate
        .authorize_plaintext(T0 + PLAINTEXT_EXPORT_HOLD_MS)
        .unwrap();
    let json = a.vault.export_plaintext_json(auth, ack(), T0).unwrap();
    assert_eq!(
        detect_format(json.expose_secret()),
        Some(DetectedFormat::Import(Format::RizzyPlaintextJson))
    );
    gate.accept_reauth(me, me, T0).unwrap();
    gate.plaintext_warning_shown(T0);
    let auth = gate
        .authorize_plaintext(T0 + PLAINTEXT_EXPORT_HOLD_MS)
        .unwrap();
    let csv = a.vault.export_plaintext_csv(auth, ack()).unwrap();
    assert_eq!(
        detect_format(csv.expose_secret()),
        Some(DetectedFormat::RizzyPlaintextCsv)
    );
}

// CXF passkey export and import (ADR 0074).

/// One passkey as the tests write it: the element's fields (ADR 0039 §1).
#[derive(Clone, Debug, PartialEq, Eq)]
struct TestPasskey {
    /// `rp_id`.
    rp_id: String,
    /// `credential_id`.
    credential_id: Vec<u8>,
    /// `user_handle`.
    user_handle: Vec<u8>,
    /// `private_key`.
    private_key: Vec<u8>,
    /// `public_key_cose`.
    public_key_cose: Vec<u8>,
    /// `alg`.
    alg: u16,
}

impl TestPasskey {
    /// An ES256 passkey created the way the extension creates one (ADR 0039 §2).
    fn es256(rng: &mut ChaCha20Rng, rp_id: &str, user_handle: &[u8]) -> Self {
        let created = crate::passkey::create_credential(
            rng,
            &format!("https://{rp_id}"),
            rp_id,
            b"challenge",
        )
        .unwrap();
        Self {
            rp_id: rp_id.to_owned(),
            credential_id: created.credential_id,
            user_handle: user_handle.to_vec(),
            private_key: created.signing_key.to_bytes().expose_secret().to_vec(),
            public_key_cose: created.public_key_cose,
            alg: 1,
        }
    }

    /// An `EdDSA` passkey from a seed (as a CXF import would bring one in).
    fn eddsa(seed: [u8; 32], rp_id: &str, credential_id: &[u8], user_handle: &[u8]) -> Self {
        let public = rizzy_core::passkey::EdDsaSigningKey::from_seed(&seed)
            .unwrap()
            .verifying_key()
            .to_bytes();
        Self {
            rp_id: rp_id.to_owned(),
            credential_id: credential_id.to_vec(),
            user_handle: user_handle.to_vec(),
            private_key: seed.to_vec(),
            public_key_cose: rizzy_import::cxf::cose_key_ed25519(&public),
            alg: 2,
        }
    }

    /// The element's writes under a fresh element id.
    fn writes(&self, rng: &mut ChaCha20Rng) -> Vec<(SchemaKey, Value)> {
        let id = ElementId::generate(rng);
        let key = |attribute: &str| id.key("passkey", attribute).unwrap();
        vec![
            (key("rp_id"), text(&self.rp_id)),
            (key("user_handle"), Value::bytes(&self.user_handle).unwrap()),
            (
                key("credential_id"),
                Value::bytes(&self.credential_id).unwrap(),
            ),
            (key("private_key"), Value::bytes(&self.private_key).unwrap()),
            (
                key("public_key_cose"),
                Value::bytes(&self.public_key_cose).unwrap(),
            ),
            (key("alg"), Value::enumeration(self.alg)),
            (key("discoverable"), Value::bool(true)),
            (key("created_ms"), Value::u64(T0)),
        ]
    }

    /// The passkeys of an item's displayed fields, in element-id order.
    fn of(fields: &BTreeMap<String, Vec<u8>>) -> Vec<Self> {
        let mut by_element: BTreeMap<&str, BTreeMap<&str, ValueRef<'_>>> = BTreeMap::new();
        for (key, value) in fields {
            let mut parts = key.split('/');
            if let (Some("passkey"), Some(element), Some(attribute)) =
                (parts.next(), parts.next(), parts.next())
            {
                by_element
                    .entry(element)
                    .or_default()
                    .insert(attribute, ValueRef::decode(value).unwrap());
            }
        }
        by_element
            .values()
            .map(|a| {
                let bytes = |name: &str| match a[name] {
                    ValueRef::Bytes(b) => b.to_vec(),
                    _ => panic!("{name} is not bytes"),
                };
                let ValueRef::Text(rp_id) = a["rp_id"] else {
                    panic!("rp_id is not text");
                };
                let ValueRef::Enum(alg) = a["alg"] else {
                    panic!("alg is not an enum");
                };
                assert!(matches!(a["discoverable"], ValueRef::Bool(true)));
                Self {
                    rp_id: rp_id.to_owned(),
                    credential_id: bytes("credential_id"),
                    user_handle: bytes("user_handle"),
                    private_key: bytes("private_key"),
                    public_key_cose: bytes("public_key_cose"),
                    alg,
                }
            })
            .collect()
    }
}

impl Fixture {
    /// Creates a Login item named `name` with `username` and `passkeys`.
    fn login_with_passkeys(
        &mut self,
        name: &str,
        username: &str,
        passkeys: &[TestPasskey],
    ) -> ItemId {
        let mut writes = vec![(k(ITEM_NAME), text(name))];
        if !username.is_empty() {
            writes.push((k("login.username"), text(username)));
        }
        for passkey in passkeys {
            writes.extend(passkey.writes(&mut self.rng));
        }
        let fields: Vec<(&SchemaKey, &Value)> = writes.iter().map(|(k, v)| (k, v)).collect();
        self.create(ItemType::LOGIN, &fields, T0 + 1)
    }
}

/// The typed acknowledgement.
fn cxf_ack() -> PlaintextExportAck {
    PlaintextExportAck::from_typed_phrase(PLAINTEXT_EXPORT_PHRASE).unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one vault of every kind of item the CXF export reads or leaves out, then the round trip"
)]
fn cxf_export_round_trips_every_active_passkey_into_a_new_vault() {
    let mut a = fixture(740);
    let es256 = TestPasskey::es256(&mut a.rng, "example.com", b"user-1");
    let eddsa = TestPasskey::eddsa([0x42; 32], "login.example.org", b"cred-2", b"user-2");
    let second_es256 = TestPasskey::es256(&mut a.rng, "example.net", &[0xFF; 64]);
    a.login_with_passkeys(
        "Site",
        "alice \"quoted\" \\ é",
        std::slice::from_ref(&es256),
    );
    a.login_with_passkeys("Two keys", "bob", &[eddsa.clone(), second_es256.clone()]);
    let gone = TestPasskey::es256(&mut a.rng, "gone.example", b"user-3");
    let trashed = a.login_with_passkeys("Trashed", "carol", &[gone]);
    a.vault
        .trash_item(&mut a.rng, &a.unlocked, trashed, T0 + 2)
        .unwrap();
    a.login_with_passkeys("No passkey", "dave", &[]);
    a.create(
        ItemType::SECURE_NOTE,
        &[(&k(ITEM_NAME), &text("A note"))],
        T0 + 3,
    );

    assert_eq!(a.vault.cxf_export_passkeys().unwrap(), 3);
    let export = a
        .vault
        .export_cxf(&mut a.rng, test_auth().1, cxf_ack(), "export pw", T0 + 100)
        .unwrap();
    assert_eq!((export.passkeys, export.items, export.skipped), (3, 2, 0));
    assert!(
        export
            .file
            .starts_with(br#"{"format":"rizzy-vault-cxf-export","version":1,"#)
    );
    assert_eq!(
        detect_format(&export.file),
        Some(DetectedFormat::RizzyCxfEncrypted)
    );

    // The decrypted document is CXF 1.0 as ADR 0074 §2 writes it.
    let payload = read_export(&export.file, "export pw").unwrap();
    let document = crate::export::cxf::parse_cxf_payload(payload.expose_secret()).unwrap();
    let root = rizzy_import::json::parse(document, rizzy_import::limits::MAX_JSON_LEN).unwrap();
    assert_eq!(
        root.get("exporterDisplayName")
            .and_then(rizzy_import::json::Json::as_str),
        Some("rizzy-vault")
    );
    assert_eq!(
        root.get("exporterRpId")
            .and_then(rizzy_import::json::Json::as_str),
        Some("")
    );
    assert_eq!(
        root.get("timestamp")
            .and_then(rizzy_import::json::Json::as_u64),
        Some((T0 + 100) / 1000)
    );
    assert_eq!(
        root.get("version")
            .and_then(|v| v.get("major"))
            .and_then(rizzy_import::json::Json::as_u64),
        Some(1)
    );

    let mut b = fixture(741);
    assert_eq!(
        b.vault
            .import_cxf_encrypted(&mut b.rng, &b.unlocked, &export.file, "wrong", T0 + 200)
            .unwrap_err(),
        ClientError::ExportDecryptionFailed
    );
    let done = b
        .vault
        .import_cxf_encrypted(&mut b.rng, &b.unlocked, &export.file, "export pw", T0 + 200)
        .unwrap();
    assert_eq!(done.imported.len(), 3);
    assert!(done.skipped.is_empty());
    assert_eq!(done.counts, rizzy_import::Counts::default());
    assert!(done.warnings.is_empty());

    // One Login per passkey; the item is named after the user (ADR 0074 §3: item.name from
    // userDisplayName, which the export writes from login.username, §2), the key material is
    // the same bytes, the public key the same COSE map.
    let mut got: Vec<(String, TestPasskey)> = b
        .vault
        .item_ids()
        .into_iter()
        .map(|item| {
            assert_eq!(b.vault.item_lifecycle(item), ItemLifecycle::Active);
            let fields: BTreeMap<String, Vec<u8>> = b
                .vault
                .field_keys(item)
                .into_iter()
                .map(|key| {
                    let value = b.vault.field_value(item, &key).unwrap();
                    (key.to_string(), value.expose_secret().to_vec())
                })
                .collect();
            let ValueRef::Text(name) = ValueRef::decode(&fields[ITEM_NAME]).unwrap() else {
                panic!("no name");
            };
            let mut passkeys = TestPasskey::of(&fields);
            assert_eq!(passkeys.len(), 1);
            (name.to_owned(), passkeys.remove(0))
        })
        .collect();
    let mut want = vec![
        ("alice \"quoted\" \\ é".to_owned(), es256),
        ("bob".to_owned(), eddsa),
        ("bob".to_owned(), second_es256),
    ];
    got.sort_by(|x, y| x.1.rp_id.cmp(&y.1.rp_id));
    want.sort_by(|x, y| x.1.rp_id.cmp(&y.1.rp_id));
    assert_eq!(got, want);
}

#[test]
fn a_swapped_export_tag_fails_at_dispatch_never_silently() {
    let mut a = fixture(742);
    let passkey = TestPasskey::es256(&mut a.rng, "example.com", b"u");
    a.login_with_passkeys("Site", "alice", &[passkey]);
    let cxf = a
        .vault
        .export_cxf(&mut a.rng, test_auth().1, cxf_ack(), "pw", T0 + 100)
        .unwrap();
    let plain = a
        .vault
        .export_encrypted(&mut a.rng, test_auth().0, "pw", T0 + 100)
        .unwrap();
    let swap = |file: &[u8], from: &str, to: &str| {
        String::from_utf8(file.to_vec())
            .unwrap()
            .replacen(from, to, 1)
            .into_bytes()
    };
    let mut b = fixture(743);
    // A CXF payload under the item-list tag: the payload version refuses it.
    let cxf_as_plain = swap(&cxf.file, "rizzy-vault-cxf-export", "rizzy-vault-export");
    assert_eq!(
        detect_format(&cxf_as_plain),
        Some(DetectedFormat::RizzyEncrypted)
    );
    assert_eq!(
        b.vault
            .import_encrypted(&mut b.rng, &b.unlocked, &cxf_as_plain, "pw", T0 + 200)
            .unwrap_err(),
        ClientError::InvalidExportFile
    );
    // An item-list payload under the CXF tag: likewise.
    let plain_as_cxf = swap(&plain.file, "rizzy-vault-export", "rizzy-vault-cxf-export");
    assert_eq!(
        b.vault
            .import_cxf_encrypted(&mut b.rng, &b.unlocked, &plain_as_cxf, "pw", T0 + 200)
            .unwrap_err(),
        ClientError::InvalidExportFile
    );
    // Each reader refuses the other's tag before any key derivation.
    assert_eq!(
        b.vault
            .import_encrypted(&mut b.rng, &b.unlocked, &cxf.file, "pw", T0 + 200)
            .unwrap_err(),
        ClientError::InvalidExportFile
    );
    assert_eq!(
        b.vault
            .import_cxf_encrypted(&mut b.rng, &b.unlocked, &plain.file, "pw", T0 + 200)
            .unwrap_err(),
        ClientError::InvalidExportFile
    );
    assert!(b.vault.item_ids().is_empty());
}

#[test]
fn a_bare_cxf_file_imports_through_the_same_reader() {
    // CXF 1.0 PS errata Appendix A's passkey credential, as another product would write it.
    let doc = r#"{"version":{"major":1,"minor":0},"exporterRpId":"exporter.example.com","exporterDisplayName":"Exporter app","timestamp":1705228800,"accounts":[{"id":"DZSXp7iBQY-Fg-OofakQtQ","username":"jane_smith","email":"jane.smith@example.com","collections":[],"items":[{"id":"akKA3Y0jQRuK7sKplB0Y9w","title":"WebAuthn.io","credentials":[{"type":"passkey","credentialId":"Y3JlZGVudGlhbElkRXhhbXBsZQ","rpId":"webauthn.io","username":"johndoe","userDisplayName":"John Doe","userHandle":"cnEzaNHWcYK3coWZjvoaV1Hj9gnI12mKe2dL2HZVFlY","key":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgARu_0sCt20EpgVxb4Puq3Ga5VVLpuTY75ngvZlyq3X6hRANCAASmdk1xLsK0oOlhxIPp0d1ZuS0sT9nf6BZtSelhqvLBW0fOL33l_bXgsr_STUHjCLn8l6gcRJwe7OQvbQubZ1dY"}]}]}]}"#;
    assert_eq!(
        detect_format(doc.as_bytes()),
        Some(DetectedFormat::Import(Format::CxfJson))
    );
    let mut f = fixture(744);
    let parsed = import(Format::CxfJson, doc.as_bytes(), &mut f.rng).unwrap();
    let done = f
        .vault
        .import_items(&mut f.rng, &f.unlocked, &parsed.items, T0 + 5)
        .unwrap();
    assert_eq!(done.imported.len(), 1);
    let shown = displayed(&f.vault);
    let (_, fields) = &shown["John Doe"];
    let passkeys = TestPasskey::of(fields);
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].rp_id, "webauthn.io");
    assert_eq!(passkeys[0].credential_id, b"credentialIdExample");
    assert_eq!(passkeys[0].alg, 1);
    // The imported key signs an assertion that verifies under the COSE key derived from it.
    let key = crate::passkey::PasskeySigningKey::from_stored(1, &passkeys[0].private_key).unwrap();
    let assertion = crate::passkey::get_assertion_with(
        &key,
        &passkeys[0].credential_id,
        &passkeys[0].user_handle,
        "https://webauthn.io",
        "webauthn.io",
        b"challenge",
    )
    .unwrap();
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&rizzy_core::passkey::client_data_hash(
        &assertion.client_data_json,
    ));
    let cose = &passkeys[0].public_key_cose;
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&cose[10..42]);
    sec1.extend_from_slice(&cose[45..77]);
    rizzy_core::passkey::Es256VerifyingKey::from_uncompressed_sec1(&sec1)
        .unwrap()
        .verify_der(&message, &assertion.signature_der)
        .unwrap();
}

/// A passkey with arbitrary fields, for the round-trip property.
fn any_passkey() -> impl Strategy<Value = (String, Vec<u8>, Vec<u8>, [u8; 32], bool, String)> {
    (
        "[a-z]{1,12}\\.[a-z]{2,6}",
        proptest::collection::vec(any::<u8>(), 1..=64),
        proptest::collection::vec(any::<u8>(), 1..=64),
        any::<[u8; 32]>(),
        any::<bool>(),
        // Not blank: a blank display name falls back to the rpId (rizzy_import::cxf "Mapping").
        "[a-zA-Z0-9\"\\\\é😀][a-zA-Z0-9 \"\\\\é😀]{0,15}",
    )
}

/// Export → import: every passkey of the vault comes back, field for field, with the user's
/// name, whatever its bytes (CXF document level, without the Argon2id of the sealed file,
/// which the round-trip test above covers).
#[test]
fn cxf_document_round_trips_arbitrary_passkeys() {
    let state = std::cell::RefCell::new((fixture(745), Vec::<(String, TestPasskey)>::new()));
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 24,
        ..ProptestConfig::default()
    });
    runner
        .run(
            &proptest::collection::vec(any_passkey(), 1..4),
            |passkeys| {
                let mut state = state.borrow_mut();
                let (f, want) = &mut *state;
                let mut made = Vec::new();
                for (rp_id, credential_id, user_handle, seed, eddsa, username) in passkeys {
                    let passkey = if eddsa {
                        TestPasskey::eddsa(seed, &rp_id, &credential_id, &user_handle)
                    } else {
                        // Not through create_credential: an arbitrary rpId may be a public suffix,
                        // which INV-64 refuses at creation, and is not what this property tests.
                        let key = rizzy_core::passkey::Es256SigningKey::generate(&mut f.rng);
                        let public = key.verifying_key();
                        TestPasskey {
                            rp_id: rp_id.clone(),
                            credential_id,
                            user_handle,
                            private_key: key.to_bytes().expose_secret().to_vec(),
                            public_key_cose: rizzy_import::cxf::cose_key_es256(
                                &public.x(),
                                &public.y(),
                            ),
                            alg: 1,
                        }
                    };
                    made.push((username, passkey));
                }
                for (username, passkey) in &made {
                    f.login_with_passkeys("item", username, std::slice::from_ref(passkey));
                }
                want.extend(made);
                let (document, counts) = f.vault.cxf_document(&mut f.rng, T0 + 9_999).unwrap();
                prop_assert_eq!(counts.passkeys, want.len());
                let parsed = import(Format::CxfJson, document.expose_secret(), &mut f.rng).unwrap();
                prop_assert_eq!(parsed.counts, rizzy_import::Counts::default());
                let mut got: Vec<(String, TestPasskey)> = parsed
                    .items
                    .iter()
                    .map(|item| {
                        let fields: BTreeMap<String, Vec<u8>> = item
                            .writes()
                            .iter()
                            .map(|w| {
                                (
                                    w.key().as_str().to_owned(),
                                    w.value().expose_secret().to_vec(),
                                )
                            })
                            .collect();
                        let ValueRef::Text(name) = ValueRef::decode(&fields[ITEM_NAME]).unwrap()
                        else {
                            panic!("no name");
                        };
                        let ValueRef::U64(ms) = ValueRef::decode(
                            &fields[fields.keys().find(|k| k.ends_with("/created_ms")).unwrap()],
                        )
                        .unwrap() else {
                            panic!("no created_ms");
                        };
                        assert_eq!(ms, (T0 + 9_999) / 1000 * 1000);
                        let mut passkeys = TestPasskey::of(&fields);
                        (name.to_owned(), passkeys.remove(0))
                    })
                    .collect();
                let key = |e: &(String, TestPasskey)| {
                    (e.1.credential_id.clone(), e.1.rp_id.clone(), e.0.clone())
                };
                got.sort_by_key(key);
                let mut sorted = want.clone();
                sorted.sort_by_key(key);
                prop_assert_eq!(got, sorted);
                Ok(())
            },
        )
        .unwrap();
}

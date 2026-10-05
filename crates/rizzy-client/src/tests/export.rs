//! Export and import tests (ADR 0027): the payload's known answer and refusal vectors, the
//! round trips vault → encrypted file → new vault and vault → plaintext JSON → new vault, the
//! import path's splitting and limits, trashed items, carried unknown keys, the plaintext
//! acknowledgement and the CSV form. The vaults are real [`VaultSync`] drivers of signed-up
//! devices of the parent module's fake server.

use std::collections::BTreeMap;

use rizzy_core::item::key::ElementId;
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_ORDER, ATTR_VALUE, CARD_NUMBER, IMPORT_CREATED_MS, ITEM_FAVORITE,
    ITEM_NAME, ITEM_NOTES, ITEM_TYPE, LIST_FIELD, LIST_URI, LOGIN_TOTP, VAULT_NAME, WriteSource,
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
/// the vault-settings item and a purged item, neither of which is exported.
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
    let reserved = k("ssh.private_key");
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

/// Checks that vault `b`, which imported an export of vault `a`, displays what `a` displays.
fn assert_same_vault(a: &Fixture, b: &Fixture, bank: ItemId) {
    let mut exported = displayed(&a.vault);
    // Neither the vault settings nor the purged item is exported.
    let settings = exported.remove("(unnamed)").unwrap();
    assert!(settings.1.contains_key(VAULT_NAME));
    let imported = displayed(&b.vault);
    assert_eq!(
        exported.keys().collect::<Vec<_>>(),
        ["Bank \"main\"", "Me", "Old note", "Visa"]
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
    assert_eq!(visa["ssh.private_key"], [0x01, b'x']);
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
    assert_eq!(export.items, 4);
    assert!(export.unresolved.is_empty());
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
    assert_eq!(report.imported.len(), 4);
    assert_eq!(
        report,
        PayloadImport {
            imported: report.imported.clone(),
            ..PayloadImport::default()
        }
    );
    // New item ids, and ops of the importing device only.
    let old: Vec<ItemId> = a.vault.item_ids();
    assert!(report.imported.iter().all(|id| !old.contains(id)));
    assert_eq!(b.vault.item_ids().len(), 4);
    assert_same_vault(&a, &b, bank);
    // Four create ops and the trash op, all stored by the server.
    assert_eq!(b.vault.next_device_seq(), 6);
    assert_eq!(b.sync(), 5);
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
    assert_eq!(doc.lines().count(), 6);
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
    assert_eq!(read.warnings, []);
    assert_eq!(read.counts, rizzy_import::Counts::default());
    assert_eq!(read.items.len(), 4);
    let done = b
        .vault
        .import_items(&mut b.rng, &b.unlocked, &read.items, T0 + 200)
        .unwrap();
    assert_eq!(done.imported.len(), 4);
    assert!(done.skipped.is_empty());
    assert_same_vault(&a, &b, bank);
    assert_eq!(b.sync(), 5);
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
        ]
    );
    // The login (custom field, password history) and the card (unknown keys, unsupported
    // values) lose data; the trashed note is left out; the identity is complete.
    let loss = a.vault.csv_export_loss().unwrap();
    assert_eq!(
        loss,
        CsvLoss {
            rows: 3,
            lossy_rows: 2,
            left_out: 1,
        }
    );
    assert_eq!(loss.items_losing_data(), 3);
    assert_eq!(
        csv_export_warning(loss.items_losing_data()),
        "Do not open this file in a spreadsheet program: a cell that begins with =, +, - or @ \
         can run as a formula, and saving from a spreadsheet can change your passwords. CSV \
         leaves out custom fields, password history, conflicting values and trashed items; 3 \
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
                empty(23).strip_suffix('"').unwrap()
            ),
            format!(
                "identity\",\"Me\",{},\"Alice\",{},\"000-00-0000\",{}",
                empty(15),
                empty(13),
                empty(2).strip_suffix('"').unwrap()
            ),
            // Every field quoted, `"` doubled, the CRLF inside the password kept, and the
            // formula-like custom field not in CSV at all.
            format!(
                "login\",\"Bank \"\"main\"\"\",\"\",\"true\",\"work\",\"https://bank.example\",\
                 \"alice\",\"p3,\r\n\"\"q\"\"\",\"JBSWY3DPEHPK3PXP\",{}",
                empty(25).strip_suffix('"').unwrap()
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
    let (a, login_type, cleared) = (text("a"), Value::enumeration(1), Value::cleared());
    for (item_type, writes) in [
        // The vault-settings type and an unsupported type are never imported as an item.
        (ItemType::VAULT_SETTINGS, vec![carried(&name, &a)]),
        (ItemType::SSH_KEY, vec![carried(&name, &a)]),
        // A key twice; a key of another item type; a blank field; another type's `item.type`.
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
    // `payload_version` = 1; any other is "update required".
    for version in [[0, 0], [0, 2], [1, 1], [0xff, 0xff]] {
        assert_eq!(
            parse_payload(&with(0, &version)).unwrap_err(),
            ClientError::ExportUpdateRequired
        );
    }
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
    reason = "five hand-built exported states, then what the import makes of each"
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
    let entries = [
        // A Login: a conflict on `item.name`, a password history with a cleared entry, the
        // history of another field, a key of another item type, `match`, an unknown key.
        LiveSnapshot::new(
            vec![
                lifecycle(&[0x01]),
                register(CARD_NUMBER, vec![entry(1, 1, 5_000, &card)]),
                register(
                    ITEM_NAME,
                    vec![entry(1, 2, 6_000, &a), entry(2, 1, 9_000, &b)],
                ),
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x01])]),
                register(LOGIN_PASSWORD, vec![entry(1, 4, 8_000, &new)]),
                register(LOGIN_USERNAME, vec![entry(1, 4, 8_000, &[])]),
                register("newer.key", vec![entry(1, 1, 5_000, &[0x7f, 0x09])]),
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
        // The vault-settings type, a reserved type, and an item without a valid type.
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
                register(ITEM_TYPE, vec![entry(1, 1, 5_000, &[0x05, 0x00, 0x09])]),
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
            importable: 2,
            skipped_items: 3,
            collapsed_fields: 1,
            history_not_carried: 2,
            fields_not_carried: 2,
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
            skipped_items: 3,
            collapsed_fields: 1,
            // The history of `item.name`, and the cleared password entry.
            history_not_carried: 2,
            // `card.number` on a Login, and `uri/<id>/match`.
            fields_not_carried: 2,
        }
    );
    assert_eq!(report.imported.len(), 2);
    assert!(!format!("{report:?}").contains("old1"));
    let shown = displayed(&f.vault);
    // The displayed value of the conflict: the higher HLC.
    let (lifecycle, fields) = &shown["B"];
    assert_eq!(*lifecycle, ItemLifecycle::Active);
    assert_eq!(
        without_import_keys(fields).keys().collect::<Vec<_>>(),
        ["item.name", "item.type", "login.password", "newer.key"]
    );
    assert_eq!(fields["newer.key"], [0x7f, 0x09]);
    assert_eq!(fields[LOGIN_PASSWORD], new);
    assert_eq!(fields[IMPORT_CREATED_MS], Value::u64(5_000).expose_secret());
    assert_eq!(
        pwhist(fields),
        [("old2".to_owned(), 7_000), ("old1".to_owned(), 5_000)]
    );
    assert_eq!(shown["x"].0, ItemLifecycle::Trashed);
    // The new item has no conflict: one create op of this device.
    assert!(!f.vault.field_conflicts(report.imported[0], ITEM_NAME));
    assert_eq!(f.vault.next_device_seq(), 4);
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
    // 4,096 custom-field values, in four ops of 1,024 writes: over the register cap.
    let value = text("v");
    for op in 0..4u32 {
        let field_keys: Vec<SchemaKey> = (0..1_024u32)
            .map(|i| {
                let mut id = [0u8; 16];
                id[..4].copy_from_slice(&(op * 1_024 + i).to_be_bytes());
                ElementId::from_bytes(id)
                    .key(LIST_FIELD, ATTR_VALUE)
                    .unwrap()
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

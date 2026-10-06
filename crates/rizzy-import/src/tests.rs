//! End-to-end tests of each importer on small synthetic fixtures. No fixture is a real export
//! and no value is a real secret.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use rizzy_core::item::key::KeyKind;
use rizzy_core::item::schema::{
    ATTR_KIND, ATTR_LABEL, ATTR_MS, ATTR_ORDER, ATTR_VALUE, LIST_FIELD, LIST_PWHIST, LIST_URI,
    WriteMode, WriteSource, check_create,
};
use rizzy_core::item::tag::tag_name;
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::ValueRef;

use crate::zip::tests::{TestMember, archive};
use crate::{
    Format, Import, ImportError, ImportedItem, WarningKind, import, import_1pux_data,
    import_aliasvault_manifest_data,
};

/// A decoded value, for comparisons.
#[derive(Clone, Debug, PartialEq, Eq)]
enum V {
    /// Text.
    T(String),
    /// Bool.
    B(bool),
    /// U64.
    U(u64),
    /// Enum.
    E(u16),
    /// Anything else.
    Other,
}

/// Decodes an encoded value.
fn v(bytes: &[u8]) -> V {
    match ValueRef::decode(bytes).unwrap() {
        ValueRef::Text(t) => V::T(t.to_owned()),
        ValueRef::Bool(b) => V::B(b),
        ValueRef::U64(u) => V::U(u),
        ValueRef::Enum(e) => V::E(e),
        _ => V::Other,
    }
}

/// Text shorthand.
fn t(s: &str) -> V {
    V::T(s.to_owned())
}

/// Runs an import with a fixed seed.
fn run(format: Format, input: &[u8]) -> Result<Import, ImportError> {
    import(format, input, &mut ChaCha20Rng::seed_from_u64(7))
}

/// A readable view of one item.
#[derive(Debug, Default)]
struct View {
    /// Fixed keys.
    fixed: BTreeMap<String, V>,
    /// URIs in order.
    uris: Vec<String>,
    /// Custom fields in order: label, kind, value.
    fields: Vec<(Option<String>, u16, Option<V>)>,
    /// Password history: value, ms.
    history: Vec<(String, Option<u64>)>,
    /// Tag names.
    tags: Vec<String>,
}

/// Decodes an item, and checks the invariants every imported item keeps.
fn view(item: &ImportedItem) -> View {
    let writes = item.writes();
    // Canonical order, no duplicates (ADR 0018 §4).
    for pair in writes.windows(2) {
        assert!(pair[0].key().as_bytes() < pair[1].key().as_bytes());
    }
    // The schema's own check for an importer's create op.
    check_create(
        item.item_type(),
        WriteMode::Import,
        writes.iter().map(|w| {
            (
                WriteSource::Entered,
                w.key().as_bytes(),
                w.value().expose_secret(),
            )
        }),
    )
    .unwrap();
    assert!(writes.len() <= crate::limits::MAX_WRITES);
    let op_len: usize = 4 + writes
        .iter()
        .map(|w| 8 + w.key().as_bytes().len() + w.value().len())
        .sum::<usize>();
    assert!(op_len <= crate::limits::MAX_OP_DATA_LEN);

    let mut out = View::default();
    let mut elements: BTreeMap<(String, String), BTreeMap<String, Vec<u8>>> = BTreeMap::new();
    for w in writes {
        let key = w.key().as_key();
        let bytes = w.value().expose_secret().to_vec();
        match key.kind() {
            KeyKind::Fixed => {
                out.fixed.insert(key.as_str().to_owned(), v(&bytes));
            }
            KeyKind::Element if key.list() == Some("tag") => {
                assert_eq!(v(&bytes), V::B(true));
                out.tags.push(tag_name(key).unwrap().to_string());
            }
            KeyKind::Element => {
                elements
                    .entry((
                        key.list().unwrap().to_owned(),
                        key.element().unwrap().to_owned(),
                    ))
                    .or_default()
                    .insert(key.attribute().unwrap().to_owned(), bytes);
            }
        }
    }
    let mut uris = Vec::new();
    let mut fields = Vec::new();
    for ((list, _), attrs) in elements {
        match list.as_str() {
            LIST_URI => {
                let V::T(value) = v(&attrs[ATTR_VALUE]) else {
                    panic!("uri value")
                };
                uris.push((attrs[ATTR_ORDER].clone(), value));
            }
            LIST_FIELD => {
                let V::E(kind) = v(&attrs[ATTR_KIND]) else {
                    panic!("kind")
                };
                let label = attrs.get(ATTR_LABEL).map(|l| match v(l) {
                    V::T(s) => s,
                    _ => panic!("label"),
                });
                fields.push((
                    attrs[ATTR_ORDER].clone(),
                    (label, kind, attrs.get(ATTR_VALUE).map(|x| v(x))),
                ));
            }
            LIST_PWHIST => {
                let V::T(value) = v(&attrs[ATTR_VALUE]) else {
                    panic!("history")
                };
                let ms = attrs.get(ATTR_MS).map(|m| match v(m) {
                    V::U(u) => u,
                    _ => panic!("ms"),
                });
                out.history.push((value, ms));
            }
            other => panic!("unexpected list {other}"),
        }
    }
    uris.sort();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    out.uris = uris.into_iter().map(|(_, u)| u).collect();
    out.fields = fields.into_iter().map(|(_, f)| f).collect();
    out.history.sort();
    out.tags.sort();
    out
}

/// The warnings of `import` as (entry, kind).
fn warns(import: &Import) -> Vec<(Option<usize>, WarningKind)> {
    import.warnings.iter().map(|w| (w.entry, w.kind)).collect()
}

const BITWARDEN: &str = r#"{
  "encrypted": false,
  "folders": [{"id": "f1", "name": "Work/Email"}],
  "collections": [{"id": "c1", "name": "Shared"}],
  "items": [
    {
      "id": "i1", "folderId": "f1", "collectionIds": ["c1", "missing"], "type": 1,
      "name": "Example", "notes": "a note", "favorite": true,
      "creationDate": "2024-02-29T12:34:56.789Z",
      "fields": [
        {"name": "PIN", "value": "1234", "type": 1},
        {"name": "Color", "value": "blue", "type": 0},
        {"name": "Enabled", "value": "true", "type": 2},
        {"name": "Linked", "value": null, "type": 3, "linkedId": 100}
      ],
      "login": {
        "uris": [{"match": null, "uri": "https://example.com"}, {"uri": "https://example.org"}],
        "username": "alice", "password": "correct horse", "totp": "otpauth://totp/x?secret=JBSWY3DP",
        "fido2Credentials": [{"credentialId": "x"}]
      },
      "passwordHistory": [
        {"lastUsedDate": "2023-01-01T00:00:00Z", "password": "old one"},
        {"lastUsedDate": "not a date", "password": "older"}
      ]
    },
    {"type": 2, "name": "Note", "notes": "secret note body", "secureNote": {"type": 0}},
    {
      "type": 3, "name": "Visa",
      "card": {"cardholderName": "Alice", "brand": "Visa", "number": "4111111111111111",
               "expMonth": "7", "expYear": 2030, "code": "123"}
    },
    {
      "type": 4, "name": "Me",
      "identity": {"firstName": "Alice", "lastName": "Liddell", "ssn": "000-00-0000",
                   "licenseNumber": "D123", "passportNumber": "P456"}
    },
    {"type": 5, "name": "Server key",
     "sshKey": {"privateKey": "-----BEGIN KEY-----", "publicKey": "ssh-ed25519 AAAA", "keyFingerprint": "SHA256:x"}},
    {"type": 1, "name": "Gone", "deletedDate": "2024-01-01T00:00:00Z", "login": {}},
    "not an object",
    {"type": 2}
  ]
}"#;

#[test]
fn bitwarden_json() {
    let import = run(Format::BitwardenJson, BITWARDEN.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 5);

    let login = &import.items[0];
    assert_eq!(login.entry(), 0);
    assert_eq!(login.item_type(), ItemType::LOGIN);
    let l = view(login);
    assert_eq!(l.fixed["item.type"], V::E(1));
    assert_eq!(l.fixed["item.name"], t("Example"));
    assert_eq!(l.fixed["item.notes"], t("a note"));
    assert_eq!(l.fixed["item.favorite"], V::B(true));
    assert_eq!(l.fixed["import.created_ms"], V::U(1_709_210_096_789));
    assert_eq!(l.fixed["login.username"], t("alice"));
    assert_eq!(l.fixed["login.password"], t("correct horse"));
    assert_eq!(l.fixed["login.totp"], t("otpauth://totp/x?secret=JBSWY3DP"));
    assert_eq!(l.uris, vec!["https://example.com", "https://example.org"]);
    assert_eq!(
        l.fields,
        vec![
            (Some("PIN".into()), 2, Some(t("1234"))),
            (Some("Color".into()), 1, Some(t("blue"))),
            (Some("Enabled".into()), 3, Some(V::B(true))),
        ]
    );
    assert_eq!(
        l.history,
        vec![
            ("old one".into(), Some(1_672_531_200_000)),
            ("older".into(), None)
        ]
    );
    assert_eq!(l.tags, vec!["Shared", "Work/Email"]);

    let note = view(&import.items[1]);
    assert_eq!(import.items[1].item_type(), ItemType::SECURE_NOTE);
    assert_eq!(note.fixed["item.notes"], t("secret note body"));

    let card = view(&import.items[2]);
    assert_eq!(import.items[2].item_type(), ItemType::CARD);
    assert_eq!(card.fixed["card.holder"], t("Alice"));
    assert_eq!(card.fixed["card.number"], t("4111111111111111"));
    assert_eq!(card.fixed["card.exp_month"], t("7"));
    assert_eq!(card.fixed["card.exp_year"], t("2030"));
    assert_eq!(card.fixed["card.code"], t("123"));

    let identity = view(&import.items[3]);
    assert_eq!(identity.fixed["identity.ssn"], t("000-00-0000"));
    assert_eq!(identity.fixed["identity.drivers_license"], t("D123"));
    assert_eq!(identity.fixed["identity.passport_number"], t("P456"));

    let ssh = view(&import.items[4]);
    assert_eq!(import.items[4].item_type(), ItemType::SECURE_NOTE);
    assert_eq!(
        ssh.fields[0],
        (Some("privateKey".into()), 2, Some(t("-----BEGIN KEY-----")))
    );
    assert_eq!(ssh.fields.len(), 3);

    assert_eq!(
        warns(&import),
        vec![
            (Some(0), WarningKind::PasskeySkipped),
            (Some(0), WarningKind::FieldSkipped),
            (Some(0), WarningKind::InvalidTimestamp),
            (Some(4), WarningKind::ConvertedToSecureNote),
            (Some(5), WarningKind::DeletedEntrySkipped),
            (Some(6), WarningKind::MalformedEntry),
            (Some(7), WarningKind::EmptyEntry),
        ]
    );
}

#[test]
fn bitwarden_refusals() {
    assert_eq!(
        run(
            Format::BitwardenJson,
            br#"{"encrypted": true, "items": []}"#
        )
        .unwrap_err(),
        ImportError::EncryptedExport
    );
    assert_eq!(
        run(
            Format::BitwardenJson,
            br#"{"passwordProtected": true, "data": "x"}"#
        )
        .unwrap_err(),
        ImportError::EncryptedExport
    );
    assert_eq!(
        run(Format::BitwardenJson, br#"{"folders": []}"#).unwrap_err(),
        ImportError::UnexpectedShape
    );
    assert_eq!(
        run(Format::BitwardenJson, b"[]").unwrap_err(),
        ImportError::UnexpectedShape
    );
    assert_eq!(
        run(Format::BitwardenJson, b"{").unwrap_err(),
        ImportError::Malformed
    );
}

const ONEPUX: &str = r#"{
  "accounts": [{
    "attrs": {"accountName": "Test"},
    "vaults": [{
      "attrs": {"name": "Personal"},
      "items": [
        {
          "uuid": "a", "favIndex": 1, "createdAt": 1700000000, "state": "active",
          "categoryUuid": "001",
          "details": {
            "loginFields": [
              {"value": "bob", "name": "username", "fieldType": "T", "designation": "username"},
              {"value": "pw1", "name": "password", "fieldType": "P", "designation": "password"},
              {"value": "extra", "name": "memo", "fieldType": "P", "designation": ""}
            ],
            "notesPlain": "n",
            "sections": [{"title": "s", "fields": [
              {"title": "one-time", "id": "t1", "value": {"totp": "otpauth://totp/y?secret=ABC"}},
              {"title": "answer", "id": "q", "value": {"concealed": "blue"}},
              {"title": "since", "id": "d", "value": {"date": 0}},
              {"title": "ref", "id": "r", "value": {"reference": "zzz"}}
            ]}],
            "passwordHistory": [{"value": "pw0", "time": 1600000000}]
          },
          "overview": {"title": "Site", "url": "https://a.example", "tags": ["x", "y/z"],
                       "urls": [{"label": "", "url": "https://a.example"}, {"url": "https://b.example"}]}
        },
        {"item": {
          "categoryUuid": "002",
          "details": {"sections": [{"fields": [
            {"title": "cardholder name", "id": "cardholder", "value": {"string": "Bob"}},
            {"title": "type", "id": "type", "value": {"creditCardType": "mc"}},
            {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "5500000000000004"}},
            {"title": "verification number", "id": "cvv", "value": {"concealed": "999"}},
            {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202701}}
          ]}]},
          "overview": {"title": "Card"}
        }},
        {
          "categoryUuid": "004",
          "details": {"sections": [{"fields": [
            {"title": "first name", "id": "firstname", "value": {"string": "Bob"}},
            {"title": "address", "id": "address", "value": {"address": {"street": "1 Main St", "city": "Town", "zip": "12345", "country": "us", "state": ""}}},
            {"title": "email", "id": "email", "value": {"email": {"email_address": "bob@example.com", "provider": null}}}
          ]}]},
          "overview": {"title": "Bob"}
        },
        {
          "categoryUuid": "108",
          "details": {"sections": [{"fields": [
            {"title": "number", "id": "n", "value": {"concealed": "123-45-6789"}}
          ]}]},
          "overview": {"title": "SSN"}
        },
        {"categoryUuid": "001", "state": "trashed", "overview": {"title": "old"}}
      ]
    }]
  }]
}"#;

#[test]
fn onepux_archive() {
    let zip = archive(
        &[
            TestMember {
                name: "export.attributes",
                data: b"{\"version\": 3}",
                deflate: false,
            },
            TestMember {
                name: "export.data",
                data: ONEPUX.as_bytes(),
                deflate: true,
            },
            TestMember {
                name: "files/abc",
                data: b"attachment bytes",
                deflate: false,
            },
        ],
        b"",
    );
    let import = run(Format::OnePux, &zip).unwrap();
    assert_eq!(import.items.len(), 4);

    let l = view(&import.items[0]);
    assert_eq!(l.fixed["item.name"], t("Site"));
    assert_eq!(l.fixed["item.favorite"], V::B(true));
    assert_eq!(l.fixed["import.created_ms"], V::U(1_700_000_000_000));
    assert_eq!(l.fixed["login.username"], t("bob"));
    assert_eq!(l.fixed["login.password"], t("pw1"));
    assert_eq!(l.fixed["login.totp"], t("otpauth://totp/y?secret=ABC"));
    assert_eq!(l.uris, vec!["https://a.example", "https://b.example"]);
    assert_eq!(l.tags, vec!["x", "y/z"]);
    assert_eq!(
        l.fields,
        vec![
            (Some("memo".into()), 2, Some(t("extra"))),
            (Some("answer".into()), 2, Some(t("blue"))),
            (Some("since".into()), 1, Some(t("1970-01-01"))),
        ]
    );
    assert_eq!(l.history, vec![("pw0".into(), Some(1_600_000_000_000))]);

    let card = view(&import.items[1]);
    assert_eq!(import.items[1].item_type(), ItemType::CARD);
    assert_eq!(card.fixed["card.holder"], t("Bob"));
    assert_eq!(card.fixed["card.brand"], t("mc"));
    assert_eq!(card.fixed["card.number"], t("5500000000000004"));
    assert_eq!(card.fixed["card.code"], t("999"));
    assert_eq!(card.fixed["card.exp_month"], t("01"));
    assert_eq!(card.fixed["card.exp_year"], t("2027"));

    let id = view(&import.items[2]);
    assert_eq!(id.fixed["identity.first_name"], t("Bob"));
    assert_eq!(id.fixed["identity.address1"], t("1 Main St"));
    assert_eq!(id.fixed["identity.city"], t("Town"));
    assert_eq!(id.fixed["identity.postal_code"], t("12345"));
    assert_eq!(id.fixed["identity.country"], t("us"));
    assert!(!id.fixed.contains_key("identity.state"));
    assert_eq!(id.fixed["identity.email"], t("bob@example.com"));

    let other = view(&import.items[3]);
    assert_eq!(import.items[3].item_type(), ItemType::SECURE_NOTE);
    assert_eq!(
        other.fields,
        vec![(Some("number".into()), 2, Some(t("123-45-6789")))]
    );

    assert_eq!(
        warns(&import),
        vec![
            (Some(0), WarningKind::FieldSkipped),
            (Some(3), WarningKind::ConvertedToSecureNote),
            (Some(4), WarningKind::DeletedEntrySkipped),
        ]
    );

    // The same document, stored rather than deflated, and read directly.
    let direct = import_1pux_data(ONEPUX.as_bytes(), &mut ChaCha20Rng::seed_from_u64(7)).unwrap();
    assert_eq!(direct.items.len(), 4);
}

#[test]
fn onepux_refusals() {
    let no_data = archive(
        &[TestMember {
            name: "x",
            data: b"{}",
            deflate: false,
        }],
        b"",
    );
    assert_eq!(
        run(Format::OnePux, &no_data).unwrap_err(),
        ImportError::UnexpectedShape
    );
    let not_1pux = archive(
        &[TestMember {
            name: "export.data",
            data: b"{\"items\": []}",
            deflate: false,
        }],
        b"",
    );
    assert_eq!(
        run(Format::OnePux, &not_1pux).unwrap_err(),
        ImportError::UnexpectedShape
    );
    assert_eq!(
        run(Format::OnePux, b"not a zip at all, long enough").unwrap_err(),
        ImportError::Malformed
    );
}

const KEEPASS: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta>
    <DatabaseName>db</DatabaseName>
    <RecycleBinEnabled>True</RecycleBinEnabled>
    <RecycleBinUUID>YmluYmluYmluYmluYmluYg==</RecycleBinUUID>
  </Meta>
  <Root>
    <Group>
      <UUID>cm9vdHJvb3Ryb290cm9vdA==</UUID>
      <Name>db</Name>
      <Entry>
        <UUID>ZW50cnllbnRyeWVudHJ5ZQ==</UUID>
        <Tags>alpha;beta, gamma</Tags>
        <Times><CreationTime>2020-05-01T10:00:00Z</CreationTime></Times>
        <String><Key>Title</Key><Value>Mail</Value></String>
        <String><Key>UserName</Key><Value>carol</Value></String>
        <String><Key>Password</Key><Value ProtectInMemory="True">p&amp;ss &lt;3</Value></String>
        <String><Key>URL</Key><Value>https://mail.example</Value></String>
        <String><Key>Notes</Key><Value>line1
line2</Value></String>
        <String><Key>otp</Key><Value ProtectInMemory="True">otpauth://totp/z?secret=XYZ</Value></String>
        <String><Key>Recovery</Key><Value ProtectInMemory="True">r-e-c</Value></String>
        <String><Key>Hint</Key><Value>blue</Value></String>
        <String><Key>Sealed</Key><Value Protected="True">c2VhbGVk</Value></String>
        <String><Key>Empty</Key><Value/></String>
        <Binary><Key>a.txt</Key><Value Ref="0"/></Binary>
        <History>
          <Entry>
            <Times><LastModificationTime>2019-01-01T00:00:00Z</LastModificationTime></Times>
            <String><Key>Password</Key><Value>first</Value></String>
          </Entry>
          <Entry>
            <String><Key>Password</Key><Value>first</Value></String>
          </Entry>
          <Entry>
            <String><Key>Password</Key><Value>p&amp;ss &lt;3</Value></String>
          </Entry>
        </History>
      </Entry>
      <Group>
        <UUID>c3ViZ3JvdXBzdWJncm91cA==</UUID>
        <Name>Work</Name>
        <Group>
          <UUID>ZGVlcGRlZXBkZWVwZGVlcA==</UUID>
          <Name>Deep</Name>
          <Entry>
            <String><Key>Title</Key><Value>Nested</Value></String>
            <String><Key>Password</Key><Value><![CDATA[a<b]]></Value></String>
          </Entry>
        </Group>
      </Group>
      <Group>
        <UUID>YmluYmluYmluYmluYmluYg==</UUID>
        <Name>Recycle Bin</Name>
        <Entry><String><Key>Title</Key><Value>Deleted</Value></String></Entry>
      </Group>
      <Entry>
        <String><Key>Title</Key><Value></Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>
"#;

#[test]
fn keepass_xml() {
    let import = run(Format::KeePassXml, KEEPASS.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 2);
    let e = view(&import.items[0]);
    assert_eq!(import.items[0].item_type(), ItemType::LOGIN);
    assert_eq!(e.fixed["item.name"], t("Mail"));
    assert_eq!(e.fixed["login.username"], t("carol"));
    assert_eq!(e.fixed["login.password"], t("p&ss <3"));
    assert_eq!(e.fixed["item.notes"], t("line1\nline2"));
    assert_eq!(e.fixed["login.totp"], t("otpauth://totp/z?secret=XYZ"));
    assert_eq!(e.fixed["import.created_ms"], V::U(1_588_327_200_000));
    assert_eq!(e.uris, vec!["https://mail.example"]);
    assert_eq!(
        e.fields,
        vec![
            (Some("Recovery".into()), 2, Some(t("r-e-c"))),
            (Some("Hint".into()), 1, Some(t("blue"))),
        ]
    );
    assert_eq!(e.tags, vec!["alpha", "beta", "gamma"]);
    assert_eq!(e.history, vec![("first".into(), Some(1_546_300_800_000))]);

    let nested = view(&import.items[1]);
    assert_eq!(nested.fixed["login.password"], t("a<b"));
    assert_eq!(nested.tags, vec!["Work/Deep"]);
    assert_eq!(import.items[1].entry(), 2);
}

#[test]
fn keepass_entry_order_and_warnings() {
    let import = run(Format::KeePassXml, KEEPASS.as_bytes()).unwrap();
    // Entries of the top group first (0: Mail, 1: the empty one), then its subgroups in
    // document order, depth first (2: Nested, 3: the recycle bin's entry).
    let entries: Vec<usize> = import.items.iter().map(ImportedItem::entry).collect();
    assert_eq!(entries, vec![0, 2]);
    let mut w = warns(&import);
    w.sort_by_key(|(e, _)| *e);
    assert_eq!(
        w,
        vec![
            (Some(0), WarningKind::ProtectedValueSkipped),
            (Some(0), WarningKind::AttachmentSkipped),
            (Some(1), WarningKind::EmptyEntry),
            (Some(3), WarningKind::DeletedEntrySkipped),
        ]
    );
}

#[test]
fn keepass_refusals() {
    let mut kdbx = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];
    kdbx.extend_from_slice(&[0; 64]);
    assert_eq!(
        run(Format::KeePassXml, &kdbx).unwrap_err(),
        ImportError::KdbxNotSupported
    );
    assert_eq!(
        run(
            Format::KeePassXml,
            b"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><KeePassFile/>"
        )
        .unwrap_err(),
        ImportError::Doctype
    );
    assert_eq!(
        run(Format::KeePassXml, b"<Other/>").unwrap_err(),
        ImportError::UnexpectedShape
    );
    assert_eq!(
        run(Format::KeePassXml, b"<KeePassFile><Meta/></KeePassFile>").unwrap_err(),
        ImportError::UnexpectedShape
    );
}

/// A `KeePass` XML document of one top group holding `entries`.
fn keepass_doc(entries: &str) -> String {
    format!("<KeePassFile><Root><Group><Name>db</Name>{entries}</Group></Root></KeePassFile>")
}

/// One `KeePass` entry of plain strings.
fn keepass_entry(strings: &[(&str, &str)]) -> String {
    let mut out = String::from("<Entry>");
    for (k, v) in strings {
        write!(out, "<String><Key>{k}</Key><Value>{v}</Value></String>").unwrap();
    }
    out.push_str("</Entry>");
    out
}

#[test]
fn keepass_totp_settings() {
    let doc = keepass_doc(
        &[
            keepass_entry(&[("Title", "a"), ("TimeOtp-Secret-Base32", "JBSWY3DP")]),
            keepass_entry(&[
                ("Title", "b"),
                ("TimeOtp-Secret-Base32", "JBSWY3DP"),
                ("TimeOtp-Period", "60"),
            ]),
            keepass_entry(&[
                ("Title", "c"),
                ("TOTP Seed", "JBSWY3DP"),
                ("TOTP Settings", "30;S"),
            ]),
            keepass_entry(&[("Title", "d"), ("TimeOtp-Secret-Hex", "48656c6c6f")]),
            keepass_entry(&[
                ("Title", "e"),
                ("TimeOtp-Secret-Base32", "JBSWY3DP"),
                ("TimeOtp-Length", "6"),
                ("TimeOtp-Algorithm", "HMAC-SHA-1"),
            ]),
        ]
        .concat(),
    );
    let import = run(Format::KeePassXml, doc.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 5);

    // Default settings: the bare secret goes to login.totp.
    let plain = view(&import.items[0]);
    assert_eq!(plain.fixed["login.totp"], t("JBSWY3DP"));
    assert!(plain.fields.is_empty());

    // A 60 s period: not in login.totp, kept hidden, the setting kept too.
    let period = view(&import.items[1]);
    assert!(!period.fixed.contains_key("login.totp"));
    assert_eq!(
        period.fields,
        vec![
            (Some("TimeOtp-Period".into()), 1, Some(t("60"))),
            (Some("TimeOtp-Secret-Base32".into()), 2, Some(t("JBSWY3DP"))),
        ]
    );

    // Steam codes.
    let steam = view(&import.items[2]);
    assert!(!steam.fixed.contains_key("login.totp"));
    assert_eq!(
        steam.fields,
        vec![
            (Some("TOTP Settings".into()), 1, Some(t("30;S"))),
            (Some("TOTP Seed".into()), 2, Some(t("JBSWY3DP"))),
        ]
    );

    // Another encoding: hidden even without ProtectInMemory.
    let hex = view(&import.items[3]);
    assert!(!hex.fixed.contains_key("login.totp"));
    assert_eq!(
        hex.fields,
        vec![(Some("TimeOtp-Secret-Hex".into()), 2, Some(t("48656c6c6f")))]
    );

    // Settings spelled out at their defaults.
    let spelled = view(&import.items[4]);
    assert_eq!(spelled.fixed["login.totp"], t("JBSWY3DP"));

    assert_eq!(
        warns(&import),
        vec![
            (Some(1), WarningKind::TotpNotConverted),
            (Some(2), WarningKind::TotpNotConverted),
            (Some(3), WarningKind::TotpNotConverted),
        ]
    );
}

#[test]
fn keepass_long_group_names_are_not_copied_per_group() {
    // A long group name above many sibling groups: its path is an invalid tag, warned about
    // once per entry and never built.
    let long = "n".repeat(100_000);
    let sibling = format!(
        "<Group><Name>s</Name>{}</Group>",
        keepass_entry(&[("Title", "x")])
    );
    let siblings = sibling.repeat(200);
    let doc = keepass_doc(&format!(
        "<Group><Name>{long}</Name>{siblings}</Group><Group><Name>ok</Name><Group><Name>fine</Name>{}</Group></Group>",
        keepass_entry(&[("Title", "y")])
    ));
    let import = run(Format::KeePassXml, doc.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 201);
    for item in &import.items[..200] {
        assert!(view(item).tags.is_empty());
    }
    assert_eq!(view(&import.items[200]).tags, vec!["ok/fine"]);
    let w = warns(&import);
    assert_eq!(w.len(), 200);
    assert!(w.iter().all(|(_, k)| *k == WarningKind::InvalidTag));
}

#[test]
fn onepux_nothing_dropped_silently() {
    let doc = r#"{"accounts": [{"vaults": [{"items": [{
      "categoryUuid": "003",
      "overview": {"title": "N", "url": "https://a.example", "urls": [{"url": "https://a.example"}]},
      "details": {
        "password": "pw",
        "sections": [{"fields": [
          {"id": "f1", "title": "no value"},
          {"id": "f2", "title": "odd", "value": {"concealed": {"x": 1}}},
          {"id": "f3", "title": "blank", "value": {"string": ""}}
        ]}]
      }
    }]}]}]}"#;
    let import = import_1pux_data(doc.as_bytes(), &mut ChaCha20Rng::seed_from_u64(7)).unwrap();
    assert_eq!(import.items.len(), 1);
    let n = view(&import.items[0]);
    assert_eq!(
        n.fields,
        vec![
            (Some("URL".into()), 1, Some(t("https://a.example"))),
            (Some("password".into()), 2, Some(t("pw"))),
        ]
    );
    // The blank field is not content and is not warned about.
    assert_eq!(
        warns(&import),
        vec![
            (Some(0), WarningKind::FieldSkipped),
            (Some(0), WarningKind::FieldSkipped),
        ]
    );
}

#[test]
fn chrome_csv() {
    let csv = "name,url,username,password,note\r\nex,https://ex.com/,dave,\"pa,ss\",\"multi\nline\"\r\n\r\n,,,,\r\nsite2,https://s2.example,,pw2,,extra\r\n";
    let import = run(Format::ChromeCsv, csv.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 2);
    let a = view(&import.items[0]);
    assert_eq!(a.fixed["item.name"], t("ex"));
    assert_eq!(a.fixed["login.username"], t("dave"));
    assert_eq!(a.fixed["login.password"], t("pa,ss"));
    assert_eq!(a.fixed["item.notes"], t("multi\nline"));
    assert_eq!(a.uris, vec!["https://ex.com/"]);
    assert_eq!(import.items[1].entry(), 3);
    assert_eq!(warns(&import), vec![(Some(3), WarningKind::ExtraColumns)]);

    assert_eq!(
        run(Format::ChromeCsv, b"url,username,password\n").unwrap_err(),
        ImportError::UnexpectedShape
    );
    assert_eq!(
        run(Format::ChromeCsv, b"").unwrap_err(),
        ImportError::UnexpectedShape
    );
}

#[test]
fn firefox_csv() {
    let csv = "\u{feff}\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\"https://user@ff.example:8443/login\",\"erin\",\"pw\",\"\",\"https://ff.example\",\"{guid}\",\"1600000000123\",\"1\",\"2\"\n\"https://x.example\",\"\",\"pw\",\"Realm\",\"\",\"\",\"bad\",\"\",\"\"\n";
    let import = run(Format::FirefoxCsv, csv.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 2);
    let a = view(&import.items[0]);
    assert_eq!(a.fixed["item.name"], t("ff.example"));
    assert_eq!(a.fixed["import.created_ms"], V::U(1_600_000_000_123));
    assert_eq!(a.uris, vec!["https://user@ff.example:8443/login"]);
    assert_eq!(
        a.fields,
        vec![(
            Some("formActionOrigin".into()),
            1,
            Some(t("https://ff.example"))
        )]
    );
    let b = view(&import.items[1]);
    assert_eq!(
        b.fields,
        vec![(Some("httpRealm".into()), 1, Some(t("Realm")))]
    );
    assert_eq!(
        warns(&import),
        vec![(Some(1), WarningKind::InvalidTimestamp)]
    );
}

#[test]
fn generic_csv() {
    let csv = "Title,User,Password,Website,Folder,Tags,Favorite,Type,Security Question,Color,TOTP\n\
               Bank,frank,pw,https://bank.example,Finance,\"a, b\",yes,,What?,red,JBSWY3DP\n\
               Memo,,hunter2,https://memo.example,,,,note,,,\n";
    let import = run(Format::GenericCsv, csv.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 2);
    let a = view(&import.items[0]);
    assert_eq!(import.items[0].item_type(), ItemType::LOGIN);
    assert_eq!(a.fixed["item.name"], t("Bank"));
    assert_eq!(a.fixed["login.username"], t("frank"));
    assert_eq!(a.fixed["login.password"], t("pw"));
    assert_eq!(a.fixed["login.totp"], t("JBSWY3DP"));
    assert_eq!(a.fixed["item.favorite"], V::B(true));
    assert_eq!(a.uris, vec!["https://bank.example"]);
    assert_eq!(a.tags, vec!["Finance", "a", "b"]);
    assert_eq!(
        a.fields,
        vec![
            (Some("Security Question".into()), 1, Some(t("What?"))),
            (Some("Color".into()), 1, Some(t("red"))),
        ]
    );
    let note = view(&import.items[1]);
    assert_eq!(import.items[1].item_type(), ItemType::SECURE_NOTE);
    assert_eq!(
        note.fields,
        vec![
            (Some("Password".into()), 2, Some(t("hunter2"))),
            (Some("URL".into()), 1, Some(t("https://memo.example"))),
        ]
    );
    assert_eq!(
        run(Format::GenericCsv, b"a,b,c\n1,2,3\n").unwrap_err(),
        ImportError::UnexpectedShape
    );
}

#[test]
fn values_too_long_are_dropped_not_truncated() {
    let long = "x".repeat(crate::limits::MAX_TEXT_LEN + 1);
    let fits = "y".repeat(crate::limits::MAX_TEXT_LEN);
    let csv = format!("name,password,notes\nitem,{long},{fits}\n");
    let import = run(Format::GenericCsv, csv.as_bytes()).unwrap();
    let a = view(&import.items[0]);
    assert!(!a.fixed.contains_key("login.password"));
    assert_eq!(a.fixed["item.notes"], V::T(fits));
    assert_eq!(warns(&import), vec![(Some(0), WarningKind::ValueTooLong)]);
}

#[test]
fn items_fit_one_op() {
    // 200 custom fields of 60 KiB each would be 12 MiB: most are dropped, whole.
    let value = "v".repeat(60_000);
    let mut header = String::from("name");
    let mut row = String::from("big");
    for i in 0..crate::limits::MAX_CUSTOM_FIELDS + 5 {
        write!(header, ",c{i}").unwrap();
        row.push(',');
        row.push_str(&value);
    }
    let csv = format!("{header}\n{row}\n");
    let import = run(Format::GenericCsv, csv.as_bytes()).unwrap();
    let a = view(&import.items[0]);
    assert!(!a.fields.is_empty());
    assert!(a.fields.len() < 20);
    assert!(a.fields.iter().all(|f| f.2 == Some(V::T(value.clone()))));
    assert_eq!(
        warns(&import),
        vec![
            (Some(0), WarningKind::TooManyElements),
            (Some(0), WarningKind::ItemTooLarge),
        ]
    );
}

#[test]
fn write_count_cap() {
    // 100 URIs (200 writes), 200 custom fields (800), 50 history entries and 100 tags: more
    // than 1,024 writes, so the op is filled in list order and the rest dropped whole.
    let uris: Vec<String> = (0..100)
        .map(|i| format!("{{\"uri\": \"https://{i}.example\"}}"))
        .collect();
    let fields: Vec<String> = (0..200)
        .map(|i| format!("{{\"name\": \"f{i}\", \"value\": \"v\", \"type\": 0}}"))
        .collect();
    let history: Vec<String> = (0..50)
        .map(|i| format!("{{\"password\": \"old{i}\"}}"))
        .collect();
    let collections: Vec<String> = (0..100)
        .map(|i| format!("{{\"id\": \"c{i}\", \"name\": \"tag{i}\"}}"))
        .collect();
    let ids: Vec<String> = (0..100).map(|i| format!("\"c{i}\"")).collect();
    let doc = format!(
        "{{\"collections\": [{}], \"items\": [{{\"type\": 1, \"name\": \"big\", \"collectionIds\": [{}], \"login\": {{\"uris\": [{}]}}, \"fields\": [{}], \"passwordHistory\": [{}]}}]}}",
        collections.join(","),
        ids.join(","),
        uris.join(","),
        fields.join(","),
        history.join(",")
    );
    let import = run(Format::BitwardenJson, doc.as_bytes()).unwrap();
    let item = &import.items[0];
    assert_eq!(item.writes().len(), crate::limits::MAX_WRITES);
    let a = view(item);
    assert_eq!(a.uris.len(), 100);
    assert_eq!(a.fields.len(), 200);
    assert_eq!(a.history.len(), 22);
    assert!(a.tags.is_empty());
    assert_eq!(warns(&import), vec![(Some(0), WarningKind::ItemTooLarge)]);
}

#[test]
fn repeated_headers_become_custom_fields() {
    let import = run(
        Format::GenericCsv,
        b"name,tags,tags,password,password\nx,t1,t2,p1,p2\n",
    )
    .unwrap();
    let a = view(&import.items[0]);
    assert_eq!(a.tags, vec!["t1"]);
    assert_eq!(a.fixed["login.password"], t("p1"));
    assert_eq!(
        a.fields,
        vec![
            (Some("tags".into()), 1, Some(t("t2"))),
            (Some("password".into()), 2, Some(t("p2"))),
        ]
    );
}

#[test]
fn nothing_secret_in_debug_or_warnings() {
    let import = run(Format::BitwardenJson, BITWARDEN.as_bytes()).unwrap();
    let shown = format!("{import:?}");
    for secret in [
        "correct horse",
        "alice",
        "4111111111111111",
        "000-00-0000",
        "Example",
        "Work",
    ] {
        assert!(!shown.contains(secret), "{secret} in Debug output");
    }
    for w in &import.warnings {
        let text = format!("{w:?} {}", w.kind);
        assert!(!text.contains("horse"));
    }
}

#[test]
fn deterministic_for_a_seed() {
    let a = run(Format::BitwardenJson, BITWARDEN.as_bytes()).unwrap();
    let b = run(Format::BitwardenJson, BITWARDEN.as_bytes()).unwrap();
    let keys = |i: &Import| -> Vec<Vec<u8>> {
        i.items
            .iter()
            .flat_map(|it| it.writes().iter().map(|w| w.key().as_bytes().to_vec()))
            .collect()
    };
    assert_eq!(keys(&a), keys(&b));
    // Element ids differ between elements.
    let ids: std::collections::BTreeSet<_> = a.items[0]
        .writes()
        .iter()
        .filter_map(|w| w.key().as_key().element().map(str::to_owned))
        .collect();
    assert!(ids.len() >= 8);
}

#[test]
fn caps() {
    assert_eq!(
        run(
            Format::BitwardenJson,
            &vec![b' '; crate::limits::MAX_JSON_LEN + 1]
        )
        .unwrap_err(),
        ImportError::TooLarge
    );
    let many = format!(
        "{{\"items\": [{}]}}",
        vec!["{}"; crate::limits::MAX_ENTRIES + 1].join(",")
    );
    assert_eq!(
        run(Format::BitwardenJson, many.as_bytes()).unwrap_err(),
        ImportError::TooMany
    );
    let deep = format!("{{\"items\": {}{}}}", "[".repeat(70), "]".repeat(70));
    assert_eq!(
        run(Format::BitwardenJson, deep.as_bytes()).unwrap_err(),
        ImportError::TooDeep
    );
}

// ---- rizzy-vault's own plaintext JSON export (ADR 0027 §3, §6) ----

/// A plaintext export document holding `items` (JSON text of the array's elements).
fn rizzy_doc(items: &str) -> String {
    format!(
        "{{\"format\":\"rizzy-vault-plaintext-export\",\"version\":1,\
         \"exported_at\":1790000000000,\"items\":[{items}]}}"
    )
}

/// The writes of a carried item as key → encoded value, with the invariants every item of our
/// own export keeps: canonical order, the carried create check, the snapshot budget.
fn carried(item: &ImportedItem) -> BTreeMap<String, Vec<u8>> {
    assert_eq!(item.source(), WriteSource::Carried);
    let writes = item.writes();
    for pair in writes.windows(2) {
        assert!(pair[0].key().as_bytes() < pair[1].key().as_bytes());
    }
    check_create(
        item.item_type(),
        WriteMode::Import,
        writes.iter().map(|w| {
            (
                WriteSource::Carried,
                w.key().as_bytes(),
                w.value().expose_secret(),
            )
        }),
    )
    .unwrap();
    assert!(writes.len() < crate::limits::MAX_REGISTERS);
    writes
        .iter()
        .map(|w| {
            (
                w.key().as_str().to_owned(),
                w.value().expose_secret().to_vec(),
            )
        })
        .collect()
}

#[test]
fn rizzy_json_reads_every_value_type() {
    let history: String = (0..52)
        .map(|i| format!("{{\"value\":{{\"text\":\"old {i}\"}},\"ms\":{}}}", 1000 + i))
        .chain(["{\"value\":{\"bytes\":\"AAEC\"},\"ms\":5}".to_owned()])
        .collect::<Vec<_>>()
        .join(",");
    let doc = rizzy_doc(&format!(
        r#"{{"id":"000102030405060708090a0b0c0d0e0f","type":1,"trashed":true,
            "created_ms":1700000000000,"modified_ms":1700000000001,
            "fields":[
              {{"key":"item.name","value":{{"text":"Bank \"é\"\n"}}}},
              {{"key":"item.type","value":{{"enum":3}}}},
              {{"key":"import.created_ms","value":{{"u64":"5"}}}},
              {{"key":"item.favorite","value":{{"bool":true}}}},
              {{"key":"login.password","value":{{"text":"hunter2"}},
                "conflicts":[{{"text":"other"}}],"history":[{history}]}},
              {{"key":"login.username","value":{{"text":""}},"history":[{{"x":1}},{{"y":2}}]}},
              {{"key":"uri/00112233445566778899aabbccddeeff/value","value":{{"text":"https://e.example"}}}},
              {{"key":"uri/00112233445566778899aabbccddeeff/order","value":{{"sort_key":"gA"}}}},
              {{"key":"newer.key","value":{{"raw":"fwEC"}}}},
              {{"key":"newer.bytes","value":{{"bytes":"AAEC"}}}},
              {{"key":"newer.u64","value":{{"u64":"18446744073709551615"}}}},
              {{"key":"newer.enum","value":{{"enum":65535}}}}
            ]}}"#
    ));
    let import = run(Format::RizzyPlaintextJson, doc.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 1);
    let item = &import.items[0];
    assert!(item.trashed());
    assert_eq!(item.item_type(), ItemType::LOGIN);
    let w = carried(item);
    // `type` decides the item type; `created_ms` decides `import.created_ms`.
    assert_eq!(v(&w["item.type"]), V::E(1));
    assert_eq!(v(&w["import.created_ms"]), V::U(1_700_000_000_000));
    assert_eq!(v(&w["item.name"]), t("Bank \"é\"\n"));
    assert_eq!(v(&w["item.favorite"]), V::B(true));
    assert_eq!(v(&w["login.password"]), t("hunter2"));
    // An empty Text is a non-empty value (one byte) and is carried verbatim.
    assert_eq!(w["login.username"], vec![0x01]);
    assert_eq!(
        v(&w["uri/00112233445566778899aabbccddeeff/value"]),
        t("https://e.example")
    );
    assert_eq!(
        w["uri/00112233445566778899aabbccddeeff/order"],
        vec![0x06, 0x80]
    );
    // Unknown keys and an unsupported value, byte for byte.
    assert_eq!(w["newer.key"], vec![0x7f, 0x01, 0x02]);
    assert_eq!(w["newer.bytes"], vec![0x02, 0x00, 0x01, 0x02]);
    assert_eq!(v(&w["newer.u64"]), V::U(u64::MAX));
    assert_eq!(v(&w["newer.enum"]), V::E(65535));
    // Fifty history entries, in file order, under fresh element ids.
    let mut history: Vec<(String, u64)> = Vec::new();
    for (key, value) in &w {
        if let Some(id) = key
            .strip_prefix("pwhist/")
            .and_then(|k| k.strip_suffix("/value"))
        {
            let V::T(text) = v(value) else { panic!() };
            let V::U(ms) = v(&w[&format!("pwhist/{id}/ms")]) else {
                panic!()
            };
            history.push((text, ms));
        }
    }
    history.sort_by_key(|(_, ms)| *ms);
    assert_eq!(history.len(), 50);
    assert_eq!(history[0], ("old 0".to_owned(), 1000));
    assert_eq!(history[49], ("old 49".to_owned(), 1049));
    assert_eq!(w.len(), 12 + 100);
    // The report: numbers and positions only.
    assert_eq!(
        import.counts,
        crate::Counts {
            skipped_items: 0,
            ignored_members: 0,
            collapsed_conflicts: 1,
            // Two past the fiftieth, one that is not a text, two of another field.
            dropped_history: 5,
            dropped_fields: 0,
        }
    );
    assert_eq!(
        warns(&import),
        vec![
            (Some(0), WarningKind::ConflictsCollapsed),
            (Some(0), WarningKind::HistoryDropped),
        ]
    );
    let shown = format!("{import:?}");
    for secret in ["hunter2", "Bank", "old 1", "newer"] {
        assert!(!shown.contains(secret), "{secret} in Debug output");
    }
}

#[test]
fn rizzy_json_whole_file_refusals() {
    let ok = rizzy_doc("");
    assert!(
        run(Format::RizzyPlaintextJson, ok.as_bytes())
            .unwrap()
            .items
            .is_empty()
    );
    // `exported_at` is optional; a BOM-less minimal document reads.
    let minimal = r#"{"items":[],"version":1,"format":"rizzy-vault-plaintext-export"}"#;
    assert!(run(Format::RizzyPlaintextJson, minimal.as_bytes()).is_ok());
    let cases: [(String, ImportError); 12] = [
        (String::new(), ImportError::Malformed),
        ("[]".to_owned(), ImportError::UnexpectedShape),
        (
            ok.replace("rizzy-vault-plaintext-export", "rizzy-vault-export"),
            ImportError::UnexpectedShape,
        ),
        (
            ok.replace("\"format\":\"rizzy-vault-plaintext-export\",", ""),
            ImportError::UnexpectedShape,
        ),
        (
            ok.replace("\"version\":1", "\"version\":2"),
            ImportError::UpdateRequired,
        ),
        (
            ok.replace("\"version\":1", "\"version\":\"1\""),
            ImportError::UpdateRequired,
        ),
        (
            ok.replace("\"version\":1", "\"version\":1.0"),
            ImportError::UpdateRequired,
        ),
        (
            ok.replace("\"version\":1,", ""),
            ImportError::UnexpectedShape,
        ),
        (
            ok.replace("\"items\":[]", "\"items\":{}"),
            ImportError::UnexpectedShape,
        ),
        (
            ok.replace(",\"items\":[]", ""),
            ImportError::UnexpectedShape,
        ),
        (
            rizzy_doc(&vec!["{}"; crate::limits::MAX_ENTRIES + 1].join(",")),
            ImportError::TooMany,
        ),
        (
            rizzy_doc(&format!("{}{}", "[".repeat(70), "]".repeat(70))),
            ImportError::TooDeep,
        ),
    ];
    for (doc, error) in cases {
        assert_eq!(
            run(Format::RizzyPlaintextJson, doc.as_bytes()).unwrap_err(),
            error,
            "{}",
            &doc[..doc.len().min(90)]
        );
    }
    assert_eq!(
        run(
            Format::RizzyPlaintextJson,
            &vec![b' '; crate::limits::MAX_JSON_LEN + 1]
        )
        .unwrap_err(),
        ImportError::TooLarge
    );
    assert_eq!(
        run(Format::RizzyPlaintextJson, b"{\"format\":\"\xff\"}").unwrap_err(),
        ImportError::Encoding
    );
    // At the entry cap the file reads, and every (empty) entry is skipped, not the file.
    let full = rizzy_doc(&vec!["{}"; crate::limits::MAX_ENTRIES].join(","));
    let import = run(Format::RizzyPlaintextJson, full.as_bytes()).unwrap();
    assert!(import.items.is_empty());
    assert_eq!(import.counts.skipped_items, crate::limits::MAX_ENTRIES);
    assert_eq!(import.warnings.len(), crate::limits::MAX_WARNINGS + 1);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one vector per per-item rule of ADR 0027 §6, each skipping exactly its item"
)]
fn rizzy_json_per_item_failures_skip_the_item_only() {
    let good = r#"{"type":2,"fields":[{"key":"item.name","value":{"text":"kept"}}]}"#;
    let big_text = "x".repeat(65_536);
    let big_raw = "A".repeat(87_383); // 65,537 bytes
    let bad: Vec<(String, WarningKind)> = [
        ("\"not an object\"", WarningKind::MalformedEntry),
        (r#"{"fields":[]}"#, WarningKind::MalformedEntry),
        (r#"{"type":"1","fields":[]}"#, WarningKind::MalformedEntry),
        (r#"{"type":65536,"fields":[]}"#, WarningKind::MalformedEntry),
        (r#"{"type":1.5,"fields":[]}"#, WarningKind::MalformedEntry),
        (r#"{"type":1}"#, WarningKind::MalformedEntry),
        (r#"{"type":1,"fields":{}}"#, WarningKind::MalformedEntry),
        (
            r#"{"type":1,"trashed":"no","fields":[]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"created_ms":-1,"fields":[]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"created_ms":18446744073709551616,"fields":[]}"#,
            WarningKind::MalformedEntry,
        ),
        // Types the schema refuses, and the vault-settings type.
        (r#"{"type":0,"fields":[]}"#, WarningKind::UnsupportedItemType),
        (r#"{"type":5,"fields":[]}"#, WarningKind::UnsupportedItemType),
        (r#"{"type":999,"fields":[]}"#, WarningKind::UnsupportedItemType),
        (
            r#"{"type":61441,"fields":[{"key":"vault.name","value":{"text":"v"}}]}"#,
            WarningKind::UnsupportedItemType,
        ),
        // Fields.
        (r#"{"type":1,"fields":[1]}"#, WarningKind::MalformedEntry),
        (
            r#"{"type":1,"fields":[{"value":{"text":"a"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"item.name"}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"Item.Name","value":{"text":"a"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"@lifecycle","value":{"raw":"AQ"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"item.name","value":{"text":"a"}},{"key":"item.name","value":{"text":"b"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"item.type","value":{"enum":1}},{"key":"item.type","value":{"enum":1}}]}"#,
            WarningKind::MalformedEntry,
        ),
        // Values.
        (
            r#"{"type":1,"fields":[{"key":"item.name","value":"a"}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"item.name","value":{}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"item.name","value":{"text":"a","raw":"AQ"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"item.name","value":{"text":1}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"bytes":"A"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"bytes":"AA=="}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"bool":"true"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"u64":5}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"u64":"05"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"u64":""}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"u64":"18446744073709551616"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"enum":65536}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"sort_key":""}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"sort_key":"gAA"}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"a.b","value":{"raw":""}}]}"#,
            WarningKind::MalformedEntry,
        ),
        // History of the wrong shape.
        (
            r#"{"type":1,"fields":[{"key":"login.password","value":{"text":"a"},"history":{}}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"login.password","value":{"text":"a"},"history":[{"value":{"text":"b"}}]}]}"#,
            WarningKind::MalformedEntry,
        ),
        (
            r#"{"type":1,"fields":[{"key":"login.password","value":{"text":"a"},"history":[{"ms":1}]}]}"#,
            WarningKind::MalformedEntry,
        ),
    ]
    .into_iter()
    .map(|(doc, kind)| (doc.to_owned(), kind))
    .chain([
        (
            format!(
                r#"{{"type":1,"fields":[{{"key":"item.name","value":{{"text":"{big_text}"}}}}]}}"#
            ),
            WarningKind::OversizeEntry,
        ),
        (
            format!(r#"{{"type":1,"fields":[{{"key":"a.b","value":{{"raw":"{big_raw}"}}}}]}}"#),
            WarningKind::OversizeEntry,
        ),
        (
            format!(r#"{{"type":1,"fields":[{{"key":"a.b","value":{{"bytes":"{big_raw}"}}}}]}}"#),
            WarningKind::OversizeEntry,
        ),
    ])
    .collect();
    for (item, kind) in bad {
        let doc = rizzy_doc(&format!("{good},{item},{good}"));
        let import = run(Format::RizzyPlaintextJson, doc.as_bytes()).unwrap();
        let shown = &item[..item.len().min(100)];
        assert_eq!(import.items.len(), 2, "{shown}");
        assert_eq!(import.items[0].entry(), 0);
        assert_eq!(import.items[1].entry(), 2);
        assert_eq!(warns(&import), vec![(Some(1), kind)], "{shown}");
        assert_eq!(import.counts.skipped_items, 1);
        assert_eq!(v(&carried(&import.items[1])["item.name"]), t("kept"));
    }
    // The largest values still read: 65,535 bytes of text, 65,536 bytes of raw.
    let text = "x".repeat(65_535);
    let raw = "A".repeat(87_382); // 65,536 bytes; the last sextet's spare bits are zero
    let doc = rizzy_doc(&format!(
        r#"{{"type":2,"fields":[{{"key":"item.notes","value":{{"text":"{text}"}}}},{{"key":"a.b","value":{{"raw":"{raw}"}}}}]}}"#
    ));
    let import = run(Format::RizzyPlaintextJson, doc.as_bytes()).unwrap();
    assert_eq!(warns(&import), vec![]);
    let w = carried(&import.items[0]);
    assert_eq!(w["item.notes"].len(), 65_536);
    assert_eq!(w["a.b"].len(), 65_536);
}

#[test]
fn rizzy_json_unknown_members_and_unwritable_fields() {
    let doc = r#"{"format":"rizzy-vault-plaintext-export","version":1,"later":[1,2],"version":9,
      "items":[
        {"type":1,"extra":null,"type":3,"fields":[
          {"key":"item.name","value":{"text":"a","note":1},"hint":"x"},
          {"key":"uri/00112233445566778899aabbccddeeff/match","value":{"enum":2}},
          {"key":"share/00112233445566778899aabbccddeeff/secret","value":{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
          {"key":"card.number","value":{"text":"4111"}},
          {"key":"login.password","value":{"text":"p"},
           "history":[{"value":{"text":"o"},"ms":1,"device":"x"}]}
        ]},
        {"type":2,"fields":[],"trashed":false},
        {"type":1,"fields":[{"key":"import.created_ms","value":{"u64":"77"}}]}
      ]}"#;
    let import = run(Format::RizzyPlaintextJson, doc.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 3);
    let w = carried(&import.items[0]);
    // The first `type` counts (the JSON reader's rule); the unwritable fields are left out.
    assert_eq!(import.items[0].item_type(), ItemType::LOGIN);
    assert_eq!(
        w.keys()
            .filter(|k| !k.starts_with("pwhist/"))
            .collect::<Vec<_>>(),
        ["item.name", "item.type", "login.password"]
    );
    assert_eq!(w.len(), 5);
    // An item with no field is an item: only its type is written.
    assert_eq!(
        carried(&import.items[1]).keys().collect::<Vec<_>>(),
        ["item.type"]
    );
    assert!(!import.items[1].trashed());
    // Without `created_ms`, an `import.created_ms` field is carried.
    assert_eq!(v(&carried(&import.items[2])["import.created_ms"]), V::U(77));
    assert_eq!(
        import.counts,
        crate::Counts {
            skipped_items: 0,
            // Root: `later`, the second `version`. Item 0: `extra`, the second `type`, `note`,
            // `hint`, `device`.
            ignored_members: 7,
            collapsed_conflicts: 0,
            dropped_history: 0,
            dropped_fields: 3,
        }
    );
    assert_eq!(
        warns(&import),
        vec![
            (None, WarningKind::UnknownMembersIgnored),
            (Some(0), WarningKind::UnknownMembersIgnored),
            (Some(0), WarningKind::FieldSkipped),
        ]
    );
}

#[test]
fn rizzy_json_item_size_limits() {
    let field = |i: usize| format!("{{\"key\":\"k.f{i}\",\"value\":{{\"bool\":true}}}}");
    let item = |n: usize| {
        format!(
            "{{\"type\":2,\"fields\":[{}]}}",
            (0..n).map(field).collect::<Vec<_>>().join(",")
        )
    };
    // 4,094 fields and `item.type` are 4,095 writes: with `@lifecycle`, the register cap.
    let doc = rizzy_doc(&format!("{},{},{}", item(4094), item(4095), item(4097)));
    let import = run(Format::RizzyPlaintextJson, doc.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 1);
    assert_eq!(import.items[0].writes().len(), 4095);
    carried(&import.items[0]);
    assert_eq!(
        warns(&import),
        vec![
            (Some(1), WarningKind::OversizeEntry),
            (Some(2), WarningKind::OversizeEntry),
        ]
    );
    // More value bytes than one item's snapshot holds: 200 values of 64 KiB are 12.5 MiB.
    let text = "y".repeat(65_535);
    let fat = format!(
        "{{\"type\":2,\"fields\":[{}]}}",
        (0..200)
            .map(|i| format!("{{\"key\":\"k.f{i}\",\"value\":{{\"text\":\"{text}\"}}}}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let import = run(Format::RizzyPlaintextJson, rizzy_doc(&fat).as_bytes()).unwrap();
    assert!(import.items.is_empty());
    assert_eq!(warns(&import), vec![(Some(0), WarningKind::OversizeEntry)]);
}

#[test]
fn aliasvault_csv_web() {
    let csv = "ServiceName,FolderPath,ServiceUrl,Username,CurrentPassword,AliasEmail,TwoFactorSecret,AliasGender,AliasFirstName,AliasLastName,AliasBirthDate,CardholderName,CardNumber,CardExpiryMonth,CardExpiryYear,CardCvv,CardPin,Notes,CreatedAt,UpdatedAt\r\n\
                Example,Work/Sites,https://example.com,alice,secretpw,alias@example.com,JBSWY3DP,female,Alice,Example,1990-01-02,,,,,,,My notes,09/12/2025 17:28:39,09/12/2025 17:28:39\r\n\
                Card,,,bob,,,,,,,,John Doe,4111111111111111,12,2030,123,9999,,,\r\n\
                ,,,,,,,,,,,,,,,,,,,\r\n\
                Extra,,,carl,pw,,,,,,,,,,,,,,,,oops\r\n";
    let import = run(Format::AliasVaultCsv, csv.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 3);
    assert_eq!(import.items[2].entry(), 3);

    let a = view(&import.items[0]);
    assert_eq!(a.fixed["item.name"], t("Example"));
    assert_eq!(a.fixed["login.username"], t("alice"));
    assert_eq!(a.fixed["login.password"], t("secretpw"));
    assert_eq!(a.fixed["login.totp"], t("JBSWY3DP"));
    assert_eq!(a.fixed["item.notes"], t("My notes"));
    assert_eq!(a.fixed["import.created_ms"], V::U(1_757_698_119_000));
    assert_eq!(a.uris, vec!["https://example.com"]);
    assert_eq!(a.tags, vec!["Work/Sites"]);
    assert_eq!(
        a.fields,
        vec![
            (Some("Alias Email".into()), 1, Some(t("alias@example.com"))),
            (Some("Gender".into()), 1, Some(t("female"))),
            (Some("First Name".into()), 1, Some(t("Alice"))),
            (Some("Last Name".into()), 1, Some(t("Example"))),
            (Some("Birth Date".into()), 1, Some(t("1990-01-02"))),
        ]
    );

    let b = view(&import.items[1]);
    assert_eq!(import.items[1].item_type(), ItemType::CARD);
    assert_eq!(b.fixed["item.name"], t("Card"));
    assert_eq!(b.fixed["card.holder"], t("John Doe"));
    assert_eq!(b.fixed["card.number"], t("4111111111111111"));
    assert_eq!(b.fixed["card.exp_month"], t("12"));
    assert_eq!(b.fixed["card.exp_year"], t("2030"));
    assert_eq!(b.fixed["card.code"], t("123"));
    assert_eq!(b.fixed["card.pin"], t("9999"));
    assert_eq!(b.fields, vec![(Some("Username".into()), 1, Some(t("bob")))]);

    assert_eq!(warns(&import), vec![(Some(3), WarningKind::ExtraColumns)]);

    assert_eq!(
        run(Format::AliasVaultCsv, b"a,b,c\n1,2,3\n").unwrap_err(),
        ImportError::UnexpectedShape
    );
    assert_eq!(
        run(Format::AliasVaultCsv, b"").unwrap_err(),
        ImportError::UnexpectedShape
    );
}

#[test]
fn aliasvault_csv_mobile() {
    // The mobile app's export has no card columns but one more alias column than the web
    // export's.
    let csv = "ServiceName,FolderPath,ServiceUrl,Username,CurrentPassword,AliasEmail,TwoFactorSecret,AliasGender,AliasFirstName,AliasLastName,AliasNickName,AliasBirthDate,Notes,CreatedAt,UpdatedAt\r\n\
                credential3,,,username3,,,test,,,,,,without password,09/12/2025 17:28:39,09/12/2025 17:28:39\r\n\
                service2,,https://service2.com,username2,password2,service2@example.tld,,gender2,firstname2,lastname2,nickname2,,,09/12/2025 17:28:39,09/12/2025 17:28:39\r\n";
    let import = run(Format::AliasVaultCsv, csv.as_bytes()).unwrap();
    assert_eq!(import.items.len(), 2);
    assert!(warns(&import).is_empty());

    let a = view(&import.items[0]);
    assert_eq!(import.items[0].item_type(), ItemType::LOGIN);
    assert_eq!(a.fixed["item.name"], t("credential3"));
    assert_eq!(a.fixed["login.username"], t("username3"));
    assert!(!a.fixed.contains_key("login.password"));
    assert_eq!(a.fixed["login.totp"], t("test"));
    assert_eq!(a.fixed["item.notes"], t("without password"));

    let b = view(&import.items[1]);
    assert_eq!(b.fixed["login.username"], t("username2"));
    assert_eq!(b.fixed["login.password"], t("password2"));
    assert_eq!(b.uris, vec!["https://service2.com"]);
    assert_eq!(
        b.fields,
        vec![
            (
                Some("Alias Email".into()),
                1,
                Some(t("service2@example.tld"))
            ),
            (Some("Gender".into()), 1, Some(t("gender2"))),
            (Some("First Name".into()), 1, Some(t("firstname2"))),
            (Some("Last Name".into()), 1, Some(t("lastname2"))),
            (Some("Nickname".into()), 1, Some(t("nickname2"))),
        ]
    );
}

/// A hand-written `.avux` manifest (no real data), covering every `fieldKey`, a folder chain,
/// item tags, custom field definitions, multiple TOTP codes, and the four item types plus one
/// this reader does not know.
const ALIASVAULT_AVUX_MANIFEST: &str = r#"{
  "version": "1.0.0",
  "exportedAt": "2024-06-01T00:00:00Z",
  "folders": [
    {"id": "f1", "name": "Work", "parentFolderId": null},
    {"id": "f2", "name": "Sites", "parentFolderId": "f1"}
  ],
  "tags": [
    {"id": "t1", "name": "Important"},
    {"id": "t2", "name": ""}
  ],
  "itemTags": [
    {"id": "it1", "itemId": "i1", "tagId": "t1"},
    {"id": "it2", "itemId": "i1", "tagId": "t2"}
  ],
  "fieldDefinitions": [
    {"id": "d1", "label": "Security Question", "isHidden": false, "fieldType": "Text"},
    {"id": "d2", "label": "Recovery Code", "isHidden": true, "fieldType": "Text"}
  ],
  "logos": [],
  "items": [
    {
      "id": "i1", "name": "Example", "itemType": "Login", "createdAt": "2024-02-29T12:34:56Z",
      "updatedAt": "2024-02-29T12:34:56Z", "folderId": "f2", "logoId": null, "archivedAt": null,
      "fieldValues": [
        {"id": "fv1", "fieldKey": "login.username", "fieldDefinitionId": null, "value": "alice", "weight": 1},
        {"id": "fv1b", "fieldKey": "login.username", "fieldDefinitionId": null, "value": "alice2", "weight": 0},
        {"id": "fv2", "fieldKey": "login.password", "fieldDefinitionId": null, "value": "secretpw", "weight": 2},
        {"id": "fv3", "fieldKey": "login.url", "fieldDefinitionId": null, "value": "https://b.example", "weight": 4},
        {"id": "fv4", "fieldKey": "login.url", "fieldDefinitionId": null, "value": "https://a.example", "weight": 3},
        {"id": "fv5", "fieldKey": "login.email", "fieldDefinitionId": null, "value": "alice@example.com", "weight": 5},
        {"id": "fv6", "fieldKey": null, "fieldDefinitionId": "d1", "value": "blue", "weight": 6},
        {"id": "fv7", "fieldKey": null, "fieldDefinitionId": "d2", "value": "xyz", "weight": 7},
        {"id": "fv8", "fieldKey": "", "fieldDefinitionId": null, "value": "", "weight": 8}
      ],
      "fieldHistories": [], "attachments": [],
      "totpCodes": [
        {"id": "c1", "name": "", "secretKey": "JBSWY3DP", "algorithm": "SHA1", "digits": 6, "period": 30},
        {"id": "c2", "name": "Backup", "secretKey": "OTHERSECRET", "algorithm": "SHA256", "digits": 8, "period": 60}
      ],
      "passkeys": []
    },
    {
      "id": "i2", "name": "Alias Identity", "itemType": "Alias", "createdAt": "2024-01-01T00:00:00Z",
      "updatedAt": "2024-01-01T00:00:00Z", "folderId": null, "logoId": null, "archivedAt": null,
      "fieldValues": [
        {"id": "fv9", "fieldKey": "alias.first_name", "fieldDefinitionId": null, "value": "Jane", "weight": 1},
        {"id": "fv10", "fieldKey": "alias.last_name", "fieldDefinitionId": null, "value": "Doe", "weight": 2},
        {"id": "fv11", "fieldKey": "alias.gender", "fieldDefinitionId": null, "value": "female", "weight": 3},
        {"id": "fv12", "fieldKey": "alias.birthdate", "fieldDefinitionId": null, "value": "1990-05-06", "weight": 4},
        {"id": "fv13", "fieldKey": "notes.content", "fieldDefinitionId": null, "value": "Alias notes", "weight": 5}
      ],
      "fieldHistories": [], "attachments": [], "totpCodes": [], "passkeys": []
    },
    {
      "id": "i3", "name": "My Card", "itemType": "CreditCard", "createdAt": "2024-03-01T00:00:00Z",
      "updatedAt": "2024-03-01T00:00:00Z", "folderId": null, "logoId": null, "archivedAt": null,
      "fieldValues": [
        {"id": "fv14", "fieldKey": "card.cardholder_name", "fieldDefinitionId": null, "value": "John Doe", "weight": 1},
        {"id": "fv15", "fieldKey": "card.number", "fieldDefinitionId": null, "value": "4111111111111111", "weight": 2},
        {"id": "fv16", "fieldKey": "card.expiry_month", "fieldDefinitionId": null, "value": "12", "weight": 3},
        {"id": "fv17", "fieldKey": "card.expiry_year", "fieldDefinitionId": null, "value": "2030", "weight": 4},
        {"id": "fv18", "fieldKey": "card.cvv", "fieldDefinitionId": null, "value": "123", "weight": 5},
        {"id": "fv19", "fieldKey": "card.pin", "fieldDefinitionId": null, "value": "9999", "weight": 6}
      ],
      "fieldHistories": [], "attachments": [], "totpCodes": [], "passkeys": []
    },
    {
      "id": "i4", "name": "Secret Note", "itemType": "Note", "createdAt": "2024-04-01T00:00:00Z",
      "updatedAt": "2024-04-01T00:00:00Z", "folderId": null, "logoId": "logo1", "archivedAt": null,
      "fieldValues": [
        {"id": "fv20", "fieldKey": "notes.content", "fieldDefinitionId": null, "value": "body text", "weight": 1}
      ],
      "fieldHistories": [],
      "attachments": [{"id": "a1", "filename": "x.txt", "relativePath": "attachments/i4_a1_x.txt"}],
      "totpCodes": [],
      "passkeys": [{"id": "pk1", "credentialId": null, "rpId": "example.com", "userHandle": null, "publicKey": "", "privateKey": "", "prfKey": null, "displayName": "", "additionalData": null}]
    },
    {
      "id": "i5", "name": "Mystery", "itemType": "SomethingNew", "createdAt": "2024-05-01T00:00:00Z",
      "updatedAt": "2024-05-01T00:00:00Z", "folderId": null, "logoId": null, "archivedAt": "2024-05-02T00:00:00Z",
      "fieldValues": [
        {"id": "fv21", "fieldKey": "notes.content", "fieldDefinitionId": null, "value": "unknown type body", "weight": 1}
      ],
      "fieldHistories": [], "attachments": [], "totpCodes": [], "passkeys": []
    }
  ]
}"#;

#[test]
fn aliasvault_avux() {
    let zip = archive(
        &[TestMember {
            name: "manifest.json",
            data: ALIASVAULT_AVUX_MANIFEST.as_bytes(),
            deflate: true,
        }],
        b"",
    );
    let import = run(Format::AliasVaultAvux, &zip).unwrap();
    assert_eq!(import.items.len(), 5);

    let i1 = view(&import.items[0]);
    assert_eq!(import.items[0].item_type(), ItemType::LOGIN);
    assert_eq!(i1.fixed["item.name"], t("Example"));
    // `fv1b` repeats `login.username` after `fv1` in array order with a *lower* `weight` (0
    // vs 1): the last array entry wins regardless of weight (module docs).
    assert_eq!(i1.fixed["login.username"], t("alice2"));
    assert_eq!(i1.fixed["login.password"], t("secretpw"));
    assert_eq!(i1.fixed["login.totp"], t("JBSWY3DP"));
    assert_eq!(i1.fixed["import.created_ms"], V::U(1_709_210_096_000));
    // `fv3` (b.example, weight 4) precedes `fv4` (a.example, weight 3) in array order: URIs
    // are kept in array order, not `weight` order (module docs; the real `AvuxImportService`
    // never sorts by `weight`).
    assert_eq!(i1.uris, vec!["https://b.example", "https://a.example"]);
    assert_eq!(i1.tags, vec!["Important", "Work/Sites"]);
    assert_eq!(
        i1.fields,
        vec![
            (Some("Email".into()), 1, Some(t("alice@example.com"))),
            (Some("Security Question".into()), 1, Some(t("blue"))),
            (Some("Recovery Code".into()), 2, Some(t("xyz"))),
            (Some("Backup".into()), 2, Some(t("OTHERSECRET"))),
        ]
    );

    let i2 = view(&import.items[1]);
    assert_eq!(import.items[1].item_type(), ItemType::IDENTITY);
    assert_eq!(i2.fixed["identity.first_name"], t("Jane"));
    assert_eq!(i2.fixed["identity.last_name"], t("Doe"));
    assert_eq!(i2.fixed["item.notes"], t("Alias notes"));
    assert_eq!(
        i2.fields,
        vec![
            (Some("Gender".into()), 1, Some(t("female"))),
            (Some("Birth Date".into()), 1, Some(t("1990-05-06"))),
        ]
    );

    let i3 = view(&import.items[2]);
    assert_eq!(import.items[2].item_type(), ItemType::CARD);
    assert_eq!(i3.fixed["card.holder"], t("John Doe"));
    assert_eq!(i3.fixed["card.number"], t("4111111111111111"));
    assert_eq!(i3.fixed["card.exp_month"], t("12"));
    assert_eq!(i3.fixed["card.exp_year"], t("2030"));
    assert_eq!(i3.fixed["card.code"], t("123"));
    assert_eq!(i3.fixed["card.pin"], t("9999"));

    let i4 = view(&import.items[3]);
    assert_eq!(import.items[3].item_type(), ItemType::SECURE_NOTE);
    assert_eq!(i4.fixed["item.notes"], t("body text"));

    let i5 = view(&import.items[4]);
    assert_eq!(import.items[4].item_type(), ItemType::SECURE_NOTE);
    assert_eq!(i5.fixed["item.notes"], t("unknown type body"));
    assert_eq!(
        i5.fields,
        vec![(Some("Archived".into()), 3, Some(V::B(true)))]
    );

    assert_eq!(
        warns(&import),
        vec![
            (Some(0), WarningKind::TotpNotConverted),
            (Some(3), WarningKind::AttachmentSkipped),
            (Some(3), WarningKind::PasskeySkipped),
            (Some(3), WarningKind::AttachmentSkipped),
            (Some(4), WarningKind::ConvertedToSecureNote),
        ]
    );

    // The same manifest, read directly without a zip (the fuzz target's own path).
    let direct = import_aliasvault_manifest_data(
        ALIASVAULT_AVUX_MANIFEST.as_bytes(),
        &mut ChaCha20Rng::seed_from_u64(7),
    )
    .unwrap();
    assert_eq!(direct.items.len(), 5);
}

#[test]
fn aliasvault_avux_refusals() {
    let bad_version = ALIASVAULT_AVUX_MANIFEST.replacen("1.0.0", "2.0.0", 1);
    let zip = archive(
        &[TestMember {
            name: "manifest.json",
            data: bad_version.as_bytes(),
            deflate: false,
        }],
        b"",
    );
    assert_eq!(
        run(Format::AliasVaultAvux, &zip).unwrap_err(),
        ImportError::UnexpectedShape
    );

    let no_manifest = archive(
        &[TestMember {
            name: "export.data",
            data: b"{}",
            deflate: false,
        }],
        b"",
    );
    assert_eq!(
        run(Format::AliasVaultAvux, &no_manifest).unwrap_err(),
        ImportError::UnexpectedShape
    );

    assert_eq!(
        run(Format::AliasVaultAvux, b"not a zip").unwrap_err(),
        ImportError::Malformed
    );
}

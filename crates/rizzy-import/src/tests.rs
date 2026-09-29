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
use crate::{Format, Import, ImportError, ImportedItem, WarningKind, import, import_1pux_data};

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

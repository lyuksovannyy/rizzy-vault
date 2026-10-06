//! Recognising the format of a file the user imports (owner decision 2026-10-05: "the app
//! recognises the file format itself"), so the common case needs no format choice.
//!
//! [`detect_format`] looks at the bytes and answers one of: our encrypted export (CRYPTO.md
//! §11.14), which the host opens with the file's own password; one of `rizzy-import`'s
//! [`Format`]s, our plaintext JSON export included; our plaintext CSV export, which has no
//! reader (ADR 0027 §6: "This ADR defines no reader for §4"), so the host refuses it and
//! names the complete forms; or nothing, when it cannot tell. A host then asks the user to
//! name the format (`rv import --format`, the web vault's format list). The answer only picks
//! the reader: the reader still checks the whole file and refuses what is not its format.
//!
//! # Rules, in order
//!
//! | Test | Answer |
//! |---|---|
//! | Over [`MAX_DETECT_LEN`] | nothing |
//! | Starts with a zip local-file header (`PK\x03\x04`) | zip, below |
//! | Starts with the KDBX signature | `KeePass` XML, whose reader refuses a KDBX database with its own message |
//! | After an optional UTF-8 byte-order mark and whitespace, starts with `{` | JSON, below |
//! | … starts with `<` and `<KeePassFile` occurs in the first 64 KiB | `KeePass` XML |
//! | … anything else | CSV, below |
//!
//! **Zip.** Its central directory (never decompressed at this stage,
//! [`rizzy_import::zip::contains`]) lists a member named exactly `manifest.json`: `AliasVault`'s
//! `.avux` export. Otherwise: 1Password 1PUX, the same default a damaged or unsupported archive
//! gets, since its own reader then explains what is wrong with it.
//!
//! **JSON.** The strict, allocation-free reader of our encrypted export
//! ([`parse_export_json`]) first: if it reads the file and `format` is
//! `rizzy-vault-export`, that is the answer. Otherwise `rizzy-import`'s bounded JSON reader
//! reads the root object: `format` = `rizzy-vault-export` is a damaged encrypted export
//! (its reader then says so), `rizzy-vault-plaintext-export` our plaintext JSON, and a root
//! with an `items` array Bitwarden's JSON export (whose reader refuses an encrypted one with
//! its own message). Anything else is nothing. (`AliasVault`'s `.avex` encrypted export also
//! starts with `{`, a JSON header; it is not recognised here — no `Format` exists for it yet,
//! see `rizzy_import::aliasvault` — and its binary payload after the header's delimiter makes
//! every rule above answer nothing, same as any other unknown JSON-like file.)
//!
//! **CSV.** The header row, read with `rizzy-import`'s bounded CSV reader. Exactly the columns
//! of our plaintext CSV export: that export. `ServiceName`, `CurrentPassword` and `AliasEmail`
//! all present (exact spelling): `AliasVault`'s CSV export (web or mobile app). `url`,
//! `username` and `password` with one of Firefox's own columns (`httpRealm`,
//! `formActionOrigin`, `guid`): Firefox. `name`, `url`, `username` and `password`, and no
//! column but those and `note`: Chrome. A header with one of the generic importer's main
//! columns (`name`, `title`, `username`, `password`, `url`, `uri`, `notes`, or Bitwarden's
//! `login_…` spellings), ASCII case ignored: generic CSV. Anything else is nothing.
//!
//! The `AliasVault` check runs before the generic one: its header's `Username` column would
//! otherwise match generic CSV's own `username` spelling first.
//!
//! # Hostile input
//!
//! An import file is untrusted (threat model A16). Every reader used here is the bounded,
//! fuzzed one its format already has; the size cap comes first; nothing panics; and the answer
//! is a kind, never a byte of the file (INV-48). The fuzz target `client_detect_format` runs
//! [`detect_format`] on arbitrary bytes. The cost is at most one extra parse of the file,
//! within the caps the importer applies anyway.

use rizzy_core::export::FORMAT;
use rizzy_import::Format;
use rizzy_import::limits::{MAX_ARCHIVE_LEN, MAX_CSV_LEN, MAX_JSON_LEN};
use rizzy_import::{csv, json, zip};

use super::parse_export_json;
use super::plaintext::csv_columns;

/// The largest file [`detect_format`] looks at: the largest input any importer accepts (a 1PUX
/// archive). Hosts refuse a larger file before reading it.
pub const MAX_DETECT_LEN: usize = MAX_ARCHIVE_LEN;

/// The `format` string of our plaintext JSON export (ADR 0027 §3).
const PLAINTEXT_FORMAT: &str = "rizzy-vault-plaintext-export";

/// A zip local-file header: the first bytes of a 1PUX archive or an `.avux` one.
const ZIP_SIGNATURE: &[u8] = b"PK\x03\x04";

/// The member of an `.avux` archive that tells it apart from a 1PUX archive.
const AVUX_MANIFEST: &str = "manifest.json";

/// The first four bytes of a KDBX database (`KeePass` signature 1, little-endian `0x9AA2D903`).
const KDBX_SIGNATURE: &[u8] = &[0x03, 0xD9, 0xA2, 0x9A];

/// The UTF-8 byte-order mark.
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// How far into an XML file `<KeePassFile` is looked for.
const XML_SNIFF_LEN: usize = 64 * 1024;

/// The generic importer's main columns (`rizzy_import::csv_import`), lowercase; one of them
/// makes a CSV header a password export.
const GENERIC_COLUMNS: &[&str] = &[
    "name",
    "title",
    "username",
    "password",
    "url",
    "uri",
    "notes",
    "login_username",
    "login_password",
    "login_uri",
];

/// What an import file is (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetectedFormat {
    /// Our encrypted export (CRYPTO.md §11.14): open it with the file's own password
    /// ([`VaultSync::import_encrypted`](crate::sync::VaultSync::import_encrypted)).
    RizzyEncrypted,
    /// A format `rizzy-import` reads, our plaintext JSON export included.
    Import(Format),
    /// Our plaintext CSV export, which has no reader (ADR 0027 §6); the JSON and encrypted
    /// exports are the complete forms.
    RizzyPlaintextCsv,
}

/// Recognises an import file's format (module docs). `None` when it cannot tell.
#[must_use]
pub fn detect_format(file: &[u8]) -> Option<DetectedFormat> {
    if file.len() > MAX_DETECT_LEN {
        return None;
    }
    if file.starts_with(ZIP_SIGNATURE) {
        return Some(DetectedFormat::Import(
            if zip::contains(file, AVUX_MANIFEST) {
                Format::AliasVaultAvux
            } else {
                Format::OnePux
            },
        ));
    }
    if file.starts_with(KDBX_SIGNATURE) {
        return Some(DetectedFormat::Import(Format::KeePassXml));
    }
    let body = file.strip_prefix(BOM).unwrap_or(file);
    let start = body
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))?;
    match body.get(start) {
        Some(b'{') => detect_json(file),
        Some(b'<') => detect_xml(body),
        _ => detect_csv(file),
    }
}

/// The JSON rules (module docs).
fn detect_json(file: &[u8]) -> Option<DetectedFormat> {
    if parse_export_json(file).is_ok_and(|fields| fields.format == FORMAT) {
        return Some(DetectedFormat::RizzyEncrypted);
    }
    if file.len() > MAX_JSON_LEN {
        return None;
    }
    let root = json::parse(file, MAX_JSON_LEN).ok()?;
    match root.get("format").and_then(json::Json::as_str) {
        Some(FORMAT) => return Some(DetectedFormat::RizzyEncrypted),
        Some(PLAINTEXT_FORMAT) => {
            return Some(DetectedFormat::Import(Format::RizzyPlaintextJson));
        }
        _ => {}
    }
    root.get("items")
        .and_then(json::Json::as_array)
        .map(|_| DetectedFormat::Import(Format::BitwardenJson))
}

/// The XML rule (module docs).
fn detect_xml(body: &[u8]) -> Option<DetectedFormat> {
    let head = body.get(..body.len().min(XML_SNIFF_LEN))?;
    head.windows(b"<KeePassFile".len())
        .any(|w| w == b"<KeePassFile")
        .then_some(DetectedFormat::Import(Format::KeePassXml))
}

/// The CSV rules (module docs).
fn detect_csv(file: &[u8]) -> Option<DetectedFormat> {
    if file.len() > MAX_CSV_LEN {
        return None;
    }
    let mut reader = csv::Reader::new(file, MAX_CSV_LEN).ok()?;
    let header = reader.next_record().ok()??;
    let names: Vec<&str> = header.iter().map(|h| h.trim()).collect();
    if names == csv_columns() {
        return Some(DetectedFormat::RizzyPlaintextCsv);
    }
    let has = |name: &str| names.contains(&name);
    if has("ServiceName") && has("CurrentPassword") && has("AliasEmail") {
        return Some(DetectedFormat::Import(Format::AliasVaultCsv));
    }
    if has("url")
        && has("username")
        && has("password")
        && (has("httpRealm") || has("formActionOrigin") || has("guid"))
    {
        return Some(DetectedFormat::Import(Format::FirefoxCsv));
    }
    if has("name")
        && has("url")
        && has("username")
        && has("password")
        && names
            .iter()
            .all(|n| matches!(*n, "name" | "url" | "username" | "password" | "note"))
    {
        return Some(DetectedFormat::Import(Format::ChromeCsv));
    }
    names
        .iter()
        .any(|n| {
            GENERIC_COLUMNS
                .iter()
                .any(|column| n.eq_ignore_ascii_case(column))
        })
        .then_some(DetectedFormat::Import(Format::GenericCsv))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(text: &str) -> Option<DetectedFormat> {
        detect_format(text.as_bytes())
    }

    /// A minimal, valid, stored (uncompressed, empty) zip archive with one member named
    /// `name`: enough for [`zip::contains`] to find it, without decompressing anything (its
    /// CRC-32 is left as 0, which `contains` never checks).
    fn zip_with(name: &str) -> Vec<u8> {
        let name = name.as_bytes();
        let name_len = u16::try_from(name.len()).unwrap().to_le_bytes();
        let mut out = Vec::new();
        // Local file header: signature, version/flags/method/modtime/moddate (10 bytes),
        // crc (4), compressed and uncompressed size (4 each, both 0), name length, extra
        // length (0), then the name itself. No data follows: the member is empty.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&name_len);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        let cd_offset = u32::try_from(out.len()).unwrap();
        // Central directory header: signature, version made/needed, flags, method, modtime,
        // moddate (12 bytes), crc (4), sizes (4 each), name length, extra/comment lengths,
        // start disk, internal attributes (12 bytes), external attributes (4), local header
        // offset (4), then the name.
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&name_len);
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name);
        let cd_size = u32::try_from(out.len()).unwrap() - cd_offset;
        // End of central directory: signature, disk numbers (4), entry counts (4), central
        // directory size and offset, comment length (0).
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn recognises_each_format() {
        let encrypted = br#"{"format":"rizzy-vault-export","version":1,"kdf_id":1,"export_salt":"AAAAAAAAAAAAAAAAAAAAAA","export_id":"AAAAAAAAAAAAAAAAAAAAAA","created_at":1,"data":"AA"}"#;
        assert_eq!(
            detect_format(encrypted),
            Some(DetectedFormat::RizzyEncrypted)
        );
        // Damaged, but still ours: the reader says what is wrong.
        assert_eq!(
            detect(r#" {"format":"rizzy-vault-export","extra":true}"#),
            Some(DetectedFormat::RizzyEncrypted)
        );
        assert_eq!(
            detect(
                "\u{feff}{\"format\":\"rizzy-vault-plaintext-export\",\"version\":1,\"items\":[]}"
            ),
            Some(DetectedFormat::Import(Format::RizzyPlaintextJson))
        );
        assert_eq!(
            detect(r#"{"encrypted":false,"folders":[],"items":[]}"#),
            Some(DetectedFormat::Import(Format::BitwardenJson))
        );
        assert_eq!(
            detect(r#"{"encrypted":true,"items":[]}"#),
            Some(DetectedFormat::Import(Format::BitwardenJson))
        );
        assert_eq!(
            detect_format(b"PK\x03\x04rest of a zip"),
            Some(DetectedFormat::Import(Format::OnePux))
        );
        assert_eq!(
            detect_format(&[0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]),
            Some(DetectedFormat::Import(Format::KeePassXml))
        );
        assert_eq!(
            detect("<?xml version=\"1.0\"?>\n<KeePassFile><Root/></KeePassFile>"),
            Some(DetectedFormat::Import(Format::KeePassXml))
        );
        assert_eq!(
            detect("name,url,username,password,note\nBank,https://b.example,me,pw,\n"),
            Some(DetectedFormat::Import(Format::ChromeCsv))
        );
        assert_eq!(
            detect(
                "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\
                 \"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n"
            ),
            Some(DetectedFormat::Import(Format::FirefoxCsv))
        );
        assert_eq!(
            detect(
                "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            ),
            Some(DetectedFormat::Import(Format::GenericCsv))
        );
        assert_eq!(
            detect("Title,User Name,Password\nx,y,z\n"),
            Some(DetectedFormat::Import(Format::GenericCsv))
        );
        let ours = csv_columns()
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            detect(&format!("{ours}\r\n")),
            Some(DetectedFormat::RizzyPlaintextCsv)
        );
        assert_eq!(
            detect(
                "ServiceName,FolderPath,ServiceUrl,Username,CurrentPassword,AliasEmail,\
                 TwoFactorSecret,Notes,CreatedAt,UpdatedAt\n"
            ),
            Some(DetectedFormat::Import(Format::AliasVaultCsv))
        );
        assert_eq!(
            detect_format(&zip_with("manifest.json")),
            Some(DetectedFormat::Import(Format::AliasVaultAvux))
        );
        assert_eq!(
            detect_format(&zip_with("export.data")),
            Some(DetectedFormat::Import(Format::OnePux))
        );
    }

    #[test]
    fn says_nothing_when_unsure() {
        for text in [
            "",
            "   \n\t",
            "{}",
            "{\"format\":\"something-else\"}",
            "[1,2,3]",
            "{not json",
            "<html><body/></html>",
            "just some text\n",
            "a,b,c\n1,2,3\n",
            "\"unclosed",
        ] {
            assert_eq!(detect(text), None, "{text:?}");
        }
        assert_eq!(detect_format(&[0xFF, 0xFE, 0x00]), None);
    }
}

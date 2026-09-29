//! The CSV importers: Chrome's and Firefox's password exports, and generic CSV.
//!
//! Every CSV import reads a header row first; columns are found by name, so their order does
//! not matter. A data row with fewer fields than the header has the missing ones empty; one
//! with more has the extra ones dropped with a warning. Blank rows are skipped. Entry positions
//! count data rows, blank ones included.
//!
//! **Chrome** (and other Chromium browsers): columns `name`, `url`, `username`, `password`
//! (required) and `note` (optional). Each row is a Login: `item.name`, a URI,
//! `login.username`, `login.password`, `item.notes`.
//!
//! **Firefox**: columns `url`, `username`, `password` (required), `httpRealm`,
//! `formActionOrigin`, `guid`, `timeCreated`, `timeLastUsed`, `timePasswordChanged`
//! (optional). Each row is a Login named after the URL's host; `timeCreated` (Unix
//! milliseconds) is `import.created_ms`; a non-empty `httpRealm` or `formActionOrigin` is kept
//! as a text custom field. `guid` and the usage times are Firefox bookkeeping and are not
//! imported.
//!
//! **Generic CSV**: headers are matched without regard to ASCII case or surrounding spaces:
//!
//! | Header | Becomes |
//! |---|---|
//! | `name`, `title` | `item.name` |
//! | `username`, `user name`, `user`, `login`, `login_username` | `login.username` |
//! | `password`, `pass`, `login_password` | `login.password` |
//! | `url`, `uri`, `website`, `web site`, `login_uri` | a URI |
//! | `totp`, `otp`, `otpauth`, `login_totp` | `login.totp` |
//! | `notes`, `note`, `comments`, `comment`, `extra` | `item.notes` |
//! | `folder`, `group`, `grouping` | a tag, the whole value |
//! | `tags`, `tag` | tags, separated by `,` or `;` |
//! | `favorite`, `favourite`, `fav` | `item.favorite` when `true`, `yes` or `1` |
//! | `type` | a Secure Note when `note`, `securenote`, `secure note` or `secure_note`; else a Login |
//! | `fields` | a hidden custom field named `fields` |
//! | `reprompt` | not imported |
//! | any other header | a custom field named after the header, hidden when the header contains `pass`, `secret`, `pin`, `cvv`, `code`, `key` or `token` (ASCII case ignored) |
//!
//! On a Secure Note, the login columns become custom fields (the password and TOTP hidden).
//! A file with none of the name, username, password, URL, TOTP and notes columns is refused
//! as not being a password export ([`ImportError::UnexpectedShape`]). If a header repeats, the
//! first column of that name is used for the fixed keys and the others become custom fields.
//!
//! The `login_…`, `folder`, `favorite` and `type` spellings cover Bitwarden's CSV export too.
//! Its `fields` column holds every custom field of the item, hidden ones included, as
//! `name: value` lines in one cell; the cell cannot say which lines were hidden, so the
//! conservative reading keeps the whole cell as one hidden field (ADR 0018 §7, concealed by
//! default). Its `reprompt` column is a Bitwarden setting, not item content, and is dropped as
//! the Bitwarden JSON importer drops it. `login_uri` is kept as one URI: whether Bitwarden
//! joins several URIs into that cell with `,` is not verified here, and a `,` can be part of a
//! URL, so the cell is not split.

use rizzy_core::item::schema::{ITEM_NAME, ITEM_NOTES, LOGIN_PASSWORD, LOGIN_TOTP, LOGIN_USERNAME};
use rizzy_core::item::types::SupportedType;
use rizzy_core::rng::CryptoRng;
use zeroize::Zeroizing;

use crate::csv::{self, Reader, Record};
use crate::error::{ImportError, WarningKind, Warnings};
use crate::item::{FieldKind, ImportedItem, ItemBuilder};
use crate::limits::MAX_CSV_LEN;
use crate::text::is_truthy;
use crate::{text, time};

/// The data rows of a CSV document after its header.
struct Rows<'a> {
    /// The reader, past the header.
    reader: Reader<'a>,
    /// The header's field count.
    columns: usize,
    /// The next data row's position.
    entry: usize,
}

impl<'a> Rows<'a> {
    /// Reads the header of `input`.
    fn new(input: &'a [u8]) -> Result<(Self, Record), ImportError> {
        let mut reader = Reader::new(input, MAX_CSV_LEN)?;
        let header = reader.next_record()?.ok_or(ImportError::UnexpectedShape)?;
        Ok((
            Self {
                reader,
                columns: header.len(),
                entry: 0,
            },
            header,
        ))
    }

    /// The next non-blank data row and its position, warning about extra fields.
    fn next(&mut self, warnings: &mut Warnings) -> Result<Option<(usize, Record)>, ImportError> {
        while let Some(record) = self.reader.next_record()? {
            let entry = self.entry;
            self.entry += 1;
            if csv::is_blank(&record) {
                continue;
            }
            if record.len() > self.columns {
                warnings.push(Some(entry), WarningKind::ExtraColumns);
            }
            return Ok(Some((entry, record)));
        }
        Ok(None)
    }
}

/// The index of the column named exactly `name` (after trimming).
fn find(header: &[Zeroizing<String>], name: &str) -> Option<usize> {
    header.iter().position(|h| h.trim() == name)
}

/// The field at `index` of `record`, or empty.
fn field(record: &[Zeroizing<String>], index: Option<usize>) -> &str {
    index.and_then(|i| record.get(i)).map_or("", |f| f.as_str())
}

/// Imports a Chrome CSV export.
pub(crate) fn chrome<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    let (mut rows, header) = Rows::new(input)?;
    let name = find(&header, "name").ok_or(ImportError::UnexpectedShape)?;
    let url = find(&header, "url").ok_or(ImportError::UnexpectedShape)?;
    let username = find(&header, "username").ok_or(ImportError::UnexpectedShape)?;
    let password = find(&header, "password").ok_or(ImportError::UnexpectedShape)?;
    let note = find(&header, "note");
    let mut out = Vec::new();
    while let Some((entry, record)) = rows.next(warnings)? {
        let mut b = ItemBuilder::new(entry, SupportedType::Login, warnings);
        b.set(ITEM_NAME, field(&record, Some(name)));
        b.add_uri(field(&record, Some(url)));
        b.set(LOGIN_USERNAME, field(&record, Some(username)));
        b.set(LOGIN_PASSWORD, field(&record, Some(password)));
        b.set(ITEM_NOTES, field(&record, note));
        out.extend(b.finish(rng));
    }
    Ok(out)
}

/// Imports a Firefox CSV export.
pub(crate) fn firefox<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    let (mut rows, header) = Rows::new(input)?;
    let url = find(&header, "url").ok_or(ImportError::UnexpectedShape)?;
    let username = find(&header, "username").ok_or(ImportError::UnexpectedShape)?;
    let password = find(&header, "password").ok_or(ImportError::UnexpectedShape)?;
    let realm = find(&header, "httpRealm");
    let action = find(&header, "formActionOrigin");
    let created = find(&header, "timeCreated");
    let mut out = Vec::new();
    while let Some((entry, record)) = rows.next(warnings)? {
        let mut b = ItemBuilder::new(entry, SupportedType::Login, warnings);
        let uri = field(&record, Some(url));
        b.set(ITEM_NAME, host(uri));
        b.add_uri(uri);
        b.set(LOGIN_USERNAME, field(&record, Some(username)));
        b.set(LOGIN_PASSWORD, field(&record, Some(password)));
        b.add_field("httpRealm", FieldKind::Text, field(&record, realm));
        b.add_field("formActionOrigin", FieldKind::Text, field(&record, action));
        let created = field(&record, created).trim();
        if !created.is_empty() {
            b.set_created_ms(text::parse_u64(created).and_then(time::millis));
        }
        out.extend(b.finish(rng));
    }
    Ok(out)
}

/// The host of a URL, for an item name: after `scheme://` and any `user@`, before the port,
/// path, query or fragment. The URL itself when that is empty. A display name only: M1 stores
/// URIs as entered, and matching (M2) parses them properly.
fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host.starts_with('[') {
        host.split_once(']')
            .map_or(host, |(h, _)| h.get(1..).unwrap_or_default())
    } else {
        host.split(':').next().unwrap_or_default()
    };
    if host.is_empty() { url } else { host }
}

/// What a generic CSV column means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Column {
    /// `item.name`.
    Name,
    /// `login.username`.
    Username,
    /// `login.password`.
    Password,
    /// A URI.
    Url,
    /// `login.totp`.
    Totp,
    /// `item.notes`.
    Notes,
    /// One tag, the whole value.
    Folder,
    /// Tags separated by `,` or `;`.
    Tags,
    /// `item.favorite`.
    Favorite,
    /// The item type.
    Type,
    /// Not imported (Bitwarden's `reprompt` setting).
    Ignored,
    /// A custom field, hidden or not.
    Custom(FieldKind),
}

/// Header spellings of each generic column, lower case.
const ALIASES: [(&[&str], Column); 10] = [
    (&["name", "title"], Column::Name),
    (
        &["username", "user name", "user", "login", "login_username"],
        Column::Username,
    ),
    (&["password", "pass", "login_password"], Column::Password),
    (
        &["url", "uri", "website", "web site", "login_uri"],
        Column::Url,
    ),
    (&["totp", "otp", "otpauth", "login_totp"], Column::Totp),
    (
        &["notes", "note", "comments", "comment", "extra"],
        Column::Notes,
    ),
    (&["folder", "group", "grouping"], Column::Folder),
    (&["tags", "tag"], Column::Tags),
    (&["favorite", "favourite", "fav"], Column::Favorite),
    (&["type"], Column::Type),
];

/// Header words that make an unknown column hidden.
const SECRET_WORDS: [&str; 7] = ["pass", "secret", "pin", "cvv", "code", "key", "token"];

/// Headers of columns that are always hidden custom fields: Bitwarden's `fields` cell, which
/// may hold hidden field values.
const HIDDEN_HEADERS: [&str; 1] = ["fields"];

/// Headers of columns that are not imported: Bitwarden's `reprompt` setting.
const IGNORED_HEADERS: [&str; 1] = ["reprompt"];

/// What a generic header means. A repeated header's later columns are custom fields.
fn classify(header: &[Zeroizing<String>]) -> Vec<Column> {
    let mut seen: Vec<Column> = Vec::new();
    header
        .iter()
        .map(|h| {
            let h = h.trim();
            let known = ALIASES
                .iter()
                .find(|(names, _)| names.iter().any(|n| h.eq_ignore_ascii_case(n)))
                .map(|(_, c)| *c)
                .filter(|c| !seen.contains(c));
            if let Some(c) = known {
                seen.push(c);
                return c;
            }
            if IGNORED_HEADERS.iter().any(|n| h.eq_ignore_ascii_case(n)) {
                return Column::Ignored;
            }
            let secret = HIDDEN_HEADERS.iter().any(|n| h.eq_ignore_ascii_case(n))
                || SECRET_WORDS.iter().any(|w| {
                    h.as_bytes()
                        .windows(w.len())
                        .any(|win| win.eq_ignore_ascii_case(w.as_bytes()))
                });
            Column::Custom(if secret {
                FieldKind::Hidden
            } else {
                FieldKind::Text
            })
        })
        .collect()
}

/// `true` for the generic `type` values of a Secure Note.
fn is_note_type(value: &str) -> bool {
    ["note", "securenote", "secure note", "secure_note"]
        .iter()
        .any(|n| value.trim().eq_ignore_ascii_case(n))
}

/// Imports a generic CSV file.
pub(crate) fn generic<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    let (mut rows, header) = Rows::new(input)?;
    let columns = classify(&header);
    if !columns.iter().any(|c| {
        matches!(
            c,
            Column::Name
                | Column::Username
                | Column::Password
                | Column::Url
                | Column::Totp
                | Column::Notes
        )
    }) {
        return Err(ImportError::UnexpectedShape);
    }
    let type_column = columns.iter().position(|c| *c == Column::Type);
    let mut out = Vec::new();
    while let Some((entry, record)) = rows.next(warnings)? {
        let kind = if is_note_type(field(&record, type_column)) {
            SupportedType::SecureNote
        } else {
            SupportedType::Login
        };
        let mut b = ItemBuilder::new(entry, kind, warnings);
        for ((column, value), label) in columns.iter().zip(record.iter()).zip(header.iter()) {
            let label = label.trim();
            match column {
                Column::Name => b.set_or_field(ITEM_NAME, label, value, false),
                Column::Username => b.set_or_field(LOGIN_USERNAME, label, value, false),
                Column::Password => b.set_or_field(LOGIN_PASSWORD, label, value, true),
                Column::Url => b.add_uri(value),
                Column::Totp => b.set_or_field(LOGIN_TOTP, label, value, true),
                Column::Notes => b.set_or_field(ITEM_NOTES, label, value, false),
                Column::Folder => b.add_tag(value),
                Column::Tags => {
                    for tag in value.split([',', ';']) {
                        b.add_tag(tag);
                    }
                }
                Column::Favorite => b.set_favorite(is_truthy(value)),
                Column::Type | Column::Ignored => {}
                Column::Custom(kind) => b.add_field(label, *kind, value),
            }
        }
        out.extend(b.finish(rng));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host("https://example.com/login?x=1"), "example.com");
        assert_eq!(host("https://user:pw@example.com:8443/"), "example.com");
        assert_eq!(host("http://[::1]:8080/"), "::1");
        assert_eq!(host("example.org"), "example.org");
        assert_eq!(host("chrome://FirefoxAccounts"), "FirefoxAccounts");
        assert_eq!(host("https://"), "https://");
    }

    #[test]
    fn generic_columns() {
        let header: Vec<_> = [
            "Title",
            " USERNAME ",
            "Password",
            "Title",
            "API Key",
            "Color",
            "fields",
            "reprompt",
        ]
        .iter()
        .map(|h| text::copy(h))
        .collect();
        assert_eq!(
            classify(&header),
            vec![
                Column::Name,
                Column::Username,
                Column::Password,
                Column::Custom(FieldKind::Text),
                Column::Custom(FieldKind::Hidden),
                Column::Custom(FieldKind::Text),
                Column::Custom(FieldKind::Hidden),
                Column::Ignored,
            ]
        );
    }
}

//! `KeePass`'s XML export (`KeePass` 2.x "`KeePass` XML (2.x)", which `KeePassXC` writes too).
//!
//! **KDBX is not read.** A KDBX database needs `KeePass`'s own KDF and ciphers (AES-KDF or
//! Argon2, AES or `ChaCha20`, the inner stream cipher). ADR 0002 point 2 puts them in this
//! crate only after ADR 0009's approval procedure, which has not run, so a KDBX file is refused
//! ([`ImportError::KdbxNotSupported`]) by its signature, before any parsing.
//!
//! **Document.** `KeePassFile` / `Root` / `Group` …, with `Meta`. Entries are the `Entry`
//! children of every group: a group's own entries first, then its subgroups, depth first, each
//! in document order. An entry's `History` entries are not entries.
//! The top group's name (the database name) is not a tag; every group below it is, as the
//! path of group names joined with `/` (folders are a UI over `/` in tag names, ADR 0018 §7).
//! Entries in the recycle bin (`Meta/RecycleBinEnabled` `True` and the group whose `UUID` is
//! `Meta/RecycleBinUUID`, with its subgroups) are skipped with a warning.
//!
//! **Entry mapping.** Every entry is a Login.
//!
//! | `KeePass` | rizzy-vault |
//! |---|---|
//! | `String` `Title`, `UserName`, `Password`, `Notes` | `item.name`, `login.username`, `login.password`, `item.notes` |
//! | `String` `URL` | `uri/<id>/value` |
//! | `String` `otp` (`KeePassXC`), else `TimeOtp-Secret-Base32` or `TOTP Seed` | `login.totp` |
//! | `TimeOtp-Secret-Base32` or `TOTP Seed` when `TimeOtp-Length`, `-Period`, `-Algorithm` or `TOTP Settings` is not the default (6, 30, `HMAC-SHA-1`, `30;6`) | a hidden custom field named after its `Key`, warning: a bare secret in `login.totp` means SHA-1, 6 digits, 30 s, so its codes would be wrong |
//! | `TimeOtp-Secret`, `-Hex`, `-Base64`, `HmacOtp-Secret…` | a hidden custom field named after its `Key`, warning (no conversion) |
//! | any other `String` | a custom field named after its `Key`; hidden if its `Value` has `ProtectInMemory="True"` |
//! | a `Value` with `Protected="True"` | not imported, warning: it is encrypted with the KDBX inner stream cipher, which only a KDBX reader has |
//! | `Tags` (separated by `;` or `,`) | tags |
//! | `Times/CreationTime` (RFC 3339) | `import.created_ms` |
//! | `History/Entry` passwords, with `Times/LastModificationTime` | `pwhist/<id>/value`, `/ms`; a password equal to the current one or to an earlier history entry is left out |
//! | `Binary` | not imported (M3), warning |
//!
//! `AutoType`, icons, colours, expiry and custom data are `KeePass` settings, not item content,
//! and are not imported. A `Times` value in KDBX 4's Base64 form is unreadable here and gives
//! the warning for an unreadable time.

use rizzy_core::item::schema::{ITEM_NAME, ITEM_NOTES, LOGIN_PASSWORD, LOGIN_TOTP, LOGIN_USERNAME};
use rizzy_core::item::types::SupportedType;
use rizzy_core::rng::CryptoRng;
use zeroize::Zeroizing;

use crate::error::{ImportError, WarningKind, Warnings};
use crate::item::{FieldKind, ImportedItem, ItemBuilder};
use crate::limits::{MAX_ENTRIES, MAX_HISTORY, MAX_XML_LEN};
use crate::xml::{self, Element};
use crate::{text, time};

/// The first four bytes of every KDBX file (`KeePass` signature 1, little-endian `0x9AA2D903`).
const KDBX_SIGNATURE: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];

/// `true` if `input` starts with the KDBX signature.
pub(crate) fn is_kdbx(input: &[u8]) -> bool {
    input.starts_with(&KDBX_SIGNATURE)
}

/// The text of child `name` of `element`, or empty.
fn child_text(element: &Element, name: &str) -> Zeroizing<String> {
    element
        .child(name)
        .map_or_else(|| text::with_capacity(0), Element::text)
}

/// `true` for `KeePass`'s spelling of a true flag.
fn is_true(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Imports a `KeePass` XML export.
pub(crate) fn import<R: CryptoRng + ?Sized>(
    input: &[u8],
    rng: &mut R,
    warnings: &mut Warnings,
) -> Result<Vec<ImportedItem>, ImportError> {
    if is_kdbx(input) {
        return Err(ImportError::KdbxNotSupported);
    }
    let doc = xml::parse(input, MAX_XML_LEN)?;
    if doc.name() != "KeePassFile" {
        return Err(ImportError::UnexpectedShape);
    }
    let root = doc.child("Root").ok_or(ImportError::UnexpectedShape)?;
    let meta = doc.child("Meta");
    let recycle_bin = meta.and_then(|m| {
        let enabled = m.child("RecycleBinEnabled").map(Element::text);
        if !is_true(enabled.as_deref().map(String::as_str)) {
            return None;
        }
        let uuid = child_text(m, "RecycleBinUUID");
        (!uuid.trim().is_empty()).then_some(uuid)
    });

    let mut out = Vec::new();
    let mut entry = 0usize;
    // Groups to visit: the group, its level (0 for a top group, whose name is not a tag), and
    // whether its parent is in the recycle bin. The XML depth cap bounds how deep this goes;
    // a stack keeps it off the call stack. The stack holds no names: the names of the groups
    // above the one being visited are in `names`, one per level, so memory stays linear in
    // the input however many sibling groups share a long ancestor name.
    let mut stack: Vec<(&Element, usize, bool)> = root
        .elements_named("Group")
        .map(|g| (g, 0, false))
        .collect();
    // Visit in document order: the stack is popped from the end.
    stack.reverse();
    let mut names: Vec<Option<Zeroizing<String>>> = Vec::new();
    while let Some((group, level, in_bin)) = stack.pop() {
        let in_bin = in_bin
            || recycle_bin
                .as_ref()
                .is_some_and(|uuid| child_text(group, "UUID").trim() == uuid.trim());
        // Drop the names of groups that are not above this one (all of them for a top group).
        names.truncate(level.saturating_sub(1));
        if level > 0 {
            let name = child_text(group, "Name");
            // A name that alone passes the path cap is not kept: the path is invalid anyway.
            names.push((name.len() <= MAX_PATH_BYTES).then_some(name));
        }
        // Built at the group's first entry, so a group with none costs no copy.
        let mut path = None;
        for e in group.elements_named("Entry") {
            if entry >= MAX_ENTRIES {
                return Err(ImportError::TooMany);
            }
            if in_bin {
                warnings.push(Some(entry), WarningKind::DeletedEntrySkipped);
            } else {
                let path = path.get_or_insert_with(|| group_path(&names));
                if let Some(item) = map_entry(entry, e, path, rng, warnings) {
                    out.push(item);
                }
            }
            entry += 1;
        }
        let children: Vec<_> = group.elements_named("Group").collect();
        for child in children.into_iter().rev() {
            stack.push((child, level + 1, in_bin));
        }
    }
    Ok(out)
}

/// Longest group path, in bytes before normalisation, that is built for a tag. A tag is at
/// most 64 bytes after NFC (ADR 0018 §7). NFC composes each output character from at most
/// four code points of at most four bytes each, so it shrinks a string by at most a factor of
/// sixteen, and a longer path is an invalid tag whatever it holds. It is never built: building
/// every path of a crafted file would otherwise copy long ancestor names once per descendant
/// group (threat model A16).
const MAX_PATH_BYTES: usize = 16 * rizzy_core::item::tag::MAX_TAG_NAME_LEN;

/// The tag path of a group, from the names of the groups from level 1 down to it.
enum GroupPath {
    /// A top group: no tag.
    None,
    /// The names joined with `/`.
    Tag(Zeroizing<String>),
    /// Longer than [`MAX_PATH_BYTES`]: an invalid tag, not built.
    TooLong,
}

/// Joins `names` with `/`, unless the result would pass [`MAX_PATH_BYTES`].
fn group_path(names: &[Option<Zeroizing<String>>]) -> GroupPath {
    if names.is_empty() {
        return GroupPath::None;
    }
    let mut len = names.len() - 1;
    for name in names {
        match name {
            Some(name) => len += name.len(),
            None => return GroupPath::TooLong,
        }
    }
    if len > MAX_PATH_BYTES {
        return GroupPath::TooLong;
    }
    let mut path = text::with_capacity(len);
    for (i, name) in names.iter().flatten().enumerate() {
        if i > 0 {
            path.push('/');
        }
        path.push_str(name);
    }
    GroupPath::Tag(path)
}

/// Keys of a plain TOTP secret in Base32, which `login.totp` can hold: `KeePass` 2.47+'s
/// `TimeOtp-Secret-Base32` and the `KeeTrayTOTP` / legacy `KeePassXC` `TOTP Seed`.
const TOTP_SECRETS: [&str; 2] = ["TimeOtp-Secret-Base32", "TOTP Seed"];

/// `true` for a key that holds a one-time-password secret: the [`TOTP_SECRETS`], `KeePass`'s
/// other TOTP secret encodings (`TimeOtp-Secret`, `-Hex`, `-Base64`) and its HOTP secrets
/// (`HmacOtp-Secret…`). Such a value is always hidden, whatever its `ProtectInMemory`.
fn is_otp_secret(key: &str) -> bool {
    TOTP_SECRETS.contains(&key)
        || key.starts_with("TimeOtp-Secret")
        || key.starts_with("HmacOtp-Secret")
}

/// For a key that changes how TOTP codes are made, its default value (the one `login.totp`'s
/// bare secret assumes: SHA-1, 6 digits, 30 s): `KeePass`'s `TimeOtp-Length`, `-Period`,
/// `-Algorithm`, and `KeeTrayTOTP`'s `TOTP Settings` (`period;digits`, or a letter such as
/// `S` for Steam in place of the digits).
fn totp_setting_default(key: &str) -> Option<&'static str> {
    match key {
        "TimeOtp-Length" => Some("6"),
        "TimeOtp-Period" => Some("30"),
        "TimeOtp-Algorithm" => Some("HMAC-SHA-1"),
        "TOTP Settings" => Some("30;6"),
        _ => None,
    }
}

/// One entry's strings: key, value element.
fn strings(entry: &Element) -> impl Iterator<Item = (Zeroizing<String>, &Element)> {
    entry
        .elements_named("String")
        .filter_map(|s| Some((child_text(s, "Key"), s.child("Value")?)))
}

/// Maps one entry.
fn map_entry<R: CryptoRng + ?Sized>(
    entry: usize,
    e: &Element,
    path: &GroupPath,
    rng: &mut R,
    warnings: &mut Warnings,
) -> Option<ImportedItem> {
    let mut b = ItemBuilder::new(entry, SupportedType::Login, warnings);
    let mut password = text::with_capacity(0);
    // The first plain TOTP secret, with its key, and whether a setting says its codes are not
    // the default ones.
    let mut totp_secret: Option<(Zeroizing<String>, Zeroizing<String>)> = None;
    let mut totp_custom = false;
    for (key, value) in strings(e) {
        if is_true(value.attribute("Protected")) {
            b.warn(WarningKind::ProtectedValueSkipped);
            continue;
        }
        let text = value.text();
        let hidden = is_true(value.attribute("ProtectInMemory"));
        if let Some(default) = totp_setting_default(&key) {
            let setting = text.trim();
            totp_custom |= !setting.is_empty() && !setting.eq_ignore_ascii_case(default);
            // The setting itself is kept as a text field below, so it is not lost.
        }
        if is_otp_secret(&key) {
            if text.is_empty() {
                continue;
            }
            if totp_secret.is_none() && TOTP_SECRETS.contains(&key.as_str()) {
                totp_secret = Some((key, text));
            } else {
                if !TOTP_SECRETS.contains(&key.as_str()) {
                    b.warn(WarningKind::TotpNotConverted);
                }
                b.add_field(&key, FieldKind::Hidden, &text);
            }
            continue;
        }
        match key.as_str() {
            "Title" => b.set_or_field(ITEM_NAME, &key, &text, hidden),
            "UserName" => b.set_or_field(LOGIN_USERNAME, &key, &text, hidden),
            "Password" => {
                b.set_or_field(LOGIN_PASSWORD, &key, &text, true);
                password = text;
            }
            "Notes" => b.set_or_field(ITEM_NOTES, &key, &text, hidden),
            "URL" => b.add_uri(&text),
            "otp" => b.set_or_field(LOGIN_TOTP, &key, &text, true),
            _ => b.add_field(
                &key,
                if hidden {
                    FieldKind::Hidden
                } else {
                    FieldKind::Text
                },
                &text,
            ),
        }
    }
    if let Some((key, secret)) = totp_secret {
        if totp_custom {
            // `login.totp` holds a bare secret as SHA-1, 6 digits, 30 s (ADR 0018 §7, CRYPTO.md
            // §11.15), so these codes would be wrong. Building an otpauth URI from KeePass's
            // settings would be a format decision this importer does not make; the secret is
            // kept, hidden, and the user is told.
            b.add_field(&key, FieldKind::Hidden, &secret);
            b.warn(WarningKind::TotpNotConverted);
        } else {
            b.set_or_field(LOGIN_TOTP, &key, &secret, true);
        }
    }
    for tag in child_text(e, "Tags").split([';', ',']) {
        b.add_tag(tag);
    }
    match path {
        GroupPath::None => {}
        GroupPath::Tag(path) => b.add_tag(path),
        GroupPath::TooLong => b.warn(WarningKind::InvalidTag),
    }
    if let Some(created) = e.child("Times").and_then(|t| t.child("CreationTime")) {
        b.set_created_ms(time::rfc3339_ms(&created.text()));
    }
    if e.child("Binary").is_some() {
        b.warn(WarningKind::AttachmentSkipped);
    }
    add_history(&mut b, e, &password);
    b.finish(rng)
}

/// Adds the passwords of `e`'s `History` entries, leaving out empty ones, the current
/// `password` and repeats.
fn add_history(b: &mut ItemBuilder<'_>, e: &Element, password: &str) {
    let history: Vec<&Element> = e
        .child("History")
        .map(|h| h.elements_named("Entry").collect())
        .unwrap_or_default();
    let mut seen: Vec<Zeroizing<String>> = Vec::new();
    for old in history {
        let Some((_, value)) = strings(old).find(|(k, _)| k.as_str() == "Password") else {
            continue;
        };
        if is_true(value.attribute("Protected")) {
            b.warn(WarningKind::ProtectedValueSkipped);
            continue;
        }
        let old_password = value.text();
        if old_password.is_empty()
            || old_password.as_str() == password
            || seen.iter().any(|s| s.as_str() == old_password.as_str())
        {
            continue;
        }
        let ms = old
            .child("Times")
            .and_then(|t| t.child("LastModificationTime"))
            .and_then(|t| time::rfc3339_ms(&t.text()));
        b.add_history(&old_password, ms);
        seen.push(old_password);
        // One past the cap, so the builder has warned; the rest would be dropped too.
        if seen.len() > MAX_HISTORY {
            break;
        }
    }
}

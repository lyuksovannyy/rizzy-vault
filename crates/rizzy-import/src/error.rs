//! Errors and warnings. Neither carries any byte of the import file: an import file is full of
//! passwords, and an error or warning may end up in a log, a bug report or a UI toast
//! (CLAUDE.md "Never log secrets", CRYPTO.md §12.2). They carry kinds, and a warning also the
//! entry's position in the file, which says nothing about its content.

use core::fmt;

/// Why a whole import failed. Nothing was imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ImportError {
    /// The input, or a part of it the importer must expand (the `export.data` member of a
    /// 1PUX archive), is larger than the format's cap ([`crate::limits`]).
    TooLarge,
    /// The input breaks its syntax: JSON, CSV, XML, the zip container or the DEFLATE stream.
    Malformed,
    /// The input is not UTF-8, or an XML declaration names another encoding.
    Encoding,
    /// Nesting deeper than [`crate::limits::MAX_DEPTH`].
    TooDeep,
    /// More syntax nodes than [`crate::limits::MAX_NODES`], more attributes on one XML element
    /// than [`crate::limits::MAX_XML_ATTRIBUTES`], more CSV rows or columns than their caps, or more
    /// entries than [`crate::limits::MAX_ENTRIES`].
    TooMany,
    /// The syntax is valid but the document is not the expected export: a required member,
    /// element or CSV column is missing or of the wrong kind.
    UnexpectedShape,
    /// A Bitwarden export protected with a password or the account key. M1 imports plain JSON
    /// only (ADR 0002, owner decision 1).
    EncryptedExport,
    /// A `KeePass` KDBX database. Reading one needs `KeePass`'s own KDF and ciphers, which need an
    /// ADR 0009 approval first (ADR 0002 point 2); M1 reads the `KeePass` XML export.
    KdbxNotSupported,
    /// A zip feature this reader does not support: ZIP64, encryption, a split archive, or a
    /// compression method other than stored or DEFLATE.
    ArchiveUnsupported,
    /// The archive's checksum does not match its content.
    Checksum,
    /// An XML document type declaration. It is refused outright, so no entity is ever
    /// defined or expanded (threat model A16).
    Doctype,
    /// A rizzy-vault plaintext JSON export of a `version` this reader does not know
    /// (ADR 0027 §6: "update required, never guessed or migrated").
    UpdateRequired,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "the import file is too large",
            Self::Malformed => "the import file is malformed",
            Self::Encoding => "the import file is not UTF-8",
            Self::TooDeep => "the import file is nested too deeply",
            Self::TooMany => "the import file has too many entries or elements",
            Self::UnexpectedShape => "the import file is not an export of the chosen format",
            Self::EncryptedExport => "encrypted exports cannot be imported; export unencrypted",
            Self::KdbxNotSupported => {
                "KeePass databases cannot be imported yet; export to KeePass XML"
            }
            Self::ArchiveUnsupported => "the archive uses an unsupported zip feature",
            Self::Checksum => "the archive's checksum does not match",
            Self::Doctype => "XML document type declarations are not accepted",
            Self::UpdateRequired => {
                "the export was written by a newer rizzy-vault; update to import it"
            }
        })
    }
}

impl core::error::Error for ImportError {}

/// Something about one entry that was not imported as it stood. The entry's other fields
/// were imported, unless the kind says the entry was skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WarningKind {
    /// A value longer than one item value may be (65,535 bytes of text, ADR 0018 §10); the
    /// field was not imported. Values are never truncated.
    ValueTooLong,
    /// The item would not fit one create op (1,024 writes, 1 MiB, ADR 0018 §10); the list
    /// elements that did not fit (URIs, custom fields, password history, tags) were not
    /// imported.
    ItemTooLarge,
    /// A list had more elements than this importer takes per item ([`crate::limits`]); the
    /// rest were not imported.
    TooManyElements,
    /// A tag, folder, group or collection name that is not a valid tag (empty, over 64 bytes
    /// after NFC, or holding a control character, ADR 0018 §7); it was not imported.
    InvalidTag,
    /// The entry's type has no M1 item type; it was imported as a Secure Note, with its fields
    /// as custom fields.
    ConvertedToSecureNote,
    /// The entry held nothing to import; skipped.
    EmptyEntry,
    /// The entry is not in the expected shape; skipped.
    MalformedEntry,
    /// An attachment, document file, or `AliasVault` logo image; not imported (attachments are
    /// M3).
    AttachmentSkipped,
    /// A passkey; not imported (passkeys are M7).
    PasskeySkipped,
    /// A `KeePass` value protected with the KDBX inner stream cipher; not imported.
    ProtectedValueSkipped,
    /// A creation time that could not be read; the item's creation time comes from its first
    /// write instead.
    InvalidTimestamp,
    /// A field of a kind with no M1 equivalent (a Bitwarden linked field, a 1Password
    /// reference, a field value of an unknown kind, password history of an item that is not a
    /// login, a field of a rizzy-vault plaintext export whose key this client never writes or
    /// that belongs to another item type); not imported.
    FieldSkipped,
    /// A one-time-password secret that could not go to `login.totp` as it stands: a `KeePass`
    /// TOTP secret whose settings (digits, period, algorithm) are not the defaults a bare
    /// secret implies, a secret in another encoding, or an HOTP secret. It was imported as a
    /// hidden custom field; its codes must be set up again by hand.
    TotpNotConverted,
    /// A deleted entry (Bitwarden `deletedDate`, the `KeePass` recycle bin); skipped.
    DeletedEntrySkipped,
    /// A CSV row with more fields than the header; the extra fields were not imported.
    ExtraColumns,
    /// More warnings than [`crate::limits::MAX_WARNINGS`]; the rest were not recorded.
    WarningsTruncated,
    /// An item of a type this client does not import: an unknown or reserved type, or the
    /// vault-settings type, which is never imported as an item (ADR 0027 §6); skipped.
    UnsupportedItemType,
    /// An item of a rizzy-vault plaintext export with more fields than an item may hold, or
    /// more value bytes than one item's snapshot may hold (ADR 0018 §10; ADR 0027 §6 "an
    /// oversize value or list"); skipped. Nothing of it was imported.
    OversizeEntry,
    /// A field of a rizzy-vault plaintext export listed `conflicts`; only its displayed value
    /// was imported (ADR 0027 §6). At most once per entry.
    ConflictsCollapsed,
    /// Password history of a rizzy-vault plaintext export that was not imported: entries past
    /// the fiftieth, history of a field other than `login.password`, or an entry whose value
    /// is not a text (ADR 0027 §6). At most once per entry.
    HistoryDropped,
    /// A member the rizzy-vault plaintext format does not define was ignored (ADR 0027 §6
    /// "Unknown members"). At most once per entry, and once for the file as a whole.
    UnknownMembersIgnored,
}

impl fmt::Display for WarningKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ValueTooLong => "a value was too long and was not imported",
            Self::ItemTooLarge => "the item was too large; some of its fields were not imported",
            Self::TooManyElements => "too many URIs, fields, tags or history entries",
            Self::InvalidTag => "a tag or folder name is not valid and was not imported",
            Self::ConvertedToSecureNote => "imported as a secure note",
            Self::EmptyEntry => "an empty entry was skipped",
            Self::MalformedEntry => "a malformed entry was skipped",
            Self::AttachmentSkipped => "an attachment was not imported",
            Self::PasskeySkipped => "a passkey was not imported",
            Self::ProtectedValueSkipped => "a protected KeePass value was not imported",
            Self::InvalidTimestamp => "a creation time could not be read",
            Self::FieldSkipped => "a field of an unsupported kind was not imported",
            Self::TotpNotConverted => {
                "a one-time-password secret was kept as a hidden field; set up its codes again"
            }
            Self::DeletedEntrySkipped => "a deleted entry was skipped",
            Self::ExtraColumns => "a row had more columns than the header",
            Self::WarningsTruncated => "more warnings were not recorded",
            Self::UnsupportedItemType => "an item of an unsupported type was skipped",
            Self::OversizeEntry => "an item too large to import was skipped",
            Self::ConflictsCollapsed => "conflicting values were reduced to the displayed one",
            Self::HistoryDropped => "some password history was not imported",
            Self::UnknownMembersIgnored => "unknown members of the file were ignored",
        })
    }
}

/// One warning: its kind, and the entry it is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Warning {
    /// The entry's position among the file's entries, from 0, in file order: Bitwarden
    /// `items`, 1PUX items across accounts and vaults, `KeePass` entries group by group (see
    /// [`crate::keepass`]), CSV data rows, `items` of a rizzy-vault plaintext export. `None` for
    /// a warning about the file as a whole.
    pub entry: Option<usize>,
    /// What happened.
    pub kind: WarningKind,
}

/// The warnings of one import, capped at [`crate::limits::MAX_WARNINGS`].
#[derive(Debug, Default)]
pub(crate) struct Warnings {
    /// The warnings recorded so far.
    list: Vec<Warning>,
    /// Whether the cap was hit and [`WarningKind::WarningsTruncated`] recorded.
    truncated: bool,
}

impl Warnings {
    /// Records a warning, unless the cap is reached.
    pub(crate) fn push(&mut self, entry: Option<usize>, kind: WarningKind) {
        if self.list.len() < crate::limits::MAX_WARNINGS {
            self.list.push(Warning { entry, kind });
        } else if !self.truncated {
            self.truncated = true;
            self.list.push(Warning {
                entry: None,
                kind: WarningKind::WarningsTruncated,
            });
        }
    }

    /// The recorded warnings.
    pub(crate) fn into_vec(self) -> Vec<Warning> {
        self.list
    }
}

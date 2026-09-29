//! The encrypted export file: writer and reader (CRYPTO.md §11.14; ROADMAP §4.2 "Export:
//! encrypted JSON (own format)"; threat model A16).
//!
//! `rizzy-core`'s `export` module holds the cryptography: the file key from the export
//! password (Argon2id, then HKDF with `export_id`), the `EXPORT_FILE` envelope, the header
//! fields and their length checks. This module writes and reads the JSON document around it:
//!
//! ```text
//! {"format":"rizzy-vault-export","version":1,"kdf_id":1,"export_salt":"…","export_id":"…",
//!  "created_at":…,"data":"<b64url Envelope(file_key, EXPORT_FILE, …)>"}
//! ```
//!
//! # The reader is strict and bounded
//!
//! An export file is untrusted input (threat model A16). Before any parsing, the whole file is
//! refused above [`MAX_EXPORT_FILE_LEN`]; then [`parse_export_json`] reads exactly the shape
//! above, with no allocation of its own:
//!
//! - one JSON object; whitespace (space, tab, CR, LF) around tokens;
//! - exactly the seven members above, each once, in any order; any other member is refused
//!   (conservative reading: §11.14 lists the fields and nothing leaves room for others);
//! - `format`, `export_salt`, `export_id` and `data` are strings of printable ASCII without
//!   escapes: every value a writer produces is ASCII (base64url, the fixed format string), so
//!   an escape could only encode something the reader would refuse later;
//! - `version`, `kdf_id` and `created_at` are non-negative JSON integers without sign,
//!   fraction, exponent or leading zero, that fit a `u64`;
//! - nothing after the object but whitespace.
//!
//! Then `rizzy-core` checks the format, the version, the `kdf_id` allow-list and each field's
//! length before decoding it (§11.14 "Field sizes"), and only then runs Argon2id. The fuzz
//! target `client_export` runs the parser and the header checks on arbitrary bytes.
//!
//! # The payload is opaque
//!
//! §11.14 fixes the file, the key and the envelope, but no Accepted ADR defines the plaintext
//! inside `data` (ADR 0001 point 5 makes an export file's contents a persistent format). This
//! module therefore takes and returns the payload as bytes and freezes no item encoding: the
//! payload layout is a reported gap.

use rizzy_core::export::{ExportFileKey, ExportHeader, FORMAT, MAX_DATA_FIELD_LEN, VERSION};
use rizzy_core::kdf::KdfId;
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret::SecretBytes;

use crate::error::ClientError;

/// Room for everything around `data`: the six other members, their names, punctuation and
/// generous whitespace. The members themselves are at most a few hundred bytes.
const ENVELOPE_SLACK: usize = 4096;

/// The largest export file the reader accepts, checked before any parsing: the longest `data`
/// value (§11.14 "Field sizes") plus 4096 bytes of slack. Every file [`write_export`] produces
/// fits.
pub const MAX_EXPORT_FILE_LEN: usize = MAX_DATA_FIELD_LEN + ENVELOPE_SLACK;

/// The seven members of an export file, borrowed from the input. Nothing is decoded yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportFields<'a> {
    /// `format`.
    pub format: &'a str,
    /// `version`.
    pub version: u64,
    /// `kdf_id`.
    pub kdf_id: u64,
    /// `export_salt`, base64url.
    pub export_salt: &'a str,
    /// `export_id`, base64url.
    pub export_id: &'a str,
    /// `created_at`, milliseconds since the Unix epoch.
    pub created_at: u64,
    /// `data`, base64url of the envelope.
    pub data: &'a str,
}

/// Writes an encrypted export of `payload` under `export_password` (§11.14): new `export_id`
/// and `export_salt` from the injected CSPRNG, one Argon2id run at the default `kdf_id`,
/// `created_at` from the host's clock. The payload is not padded, so the file reveals its
/// length (see `rizzy_core::export`).
///
/// # Errors
/// [`ClientError::InvalidInput`] for an empty export password, one with an unassigned code
/// point, or a payload over 16 MiB; [`ClientError::Internal`].
pub fn write_export<R: CryptoRng + ?Sized>(
    rng: &mut R,
    export_password: &str,
    payload: &[u8],
    now_ms: u64,
) -> Result<Vec<u8>, ClientError> {
    let key = ExportFileKey::derive_new(rng, export_password, now_ms, KdfId::DEFAULT)
        .map_err(|_| ClientError::InvalidInput)?;
    let data = key
        .seal_data_field(rng, payload)
        .map_err(|_| ClientError::InvalidInput)?;
    let header = key.header();
    let text = format!(
        "{{\"format\":\"{FORMAT}\",\"version\":{VERSION},\"kdf_id\":{},\"export_salt\":\"{}\",\
         \"export_id\":\"{}\",\"created_at\":{},\"data\":\"{data}\"}}",
        header.kdf_id.get(),
        header.export_salt_b64(),
        header.export_id_b64(),
        header.created_at_ms,
    );
    Ok(text.into_bytes())
}

/// Reads an encrypted export: the size cap, the strict JSON shape, the header checks, then
/// the key (one Argon2id run) and the envelope. Returns the payload in a zeroizing buffer.
///
/// # Errors
/// [`ClientError::InvalidExportFile`] for anything but a well-formed file of a supported
/// format, version and `kdf_id`; [`ClientError::ExportDecryptionFailed`] for a wrong password
/// or a changed file (one error, CRYPTO.md §9.5); [`ClientError::Internal`].
pub fn read_export(file: &[u8], export_password: &str) -> Result<SecretBytes, ClientError> {
    let fields = parse_export_json(file)?;
    let header = header_of(&fields)?;
    let key = ExportFileKey::derive(export_password, &header).map_err(|_| ClientError::Internal)?;
    key.open_data_field(fields.data)
        .map_err(|_| ClientError::ExportDecryptionFailed)
}

/// The size cap, the strict JSON shape and the header checks of [`read_export`], without the
/// password: everything that runs before Argon2id.
///
/// # Errors
/// [`ClientError::InvalidExportFile`].
pub fn read_export_header(file: &[u8]) -> Result<ExportHeader, ClientError> {
    header_of(&parse_export_json(file)?)
}

/// The header checks of `rizzy-core` on parsed fields.
fn header_of(fields: &ExportFields<'_>) -> Result<ExportHeader, ClientError> {
    ExportHeader::from_json_fields(
        fields.format,
        fields.version,
        fields.kdf_id,
        fields.export_salt,
        fields.export_id,
        fields.created_at,
    )
    .map_err(|_| ClientError::InvalidExportFile)
}

/// Parses the JSON document of an export file (see the module docs). Refuses a file over
/// [`MAX_EXPORT_FILE_LEN`] before reading a byte of it. Never panics, never allocates.
///
/// # Errors
/// [`ClientError::InvalidExportFile`].
pub fn parse_export_json(file: &[u8]) -> Result<ExportFields<'_>, ClientError> {
    if file.len() > MAX_EXPORT_FILE_LEN {
        return Err(ClientError::InvalidExportFile);
    }
    let mut p = Parser { input: file, at: 0 };
    let mut format = None;
    let mut version = None;
    let mut kdf_id = None;
    let mut export_salt = None;
    let mut export_id = None;
    let mut created_at = None;
    let mut data = None;
    p.expect(b'{')?;
    loop {
        let name = p.string()?;
        p.expect(b':')?;
        let fresh = match name {
            "format" => set(&mut format, p.string()?),
            "version" => set(&mut version, p.integer()?),
            "kdf_id" => set(&mut kdf_id, p.integer()?),
            "export_salt" => set(&mut export_salt, p.string()?),
            "export_id" => set(&mut export_id, p.string()?),
            "created_at" => set(&mut created_at, p.integer()?),
            "data" => set(&mut data, p.string()?),
            _ => false,
        };
        if !fresh {
            return Err(ClientError::InvalidExportFile);
        }
        match p.next_token()? {
            b',' => {}
            b'}' => break,
            _ => return Err(ClientError::InvalidExportFile),
        }
    }
    p.skip_ws();
    if p.at != file.len() {
        return Err(ClientError::InvalidExportFile);
    }
    Ok(ExportFields {
        format: format.ok_or(ClientError::InvalidExportFile)?,
        version: version.ok_or(ClientError::InvalidExportFile)?,
        kdf_id: kdf_id.ok_or(ClientError::InvalidExportFile)?,
        export_salt: export_salt.ok_or(ClientError::InvalidExportFile)?,
        export_id: export_id.ok_or(ClientError::InvalidExportFile)?,
        created_at: created_at.ok_or(ClientError::InvalidExportFile)?,
        data: data.ok_or(ClientError::InvalidExportFile)?,
    })
}

/// Sets `slot` to `value` if it is empty; `false` for a repeated member.
fn set<T>(slot: &mut Option<T>, value: T) -> bool {
    if slot.is_some() {
        return false;
    }
    *slot = Some(value);
    true
}

/// A cursor over the input. Every read is bounds-checked through `get`.
struct Parser<'a> {
    /// The whole input.
    input: &'a [u8],
    /// The next byte's offset.
    at: usize,
}

impl<'a> Parser<'a> {
    /// Skips JSON whitespace.
    fn skip_ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\r' | b'\n') = self.input.get(self.at) {
            self.at += 1;
        }
    }

    /// The next non-whitespace byte, consumed.
    fn next_token(&mut self) -> Result<u8, ClientError> {
        self.skip_ws();
        let b = *self
            .input
            .get(self.at)
            .ok_or(ClientError::InvalidExportFile)?;
        self.at += 1;
        Ok(b)
    }

    /// Consumes `byte` after optional whitespace.
    fn expect(&mut self, byte: u8) -> Result<(), ClientError> {
        if self.next_token()? == byte {
            Ok(())
        } else {
            Err(ClientError::InvalidExportFile)
        }
    }

    /// A string of printable ASCII without escapes.
    fn string(&mut self) -> Result<&'a str, ClientError> {
        self.expect(b'"')?;
        let start = self.at;
        loop {
            match self.input.get(self.at) {
                Some(b'"') => break,
                Some(b) if (0x20..0x7F).contains(b) && *b != b'\\' => self.at += 1,
                _ => return Err(ClientError::InvalidExportFile),
            }
        }
        let text = self
            .input
            .get(start..self.at)
            .ok_or(ClientError::InvalidExportFile)?;
        self.at += 1;
        core::str::from_utf8(text).map_err(|_| ClientError::InvalidExportFile)
    }

    /// A non-negative integer without sign, fraction, exponent or leading zero, fitting `u64`.
    fn integer(&mut self) -> Result<u64, ClientError> {
        self.skip_ws();
        let start = self.at;
        let mut value: u64 = 0;
        while let Some(b) = self.input.get(self.at).filter(|b| b.is_ascii_digit()) {
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(b - b'0')))
                .ok_or(ClientError::InvalidExportFile)?;
            self.at += 1;
        }
        let digits = self.at - start;
        let leading_zero = digits > 1 && self.input.get(start) == Some(&b'0');
        if digits == 0 || leading_zero {
            return Err(ClientError::InvalidExportFile);
        }
        if matches!(self.input.get(self.at), Some(b'.' | b'e' | b'E')) {
            return Err(ClientError::InvalidExportFile);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use chacha20::ChaCha20Rng;
    use rand_core::SeedableRng as _;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let file =
            write_export(&mut rng, "export pw", b"payload bytes", 1_790_000_000_000).unwrap();
        let header = read_export_header(&file).unwrap();
        assert_eq!(header.created_at_ms, 1_790_000_000_000);
        let payload = read_export(&file, "export pw").unwrap();
        assert_eq!(payload.expose_secret(), b"payload bytes");
        assert_eq!(
            read_export(&file, "wrong").unwrap_err(),
            ClientError::ExportDecryptionFailed
        );
        // A changed header field fails to open (the context binds it).
        let text = String::from_utf8(file.clone()).unwrap();
        let changed = text.replace(
            "\"created_at\":1790000000000",
            "\"created_at\":1790000000001",
        );
        assert_ne!(changed, text);
        assert_eq!(
            read_export(changed.as_bytes(), "export pw").unwrap_err(),
            ClientError::ExportDecryptionFailed
        );
        // Whitespace and member order do not matter.
        let f = parse_export_json(&file).unwrap();
        let reordered = format!(
            " {{ \"data\" : \"{}\" ,\n\"created_at\":{},\"export_id\":\"{}\",\"export_salt\":\"{}\",\"kdf_id\":{},\"version\":{},\"format\":\"{}\" }} \n",
            f.data, f.created_at, f.export_id, f.export_salt, f.kdf_id, f.version, f.format
        );
        assert_eq!(parse_export_json(reordered.as_bytes()).unwrap(), f);
    }

    #[test]
    fn refuses_malformed() {
        let ok = r#"{"format":"rizzy-vault-export","version":1,"kdf_id":1,"export_salt":"AAAAAAAAAAAAAAAAAAAAAA","export_id":"AAAAAAAAAAAAAAAAAAAAAA","created_at":5,"data":"AA"}"#;
        assert!(parse_export_json(ok.as_bytes()).is_ok());
        assert!(read_export_header(ok.as_bytes()).is_ok());
        for bad in [
            "",
            "{}",
            "[]",
            &ok.replace("\"version\":1", "\"version\":01"),
            &ok.replace("\"version\":1", "\"version\":-1"),
            &ok.replace("\"version\":1", "\"version\":1.0"),
            &ok.replace("\"version\":1", "\"version\":1e0"),
            &ok.replace("\"version\":1", "\"version\":\"1\""),
            &ok.replace("\"version\":1", "\"version\":18446744073709551616"),
            &ok.replace("\"data\":\"AA\"", "\"data\":\"A\\u0041\""),
            &ok.replace("\"data\":\"AA\"", "\"data\":\"AA\",\"data\":\"AA\""),
            &ok.replace("\"data\":\"AA\"", "\"data\":\"AA\",\"extra\":1"),
            &ok.replace(",\"data\":\"AA\"", ""),
            &format!("{ok}x"),
            &format!("{ok},"),
            &ok.replace('}', ""),
        ] {
            assert_eq!(
                parse_export_json(bad.as_bytes()).unwrap_err(),
                ClientError::InvalidExportFile,
                "{bad}"
            );
        }
        // Header checks after the parse.
        for bad in [
            ok.replace("\"kdf_id\":1", "\"kdf_id\":2"),
            ok.replace("\"version\":1", "\"version\":2"),
            ok.replace("rizzy-vault-export", "other"),
            ok.replace(
                "\"export_id\":\"AAAAAAAAAAAAAAAAAAAAAA\"",
                "\"export_id\":\"AAAA\"",
            ),
        ] {
            assert_eq!(
                read_export_header(bad.as_bytes()).unwrap_err(),
                ClientError::InvalidExportFile
            );
        }
        // The whole-file cap runs first.
        let huge = vec![b' '; MAX_EXPORT_FILE_LEN + 1];
        assert_eq!(
            parse_export_json(&huge).unwrap_err(),
            ClientError::InvalidExportFile
        );
    }
}

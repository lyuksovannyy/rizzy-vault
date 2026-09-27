//! Fuzzes the export-file field decoders and the server-secrets backup header (CRYPTO.md
//! §11.14, §5.11, §15 item 7): they never panic, the export and backup headers accept exactly
//! the same fields, an accepted header encodes back to the same text, and no `data` value opens
//! except the one the fixture sealed.
//!
//! The input is `u64 version ‖ u64 kdf_id ‖ u64 created_at ‖ rest`, big-endian; an input
//! shorter than 24 bytes is all `rest`, with the three numbers 0. When `rest` is UTF-8, it
//! splits at its first three `\n` into `format`, the salt, the id and `data` (missing fields are
//! empty). For each input:
//!
//! - **Headers.** [`ExportHeader::from_json_fields`] with the valid format and version, and
//!   [`BackupHeader::from_fields`], on the same `kdf_id`, salt, id and `created_at`: both give
//!   the same header or the same error. An accepted header had a 22-character salt and id,
//!   encodes them back to exactly the input text (the decoder is strict), and keeps `kdf_id`
//!   and `created_at`. With the fuzzed `format` and `version`, the export header gives the same
//!   result when they are the valid ones, and `UnsupportedFormat` otherwise.
//! - **`data`.** [`ExportFileKey::open_data_field`] under the fixture's key opens the text only
//!   if it is exactly the fixture's sealed `data` value. The `MAX_DATA_FIELD_LEN` bound (22 MB
//!   of text) is out of reach here, since libFuzzer's default input limit is 4096 bytes;
//!   `rizzy-core`'s unit tests check it.
//! - **Tampering.** `rest`, UTF-8 or not, is XORed into the sealed envelope after its 18-byte
//!   header (bytes past the end are appended), so the key id still matches and the commitment
//!   check runs on fuzzed bytes, and the AEAD too when the nonce and commitment are left
//!   unchanged. The re-encoded result opens only if nothing changed.
//!
//! Argon2id never runs per input. The fixture (one export key at `kdf_id` 1 and one envelope it
//! sealed) is built once per process in a [`OnceLock`]; that is the process's one Argon2id run.
//! Per input the work is the header decoders, base64url, and at most two envelope opens (HKDF,
//! and XChaCha20-Poly1305 over at most a few KiB). The sealing RNG returns a constant: it is
//! deterministic, so a crash reproduces from its input alone, and it is not a CSPRNG, which
//! nothing here needs.
#![no_main]

use std::convert::Infallible;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};
use rizzy_core::encoding::b64url_encode;
use rizzy_core::envelope::HEADER_LEN;
use rizzy_core::export::{ExportError, ExportFileKey, ExportHeader, FORMAT, VERSION};
use rizzy_core::ids::ExportId;
use rizzy_core::kdf::KdfId;
use rizzy_core::server_seal::BackupHeader;

/// The fixture's export payload.
const PLAINTEXT: &[u8] = b"{\"items\":[]}";

/// The randomness the fixture's one seal draws (its nonce). A constant, not a CSPRNG: like
/// `rizzy-core`'s test `FixedRng`, it is marked `CryptoRng` only so the API accepts it.
struct ConstantRng;

impl TryRng for ConstantRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0x5a5a_5a5a)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0x5a5a_5a5a_5a5a_5a5a)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(0x5a);
        Ok(())
    }
}

impl TryCryptoRng for ConstantRng {}

/// What every input runs against, built once per process.
struct Fixture {
    /// The export key for a fixed header, at `kdf_id` 1.
    key: ExportFileKey,
    /// An `EXPORT_FILE` envelope of [`PLAINTEXT`] sealed under `key`.
    envelope: Vec<u8>,
    /// `envelope` as the JSON `data` value.
    sealed: String,
}

/// The fixture, built on first use: the one Argon2id run of the process.
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let header = ExportHeader {
            export_id: ExportId::from_bytes([0x44; 16]),
            created_at_ms: 1_700_000_000_000,
            kdf_id: KdfId::DEFAULT,
            export_salt: [0x33; 16],
        };
        // The process's one Argon2id run.
        let key = ExportFileKey::derive("fuzz export password", &header).expect("key");
        let envelope = key.seal(&mut ConstantRng, PLAINTEXT).expect("seal");
        let sealed = key
            .seal_data_field(&mut ConstantRng, PLAINTEXT)
            .expect("seal");
        // The constant RNG draws the same nonce, so both seals give the same envelope.
        assert_eq!(sealed, b64url_encode(&envelope));
        Fixture {
            key,
            envelope,
            sealed,
        }
    })
}

/// The fields a header decoder returned, comparable across the export and backup headers.
type Fields = ([u8; 16], u64, KdfId, [u8; 16]);

/// The header properties: export and backup headers agree, an accepted header round-trips, and
/// a wrong `format` or `version` is `UnsupportedFormat`. `fields` is `[format, salt, id, data]`.
fn headers(fields: [&str; 4], version: u64, kdf_id: u64, created_at: u64) {
    let [format, salt, id, _] = fields;
    let export = ExportHeader::from_json_fields(FORMAT, VERSION, kdf_id, salt, id, created_at);
    let backup = BackupHeader::from_fields(kdf_id, salt, id, created_at);
    let export_fields: Result<Fields, ExportError> = export.map(|h| {
        (
            *h.export_id.as_bytes(),
            h.created_at_ms,
            h.kdf_id,
            h.export_salt,
        )
    });
    let backup_fields: Result<Fields, ExportError> = backup.map(|h| {
        (
            *h.backup_id.as_bytes(),
            h.created_at_ms,
            h.kdf_id,
            h.backup_salt,
        )
    });
    assert_eq!(export_fields, backup_fields);
    if let Ok(h) = export {
        assert_eq!((salt.len(), id.len()), (22, 22));
        assert_eq!(h.export_salt_b64(), salt);
        assert_eq!(h.export_id_b64(), id);
        assert_eq!(u64::from(h.kdf_id.get()), kdf_id);
        assert_eq!(h.created_at_ms, created_at);
    }
    let fuzzed = ExportHeader::from_json_fields(format, version, kdf_id, salt, id, created_at);
    if format == FORMAT && version == VERSION {
        assert_eq!(fuzzed, export);
    } else {
        assert_eq!(fuzzed, Err(ExportError::UnsupportedFormat));
    }
}

/// Opens `data` as the JSON `data` value: only the fixture's own sealed value opens.
fn data_field(f: &Fixture, data: &str) {
    let opened = f.key.open_data_field(data);
    assert_eq!(opened.is_ok(), data == f.sealed);
    if let Ok(plaintext) = opened {
        assert_eq!(plaintext.expose_secret(), PLAINTEXT);
    }
}

/// XORs `mask` into the fixture's envelope after its header (appending what runs past the end)
/// and opens the re-encoded result: it opens only if nothing changed.
fn tampered(f: &Fixture, mask: &[u8]) {
    let mut envelope = f.envelope.clone();
    for (i, &m) in mask.iter().enumerate() {
        match envelope.get_mut(HEADER_LEN + i) {
            Some(b) => *b ^= m,
            None => envelope.push(m),
        }
    }
    let unchanged = envelope == f.envelope;
    let opened = f.key.open_data_field(&b64url_encode(&envelope));
    assert_eq!(opened.is_ok(), unchanged);
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let (numbers, rest) = data
        .split_first_chunk::<24>()
        .map_or(([0u8; 24], data), |(n, r)| (*n, r));
    let (words, _) = numbers.as_chunks::<8>();
    let [version, kdf_id, created_at] =
        [0, 1, 2].map(|i| words.get(i).map_or(0, |w| u64::from_be_bytes(*w)));
    if let Ok(text) = core::str::from_utf8(rest) {
        let mut parts = text.splitn(4, '\n');
        let fields = [(); 4].map(|()| parts.next().unwrap_or(""));
        headers(fields, version, kdf_id, created_at);
        data_field(f, fields[3]);
    }
    tampered(f, rest);
});

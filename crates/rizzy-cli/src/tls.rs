//! TLS for `https://` origins: the client configuration and the trust store of [ADR 0030].
//!
//! # Protocol (Decision 2)
//!
//! TLS 1.3 only, with rustls' `ring` provider **passed explicitly** to
//! `ClientConfig::builder_with_provider`, never installed process-wide. The suites and groups
//! are the provider's TLS 1.3 ones in its order: AES-256-GCM-SHA384, AES-128-GCM-SHA256,
//! ChaCha20-Poly1305-SHA256; X25519, P-256, P-384. A `--workspace` build turns
//! `rustls/tls12` on through sqlx (feature unification), so it is this run-time configuration,
//! not a feature, that keeps TLS 1.2 out. ALPN offers `http/1.1` only. SNI is on (rustls omits
//! it for an IP literal). Early data is off, no client certificate is sent, session tickets
//! stay in the in-memory cache of the process, and the key log is rustls' `NoKeyLog`:
//! `SSLKEYLOGFILE` is not honoured. Nothing TLS-related is written to disk.
//!
//! # Trust (Decisions 3–5)
//!
//! By default the trust anchors are Mozilla's root set compiled in by `webpki-roots`. With a
//! private CA file (`--ca-file <PATH>`, else `RIZZY_CLI_CA_FILE`), its certificates
//! **replace** the public roots: the file names exactly whom `rv` trusts. Verification is
//! rustls' `WebPkiServerVerifier`: the chain, validity times, and the origin's host name or IP
//! address. No revocation checking. No certificate pinning in M1, and the CA file is no pin:
//! it must hold a CA certificate (`cA=true`) that issues a separate server certificate. Both
//! kinds of self-signed server certificate are refused: one with `cA=false` when the CA file
//! is read (its `basicConstraints` is checked by `is_ca_certificate`, because `rustls-webpki`
//! would otherwise accept it as both trust anchor and end entity, a pin in effect), and one
//! with `cA=true` at the handshake (`rustls-webpki` refuses a CA certificate used as the end
//! entity).
//!
//! The rustls APIs that turn verification off or replace the verifier are never used in
//! first-party code; `cargo xtask check-deps` scans `crates/*/src` for their tokens as it
//! scans for `unsafe` (Decision 3).
//!
//! # The CA file (Decision 4)
//!
//! Untrusted input, parsed by [`parse_ca_pem`] without panics and fuzzed
//! (`fuzz/fuzz_targets/ca_pem.rs`): read whole, at most [`MAX_CA_FILE_LEN`] bytes; at most
//! [`MAX_CA_CERTIFICATES`] `CERTIFICATE` blocks, at least one; other PEM sections ignored;
//! each certificate must be a CA certificate (`cA=true`, Decision 5) and become a trust
//! anchor (`RootCertStore::add`). Any failure is
//! [`CliError::BadInput`], before a byte is sent to any server. The file is read when the
//! first `https://` connection is configured, so a command that dials nothing never reads it.
//!
//! [ADR 0030]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0030-client-tls-rv.md

use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::{PemObject as _, SectionKind};
use rustls::{ClientConfig, RootCertStore};

use crate::error::{CliError, TlsFailure};

/// The environment variable that names the private CA file when `--ca-file` is not given
/// (ADR 0030 Decision 4; `rv` has no settings file).
pub const CA_FILE_ENV: &str = "RIZZY_CLI_CA_FILE";

/// The largest CA file read: 64 KiB (ADR 0030 Decision 4).
pub const MAX_CA_FILE_LEN: usize = 64 * 1024;

/// The most `CERTIFICATE` blocks a CA file may hold (ADR 0030 Decision 4).
pub const MAX_CA_CERTIFICATES: usize = 16;

/// The one ALPN protocol offered (ADR 0030 Decision 2).
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// Which trust anchors `https://` connections use, and the client configuration built from
/// them once per process (so session tickets are reused across the requests of one run).
pub struct Trust {
    /// The private CA file, if one was given; `None` for the public roots.
    ca_file: Option<PathBuf>,
    /// The configuration, built at the first `https://` connection.
    config: OnceLock<Arc<ClientConfig>>,
}

impl std::fmt::Debug for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trust")
            .field("ca_file", &self.ca_file)
            .finish_non_exhaustive()
    }
}

impl Default for Trust {
    fn default() -> Self {
        Self::public_roots()
    }
}

impl Trust {
    /// Mozilla's root set (`webpki-roots`), the default.
    #[must_use]
    pub const fn public_roots() -> Self {
        Self {
            ca_file: None,
            config: OnceLock::new(),
        }
    }

    /// The certificates of the PEM file at `path`, replacing the public roots.
    #[must_use]
    pub const fn ca_file(path: PathBuf) -> Self {
        Self {
            ca_file: Some(path),
            config: OnceLock::new(),
        }
    }

    /// The trust of a command line: `--ca-file` if given, else [`CA_FILE_ENV`] if set, else
    /// the public roots. `var` reads the environment. A set but empty variable names no file
    /// and is refused at the first `https://` connection, never read as "unset".
    #[must_use]
    pub fn from_settings(flag: Option<PathBuf>, var: &dyn Fn(&str) -> Option<OsString>) -> Self {
        match flag.or_else(|| var(CA_FILE_ENV).map(PathBuf::from)) {
            Some(path) => Self::ca_file(path),
            None => Self::public_roots(),
        }
    }

    /// The private CA file, if one is used.
    #[must_use]
    pub fn ca_file_path(&self) -> Option<&Path> {
        self.ca_file.as_deref()
    }

    /// The client configuration, built on first use.
    ///
    /// # Errors
    /// [`CliError::BadInput`] for a CA file that cannot be read or is not acceptable (module
    /// docs); [`CliError::Tls`] if rustls refuses the configuration (never with the pinned
    /// provider).
    pub fn client_config(&self, origin: &str) -> Result<Arc<ClientConfig>, CliError> {
        if let Some(config) = self.config.get() {
            return Ok(config.clone());
        }
        let roots = match &self.ca_file {
            Some(path) => parse_ca_pem(&read_ca_file(path)?)?,
            None => public_roots(),
        };
        let config = Arc::new(client_config(roots).map_err(|_| CliError::Tls {
            origin: origin.to_owned(),
            failure: TlsFailure::Configuration,
        })?);
        // Single-threaded use: if another caller set it first, theirs is equivalent.
        Ok(self.config.get_or_init(|| config).clone())
    }
}

/// Mozilla's root set as a root store.
fn public_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// The rustls client configuration of ADR 0030 Decision 2 over `roots`.
///
/// # Errors
/// rustls' error if the provider offers no TLS 1.3 suite (never with the pinned `ring`).
pub fn client_config(roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
    // The defaults, restated so that a change of default upstream does not change `rv`.
    config.enable_sni = true;
    config.enable_early_data = false;
    config.key_log = Arc::new(rustls::NoKeyLog);
    Ok(config)
}

/// Reads the CA file whole, refusing one over [`MAX_CA_FILE_LEN`] bytes without reading the
/// rest.
fn read_ca_file(path: &Path) -> Result<Vec<u8>, CliError> {
    let file = std::fs::File::open(path)
        .map_err(|_| CliError::BadInput("the CA file (--ca-file) cannot be read"))?;
    let mut bytes = Vec::new();
    // One byte past the cap tells a file at the cap from a larger one.
    file.take(u64::try_from(MAX_CA_FILE_LEN).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::BadInput("the CA file (--ca-file) cannot be read"))?;
    if bytes.len() > MAX_CA_FILE_LEN {
        return Err(CliError::BadInput(
            "the CA file (--ca-file) is larger than 64 KiB",
        ));
    }
    Ok(bytes)
}

/// The trust anchors of a CA file's bytes (module docs, "The CA file").
///
/// # Errors
/// [`CliError::BadInput`]: more than [`MAX_CA_FILE_LEN`] bytes, a PEM syntax or base64 error,
/// no `CERTIFICATE` block, more than [`MAX_CA_CERTIFICATES`], or a certificate that is not a
/// CA certificate (`cA=true`) or cannot be a trust anchor.
pub fn parse_ca_pem(pem: &[u8]) -> Result<RootCertStore, CliError> {
    if pem.len() > MAX_CA_FILE_LEN {
        return Err(CliError::BadInput(
            "the CA file (--ca-file) is larger than 64 KiB",
        ));
    }
    let mut roots = RootCertStore::empty();
    let mut count = 0_usize;
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
        let (kind, der) =
            section.map_err(|_| CliError::BadInput("the CA file (--ca-file) is not valid PEM"))?;
        if kind != SectionKind::Certificate {
            continue;
        }
        count += 1;
        if count > MAX_CA_CERTIFICATES {
            return Err(CliError::BadInput(
                "the CA file (--ca-file) holds more than 16 certificates",
            ));
        }
        // Decision 5 before the store: a certificate that is not `cA=true` would act as a pin.
        if !is_ca_certificate(&der) {
            return Err(CliError::BadInput(
                "a certificate in the CA file (--ca-file) is not a CA certificate (cA=true); \
                 a server certificate cannot be trusted directly",
            ));
        }
        roots.add(CertificateDer::from(der)).map_err(|_| {
            CliError::BadInput("a certificate in the CA file (--ca-file) cannot be a trust anchor")
        })?;
    }
    if roots.is_empty() {
        return Err(CliError::BadInput(
            "the CA file (--ca-file) holds no CERTIFICATE block",
        ));
    }
    Ok(roots)
}

/// Whether the DER certificate `der` is a CA certificate: its `basicConstraints` extension
/// (OID 2.5.29.19) is present and its `cA` field is `TRUE` (RFC 5280 §4.2.1.9).
///
/// ADR 0030 Decision 5 requires every certificate of the CA file to be one, so that the file
/// cannot act as a pin: `rustls-webpki` accepts a self-signed `cA=false` certificate both as a
/// trust anchor and as the end entity it anchors, and exposes no accessor for this field. This
/// is a read-only walk of the standard X.509 structure (RFC 5280 §4.1), not a parser of
/// ours for anything else: `RootCertStore::add` then parses the certificate in full. It fails
/// closed: anything it cannot read, a certificate with no extensions (version 1), no
/// `basicConstraints`, or `cA` absent or not the DER `TRUE` (`0xFF`), is "not a CA".
fn is_ca_certificate(der: &[u8]) -> bool {
    is_ca_walk(der).unwrap_or(false)
}

/// The walk of [`is_ca_certificate`]; `None` for anything it cannot read.
fn is_ca_walk(der: &[u8]) -> Option<bool> {
    /// DER tags used below (universal and context-specific, all single-byte).
    const SEQUENCE: u8 = 0x30;
    const INTEGER: u8 = 0x02;
    const BOOLEAN: u8 = 0x01;
    const OID: u8 = 0x06;
    const OCTET_STRING: u8 = 0x04;
    const VERSION: u8 = 0xA0;
    const EXTENSIONS: u8 = 0xA3;
    /// The content octets of the OID 2.5.29.19 (`id-ce-basicConstraints`).
    const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (cert, _) = der_expect(der, SEQUENCE)?;
    let (tbs, _) = der_expect(cert, SEQUENCE)?;
    // TBSCertificate: [0] version OPTIONAL, serialNumber, signature, issuer, validity,
    // subject, subjectPublicKeyInfo, [1] and [2] unique IDs OPTIONAL, [3] extensions OPTIONAL.
    let mut rest = tbs;
    let (tag, _, after) = der_tlv(rest)?;
    if tag == VERSION {
        rest = after;
    }
    for expected in [INTEGER, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE] {
        let (_, after) = der_expect(rest, expected)?;
        rest = after;
    }
    while !rest.is_empty() {
        let (tag, value, after) = der_tlv(rest)?;
        rest = after;
        if tag != EXTENSIONS {
            continue;
        }
        // Extensions ::= SEQUENCE OF Extension
        let (mut extensions, _) = der_expect(value, SEQUENCE)?;
        while !extensions.is_empty() {
            // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }
            let (extension, after) = der_expect(extensions, SEQUENCE)?;
            extensions = after;
            let (oid, mut fields) = der_expect(extension, OID)?;
            if oid != BASIC_CONSTRAINTS {
                continue;
            }
            let (tag, _, after) = der_tlv(fields)?;
            if tag == BOOLEAN {
                fields = after;
            }
            let (octets, _) = der_expect(fields, OCTET_STRING)?;
            // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen OPTIONAL }
            let (constraints, _) = der_expect(octets, SEQUENCE)?;
            if constraints.is_empty() {
                return Some(false);
            }
            let (tag, value, _) = der_tlv(constraints)?;
            return Some(tag == BOOLEAN && value == [0xFF]);
        }
        return Some(false);
    }
    Some(false)
}

/// One DER element of `input` with the tag `tag`: its value and the bytes after it.
fn der_expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, value, rest) = der_tlv(input)?;
    (found == tag).then_some((value, rest))
}

/// The first DER element of `input`: its tag, its value and the bytes after it. Only
/// single-byte tags and definite lengths of at most four length bytes; `None` otherwise or
/// if the element runs past the input.
fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1F == 0x1F {
        return None;
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let (bytes, after) = rest.split_at_checked(count)?;
        rest = after;
        bytes.iter().try_fold(0_usize, |acc, &b| {
            acc.checked_mul(256)?.checked_add(usize::from(b))
        })?
    };
    let (value, after) = rest.split_at_checked(len)?;
    Some((tag, value, after))
}

/// The fixed kind of a TLS failure (ADR 0030 Decision 6): the rustls error's kind only, no
/// data from the peer.
#[must_use]
pub fn failure_of(error: &rustls::Error) -> TlsFailure {
    use rustls::{AlertDescription, CertificateError, Error};
    match error {
        Error::InvalidCertificate(CertificateError::UnknownIssuer) => TlsFailure::UnknownIssuer,
        Error::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. },
        ) => TlsFailure::Expired,
        Error::InvalidCertificate(
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. },
        ) => TlsFailure::NotValidYet,
        Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => TlsFailure::WrongName,
        Error::InvalidCertificate(_) | Error::NoCertificatesPresented => TlsFailure::BadCertificate,
        Error::PeerIncompatible(_)
        | Error::AlertReceived(
            AlertDescription::ProtocolVersion
            | AlertDescription::HandshakeFailure
            | AlertDescription::InsufficientSecurity
            | AlertDescription::NoApplicationProtocol,
        ) => TlsFailure::Incompatible,
        _ => TlsFailure::Handshake,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test CA certificate, as committed for the loopback tests.
    const CA: &str = include_str!("../tests/fixtures/tls/ca.pem");
    /// A server certificate issued by the test CA (`cA=false`).
    const LEAF: &str = include_str!("../tests/fixtures/tls/leaf.pem");
    /// A self-signed server certificate with `cA=false`.
    const SELF_SIGNED_LEAF: &str = include_str!("../tests/fixtures/tls/self-signed-leaf.pem");
    /// A self-signed server certificate with `cA=true`.
    const SELF_SIGNED_CA: &str = include_str!("../tests/fixtures/tls/self-signed.pem");

    fn bad_input(result: Result<RootCertStore, CliError>) -> &'static str {
        match result {
            Err(CliError::BadInput(what)) => what,
            other => panic!("expected BadInput, got {:?}", other.map(|r| r.len())),
        }
    }

    #[test]
    fn the_configuration_is_tls_1_3_only_with_http_1_1_and_no_key_log() {
        let config = client_config(public_roots()).unwrap();
        assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
        assert!(config.enable_sni && !config.enable_early_data);
        assert!(!config.key_log.will_log("CLIENT_HANDSHAKE_TRAFFIC_SECRET"));
        // The provider is ring's, passed explicitly; no process-wide default is installed.
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        let suites: Vec<_> = config
            .crypto_provider()
            .cipher_suites
            .iter()
            .filter(|s| s.version() == &rustls::version::TLS13)
            .map(rustls::SupportedCipherSuite::suite)
            .collect();
        assert_eq!(
            suites,
            [
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ]
        );
        let groups: Vec<_> = config
            .crypto_provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect();
        assert_eq!(
            groups,
            [
                rustls::NamedGroup::X25519,
                rustls::NamedGroup::secp256r1,
                rustls::NamedGroup::secp384r1,
            ]
        );
        assert_eq!(public_roots().len(), webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[test]
    fn a_ca_file_with_certificates_becomes_the_roots() {
        assert_eq!(parse_ca_pem(CA.as_bytes()).unwrap().len(), 1);
        // Other sections are ignored, and so is text around the blocks.
        let mixed = format!(
            "comment\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{CA}\
             -----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n{CA}"
        );
        assert_eq!(parse_ca_pem(mixed.as_bytes()).unwrap().len(), 2);
        // Exactly the cap.
        let sixteen = CA.repeat(MAX_CA_CERTIFICATES);
        assert_eq!(
            parse_ca_pem(sixteen.as_bytes()).unwrap().len(),
            MAX_CA_CERTIFICATES
        );
    }

    #[test]
    fn the_pem_limits_are_enforced() {
        assert!(bad_input(parse_ca_pem(b"")).contains("no CERTIFICATE"));
        assert!(
            bad_input(parse_ca_pem(
                b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
            ))
            .contains("no CERTIFICATE")
        );
        let seventeen = CA.repeat(MAX_CA_CERTIFICATES + 1);
        assert!(bad_input(parse_ca_pem(seventeen.as_bytes())).contains("more than 16"));
        let mut large = CA.as_bytes().to_vec();
        large.resize(MAX_CA_FILE_LEN + 1, b'\n');
        assert!(bad_input(parse_ca_pem(&large)).contains("64 KiB"));
        let mut at_cap = CA.as_bytes().to_vec();
        at_cap.resize(MAX_CA_FILE_LEN, b'\n');
        assert_eq!(parse_ca_pem(&at_cap).unwrap().len(), 1);
        // Broken base64, an unterminated block, and DER that is no certificate.
        assert!(
            bad_input(parse_ca_pem(
                b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"
            ))
            .contains("not valid PEM")
        );
        assert!(
            bad_input(parse_ca_pem(b"-----BEGIN CERTIFICATE-----\nAAAA\n"))
                .contains("not valid PEM")
        );
        assert!(
            bad_input(parse_ca_pem(
                b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
            ))
            .contains("not a CA certificate")
        );
    }

    #[test]
    fn a_certificate_that_is_not_a_ca_cannot_be_in_the_ca_file() {
        // ADR 0030 Decision 5: the CA file is no pin. A server certificate issued by the CA,
        // and a self-signed cA=false server certificate, are refused when the file is read,
        // alone or next to a real CA.
        for leaf in [LEAF, SELF_SIGNED_LEAF] {
            assert!(bad_input(parse_ca_pem(leaf.as_bytes())).contains("not a CA certificate"));
            let mixed = format!("{CA}{leaf}");
            assert!(bad_input(parse_ca_pem(mixed.as_bytes())).contains("not a CA certificate"));
        }
        // The self-signed cA=true certificate passes here; it is refused at the handshake.
        assert_eq!(parse_ca_pem(SELF_SIGNED_CA.as_bytes()).unwrap().len(), 1);
    }

    /// The DER of the first `CERTIFICATE` block of `pem`.
    fn der_of(pem: &str) -> Vec<u8> {
        CertificateDer::from_pem_slice(pem.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec()
    }

    #[test]
    fn the_basic_constraints_walk_fails_closed() {
        assert!(is_ca_certificate(&der_of(CA)));
        assert!(is_ca_certificate(&der_of(SELF_SIGNED_CA)));
        assert!(!is_ca_certificate(&der_of(LEAF)));
        assert!(!is_ca_certificate(&der_of(SELF_SIGNED_LEAF)));
        // Every truncation of a CA certificate is unreadable, so "not a CA".
        let ca = der_of(CA);
        for len in 0..ca.len() {
            assert!(!is_ca_certificate(&ca[..len]), "truncated at {len}");
        }
        // Lengths: short and long form, indefinite and oversized refused.
        assert_eq!(
            der_tlv(&[0x04, 0x01, 0xAA, 0xBB]),
            Some((0x04, &[0xAA][..], &[0xBB][..]))
        );
        assert_eq!(
            der_tlv(&[0x04, 0x81, 0x01, 0xAA]),
            Some((0x04, &[0xAA][..], &[][..]))
        );
        assert_eq!(der_tlv(&[0x04, 0x80, 0x00, 0x00]), None);
        assert_eq!(der_tlv(&[0x04, 0x85, 1, 0, 0, 0, 0]), None);
        assert_eq!(der_tlv(&[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]), None);
        assert_eq!(der_tlv(&[0x1F, 0x01, 0x00]), None);
        assert_eq!(der_tlv(&[]), None);
    }

    #[test]
    fn the_ca_file_is_read_with_its_cap() {
        let dir = std::env::temp_dir().join(format!("rv-tls-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ca.pem");
        std::fs::write(&path, CA).unwrap();
        let trust = Trust::ca_file(path.clone());
        let first = trust.client_config("https://localhost").unwrap();
        let again = trust.client_config("https://localhost").unwrap();
        assert!(Arc::ptr_eq(&first, &again), "built once per process");

        let mut large = CA.as_bytes().to_vec();
        large.resize(MAX_CA_FILE_LEN + 1, b'\n');
        std::fs::write(&path, &large).unwrap();
        assert!(matches!(
            Trust::ca_file(path.clone()).client_config("https://localhost"),
            Err(CliError::BadInput(what)) if what.contains("64 KiB")
        ));
        assert!(matches!(
            Trust::ca_file(dir.join("missing.pem")).client_config("https://localhost"),
            Err(CliError::BadInput(what)) if what.contains("cannot be read")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_flag_wins_over_the_environment() {
        let env = |name: &str| (name == CA_FILE_ENV).then(|| OsString::from("/env/ca.pem"));
        let none = |_: &str| None;
        assert_eq!(
            Trust::from_settings(Some("/flag/ca.pem".into()), &env).ca_file_path(),
            Some(Path::new("/flag/ca.pem"))
        );
        assert_eq!(
            Trust::from_settings(None, &env).ca_file_path(),
            Some(Path::new("/env/ca.pem"))
        );
        assert_eq!(Trust::from_settings(None, &none).ca_file_path(), None);
        assert_eq!(Trust::default().ca_file_path(), None);
    }

    #[test]
    fn rustls_errors_map_to_fixed_kinds() {
        use rustls::{AlertDescription, CertificateError, Error};
        for (error, failure) in [
            (
                Error::InvalidCertificate(CertificateError::UnknownIssuer),
                TlsFailure::UnknownIssuer,
            ),
            (
                Error::InvalidCertificate(CertificateError::Expired),
                TlsFailure::Expired,
            ),
            (
                Error::InvalidCertificate(CertificateError::NotValidYet),
                TlsFailure::NotValidYet,
            ),
            (
                Error::InvalidCertificate(CertificateError::NotValidForName),
                TlsFailure::WrongName,
            ),
            (
                Error::InvalidCertificate(CertificateError::Revoked),
                TlsFailure::BadCertificate,
            ),
            (
                Error::AlertReceived(AlertDescription::ProtocolVersion),
                TlsFailure::Incompatible,
            ),
            (
                Error::AlertReceived(AlertDescription::BadRecordMac),
                TlsFailure::Handshake,
            ),
            (Error::DecryptError, TlsFailure::Handshake),
        ] {
            assert_eq!(failure_of(&error), failure, "{error:?}");
        }
    }
}

//! `clientDataJSON` and `authenticatorData` assembly (`WebAuthn` L3 §5.8.1, §6.1; ADR 0039 §2,
//! §4, §5).
//!
//! Neither structure needs a parser here: this crate only ever *produces* `clientDataJSON` (the
//! relying party parses it) and only ever *produces* `authenticatorData` (ADR 0039 §4, "we are
//! not a hardware authenticator" receiving someone else's).

use rizzy_core::encoding::b64url_encode;
use rizzy_core::passkey::rp_id_hash;
use rizzy_match::NormalizedUrl;

/// The serialized origin `clientDataJSON`'s `"origin"` field carries (`WebAuthn` L3 §5.8.1,
/// `HTML` "serialization of an origin"): `scheme://host[:port]`, **never** a path or query.
/// [`NormalizedUrl`] always carries a path (`super::verify_rp_id`'s return value defaults it to
/// `/` even for a bare `https://example.com`), so this is deliberately not
/// `NormalizedUrl::normalized_string`, which would silently write a path into a field the spec
/// defines as having none.
pub(super) fn origin_string(origin: &NormalizedUrl) -> String {
    match origin.port() {
        Some(port) => format!("{}://{}:{port}", origin.scheme().as_str(), origin.host()),
        None => format!("{}://{}", origin.scheme().as_str(), origin.host()),
    }
}

// `authenticatorData`'s flags byte (`WebAuthn` L3 §6.1). This project's extension always
// requires user presence and verification before either ceremony completes, so `UP` and `UV`
// are always set; every credential this project creates is a synced/backed-up passkey (ADR
// 0039 §1, "discoverable... resident"), so `BE` and `BS` are always set too, the same as a
// real platform authenticator reports for a synced passkey.

/// User Present.
const FLAG_UP: u8 = 0x01;
/// User Verified.
const FLAG_UV: u8 = 0x04;
/// Backup Eligible.
const FLAG_BE: u8 = 0x08;
/// Backup State (currently backed up).
const FLAG_BS: u8 = 0x10;
/// `attestedCredentialData` follows: registration only, never set on an assertion.
const FLAG_AT: u8 = 0x40;

/// The `"type"` discriminant `clientDataJSON` carries (`WebAuthn` L3 §5.8.1): which ceremony
/// produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ceremony {
    /// `navigator.credentials.create()`.
    Create,
    /// `navigator.credentials.get()`.
    Get,
}

impl Ceremony {
    /// The exact `"type"` string value `WebAuthn` L3 §5.8.1 fixes for this ceremony.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

/// Builds `clientDataJSON` (`WebAuthn` L3 §5.8.1). `origin` must already be the
/// browser-verified origin [`super::verify_rp_id`] checked; `crossOrigin` is hard-coded
/// `false` because a cross-origin iframe is refused before either ceremony function in this
/// module is ever called (ADR 0039 §2, [`super`] module docs) — there is no `topOrigin` field
/// for the same reason.
///
/// This is assembled by hand, not through a JSON library: it is one fixed four-field object,
/// and the one value that is not already a literal or a base64url alphabet character
/// (`origin`) is escaped byte-by-byte below (RFC 8259 §7), so nothing this function writes can
/// break out of the JSON string it is placed in even though `origin` is, in principle, text
/// this project did not choose the bytes of.
pub(super) fn client_data_json(ceremony: Ceremony, challenge: &[u8], origin: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + challenge.len() + origin.len());
    out.extend_from_slice(br#"{"type":""#);
    out.extend_from_slice(ceremony.as_str().as_bytes());
    out.extend_from_slice(br#"","challenge":""#);
    out.extend_from_slice(b64url_encode(challenge).as_bytes());
    out.extend_from_slice(br#"","origin":""#);
    escape_json_string(&mut out, origin);
    out.extend_from_slice(br#"","crossOrigin":false}"#);
    out
}

/// Appends `s` inside an already-open JSON string, escaping `"`, `\` and every C0 control byte
/// (RFC 8259 §7). `origin` is a normalised `scheme://host[:port]` string that should never
/// contain any of these, but this project never writes unescaped text it did not choose the
/// bytes of into a value a relying party then parses as JSON.
fn escape_json_string(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in s.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x00..=0x1F => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'));
                out.push(HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or(b'0'));
            }
            _ => out.push(byte),
        }
    }
}

/// `authenticatorData` for a registration ceremony: `rpIdHash ‖ flags ‖ counter ‖
/// attestedCredentialData` (`WebAuthn` L3 §6.1), where `attestedCredentialData` is `aaguid ‖
/// credentialIdLength ‖ credentialId ‖ credentialPublicKey`.
///
/// The counter is always `0`: a synced passkey has no meaningful signature-counter semantics,
/// and this project is the only authenticator that will ever present this credential, so no
/// relying party's clone-detection heuristic can ever see it move (ADR 0039 §1). The AAGUID is
/// always all-zero: this project claims no certified authenticator identity, matching the
/// `"none"` attestation format it wraps this in (ADR 0039 §4).
pub(super) fn authenticator_data_registration(
    rp_id: &str,
    credential_id: &[u8],
    public_key_cose: &[u8],
) -> Vec<u8> {
    const AAGUID: [u8; 16] = [0; 16];
    let mut out = Vec::with_capacity(37 + 16 + 2 + credential_id.len() + public_key_cose.len());
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&AAGUID);
    let credential_id_len = u16::try_from(credential_id.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&credential_id_len.to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(public_key_cose);
    out
}

/// `authenticatorData` for an assertion ceremony: `rpIdHash ‖ flags ‖ counter`, with no
/// `attestedCredentialData` (`WebAuthn` L3 §6.1; the `AT` flag is unset, [`super::wire`]
/// module docs — an assertion presents an existing credential, it does not attest a new one).
pub(super) fn authenticator_data_assertion(rp_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&rp_id_hash(rp_id));
    out.push(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS);
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::{
        Ceremony, authenticator_data_assertion, authenticator_data_registration, client_data_json,
    };

    #[test]
    fn client_data_json_is_well_formed_and_round_trips_through_a_json_parser_shaped_check() {
        let json = client_data_json(Ceremony::Create, b"challenge-bytes", "https://example.com");
        let text = core::str::from_utf8(&json).expect("ASCII-safe by construction");
        assert!(text.starts_with(r#"{"type":"webauthn.create","challenge":""#));
        assert!(text.contains(r#""origin":"https://example.com""#));
        assert!(text.ends_with(r#""crossOrigin":false}"#));
    }

    #[test]
    fn client_data_json_uses_the_get_ceremony_type_for_an_assertion() {
        let json = client_data_json(Ceremony::Get, b"c", "https://example.com");
        let text = core::str::from_utf8(&json).expect("ASCII-safe by construction");
        assert!(text.starts_with(r#"{"type":"webauthn.get","#));
    }

    #[test]
    fn client_data_json_escapes_a_quote_and_backslash_in_origin() {
        // No real browser-verified origin ever contains these, but the escaper must still
        // never let such a byte close the JSON string early.
        let json = client_data_json(Ceremony::Create, b"c", "https://evil\"}injected");
        let text = core::str::from_utf8(&json).expect("ASCII-safe by construction");
        assert!(text.contains(r#"evil\"}injected"#));
        assert!(!text.contains("evil\"}injected\","));
    }

    /// A flags byte read with `.get()`, never a bare index, for the tests below.
    fn flags_byte(auth_data: &[u8]) -> u8 {
        auth_data.get(32).copied().unwrap_or(0)
    }

    #[test]
    fn registration_authenticator_data_has_the_attested_credential_data_flag_set() {
        let auth_data = authenticator_data_registration("example.com", &[0xAA; 16], &[0xBB; 10]);
        assert_eq!(auth_data.len(), 32 + 1 + 4 + 16 + 2 + 16 + 10);
        assert_eq!(flags_byte(&auth_data) & 0x40, 0x40, "AT flag must be set");
        assert_eq!(
            auth_data.get(33..37),
            Some([0, 0, 0, 0].as_slice()),
            "counter is always zero"
        );
        assert_eq!(
            auth_data.get(37..53),
            Some([0u8; 16].as_slice()),
            "AAGUID is always all-zero"
        );
        assert_eq!(
            auth_data.get(53..55),
            Some([0, 16].as_slice()),
            "credentialIdLength, big-endian"
        );
    }

    #[test]
    fn assertion_authenticator_data_has_no_attested_credential_data_flag() {
        let auth_data = authenticator_data_assertion("example.com");
        assert_eq!(auth_data.len(), 37);
        let flags = flags_byte(&auth_data);
        assert_eq!(flags & 0x40, 0, "AT flag must be unset for an assertion");
        assert_eq!(flags & 0x01, 0x01, "UP flag must be set");
        assert_eq!(flags & 0x04, 0x04, "UV flag must be set");
    }

    #[test]
    fn registration_and_assertion_rp_id_hash_agree_for_the_same_rp_id() {
        let reg = authenticator_data_registration("example.com", &[1], &[2]);
        let assertion = authenticator_data_assertion("example.com");
        assert_eq!(reg.get(..32), assertion.get(..32));
    }
}

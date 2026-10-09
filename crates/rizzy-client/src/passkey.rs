//! INV-64: checking a `WebAuthn` `rpId` against the browser-verified origin
//! ([THREAT_MODEL] §8 INV-64; [ADR 0039] §2; the PSL from [ADR 0037] §3).
//!
//! [ADR 0039] §2 states the rule this module enforces: "The background takes the caller's
//! origin from the browser's own sender information (`sender.origin`), never from the
//! page-supplied `postMessage` payload. It requires HTTPS. It checks the requested `rpId`
//! equals the origin's host, or is a registrable-domain suffix of it per the PSL ([ADR 0037]
//! §3), and is never a bare public suffix."
//!
//! **Scope boundary.** `verify_rp_id` decides only the relationship between two strings it is
//! given: `origin` and `rp_id`. It cannot tell a browser-verified origin from a page-forged one
//! — no pure function over `&str` can. That guarantee is structural, made by the caller
//! (the extension's background script, [ADR 0036] §4): it must read `origin` from
//! `sender.origin` or the equivalent host API, never from the intercepted
//! `navigator.credentials.create`/`.get` call's own relayed payload, which the page fully
//! controls. Likewise, whether the calling frame is even allowed to ask (the cross-origin
//! iframe refusal [ADR 0039] §2 asks for, "mirroring [ADR 0037] §5's rule for password fills")
//! is decided before this function is called, by the same frame-narrowing logic
//! [`crate::matching::decide_candidates`] already applies for autofill — it is not repeated
//! here because it has nothing to do with `rpId` validity once a frame is allowed to ask at
//! all.
//!
//! No I/O, no randomness; builds for `wasm32-unknown-unknown` (inherits `rizzy-match`'s and
//! `rizzy-core`'s R1 properties; ADR 0016 §4 R1).
//!
//! [THREAT_MODEL]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/THREAT_MODEL.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0036]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0036-browser-extension-architecture-and-key-custody.md
//! [ADR 0037]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0037-url-matching-and-autofill-rules.md
//! [ADR 0039]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0039-passkeys-vault-and-extension.md

use rizzy_core::passkey::{Es256SigningKey, client_data_hash};
use rizzy_core::rng::CryptoRng;
use rizzy_match::{NormalizedUrl, Scheme, normalize_domain, suffix};

use crate::error::{ClientError, internal};

mod cbor;
mod wire;

/// The origin and `rpId` `verify_rp_id` accepted, both already normalised.
///
/// Every later step (`clientDataJSON`'s `"origin"`, `authenticatorData`'s `rpIdHash`) must use
/// these fields, never the caller's original `&str` arguments: `rp_id` in particular is folded
/// by [`normalize_domain`] (lower-case, IDNA A-label, trailing dot stripped) only *inside*
/// `verify_rp_id`, so a page spelling `rpId` as `"EXAMPLE.COM"` or with a trailing dot would
/// otherwise still pass INV-64 (it folds to the same host) but hash to a different
/// `rpIdHash` than a relying party computing `SHA-256("example.com")` expects — and a different
/// hash than this project's *own* registration wrote, if the page spelled it differently each
/// time (ADR 0039 §2; `WebAuthn` L3 §6.1).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VerifiedRp {
    /// The parsed, normalised origin.
    pub(crate) origin: NormalizedUrl,
    /// The normalised `rpId`, ready for [`rizzy_core::passkey::rp_id_hash`].
    pub(crate) rp_id: String,
}

/// Checks a `WebAuthn` `rpId` against the frame's origin (INV-64, [ADR 0039] §2; module docs).
///
/// `origin` must be the browser-verified origin of the calling frame
/// (`scheme://host[:port]`) — see the module docs' scope boundary. `rp_id` is the `rpId` the
/// page asked for, or the origin's own host when the call omitted it (the caller resolves that
/// default before calling this function; an empty `rp_id` is never passed in as "default to
/// the origin" implicitly here, to keep this function's contract exactly what its name says).
///
/// Accepts when `origin` is `https` and, once `rp_id` is normalised as a domain, either:
/// - `rp_id` equals `origin`'s host, or
/// - `rp_id` *is* `origin`'s registrable domain (eTLD+1) per the compiled-in Public Suffix
///   List ([`rizzy_match::suffix::registrable_domain`]) — checked both ways, so `rp_id` must
///   equal its own registrable domain too. That second half is what refuses a bare public
///   suffix such as `co.uk` or `github.io`: neither has a registrable domain at all (it is
///   `None`), so it can never equal `rp_id` itself.
///
/// This does not accept every suffix `WebAuthn`'s own algorithm would (an intermediate label
/// between the full host and the eTLD+1, such as `rp_id = "pay.example.com"` for an origin host
/// of `checkout.pay.example.com`): this project has one registrable-domain concept
/// ([`rizzy_match::normalize::NormalizedUrl::registrable_domain`]), used the same way
/// everywhere else a host is compared (ADR 0037 §4's registrable-domain gate), and `rpId`
/// validation uses it unchanged rather than adding a second, looser notion of "suffix."
///
/// Returns the normalised origin and `rp_id` on success ([`VerifiedRp`]'s own docs), so a
/// caller building `clientDataJSON` or `authenticatorData` uses the exact values this check
/// ran against, rather than re-deriving them — or worse, hashing the page's original,
/// differently-cased or differently-dotted `rpId` spelling into `rpIdHash`.
///
/// # Errors
/// [`ClientError::InvalidInput`] if `origin` does not parse as a normalised URL
/// ([`NormalizedUrl::parse`]) or `rp_id` does not normalise as a domain (empty, too long, or
/// not valid IDNA). [`ClientError::RpIdRejected`] for every refusal INV-64 itself names: a
/// non-`https` origin, or an `rp_id` that is neither the origin's host nor its registrable
/// domain.
pub(crate) fn verify_rp_id(origin: &str, rp_id: &str) -> Result<VerifiedRp, ClientError> {
    let origin = NormalizedUrl::parse(origin).map_err(|_| ClientError::InvalidInput)?;
    let rp_id = normalize_domain(rp_id).map_err(|_| ClientError::InvalidInput)?;

    if origin.scheme() != Scheme::Https {
        return Err(ClientError::RpIdRejected);
    }
    // "Never a bare public suffix" (ADR 0039 §2) applies to `rp_id` itself, not only to the
    // widening branch below: an exact match against an origin whose host literally *is* a bare
    // suffix (`https://co.uk` asking for `rp_id = "co.uk"`) must be refused too, so this gate
    // runs before either acceptance branch. An IP-literal `rp_id` is refused outright — WebAuthn
    // never accepts one — even though [`NormalizedUrl`] treats an IP-literal *origin* host as
    // its own registrable domain for unrelated reasons (ADR 0037 §2's note on
    // [`rizzy_match::suffix::registrable_domain`]'s `192.168.1.1` → `"1.1"` collision); that
    // origin-side special case must never leak into what `rp_id` is allowed to claim.
    if !rp_id_is_a_valid_leaf(&rp_id) {
        return Err(ClientError::RpIdRejected);
    }

    if rp_id == origin.host() || origin.registrable_domain() == Some(rp_id.as_str()) {
        return Ok(VerifiedRp { origin, rp_id });
    }
    Err(ClientError::RpIdRejected)
}

/// Whether `rp_id` (already normalised by [`normalize_domain`]) is a shape INV-64 ever allows,
/// independent of any origin: never an IP literal, and — once it carries a dot, so the PSL
/// has an opinion about it at all — never a bare public suffix (`verify_rp_id`'s own docs).
///
/// A dotless single label (`localhost`, an internal hostname) is not a Public Suffix List entry
/// either, but it is not the shared-infrastructure risk that rule targets (no other tenant can
/// ever present a different origin with the same dotless host, the way `tenant.co.uk` and
/// `other-tenant.co.uk` share the suffix `co.uk`); [`NormalizedUrl::parse`] draws the identical
/// distinction for the same reason (its own doc comment on `registrable_domain`). It is still
/// only ever accepted through `verify_rp_id`'s exact-host-match branch, never the widening
/// one, because [`NormalizedUrl`] gives such a host `registrable_domain() == Some(host)` too —
/// that equality is coincidental, not a real eTLD+1, and this function does not need to care
/// which branch the caller takes.
fn rp_id_is_a_valid_leaf(rp_id: &str) -> bool {
    if rp_id.parse::<core::net::IpAddr>().is_ok() {
        return false;
    }
    if !rp_id.contains('.') {
        return true;
    }
    suffix::registrable_domain(rp_id).as_deref() == Some(rp_id)
}

/// Everything one `navigator.credentials.create()` ceremony produces (ADR 0039 §1's field
/// list; §5 "the API is coarse"), for the caller (`rizzy-wasm`, then the extension) to hand
/// back to the page and to store.
#[derive(Debug)]
pub struct CreatedCredential {
    /// The fresh ES256 signing key. The caller encrypts [`Es256SigningKey::to_bytes`] into
    /// `passkey/<id>/private_key`, exactly like `login.password` (ADR 0039 §1); this crate
    /// never persists it itself.
    pub signing_key: Es256SigningKey,
    /// `passkey/<id>/credential_id`: 32 random bytes drawn from the same `rng` as the key.
    pub credential_id: Vec<u8>,
    /// `passkey/<id>/public_key_cose`: the COSE `EC2` map (`cbor::cose_key_es256`).
    pub public_key_cose: Vec<u8>,
    /// `clientDataJSON`, for the caller to hand back to the page verbatim.
    pub client_data_json: Vec<u8>,
    /// The CBOR `attestationObject`, `"none"` format, for the caller to hand back to the page.
    pub attestation_object: Vec<u8>,
}

/// Runs a `WebAuthn` registration ceremony for one new ES256 passkey (ADR 0039 §1, §2, §4):
/// checks INV-64, generates a fresh key from `rng`, and assembles every byte structure the
/// page's `create()` promise resolves with.
///
/// `origin` must be the browser-verified origin (`verify_rp_id`'s own scope-boundary docs);
/// `rp_id` is the `rpId` the page asked for, already defaulted by the caller to the origin's
/// host if the page omitted it; `challenge` is the relying party's own randomness, opaque to
/// this function (it is never generated here).
///
/// # Errors
/// Whatever `verify_rp_id` returns; nothing else, for a valid `rng`.
pub fn create_credential<R: CryptoRng + ?Sized>(
    rng: &mut R,
    origin: &str,
    rp_id: &str,
    challenge: &[u8],
) -> Result<CreatedCredential, ClientError> {
    let verified = verify_rp_id(origin, rp_id)?;
    let origin_string = wire::origin_string(&verified.origin);

    let signing_key = Es256SigningKey::generate(rng);
    let verifying_key = signing_key.verifying_key();
    let public_key_cose = cbor::cose_key_es256(&verifying_key.x(), &verifying_key.y());

    let mut credential_id = vec![0u8; 32];
    rng.fill_bytes(&mut credential_id);

    let client_data_json =
        wire::client_data_json(wire::Ceremony::Create, challenge, &origin_string);
    // `verified.rp_id`, never the caller's raw `rp_id`: it is already normalised the same way
    // `verify_rp_id` compared it (`VerifiedRp`'s own docs) — a page spelling `rpId` in another
    // case or with a trailing dot must still hash to the one `rpIdHash` a relying party and
    // this project's own later assertion both compute.
    let auth_data =
        wire::authenticator_data_registration(&verified.rp_id, &credential_id, &public_key_cose);
    let attestation_object = cbor::attestation_object_none(&auth_data);

    Ok(CreatedCredential {
        signing_key,
        credential_id,
        public_key_cose,
        client_data_json,
        attestation_object,
    })
}

/// Everything one `navigator.credentials.get()` ceremony produces (ADR 0039 §2).
#[derive(Debug)]
pub struct Assertion {
    /// `passkey/<id>/credential_id`, echoed back unchanged: the page's `PublicKeyCredential`
    /// response needs its own `rawId`/`id`, and the caller must not have to thread it through a
    /// second path parallel to this one just to hand it back (ADR 0039 §5, "the API is coarse").
    pub credential_id: Vec<u8>,
    /// `clientDataJSON`, for the caller to hand back to the page verbatim.
    pub client_data_json: Vec<u8>,
    /// `authenticatorData`, for the caller to hand back to the page verbatim.
    pub authenticator_data: Vec<u8>,
    /// The DER-encoded ECDSA signature over `authenticatorData ‖ SHA-256(clientDataJSON)`
    /// ([`Es256SigningKey::sign_der`]).
    pub signature_der: Vec<u8>,
}

/// Runs a `WebAuthn` assertion ceremony with one existing credential, already selected by the
/// caller (from the page's `allowCredentials`, or the one discoverable credential the person
/// picked) and its signing key already decrypted from `passkey/<id>/private_key` (ADR 0039 §2).
///
/// `credential_id` is `passkey/<id>/credential_id` for that same credential: this function
/// does not look it up or check it against anything (there is nothing in this crate yet to look
/// it up *in*, module docs), it only carries it through to [`Assertion::credential_id`] so the
/// caller has one self-contained ceremony result instead of a second value to remember to
/// attach. Matching `credential_id` to `signing_key` — and, when the page sent
/// `allowCredentials`, checking this credential is one of them — is entirely the caller's.
///
/// # Errors
/// Whatever `verify_rp_id` returns. [`ClientError::Internal`] only for the unreachable
/// signing failure [`Es256SigningKey::sign_der`] itself documents — unreachable for a key this
/// crate ever constructs, since every `Es256SigningKey` the caller can have came from
/// [`Es256SigningKey::generate`] or [`Es256SigningKey::from_bytes`], both of which already rule
/// out the one scalar `sign_der` would refuse.
pub fn get_assertion(
    signing_key: &Es256SigningKey,
    credential_id: &[u8],
    origin: &str,
    rp_id: &str,
    challenge: &[u8],
) -> Result<Assertion, ClientError> {
    let verified = verify_rp_id(origin, rp_id)?;
    let origin_string = wire::origin_string(&verified.origin);

    let client_data_json = wire::client_data_json(wire::Ceremony::Get, challenge, &origin_string);
    let authenticator_data = wire::authenticator_data_assertion(&verified.rp_id);

    let mut message = Vec::with_capacity(authenticator_data.len() + 32);
    message.extend_from_slice(&authenticator_data);
    message.extend_from_slice(&client_data_hash(&client_data_json));

    let signature_der = signing_key.sign_der(&message).map_err(internal)?;

    Ok(Assertion {
        credential_id: credential_id.to_vec(),
        client_data_json,
        authenticator_data,
        signature_der,
    })
}

#[cfg(test)]
mod tests {
    use super::verify_rp_id;
    use crate::error::ClientError;

    /// `rp_id` equal to the origin's own host (the common case: no subdomain narrowing asked
    /// for) is accepted.
    #[test]
    fn rp_id_equal_to_origin_host_is_accepted() {
        assert!(verify_rp_id("https://example.com", "example.com").is_ok());
    }

    /// A login page on a subdomain may narrow its passkeys to the whole site's registrable
    /// domain, same as a saved URI's registrable-domain match (ADR 0037 §4).
    #[test]
    fn rp_id_equal_to_registrable_domain_of_a_subdomain_origin_is_accepted() {
        assert!(verify_rp_id("https://login.example.com", "example.com").is_ok());
    }

    /// `evil.example` cannot claim `rp_id = "bank.com"`: the registrable domains differ, no
    /// matter how the PSL treats either individual host.
    #[test]
    fn a_different_site_cannot_claim_another_sites_rp_id() {
        assert_eq!(
            verify_rp_id("https://evil.example", "bank.com"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// A bare ICANN public suffix is never an acceptable `rp_id`, even for a site that is
    /// itself hosted directly under it.
    #[test]
    fn bare_public_suffix_rp_id_co_uk_is_rejected() {
        assert_eq!(
            verify_rp_id("https://attacker.co.uk", "co.uk"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// A bare public suffix is refused even on an exact host match: a site actually served at
    /// the literal apex `co.uk` still cannot claim `rp_id = "co.uk"`. This is what the earlier
    /// `attacker.co.uk` case does not exercise — it never reaches the exact-match branch.
    #[test]
    fn bare_public_suffix_rp_id_is_rejected_even_on_an_exact_host_match() {
        assert_eq!(
            verify_rp_id("https://co.uk", "co.uk"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// `WebAuthn` never accepts an IP-literal `rp_id`, even when it is the origin's own host
    /// byte-for-byte: `NormalizedUrl` treats an IP-literal origin as its own registrable domain
    /// for an unrelated reason (ADR 0037 §2), and that must not leak into `rp_id` validity.
    #[test]
    fn ip_literal_rp_id_is_rejected_even_matching_an_ip_literal_origin() {
        assert_eq!(
            verify_rp_id("https://192.168.1.1", "192.168.1.1"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// A dotless single-label `rp_id` (`localhost`, an internal hostname) is not a Public
    /// Suffix List entry, but it is not the shared-suffix risk the "never a bare public suffix"
    /// rule targets either, so an exact host match against it is still accepted.
    #[test]
    fn dotless_localhost_rp_id_is_accepted_on_an_exact_host_match() {
        assert!(verify_rp_id("https://localhost", "localhost").is_ok());
    }

    /// A bare *private* PSL suffix (a hosting platform's own domain) is refused the same way as
    /// an ICANN one — `github.io` has no registrable domain of its own either.
    #[test]
    fn bare_private_suffix_rp_id_github_io_is_rejected() {
        assert_eq!(
            verify_rp_id("https://someuser.github.io", "github.io"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// Passkeys require a secure context; a plain `http` origin is refused regardless of how
    /// well `rp_id` would otherwise match.
    #[test]
    fn http_origin_is_rejected_even_with_a_matching_rp_id() {
        assert_eq!(
            verify_rp_id("http://example.com", "example.com"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// An intermediate label between the full host and the eTLD+1 is not accepted: this
    /// project's one registrable-domain concept has no notion of a "partial" suffix.
    #[test]
    fn intermediate_label_narrower_than_the_registrable_domain_is_rejected() {
        assert_eq!(
            verify_rp_id("https://checkout.pay.example.com", "pay.example.com"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// An `rp_id` naming an unrelated host that happens to share a suffix letter sequence
    /// (`example.com` vs `notexample.com`) is rejected: comparison is by registrable domain,
    /// never by string suffix/substring.
    #[test]
    fn similar_looking_but_different_registrable_domain_is_rejected() {
        assert_eq!(
            verify_rp_id("https://notexample.com", "example.com"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// A malformed `rp_id` (empty) is `InvalidInput`, not `RpIdRejected`: it never reached the
    /// INV-64 comparison at all.
    #[test]
    fn empty_rp_id_is_invalid_input() {
        assert_eq!(
            verify_rp_id("https://example.com", ""),
            Err(ClientError::InvalidInput)
        );
    }

    /// A malformed origin (no scheme) is `InvalidInput` for the same reason.
    #[test]
    fn malformed_origin_is_invalid_input() {
        assert_eq!(
            verify_rp_id("not-a-url", "example.com"),
            Err(ClientError::InvalidInput)
        );
    }
}

#[cfg(test)]
mod ceremony_tests {
    use chacha20::ChaCha20Rng;
    use rand_core::SeedableRng as _;

    use super::{create_credential, get_assertion};
    use crate::error::ClientError;

    #[test]
    fn create_credential_rejects_an_origin_that_fails_inv_64() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let err = create_credential(&mut rng, "https://evil.example", "bank.com", b"chal")
            .expect_err("bank.com does not belong to evil.example");
        assert_eq!(err, ClientError::RpIdRejected);
    }

    /// `clientDataJSON`'s `"origin"` field must be the bare `scheme://host[:port]`
    /// serialization, never the path or query a caller's raw origin string happened to carry —
    /// the exact bug this test would have caught: writing the unnormalised input straight into
    /// a field the relying party parses and compares against.
    #[test]
    fn created_credential_client_data_json_origin_has_no_path_or_query() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let created = create_credential(
            &mut rng,
            "https://example.com/some/path?query=1",
            "example.com",
            b"chal",
        )
        .expect("origin and rp_id are valid for INV-64");
        let text = core::str::from_utf8(&created.client_data_json).expect("ASCII JSON");
        assert!(text.contains(r#""origin":"https://example.com""#));
        assert!(!text.contains("/some/path"));
        assert!(!text.contains("query=1"));
    }

    #[test]
    fn create_credential_then_get_assertion_signature_verifies() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let created = create_credential(&mut rng, "https://example.com", "example.com", b"reg")
            .expect("valid origin/rp_id");

        let assertion = get_assertion(
            &created.signing_key,
            &created.credential_id,
            "https://example.com",
            "example.com",
            b"login-challenge",
        )
        .expect("valid origin/rp_id");

        assert_eq!(assertion.credential_id, created.credential_id);

        let mut message = assertion.authenticator_data.clone();
        message.extend_from_slice(&rizzy_core::passkey::client_data_hash(
            &assertion.client_data_json,
        ));
        created
            .signing_key
            .verifying_key()
            .verify_der(&message, &assertion.signature_der)
            .expect("the assertion signature must verify under the credential's own public key");
    }

    #[test]
    fn get_assertion_rejects_an_origin_that_fails_inv_64() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let created = create_credential(&mut rng, "https://example.com", "example.com", b"reg")
            .expect("valid origin/rp_id");

        let err = get_assertion(
            &created.signing_key,
            &created.credential_id,
            "http://example.com",
            "example.com",
            b"c",
        )
        .expect_err("http is not an acceptable origin for an assertion either");
        assert_eq!(err, ClientError::RpIdRejected);
    }

    /// The regression this module's own `rp_id` normalisation bug would have needed: a
    /// registration spelling `rpId` as `"EXAMPLE.COM"` and a later assertion spelling it
    /// `"example.com"` must hash to the *same* `rpIdHash`, because [`get_assertion`] and
    /// [`create_credential`] both normalise through [`super::verify_rp_id`] before hashing,
    /// never hashing the caller's original, possibly differently-cased or differently-dotted,
    /// `rp_id` argument.
    #[test]
    fn rp_id_case_and_trailing_dot_do_not_change_the_rp_id_hash() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let created = create_credential(&mut rng, "https://example.com", "EXAMPLE.COM", b"reg")
            .expect("EXAMPLE.COM folds to the origin's own host");

        let assertion = get_assertion(
            &created.signing_key,
            &created.credential_id,
            "https://example.com",
            "example.com.",
            b"c",
        )
        .expect("a trailing dot folds the same way");

        // The registration's rpIdHash is the first 32 bytes of the authenticatorData the CBOR
        // attestationObject wraps; recomputing it directly (rather than decoding CBOR back out,
        // which this crate deliberately never does) is the simplest independent check.
        let registration_rp_id_hash =
            rizzy_core::passkey::rp_id_hash(&normalize_rp_id_for_test("EXAMPLE.COM"));
        assert_eq!(
            assertion.authenticator_data.get(..32),
            Some(registration_rp_id_hash.as_slice())
        );
    }

    /// Mirrors exactly what [`super::verify_rp_id`] does to `rp_id`, so the test above asserts
    /// against the same normalisation the code under test uses, not a hand-typed guess at it.
    fn normalize_rp_id_for_test(rp_id: &str) -> String {
        rizzy_match::normalize_domain(rp_id).expect("valid domain")
    }
}

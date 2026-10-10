// SPDX-License-Identifier: AGPL-3.0-only

//! Threat model INV-1: "the server never receives a value from which the master password can be
//! verified offline without the OPRF seed. Registration, login and password change send only
//! OPAQUE protocol messages (RFC 9807)." Its verification: "an integration test captures every
//! request body during register, login and password change and checks it contains only OPAQUE
//! messages."
//!
//! Real `rizzy-client` flows run against the router over a real `SQLite` database: a signup with
//! a recovery code, a login on a new device, and a password change in Server mode (CRYPTO.md
//! §11.5: re-authentication over the device session, `account/reregister/start`,
//! `account/commit`). Every request body is captured ([`Server::record`]). Then:
//!
//! 1. **The field allow-list.** Each body of those six endpoints has exactly the top-level
//!    fields listed in [`EXPECTED`]. A field added later fails this test until it is reviewed
//!    and listed here, with the reason it cannot verify a password guess.
//! 2. **The OPAQUE messages.** Each OPAQUE field has exactly the size of its RFC 9807 message
//!    for `RizzySuiteV1` ([`OPAQUE_SIZES`]).
//! 3. **No password, Secret Key or recovery code** in any captured request or response body,
//!    raw, as hex or as base64 at any alignment (the weaker half: it only finds what the test
//!    knows to look for).
//!
//! Why the other listed fields cannot verify a guess: `account_key_server_wrap` (`E_srv`) is
//! sealed under a key derived from OPAQUE's `export_key`, which needs the OPRF output, so the
//! OPRF seed; `identity_secret_keys` and `vault_self_grant` are sealed under the account key;
//! statements, certificates and ids are public; `recovery` holds `E_rec` and the hash of a
//! token derived from the recovery code, not the password (CRYPTO.md §11.9).

use std::collections::BTreeSet;

use axum::http::StatusCode;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::credentials::{CredentialChangeInput, start_credential_change};

use crate::common::{Exchange, Server, block_on};
use crate::rotation::{Auth, Client, NAME, PASSWORD, copy_token, login, now_ms, post, signup};

/// The master password after the change.
const NEW_PASSWORD: &str = "a different master password";

/// The endpoints of INV-1 and the exact top-level fields of each request body.
const EXPECTED: &[(&str, &[&str])] = &[
    (
        "/api/v1/register/start",
        &["account_id", "login_name", "registration_request"],
    ),
    (
        "/api/v1/register/finish",
        &[
            "account_key_server_wrap",
            "account_state",
            "bundle",
            "device_certificate",
            "identity_secret_keys",
            "recovery",
            "registration_upload",
            "setup_id",
            "vault_self_grant",
        ],
    ),
    ("/api/v1/login/start", &["ke1", "login_name"]),
    ("/api/v1/login/finish", &["ke3", "login_id"]),
    (
        "/api/v1/account/reregister/start",
        &["registration_request"],
    ),
    (
        "/api/v1/account/commit",
        &[
            "account_key_server_wrap",
            "account_state",
            "device_certificates",
            "device_revocations",
            "registration_upload",
            "setup_id",
        ],
    ),
];

/// The OPAQUE fields and the size of each message for `RizzySuiteV1` (CRYPTO.md §5.1:
/// ristretto255, SHA-512; RFC 9807 §4 with `Noe = Npk = Nn = 32`, `Nh = Nm = 64`):
/// `RegistrationRequest` is `Noe`; the registration record is `Npk + Nh + Nn + Nm`; `KE1` is
/// `Noe + Nn + Npk`; `KE3` is `Nm`.
const OPAQUE_SIZES: &[(&str, usize)] = &[
    ("registration_request", 32),
    ("registration_upload", 32 + 64 + 32 + 64),
    ("ke1", 32 + 32 + 32),
    ("ke3", 64),
];

/// INV-1 (module docs).
#[test]
fn register_login_and_password_change_send_only_opaque_messages() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(1_000_001);
        let (up, sk, code) = signup(&server, &mut rng, true).await;
        let code = code.unwrap();
        let mut client = Client::signed_up(&server, up).await;

        // A login on a new device: OPAQUE without a device session.
        let _fresh = login(&server, &mut rng, &sk, None).await;

        // The password change (CRYPTO.md §11.5), without a rotation.
        let reauth = login(
            &server,
            &mut rng,
            &sk,
            Some((&mut client.session, &client.unlocked)),
        )
        .await;
        let token = copy_token(reauth.bearer_token());
        let input = CredentialChangeInput {
            login_name: NAME,
            new_password: NEW_PASSWORD,
            new_secret_key: false,
            rotate: false,
            full_rotation: false,
            recovery_code: None,
            now_ms: now_ms(),
        };
        let (started, request) =
            start_credential_change(&mut rng, reauth, &client.state, &client.unlocked, &input)
                .unwrap();
        let reply = post(
            &server,
            "/api/v1/account/reregister/start",
            &request,
            Auth::Bearer(&token),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let pending = started
            .finish(
                &mut rng,
                &reply.json(),
                &client.state,
                &client.unlocked,
                &[],
            )
            .unwrap();
        let reply = post(
            &server,
            "/api/v1/account/commit",
            pending.commit_request().unwrap(),
            Auth::Bearer(&token),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        pending
            .finalize(&mut rng, &mut client.state, &mut client.unlocked, &mut [])
            .unwrap();

        let exchanges = server.exchanges();
        check_fields(&exchanges);

        // 3. No known secret in any request body.
        let compact_sk: String = sk.chars().filter(|c| *c != '-').collect();
        let secrets: [(&str, &[u8]); 5] = [
            ("the master password", PASSWORD.as_bytes()),
            ("the new master password", NEW_PASSWORD.as_bytes()),
            ("the Secret Key", sk.as_bytes()),
            ("the Secret Key without separators", compact_sk.as_bytes()),
            ("the recovery code", code.as_bytes()),
        ];
        for (label, secret) in secrets {
            let forms = forms(secret);
            for exchange in &exchanges {
                for (side, body) in [
                    ("request", &exchange.request),
                    ("response", &exchange.response),
                ] {
                    assert!(
                        !forms.iter().any(|f| contains(body, f)),
                        "{label} in a {side} body of {}",
                        exchange.path
                    );
                }
            }
        }
    });
}

/// Steps 1 and 2 of the module docs over the captured `exchanges`.
fn check_fields(exchanges: &[Exchange]) {
    let mut seen = BTreeSet::new();
    for (path, fields) in EXPECTED {
        let sent: Vec<&Exchange> = exchanges.iter().filter(|e| e.path == *path).collect();
        assert!(!sent.is_empty(), "{path} was not exercised");
        for exchange in sent {
            assert!(exchange.status.is_success(), "{path}: {}", exchange.status);
            let body: serde_json::Value = serde_json::from_slice(&exchange.request).unwrap();
            let keys: BTreeSet<&str> = body
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            let expected: BTreeSet<&str> = fields.iter().copied().collect();
            assert_eq!(keys, expected, "the fields of a request to {path}");
            for (field, size) in OPAQUE_SIZES {
                if let Some(value) = body.get(*field) {
                    let bytes = Base64UrlUnpadded::decode_vec(value.as_str().unwrap()).unwrap();
                    assert_eq!(bytes.len(), *size, "{path}: {field}");
                    seen.insert(*field);
                }
            }
        }
    }
    // Every OPAQUE message was seen, and checked, at least once.
    for (field, _) in OPAQUE_SIZES {
        assert!(seen.contains(field), "{field} was never sent");
    }
}

/// Whether `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Lowercase hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

/// Every form of `secret` this test searches for: raw, lower- and upper-case hex, and base64
/// in the standard and URL alphabets at each of the three byte alignments, so that the secret
/// is found inside a longer encoded value too (with or without padding).
fn forms(secret: &[u8]) -> Vec<Vec<u8>> {
    let hex = to_hex(secret);
    let mut out = vec![
        secret.to_vec(),
        hex.to_ascii_uppercase().into_bytes(),
        hex.into_bytes(),
    ];
    for shift in 0..3 {
        let mut shifted = vec![0u8; shift];
        shifted.extend_from_slice(secret);
        // The characters that encode only bits of the secret.
        let (start, end) = ((8 * shift).div_ceil(6), 8 * shifted.len() / 6);
        for text in [
            base64ct::Base64Unpadded::encode_string(&shifted),
            Base64UrlUnpadded::encode_string(&shifted),
        ] {
            out.push(text.as_bytes()[start..end].to_vec());
        }
    }
    assert!(
        out.iter().all(|f| f.len() >= 8),
        "a needle too short to mean anything"
    );
    out
}

/// The search finds a secret in every form, inside longer values (a positive control: a
/// search that silently matched nothing would make step 3 pass forever).
#[test]
fn the_search_finds_every_form() {
    let secret = b"a canary secret of 32 bytes!!!!!";
    for shift in 0..3 {
        let mut value = vec![0xa5u8; shift];
        value.extend_from_slice(secret);
        value.extend_from_slice(&[0x5a; 5]);
        let hex = to_hex(&value);
        let haystacks = [
            value.clone(),
            hex.to_ascii_uppercase().into_bytes(),
            hex.into_bytes(),
            base64ct::Base64::encode_string(&value).into_bytes(),
            base64ct::Base64Unpadded::encode_string(&value).into_bytes(),
            base64ct::Base64Url::encode_string(&value).into_bytes(),
            Base64UrlUnpadded::encode_string(&value).into_bytes(),
        ];
        for haystack in haystacks {
            let haystack = [b"{\"x\":\"".as_slice(), &haystack, b"\"}"].concat();
            assert!(forms(secret).iter().any(|f| contains(&haystack, f)));
        }
    }
    assert!(
        !forms(secret)
            .iter()
            .any(|f| contains(b"{\"x\":\"nothing\"}", f))
    );
}

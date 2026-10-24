// SPDX-License-Identifier: AGPL-3.0-only

//! `WebAuthn` security keys over HTTP (ADR 0058 as amended by ADR 0077; CRYPTO.md §11.17): an
//! enrolment and a login with a software authenticator (an ES256 key from `rizzy-core`, a
//! `"none"` attestation built here, on the server's origin), the second-factor-pending row named
//! by the `login_id`, single use, the ceremony state never in a response body, `not_found` for
//! an unknown pending id, strict bodies and the session gating.

use axum::http::StatusCode;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::login::{LoginInput, start_login};
use rizzy_client::rizzy_core::passkey::{Es256SigningKey, client_data_hash, rp_id_hash};
use rizzy_client::rizzy_proto::webauthn::{WebauthnEnrolStartResponse, WebauthnListResponse};
use rizzy_client::webauthn::{
    enrol_confirm_request, login_challenge_request, login_finish_request, remove_request,
};
use rizzy_domain_auth::types::SessionToken;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::common::{ORIGIN, Reply, Server, block_on};
use crate::rotation::{Auth, NAME, PASSWORD, call, copy_token, login, post, signup};

/// The test origin's host.
const RP_ID: &str = "vault.example.com";

fn challenge_of(options: &str) -> Vec<u8> {
    let opts: Value = serde_json::from_str(options).unwrap();
    Base64UrlUnpadded::decode_vec(opts["publicKey"]["challenge"].as_str().unwrap()).unwrap()
}

fn b64(v: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(v)
}

/// A software security key (the domain tests' `SoftKey`, reduced to `"none"` and ES256).
struct SoftKey {
    signing: Es256SigningKey,
    cred_id: Vec<u8>,
}

fn cbor_head(out: &mut Vec<u8>, major: u8, n: usize) {
    if n < 24 {
        out.push((major << 5) | u8::try_from(n).unwrap());
    } else if n < 256 {
        out.push((major << 5) | 0x18);
        out.push(u8::try_from(n).unwrap());
    } else {
        out.push((major << 5) | 0x19);
        out.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
    }
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    cbor_head(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len());
    out.extend_from_slice(b);
}

fn client_data(kind: &str, options: &str) -> Vec<u8> {
    let challenge = b64(&challenge_of(options));
    json!({"type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": false})
        .to_string()
        .into_bytes()
}

impl SoftKey {
    fn register(&self, options: &str) -> String {
        let cdj = client_data("webauthn.create", options);
        let vk = self.signing.verifying_key();
        let mut auth_data = rp_id_hash(RP_ID).to_vec();
        auth_data.push(0x41); // UP | AT
        auth_data.extend_from_slice(&[0; 4 + 16]);
        auth_data.extend_from_slice(&u16::try_from(self.cred_id.len()).unwrap().to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        // COSE EC2 key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
        auth_data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]);
        cbor_bytes(&mut auth_data, &vk.x());
        auth_data.push(0x22);
        cbor_bytes(&mut auth_data, &vk.y());
        let mut att = vec![0xa3];
        cbor_text(&mut att, "fmt");
        cbor_text(&mut att, "none");
        cbor_text(&mut att, "attStmt");
        att.push(0xa0);
        cbor_text(&mut att, "authData");
        cbor_bytes(&mut att, &auth_data);
        json!({
            "id": b64(&self.cred_id),
            "rawId": b64(&self.cred_id),
            "type": "public-key",
            "response": {"attestationObject": b64(&att), "clientDataJSON": b64(&cdj)},
            "clientExtensionResults": {},
        })
        .to_string()
    }

    fn assert(&self, options: &str, counter: u32) -> String {
        let cdj = client_data("webauthn.get", options);
        let mut auth_data = rp_id_hash(RP_ID).to_vec();
        auth_data.push(0x01); // UP
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash(&cdj));
        let sig = self.signing.sign_der(&signed).unwrap();
        json!({
            "id": b64(&self.cred_id),
            "rawId": b64(&self.cred_id),
            "type": "public-key",
            "response": {
                "authenticatorData": b64(&auth_data),
                "clientDataJSON": b64(&cdj),
                "signature": b64(&sig),
                "userHandle": null,
            },
            "clientExtensionResults": {},
        })
        .to_string()
    }
}

/// `POST path` with no body.
async fn empty(server: &Server, path: &str, auth: Auth<'_>) -> Reply {
    call(server, "POST", path, Vec::new(), auth).await
}

#[test]
#[expect(clippy::too_many_lines, reason = "one ceremony end to end reads best in one test")]
fn enrolment_and_login_with_a_security_key() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(5800);
        let (_, sk, _) = signup(&server, &mut rng, false).await;
        let web = login(&server, &mut rng, &sk, None).await;
        let token = copy_token(web.bearer_token());

        // Enrolment: the options, never the state.
        let reply = empty(
            &server,
            "/api/v1/webauthn/enrol/start",
            Auth::Bearer(&token),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let body = String::from_utf8(reply.body.clone()).unwrap();
        for state_field in ["\"rs\"", "ca_list", "policy", "\"ast\""] {
            assert!(!body.contains(state_field), "{state_field} in {body}");
        }
        let start: WebauthnEnrolStartResponse = reply.json();
        let key = SoftKey {
            signing: Es256SigningKey::generate(&mut rng),
            cred_id: vec![0x5a; 32],
        };
        let credential = key.register(start.options.as_str());
        let confirm = enrol_confirm_request(start.enrolment_id, "Desk key", &credential).unwrap();
        let reply = post(
            &server,
            "/api/v1/webauthn/enrol/confirm",
            &confirm,
            Auth::Bearer(&token),
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::NO_CONTENT,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        let reply = empty(&server, "/api/v1/webauthn/list", Auth::Bearer(&token)).await;
        let list: WebauthnListResponse = reply.json();
        assert_eq!(list.credentials.as_slice().len(), 1);

        // Login: second_factor_required after KE3, then the pending row named by the login id.
        let input = LoginInput {
            server_origin: ORIGIN,
            login_name: NAME,
            secret_key: &sk,
            password: PASSWORD,
        };
        let (started, request) = start_login(&mut rng, &input).unwrap();
        let reply = post(&server, "/api/v1/login/start", &request, Auth::None).await;
        let (awaiting, finish) = started.finish(&mut rng, &reply.json(), None).unwrap();
        let reply = post(&server, "/api/v1/login/finish", &finish, Auth::None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.body, br#"{"error":"second_factor_required"}"#);
        let reply = post(
            &server,
            "/api/v1/webauthn/login/challenge",
            &login_challenge_request(finish.login_id),
            Auth::None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let answer: Value = reply.json();
        assert_eq!(answer["totp"], false);
        let options = answer["options"].as_str().unwrap();
        let credential = key.assert(options, 1);
        let request = login_finish_request(finish.login_id, &credential).unwrap();
        let reply = post(
            &server,
            "/api/v1/webauthn/login/finish",
            &request,
            Auth::None,
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        let logged_in = awaiting.complete(reply.json()).unwrap();
        let fresh = copy_token(logged_in.bearer_token());

        // Single use: the same assertion again is refused.
        let reply = post(
            &server,
            "/api/v1/webauthn/login/finish",
            &request,
            Auth::None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.body, br#"{"error":"unauthorized"}"#);

        // Removal with the new fresh session; then a password alone logs in again.
        let id = list
            .credentials
            .as_slice()
            .first()
            .unwrap()
            .credential_id
            .as_slice()
            .to_vec();
        let remove = remove_request(&id).unwrap();
        let reply = post(
            &server,
            "/api/v1/webauthn/remove",
            &remove,
            Auth::Bearer(&fresh),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        login(&server, &mut rng, &sk, None).await;
    });
}

#[test]
fn routes_are_gated_and_strict() {
    block_on(async {
        let server = Server::start().await;
        let unknown = SessionToken::new(Zeroizing::new([0x42; 32]));
        for (path, body) in [
            ("/api/v1/webauthn/enrol/start", ""),
            (
                "/api/v1/webauthn/enrol/confirm",
                r#"{"enrolment_id":"AAAAAAAAAAAAAAAAAAAAAA","label":"k","credential":"{}"}"#,
            ),
            ("/api/v1/webauthn/list", ""),
            ("/api/v1/webauthn/remove", r#"{"credential_id":"AQ"}"#),
        ] {
            let reply = call(&server, "POST", path, body.as_bytes().to_vec(), Auth::None).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{path}");
            let reply = call(
                &server,
                "POST",
                path,
                body.as_bytes().to_vec(),
                Auth::Bearer(&unknown),
            )
            .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{path}");
        }
        // No pending row: not_found, which tells a client to ask for a TOTP code instead.
        let reply = call(
            &server,
            "POST",
            "/api/v1/webauthn/login/challenge",
            br#"{"pending_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#.to_vec(),
            Auth::None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.body, br#"{"error":"not_found"}"#);
        let reply = call(
            &server,
            "POST",
            "/api/v1/webauthn/login/finish",
            br#"{"pending_id":"AAAAAAAAAAAAAAAAAAAAAA","credential":"{}"}"#.to_vec(),
            Auth::None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        // Strict bodies: an unknown field, a bad id, JSON that is not ASCII text.
        for (path, body) in [
            (
                "/api/v1/webauthn/login/challenge",
                r#"{"pending_id":"AAAAAAAAAAAAAAAAAAAAAA","x":1}"#,
            ),
            ("/api/v1/webauthn/login/challenge", r#"{"pending_id":"AA"}"#),
            (
                "/api/v1/webauthn/login/finish",
                r#"{"pending_id":"AAAAAAAAAAAAAAAAAAAAAA","credential":{"id":"x"}}"#,
            ),
        ] {
            let reply = call(&server, "POST", path, body.as_bytes().to_vec(), Auth::None).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path} {body}");
            assert_eq!(reply.body, br#"{"error":"invalid_request"}"#);
        }
    });
}

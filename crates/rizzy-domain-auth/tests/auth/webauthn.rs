// SPDX-License-Identifier: AGPL-3.0-only

//! `WebAuthn` security keys as a second factor (ADR 0058 as amended by ADR 0077; CRYPTO.md
//! §11.17), against a software authenticator built on `rizzy-core`'s ES256 code (ADR 0077 §4):
//! enrolment, login, single use, TTL, RP ID and origin, UV, INV-83 against the counter of record,
//! a credential removed mid-ceremony, attestation, algorithms, rate limits, and the committed
//! `webauthn-rs` 0.5.5 fixture rows.

use rizzy_core::passkey::{Es256SigningKey, client_data_hash, rp_id_hash};
use rizzy_domain_auth::AuthError;
use rizzy_proto::auth::LoginFinishResponse;
use rizzy_proto::webauthn::{
    WebauthnCredentialId, WebauthnEnrolConfirmRequest, WebauthnJson, WebauthnLabel,
    WebauthnLoginChallengeRequest, WebauthnLoginFinishRequest, WebauthnRemoveRequest,
};
use rizzy_proto::wire::{Bytes, Id};
use rizzy_storage::Conn;
use serde_json::{Value, json};
use sqlx::Row as _;

use crate::common::{Client, Env, block_on};

/// The test origin's host: the RP ID.
const RP_ID: &str = "vault.example.com";
/// The test origin (`common::ORIGIN`).
const ORIGIN: &str = "https://vault.example.com";
/// Authenticator-data flags.
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;

fn b64(v: &[u8]) -> String {
    serde_json::to_value(Bytes::<65_536>::new(v.to_vec()).unwrap())
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn unb64(s: &str) -> Vec<u8> {
    serde_json::from_value::<Bytes<65_536>>(Value::String(s.to_owned()))
        .unwrap()
        .as_slice()
        .to_vec()
}

// ---- A minimal CBOR writer, for the authenticator's side only ------------------------------

fn head(out: &mut Vec<u8>, major: u8, n: usize) {
    let m = major << 5;
    if n < 24 {
        out.push(m | u8::try_from(n).unwrap());
    } else if n < 256 {
        out.push(m | 0x18);
        out.push(u8::try_from(n).unwrap());
    } else {
        out.push(m | 0x19);
        out.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
    }
}

fn bstr(out: &mut Vec<u8>, b: &[u8]) {
    head(out, 2, b.len());
    out.extend_from_slice(b);
}

fn tstr(out: &mut Vec<u8>, s: &str) {
    head(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn int(out: &mut Vec<u8>, i: i64) {
    if i >= 0 {
        head(out, 0, usize::try_from(i).unwrap());
    } else {
        head(out, 1, usize::try_from(-1 - i).unwrap());
    }
}

/// The attestation statement a [`SoftKey`] returns.
#[derive(Clone, Copy)]
enum Statement {
    None,
    Packed,
    PackedBroken,
}

/// The key a [`SoftKey`] claims at enrolment.
#[derive(Clone, Copy)]
enum Alg {
    Es256,
    /// A COSE RS256 key with a made-up modulus: with `"none"` attestation nothing is signed at
    /// enrolment, so only the algorithm check can refuse it (ADR 0077 §6).
    Rs256,
}

/// A software security key: an ES256 key pair from `rizzy-core` and a credential id.
struct SoftKey {
    signing: Es256SigningKey,
    cred_id: Vec<u8>,
}

fn client_data(kind: &str, options: &str, origin: &str) -> Vec<u8> {
    let opts: Value = serde_json::from_str(options).unwrap();
    let challenge = opts["publicKey"]["challenge"].as_str().unwrap();
    json!({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
        .to_string()
        .into_bytes()
}

impl SoftKey {
    fn new(env: &mut Env, id: u8) -> Self {
        Self {
            signing: Es256SigningKey::generate(&mut env.rng),
            cred_id: vec![id; 32],
        }
    }

    fn cose_key(&self, alg: Alg) -> Vec<u8> {
        let mut out = Vec::new();
        match alg {
            Alg::Es256 => {
                let vk = self.signing.verifying_key();
                head(&mut out, 5, 5);
                int(&mut out, 1);
                int(&mut out, 2);
                int(&mut out, 3);
                int(&mut out, -7);
                int(&mut out, -1);
                int(&mut out, 1);
                int(&mut out, -2);
                bstr(&mut out, &vk.x());
                int(&mut out, -3);
                bstr(&mut out, &vk.y());
            }
            Alg::Rs256 => {
                let mut n = vec![0xc5; 256];
                n[255] = 0x01;
                head(&mut out, 5, 4);
                int(&mut out, 1);
                int(&mut out, 3);
                int(&mut out, 3);
                int(&mut out, -257);
                int(&mut out, -1);
                bstr(&mut out, &n);
                int(&mut out, -2);
                bstr(&mut out, &[1, 0, 1]);
            }
        }
        out
    }

    /// The JSON of `navigator.credentials.create()` for `options`.
    fn register(&self, options: &str, flags: u8, statement: Statement, alg: Alg) -> WebauthnJson {
        let cdj = client_data("webauthn.create", options, ORIGIN);
        let mut auth_data = rp_id_hash(RP_ID).to_vec();
        auth_data.push(flags | AT);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&u16::try_from(self.cred_id.len()).unwrap().to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        auth_data.extend_from_slice(&self.cose_key(alg));
        let mut att = Vec::new();
        head(&mut att, 5, 3);
        tstr(&mut att, "fmt");
        match statement {
            Statement::None => {
                tstr(&mut att, "none");
                tstr(&mut att, "attStmt");
                head(&mut att, 5, 0);
            }
            Statement::Packed | Statement::PackedBroken => {
                let mut signed = auth_data.clone();
                signed.extend_from_slice(&client_data_hash(&cdj));
                let mut sig = self.signing.sign_der(&signed).unwrap();
                if matches!(statement, Statement::PackedBroken) {
                    let last = sig.len() - 1;
                    sig[last] ^= 0x01;
                }
                tstr(&mut att, "packed");
                tstr(&mut att, "attStmt");
                head(&mut att, 5, 2);
                tstr(&mut att, "alg");
                int(&mut att, -7);
                tstr(&mut att, "sig");
                bstr(&mut att, &sig);
            }
        }
        tstr(&mut att, "authData");
        bstr(&mut att, &auth_data);
        let body = json!({
            "id": b64(&self.cred_id),
            "rawId": b64(&self.cred_id),
            "type": "public-key",
            "response": {"attestationObject": b64(&att), "clientDataJSON": b64(&cdj)},
            "clientExtensionResults": {},
        });
        WebauthnJson::new(body.to_string()).unwrap()
    }

    /// The JSON of `navigator.credentials.get()` for `options`.
    fn assert_with(
        &self,
        options: &str,
        flags: u8,
        counter: u32,
        origin: &str,
        rp_id: &str,
    ) -> WebauthnJson {
        let cdj = client_data("webauthn.get", options, origin);
        let mut auth_data = rp_id_hash(rp_id).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash(&cdj));
        let sig = self.signing.sign_der(&signed).unwrap();
        let body = json!({
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
        });
        WebauthnJson::new(body.to_string()).unwrap()
    }

    fn assert(&self, options: &str, flags: u8, counter: u32) -> WebauthnJson {
        self.assert_with(options, flags, counter, ORIGIN, RP_ID)
    }
}

/// Logs `client` in with its password alone (no key enrolled yet) and returns the fresh session.
async fn fresh(env: &mut Env, client: &Client) -> rizzy_domain_auth::Session {
    let login = env.login(client).await;
    env.bearer(&login.response.session_token).await
}

/// Enrols `key` under `label` through the fresh session `session`.
async fn enrol(
    env: &mut Env,
    session: &rizzy_domain_auth::Session,
    key: &SoftKey,
    flags: u8,
    label: &str,
) -> Result<(), AuthError> {
    let start = env
        .svc
        .webauthn_enrol_start(&mut env.rng, session, env.now)
        .await?;
    let req = WebauthnEnrolConfirmRequest {
        enrolment_id: start.enrolment_id,
        label: WebauthnLabel::new(label.to_owned()).unwrap(),
        credential: key.register(start.options.as_str(), flags, Statement::None, Alg::Es256),
    };
    env.svc.webauthn_enrol_confirm(session, &req, env.now).await
}

/// The login challenge options for `pending`.
async fn challenge(env: &mut Env, pending: Id) -> Result<String, AuthError> {
    let req = WebauthnLoginChallengeRequest {
        pending_id: pending,
    };
    Ok(env
        .svc
        .webauthn_login_challenge(&req, env.now)
        .await?
        .options
        .as_str()
        .to_owned())
}

/// Finishes `pending` with `credential`.
async fn finish(
    env: &mut Env,
    pending: Id,
    credential: WebauthnJson,
) -> Result<LoginFinishResponse, AuthError> {
    let req = WebauthnLoginFinishRequest {
        pending_id: pending,
        credential,
    };
    let source = env.source.clone();
    env.svc
        .webauthn_login_finish(&mut env.rng, &req, &source, None, env.now)
        .await
}

/// A whole login with `key` asserting `counter` with `flags`.
async fn login_with(
    env: &mut Env,
    client: &Client,
    key: &SoftKey,
    flags: u8,
    counter: u32,
) -> Result<LoginFinishResponse, AuthError> {
    let pending = env.login_pending(client).await;
    let options = challenge(env, pending).await?;
    let credential = key.assert(&options, flags, counter);
    finish(env, pending, credential).await
}

/// Runs `sql` with `binds` on the test database (a database writer, for the state tests).
async fn sql_exec(env: &Env, sql: &'static str, binds: &[i64]) {
    let mut tx = env.db.begin_write().await.unwrap();
    let Conn::Sqlite(c) = tx.conn() else {
        panic!("the tests run on SQLite")
    };
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    q.execute(&mut *c).await.unwrap();
    tx.commit().await.unwrap();
}

/// The `sign_count` and `security_key` of the only credential row.
async fn stored_row(env: &Env) -> (i64, String) {
    let mut tx = env.db.begin_write().await.unwrap();
    let Conn::Sqlite(c) = tx.conn() else {
        panic!("the tests run on SQLite")
    };
    let row = sqlx::query("SELECT sign_count, security_key FROM auth_webauthn_credentials")
        .fetch_one(&mut *c)
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

/// The number of ceremony states and pending rows.
async fn live_rows(env: &Env) -> (i64, i64) {
    let mut tx = env.db.begin_write().await.unwrap();
    let Conn::Sqlite(c) = tx.conn() else {
        panic!("the tests run on SQLite")
    };
    let states: i64 = sqlx::query("SELECT COUNT(*) FROM auth_webauthn_challenges")
        .fetch_one(&mut *c)
        .await
        .unwrap()
        .get(0);
    let pending: i64 = sqlx::query("SELECT COUNT(*) FROM auth_webauthn_pending")
        .fetch_one(&mut *c)
        .await
        .unwrap()
        .get(0);
    (states, pending)
}

#[test]
fn enrolment_login_list_and_removal() {
    block_on(async {
        let mut env = Env::new(81).await;
        let client = env.signup("wen", "pw").await;
        let session = fresh(&mut env, &client).await;
        let key = SoftKey::new(&mut env, 1);

        // The creation options (ADR 0077 §9 entry 12): attestation "none", the RP ID, the
        // account id as user.id, ES256 then RS256, 60 s, no excluded key yet.
        let start = env
            .svc
            .webauthn_enrol_start(&mut env.rng, &session, env.now)
            .await
            .unwrap();
        let opts: Value = serde_json::from_str(start.options.as_str()).unwrap();
        let pk = &opts["publicKey"];
        assert_eq!(pk["rp"]["id"], RP_ID);
        assert_eq!(pk["attestation"], "none");
        assert_eq!(pk["timeout"], 60_000);
        assert_eq!(
            unb64(pk["user"]["id"].as_str().unwrap()),
            client.account_id.to_bytes()
        );
        assert_eq!(unb64(pk["challenge"].as_str().unwrap()).len(), 32);
        let algs: Vec<i64> = pk["pubKeyCredParams"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["alg"].as_i64().unwrap())
            .collect();
        assert_eq!(algs, [-7, -257]);
        assert!(
            pk["excludeCredentials"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        // The state never leaves the server (ADR 0077 §2 rule 3).
        let (states, _) = live_rows(&env).await;
        assert_eq!(states, 1);
        assert!(!start.options.as_str().contains("\"rs\""));
        let req = WebauthnEnrolConfirmRequest {
            enrolment_id: start.enrolment_id,
            label: WebauthnLabel::new("Desk key".to_owned()).unwrap(),
            credential: key.register(start.options.as_str(), UP, Statement::None, Alg::Es256),
        };
        env.svc
            .webauthn_enrol_confirm(&session, &req, env.now)
            .await
            .unwrap();
        // Single use: the same enrolment cannot be confirmed twice.
        assert!(matches!(
            env.svc
                .webauthn_enrol_confirm(&session, &req, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));

        let list = env.svc.webauthn_list(&session).await.unwrap();
        let only = list.credentials.as_slice().first().unwrap();
        assert_eq!(only.label.as_str(), "Desk key");
        assert_eq!(only.credential_id.as_slice(), key.cred_id.as_slice());
        assert_eq!(only.created_ms, env.now);

        // A second enrolment excludes the first key, and the same key is refused again.
        let again = env
            .svc
            .webauthn_enrol_start(&mut env.rng, &session, env.now)
            .await
            .unwrap();
        let opts: Value = serde_json::from_str(again.options.as_str()).unwrap();
        let excluded = opts["publicKey"]["excludeCredentials"][0]["id"]
            .as_str()
            .unwrap();
        assert_eq!(unb64(excluded), key.cred_id);
        let dup = WebauthnEnrolConfirmRequest {
            enrolment_id: again.enrolment_id,
            label: WebauthnLabel::new("Again".to_owned()).unwrap(),
            credential: key.register(again.options.as_str(), UP, Statement::None, Alg::Es256),
        };
        // The ceremony itself refuses a key in `excludeCredentials`.
        assert!(matches!(
            env.svc
                .webauthn_enrol_confirm(&session, &dup, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));

        // A password-only login now stops at the second factor; the key finishes it.
        let response = login_with(&mut env, &client, &key, UP, 1).await.unwrap();
        let fresh_again = env.bearer(&response.session_token).await;
        assert_eq!(fresh_again.account_id, client.account_id);
        assert_eq!(stored_row(&env).await.0, 1);
        assert_eq!(
            live_rows(&env).await,
            (0, 0),
            "state and pending row used once"
        );

        // Removal needs a fresh session and names the key; an unknown key is not found.
        let other = WebauthnRemoveRequest {
            credential_id: WebauthnCredentialId::new(vec![9; 32]).unwrap(),
        };
        assert!(matches!(
            env.svc.webauthn_remove(&fresh_again, &other, env.now).await,
            Err(AuthError::NotFound)
        ));
        env.tick(6 * 60_000);
        let mine = WebauthnRemoveRequest {
            credential_id: WebauthnCredentialId::new(key.cred_id.clone()).unwrap(),
        };
        assert!(matches!(
            env.svc.webauthn_remove(&fresh_again, &mine, env.now).await,
            Err(AuthError::FreshSessionRequired)
        ));
        let response = login_with(&mut env, &client, &key, UP, 2).await.unwrap();
        let newest = env.bearer(&response.session_token).await;
        env.svc
            .webauthn_remove(&newest, &mine, env.now)
            .await
            .unwrap();
        assert!(
            env.svc
                .webauthn_list(&newest)
                .await
                .unwrap()
                .credentials
                .as_slice()
                .is_empty()
        );
        // Without a key, a password-only login succeeds again.
        env.login(&client).await;
    });
}

#[test]
fn state_and_pending_rows_are_single_use_and_expire() {
    block_on(async {
        let mut env = Env::new(82).await;
        let client = env.signup("ada", "pw").await;
        let session = fresh(&mut env, &client).await;
        let key = SoftKey::new(&mut env, 2);
        enrol(&mut env, &session, &key, UP, "k").await.unwrap();

        // A failed finish (a wrong signature: another key) deletes both rows; the right
        // assertion afterwards finds nothing.
        let pending = env.login_pending(&client).await;
        let options = challenge(&mut env, pending).await.unwrap();
        let mut impostor = SoftKey::new(&mut env, 2);
        impostor.cred_id.clone_from(&key.cred_id);
        let bad = impostor.assert(&options, UP, 1);
        assert!(matches!(
            finish(&mut env, pending, bad).await,
            Err(AuthError::Unauthorized)
        ));
        assert_eq!(live_rows(&env).await, (0, 0));
        let good = key.assert(&options, UP, 1);
        assert!(matches!(
            finish(&mut env, pending, good).await,
            Err(AuthError::Unauthorized)
        ));

        // A successful finish cannot be repeated.
        let pending = env.login_pending(&client).await;
        let options = challenge(&mut env, pending).await.unwrap();
        let good = key.assert(&options, UP, 1);
        finish(&mut env, pending, good.clone()).await.unwrap();
        assert!(matches!(
            finish(&mut env, pending, good).await,
            Err(AuthError::Unauthorized)
        ));

        // A new challenge replaces the previous state: an assertion over the old one fails.
        let pending = env.login_pending(&client).await;
        let first = challenge(&mut env, pending).await.unwrap();
        let _second = challenge(&mut env, pending).await.unwrap();
        assert_eq!(live_rows(&env).await, (1, 1));
        let stale = key.assert(&first, UP, 2);
        assert!(matches!(
            finish(&mut env, pending, stale).await,
            Err(AuthError::Unauthorized)
        ));

        // A state read after its 60 s is refused, even though the row still exists.
        let pending = env.login_pending(&client).await;
        let options = challenge(&mut env, pending).await.unwrap();
        env.tick(60_001);
        let late = key.assert(&options, UP, 2);
        assert!(matches!(
            finish(&mut env, pending, late).await,
            Err(AuthError::Unauthorized)
        ));
        // An expired pending row gives no challenge.
        let pending = env.login_pending(&client).await;
        env.tick(60_000);
        assert!(matches!(
            challenge(&mut env, pending).await,
            Err(AuthError::NotFound)
        ));

        // An unknown state_format, and an oversized state, are refused (fail closed).
        for tamper in [
            "UPDATE auth_webauthn_challenges SET state_format = 2",
            "UPDATE auth_webauthn_challenges SET state = state || printf('%.*c', 65536, ' ')",
        ] {
            let pending = env.login_pending(&client).await;
            let options = challenge(&mut env, pending).await.unwrap();
            sql_exec(&env, tamper, &[]).await;
            let ok = key.assert(&options, UP, 2);
            assert!(
                matches!(
                    finish(&mut env, pending, ok).await,
                    Err(AuthError::Unauthorized)
                ),
                "{tamper}"
            );
        }
        // An unknown pending id gets nothing; worker purges what expired.
        assert!(matches!(
            challenge(&mut env, Id::from_bytes([0xee; 16])).await,
            Err(AuthError::NotFound)
        ));
        let _ = env.login_pending(&client).await;
        env.tick(60_000);
        let purged = env.svc.purge_expired(env.now).await.unwrap();
        assert!(purged.webauthn_pending >= 1);
        assert_eq!(live_rows(&env).await, (0, 0));
    });
}

#[test]
fn inv_83_is_decided_against_the_counter_of_record() {
    block_on(async {
        let mut env = Env::new(83).await;
        let client = env.signup("lin", "pw").await;
        let session = fresh(&mut env, &client).await;
        let key = SoftKey::new(&mut env, 3);
        enrol(&mut env, &session, &key, UP, "k").await.unwrap();

        // stored 0, received 0: accepted, nothing to track.
        login_with(&mut env, &client, &key, UP, 0).await.unwrap();
        assert_eq!(stored_row(&env).await.0, 0);
        // stored 0, received 5: accepted, tracking starts.
        login_with(&mut env, &client, &key, UP, 5).await.unwrap();
        assert_eq!(stored_row(&env).await.0, 5);
        // stored 5, received 6: accepted and stored.
        login_with(&mut env, &client, &key, UP, 6).await.unwrap();
        let (count, json) = stored_row(&env).await;
        assert_eq!(count, 6);
        let sk: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            sk["cred"]["counter"], 6,
            "the SecurityKey is updated with it"
        );
        // stored 6, received 6 or below: refused as a possible clone; the row is unchanged and
        // the key stays enrolled (ADR 0058 owner answer 4).
        for received in [6, 3] {
            assert!(matches!(
                login_with(&mut env, &client, &key, UP, received).await,
                Err(AuthError::PossibleClone)
            ));
            assert_eq!(stored_row(&env).await.0, 6);
        }
        // The row decides, not the state's copy: raise the row after the challenge.
        let pending = env.login_pending(&client).await;
        let options = challenge(&mut env, pending).await.unwrap();
        sql_exec(
            &env,
            "UPDATE auth_webauthn_credentials SET sign_count = $1",
            &[10],
        )
        .await;
        let assertion = key.assert(&options, UP, 8);
        assert!(matches!(
            finish(&mut env, pending, assertion).await,
            Err(AuthError::PossibleClone)
        ));
        login_with(&mut env, &client, &key, UP, 11).await.unwrap();
        assert_eq!(stored_row(&env).await.0, 11);
        assert_eq!(
            env.svc
                .webauthn_list(&session)
                .await
                .unwrap()
                .credentials
                .as_slice()
                .len(),
            1
        );
    });
}

#[test]
fn a_key_removed_mid_ceremony_is_refused() {
    block_on(async {
        let mut env = Env::new(84).await;
        let client = env.signup("rae", "pw").await;
        let session = fresh(&mut env, &client).await;
        let (one, two) = (SoftKey::new(&mut env, 4), SoftKey::new(&mut env, 5));
        enrol(&mut env, &session, &one, UP, "one").await.unwrap();
        enrol(&mut env, &session, &two, UP, "two").await.unwrap();
        let pending = env.login_pending(&client).await;
        let options = challenge(&mut env, pending).await.unwrap();
        let opts: Value = serde_json::from_str(&options).unwrap();
        assert_eq!(
            opts["publicKey"]["allowCredentials"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(opts["publicKey"]["rpId"], RP_ID);
        sql_exec(
            &env,
            "DELETE FROM auth_webauthn_credentials WHERE label = 'one'",
            &[],
        )
        .await;
        let assertion = one.assert(&options, UP, 1);
        assert!(matches!(
            finish(&mut env, pending, assertion).await,
            Err(AuthError::Unauthorized)
        ));
        login_with(&mut env, &client, &two, UP, 1).await.unwrap();
    });
}

#[test]
fn rp_id_origin_and_type_are_bound() {
    block_on(async {
        let mut env = Env::new(85).await;
        let client = env.signup("ivo", "pw").await;
        let session = fresh(&mut env, &client).await;
        let key = SoftKey::new(&mut env, 6);
        enrol(&mut env, &session, &key, UP, "k").await.unwrap();
        for (origin, rp_id) in [
            ("https://evil.example.com", RP_ID),
            ("https://vault.example.com:8443", RP_ID),
            ("https://sub.vault.example.com", RP_ID),
            (ORIGIN, "example.com"),
            (ORIGIN, "evil.example.com"),
        ] {
            let pending = env.login_pending(&client).await;
            let options = challenge(&mut env, pending).await.unwrap();
            let assertion = key.assert_with(&options, UP, 1, origin, rp_id);
            assert!(
                matches!(
                    finish(&mut env, pending, assertion).await,
                    Err(AuthError::Unauthorized)
                ),
                "{origin} {rp_id}"
            );
        }
        // An enrolment response is not an assertion, and the wrong origin cannot enrol.
        let start = env
            .svc
            .webauthn_enrol_start(&mut env.rng, &session, env.now)
            .await
            .unwrap();
        let other = SoftKey::new(&mut env, 7);
        let mut body: Value = serde_json::from_str(
            other
                .register(start.options.as_str(), UP, Statement::None, Alg::Es256)
                .as_str(),
        )
        .unwrap();
        let cdj = client_data(
            "webauthn.create",
            start.options.as_str(),
            "https://evil.example.com",
        );
        body["response"]["clientDataJSON"] = Value::String(b64(&cdj));
        let req = WebauthnEnrolConfirmRequest {
            enrolment_id: start.enrolment_id,
            label: WebauthnLabel::new("x".to_owned()).unwrap(),
            credential: WebauthnJson::new(body.to_string()).unwrap(),
        };
        assert!(matches!(
            env.svc
                .webauthn_enrol_confirm(&session, &req, env.now)
                .await,
            Err(AuthError::Unauthorized)
        ));
        // Not JSON a browser would send: invalid request, and the state is still used up.
        let start = env
            .svc
            .webauthn_enrol_start(&mut env.rng, &session, env.now)
            .await
            .unwrap();
        let req = WebauthnEnrolConfirmRequest {
            enrolment_id: start.enrolment_id,
            label: WebauthnLabel::new("x".to_owned()).unwrap(),
            credential: WebauthnJson::new("{\"id\":1}".to_owned()).unwrap(),
        };
        assert!(matches!(
            env.svc
                .webauthn_enrol_confirm(&session, &req, env.now)
                .await,
            Err(AuthError::InvalidRequest)
        ));
        assert_eq!(live_rows(&env).await.0, 0);
    });
}

#[test]
fn attestation_and_algorithms() {
    block_on(async {
        let mut env = Env::new(86).await;
        let client = env.signup("oz", "pw").await;
        let session = fresh(&mut env, &client).await;
        let confirm = async |env: &mut Env, key: &SoftKey, statement, alg| {
            let start = env
                .svc
                .webauthn_enrol_start(&mut env.rng, &session, env.now)
                .await
                .unwrap();
            let req = WebauthnEnrolConfirmRequest {
                enrolment_id: start.enrolment_id,
                label: WebauthnLabel::new("k".to_owned()).unwrap(),
                credential: key.register(start.options.as_str(), UP, statement, alg),
            };
            env.svc
                .webauthn_enrol_confirm(&session, &req, env.now)
                .await
        };
        // A key that chose RS256 is refused before anything is stored (ADR 0077 §6).
        let rsa = SoftKey::new(&mut env, 10);
        assert!(matches!(
            confirm(&mut env, &rsa, Statement::None, Alg::Rs256).await,
            Err(AuthError::KeyAlgorithm)
        ));
        // A packed statement with a broken signature is refused (§5).
        let broken = SoftKey::new(&mut env, 11);
        assert!(matches!(
            confirm(&mut env, &broken, Statement::PackedBroken, Alg::Es256).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(
            env.svc
                .webauthn_list(&session)
                .await
                .unwrap()
                .credentials
                .as_slice()
                .is_empty()
        );
        // A valid packed self-attestation is accepted and kept, parsed, in security_key.
        let packed = SoftKey::new(&mut env, 12);
        confirm(&mut env, &packed, Statement::Packed, Alg::Es256)
            .await
            .unwrap();
        let (_, json) = stored_row(&env).await;
        let sk: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(sk["cred"]["attestation_format"], "packed");
        assert!(
            json.contains("Self"),
            "the parsed self attestation is kept: {json}"
        );
        login_with(&mut env, &client, &packed, UP, 1).await.unwrap();
    });
}

#[test]
fn user_verification_follows_enrolment() {
    block_on(async {
        let mut env = Env::new(87).await;
        let client = env.signup("uma", "pw").await;
        let session = fresh(&mut env, &client).await;
        // A key that performed UV at enrolment must perform it at every assertion.
        let pin = SoftKey::new(&mut env, 20);
        enrol(&mut env, &session, &pin, UP | UV, "pin")
            .await
            .unwrap();
        assert!(matches!(
            login_with(&mut env, &client, &pin, UP, 1).await,
            Err(AuthError::Unauthorized)
        ));
        login_with(&mut env, &client, &pin, UP | UV, 2)
            .await
            .unwrap();
        // User presence is always required.
        assert!(matches!(
            login_with(&mut env, &client, &pin, UV, 3).await,
            Err(AuthError::Unauthorized)
        ));

        let mut env = Env::new(88).await;
        let client = env.signup("vic", "pw").await;
        let session = fresh(&mut env, &client).await;
        // A key enrolled with UP alone asserts with UP alone.
        let plain = SoftKey::new(&mut env, 21);
        enrol(&mut env, &session, &plain, UP, "plain")
            .await
            .unwrap();
        login_with(&mut env, &client, &plain, UP, 1).await.unwrap();
    });
}

#[test]
fn totp_and_a_key_each_satisfy_the_second_factor() {
    block_on(async {
        let mut env = Env::new(89).await;
        let client = env.signup("tess", "pw").await;
        let session = fresh(&mut env, &client).await;
        let key = SoftKey::new(&mut env, 30);
        enrol(&mut env, &session, &key, UP, "k").await.unwrap();
        let enrolment = env
            .svc
            .totp_enrol_start(&mut env.rng, &session, env.now)
            .await
            .unwrap();
        let code = |now: u64| {
            rizzy_core::totp::TotpParams::DEFAULT
                .code_at(&enrolment.secret, now / 1000)
                .unwrap()
                .to_digits()
                .to_string()
        };
        env.svc
            .totp_enrol_confirm(&session, 1, &code(env.now), env.now)
            .await
            .unwrap();
        // The challenge tells the client a code would also do.
        let pending = env.login_pending(&client).await;
        let req = WebauthnLoginChallengeRequest {
            pending_id: pending,
        };
        assert!(
            env.svc
                .webauthn_login_challenge(&req, env.now)
                .await
                .unwrap()
                .totp
        );
        // A code alone logs in, without the key.
        env.tick(30_000);
        let (name, password) = (client.name.clone(), client.password.clone());
        let c = code(env.now);
        env.login_as(&name, &password, &client.secret_key, Some(&c), None)
            .await
            .unwrap();
        // The key alone too.
        login_with(&mut env, &client, &key, UP, 1).await.unwrap();
    });
}

#[test]
fn assertions_are_rate_limited_per_account() {
    block_on(async {
        let mut env = Env::with_config(90, |c| {
            c.rate_limits.webauthn_per_account.max_attempts = 2;
        })
        .await;
        let client = env.signup("ray", "pw").await;
        let session = fresh(&mut env, &client).await;
        let key = SoftKey::new(&mut env, 40);
        enrol(&mut env, &session, &key, UP, "k").await.unwrap();
        // Failed assertions (no user presence) count until the bucket blocks; then even a valid
        // assertion is refused until the backoff ends.
        let mut refused = 0;
        loop {
            match login_with(&mut env, &client, &key, UV, 1).await {
                Err(AuthError::Unauthorized) => refused += 1,
                Err(AuthError::RateLimited { .. }) => break,
                other => panic!("unexpected {other:?}"),
            }
            assert!(refused <= 3, "the bucket never blocked");
        }
        assert!(refused >= 2);
        assert!(matches!(
            login_with(&mut env, &client, &key, UP, 1).await,
            Err(AuthError::RateLimited { .. })
        ));
        env.tick(16 * 60_000);
        login_with(&mut env, &client, &key, UP, 1).await.unwrap();
    });
}

/// `webauthn-rs` 0.5.5 `SecurityKey` rows, committed (ADR 0077 §4 "Durability"): each
/// deserialises from the stored JSON and verifies an assertion from its private key.
#[test]
fn committed_fixture_rows_still_verify() {
    block_on(async {
        let fixtures: Value =
            serde_json::from_str(include_str!("fixtures/webauthn_security_keys_0_5_5.json"))
                .unwrap();
        for (i, fixture) in fixtures.as_array().unwrap().iter().enumerate() {
            let mut env = Env::new(100 + u64::try_from(i).unwrap()).await;
            let client = env.signup("fix", "pw").await;
            let key = SoftKey {
                signing: Es256SigningKey::from_bytes(&unb64(
                    fixture["test_es256_scalar"].as_str().unwrap(),
                ))
                .unwrap(),
                cred_id: unb64(fixture["credential_id"].as_str().unwrap()),
            };
            let mut tx = env.db.begin_write().await.unwrap();
            let Conn::Sqlite(c) = tx.conn() else {
                panic!("the tests run on SQLite")
            };
            sqlx::query(
                "INSERT INTO auth_webauthn_credentials (account_id, credential_id, alg, \
                 security_key, security_key_format, sign_count, label, created_ms) \
                 VALUES ($1, $2, 1, $3, 1, $4, 'fixture', 1)",
            )
            .bind(&client.account_id.as_bytes()[..])
            .bind(&key.cred_id)
            .bind(fixture["security_key"].as_str().unwrap())
            .bind(fixture["sign_count"].as_i64().unwrap())
            .execute(&mut *c)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            let flags = u8::try_from(fixture["flags"].as_u64().unwrap()).unwrap();
            let next = u32::try_from(fixture["sign_count"].as_u64().unwrap()).unwrap() + 1;
            login_with(&mut env, &client, &key, flags, next)
                .await
                .unwrap();
        }
    });
}

//! Flow tests that need no server: the order of the steps, the requests built, the answers
//! refused. The flows against a real `rizzy-vault` run in `packages/core`'s end-to-end test,
//! through the built wasm module (this crate may not depend on `rizzy-server`, ADR 0016 R6).

use rizzy_client::rizzy_core::secret_key::SecretKey;

use crate::rng::os_rng;
use crate::{LoginFlow, SignupFlow};

const ORIGIN: &str = "https://vault.example.com";

/// A secret as the host passes it: UTF-8 bytes in an array the call zeroes.
fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

/// A well-formed Secret Key text.
fn secret_key() -> String {
    SecretKey::generate(&mut os_rng())
        .to_formatted()
        .to_string()
}

#[test]
fn a_login_starts_with_login_start_and_refuses_bad_input() {
    for (origin, name, sk) in [
        ("not an origin", "alice", secret_key()),
        (ORIGIN, "", secret_key()),
        (ORIGIN, "alice", "RV1-not-a-key".to_owned()),
    ] {
        let error =
            LoginFlow::start(origin, name, &mut bytes(&sk), &mut bytes("pw"), None).unwrap_err();
        assert_eq!(error.as_str(), "invalid_input");
    }
    // A malformed second factor is refused when the finish is built, not at the start.
    let mut flow = LoginFlow::start(
        ORIGIN,
        "alice",
        &mut bytes(&secret_key()),
        &mut bytes("pw"),
        Some("12".to_owned()),
    )
    .unwrap();
    assert_eq!(flow.state(), "request");
    let request = flow.request().unwrap();
    assert_eq!(request.method(), "POST");
    assert_eq!(request.path(), "/api/v1/login/start");
    assert!(request.authorization().is_none());
    assert_eq!(request.content_type().as_deref(), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(&request.body().unwrap()).unwrap();
    assert_eq!(body["login_name"], "alice");
    // The same request again until an answer arrives.
    assert_eq!(flow.request().unwrap().body(), request.body());

    // Out-of-order calls are refused and change nothing.
    assert_eq!(
        flow.provide_totp("123456").unwrap_err().as_str(),
        "wrong_state"
    );
    assert_eq!(flow.state(), "request");

    // A refusal ends the flow.
    let error = flow
        .respond(429, br#"{"error":"rate_limited"}"#, 0)
        .unwrap_err();
    assert_eq!(error.as_str(), "server_rate_limited");
    assert_eq!(flow.state(), "failed");
    assert_eq!(flow.request().unwrap_err().as_str(), "wrong_state");
    assert_eq!(
        flow.respond(200, b"{}", 0).unwrap_err().as_str(),
        "wrong_state"
    );
    assert_eq!(flow.finish().unwrap_err().as_str(), "wrong_state");
}

#[test]
fn a_login_answer_that_does_not_parse_fails_the_flow() {
    let mut flow = LoginFlow::start(
        ORIGIN,
        "alice",
        &mut bytes(&secret_key()),
        &mut bytes("pw"),
        None,
    )
    .unwrap();
    let error = flow.respond(200, b"{\"login_id\":1}", 0).unwrap_err();
    assert_eq!(error.as_str(), "invalid_server_response");
    assert_eq!(flow.state(), "failed");
}

#[test]
fn a_signup_registers_first_and_hands_out_nothing_early() {
    assert_eq!(
        SignupFlow::start(ORIGIN, "alice", &mut [], None, true, 0)
            .unwrap_err()
            .as_str(),
        "invalid_input",
        "an empty new password is refused"
    );
    let mut flow = SignupFlow::start(
        ORIGIN,
        "Alice",
        &mut bytes("correct horse"),
        Some("inv".to_owned()),
        true,
        0,
    )
    .unwrap();
    assert_eq!(flow.state(), "request");
    let request = flow.request().unwrap();
    assert_eq!(request.path(), "/api/v1/register/start");
    let body: serde_json::Value = serde_json::from_slice(&request.body().unwrap()).unwrap();
    assert_eq!(body["login_name"], "alice");
    assert!(body.get("invite").is_some());
    // No kit, no confirmation, no login before the server answered.
    assert_eq!(flow.emergency_kit().unwrap_err().as_str(), "wrong_state");
    assert_eq!(
        flow.confirm_kit("ABCD").unwrap_err().as_str(),
        "wrong_state"
    );
    // A refusal ends it.
    assert_eq!(
        flow.respond(400, br#"{"error":"invalid_request"}"#)
            .unwrap_err()
            .as_str(),
        "server_invalid_request"
    );
    assert_eq!(flow.state(), "failed");
    assert_eq!(flow.login().unwrap_err().as_str(), "wrong_state");
}

#[test]
fn debug_output_shows_no_input() {
    let sk = secret_key();
    let flow = LoginFlow::start(
        ORIGIN,
        "alice",
        &mut bytes(&sk),
        &mut bytes("hunter2"),
        None,
    )
    .unwrap();
    let shown = format!("{flow:?}");
    assert!(!shown.contains("hunter2") && !shown.contains(&sk));
    let signup = SignupFlow::start(ORIGIN, "alice", &mut bytes("hunter2"), None, false, 0).unwrap();
    assert!(!format!("{signup:?}").contains("hunter2"));
}

#[test]
fn secrets_passed_in_are_zeroed_whatever_the_outcome() {
    // Accepted: both arrays hold zeroes afterwards.
    let mut sk = bytes(&secret_key());
    let mut pw = bytes("hunter2");
    LoginFlow::start(ORIGIN, "alice", &mut sk, &mut pw, None).unwrap();
    assert!(sk.iter().chain(&pw).all(|&b| b == 0));
    // Refused for the Secret Key: the password is wiped as well.
    let mut sk = bytes("RV1-not-a-key");
    let mut pw = bytes("hunter2");
    let error = LoginFlow::start(ORIGIN, "alice", &mut sk, &mut pw, None).unwrap_err();
    assert_eq!(error.as_str(), "invalid_input");
    assert!(sk.iter().chain(&pw).all(|&b| b == 0));
    // Refused before the secrets are read (a bad origin): still wiped.
    let mut sk = bytes(&secret_key());
    let mut pw = bytes("hunter2");
    LoginFlow::start("not an origin", "alice", &mut sk, &mut pw, None).unwrap_err();
    assert!(sk.iter().chain(&pw).all(|&b| b == 0));
    // A password that is not UTF-8 is refused, and wiped.
    let mut sk = bytes(&secret_key());
    let mut pw = vec![0xff, 0xfe];
    let error = LoginFlow::start(ORIGIN, "alice", &mut sk, &mut pw, None).unwrap_err();
    assert_eq!(error.as_str(), "invalid_input");
    assert!(sk.iter().chain(&pw).all(|&b| b == 0));
    // A signup's password, refused by the origin check: wiped.
    let mut pw = bytes("correct horse");
    SignupFlow::start("not an origin", "alice", &mut pw, None, true, 0).unwrap_err();
    assert!(pw.iter().all(|&b| b == 0));
}

#[test]
fn import_files_are_recognised_by_kind_only() {
    use crate::session::{detect_import_format, plaintext_export_hold_ms};

    assert_eq!(plaintext_export_hold_ms(), 10_000);
    assert_eq!(
        detect_import_format(br#"{"format":"rizzy-vault-export","version":1}"#),
        "rizzy-encrypted"
    );
    assert_eq!(
        detect_import_format(
            br#"{"format":"rizzy-vault-plaintext-export","version":1,"items":[]}"#
        ),
        "rizzy-json"
    );
    assert_eq!(
        detect_import_format(br#"{"encrypted":false,"items":[]}"#),
        "bitwarden-json"
    );
    assert_eq!(detect_import_format(b"PK\x03\x04"), "1pux");
    assert_eq!(
        detect_import_format(b"name,url,username,password\n"),
        "chrome-csv"
    );
    assert_eq!(detect_import_format(b"hello\n"), "unknown");
    assert_eq!(detect_import_format(b""), "unknown");
}

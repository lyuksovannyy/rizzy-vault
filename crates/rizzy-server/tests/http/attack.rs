// SPDX-License-Identifier: AGPL-3.0-only

//! Bulk adversarial testing of the HTTP surface: threat model attackers A1 (passive DB/backup
//! theft, `THREAT_MODEL.md` §4 "A1") and A15 (other users and the anonymous internet, §4 "A15"),
//! and the `api`/`web`/`worker` STRIDE rows (§7.6, §7.7, §7.9, §7.12, §7.13). The oracle is the
//! security invariants of §8 (INV-*) and the attacker sections, never the implementation: see
//! [`oracle`] and its positive controls ([`oracle::positive_controls`]).
//!
//! # Budget (`rizzy-sync`'s `convergence/generate.rs` pattern, ADR 0012 §12 "Budget")
//! One server and three accounts (A, B, C) are built once per test ([`Scenario::build`]): each
//! account's signup pays the real Argon2id floor (`THREAT_MODEL.md` §A1, two client-side
//! evaluations), so the fixture costs a couple of seconds. Every generated case after that is an
//! in-process `tower::ServiceExt::oneshot`, a few milliseconds each, so thousands of cases fit
//! comfortably inside a PR budget. [`bulk_fuzz_pr_budget`] runs [`PR_CASES`] on proptest's
//! deterministic RNG, so it is never flaky in CI; [`bulk_fuzz_nightly`] is `#[ignore]`d and runs
//! [`NIGHTLY_MULTIPLIER`] times as many on fresh seeds (`RIZZY_ATTACK_MULTIPLIER` overrides the
//! multiplier, for splitting a larger local run into chunks under the harness's own time limit).
//! `Seeds` is private in `convergence/generate.rs`, so its shape is mirrored here rather than
//! imported (ADR 0016 §3: this crate does not depend on `rizzy-sync`).
//!
//! # What is generated, broadly (combinatorial, not hand-picked)
//! [`generator`] draws, for each case: one of [`rizzy_server::http::api::Endpoint::ALL`] (every
//! `/api/v1` route; the three that end sessions, [`SESSION_ENDING`], in a run of their own that
//! re-opens what each case ended, [`session_ending_routes_under_generated_cases`]); a body mutation ([`generator::Mutation`]: truncated, bit-flipped, wrong
//! top-level JSON type, a null or wrong-typed field, an extra field, an oversized body, bounded
//! deep nesting, injected control characters, or no JSON at all); and an auth mode
//! ([`generator::AuthChoice`]: no token, a forged token, a malformed `Authorization` header,
//! another account's real bearer token, another account's real signed device request, this
//! account's bearer-only session, or this account's fully signed device session as the
//! positive control that body validation still runs once auth passes). Each case's source
//! address is drawn from the case's own seed, so one case's rate-limit backoff never swallows
//! the next one's answer (threat model A15 "IDOR attempts", INV-7).
//!
//! # What is enumerated, exhaustively
//! - [`idor`]: every ordered pair of the three accounts, for every route that takes a
//!   client-supplied resource id — `devices/suspend`, `devices/unsuspend` (`device_id`),
//!   `vault/upload`, `vault/fetch`, `vault/heal` (`vault_id`), and `device-auth/start`,
//!   `device-auth/finish` (an `account_id`/`device_id` pair from two different accounts).
//!   Threat model A15 "IDOR attempts against other users' ciphertext, shares and device lists",
//!   INV-7 "authorization check and test for every endpoint and resource type". The one other
//!   client-supplied id, `sessions/end`'s `session_id`, is tested across accounts in
//!   `sessions.rs` (`another_accounts_session_is_not_found`).
//! - [`method_confusion`]: every endpoint against every method it does not serve.
//! - [`web_paths`]: path traversal, odd encodings and method confusion on the `web` role
//!   (§7.7 "E": "Path traversal in static serving").
//! - [`replay`]: a signed device request resent byte for byte, and the same signature and
//!   counter retargeted at a different endpoint or a different body.
//! - [`lockout`]: the INV-7 "D" row exemption — an unauthenticated flood against a known login
//!   name never blocks that account's own re-authentication from an enrolled device.
//! - [`canary`]: the INV-15/INV-50 scan of the quiesced database, the secrets file and a real
//!   `rizzy-vault backup` file, for every secret the fixture ever held, raw, hex and base64
//!   (standard and url-safe, padded and unpadded). A planted canary proves the walker reaches
//!   the real data dir, not just that the predicate works on a buffer handed to it directly.
//! - [`xff`]: `X-Forwarded-For` forged from an untrusted peer (ADR 0028 item 11, INV-7, §7.6
//!   "S") never escapes the forger's own rate-limit bucket and never lands in a real client's
//!   bucket. `conventions.rs` already pins the same rule end to end against a real configured
//!   proxy; this is the same property against the bulk fixture's own accounts.
//!
//! # Not covered (recorded, not hidden)
//! - Deeply nested JSON is capped at [`generator::MAX_NESTING`]. `serde_json`'s recursive-
//!   descent parser has no built-in depth limit, and a stack overflow aborts the whole test
//!   process rather than failing one case (Rust cannot catch it), so probing past a safe margin
//!   would crash this harness instead of exercising the server under test. The cap is far above
//!   any legitimate document.
//! - `account/commit` is the one endpoint [`the_generator_reaches_past_the_parse_boundary`]
//!   measures and finds genuinely parse-only at 20,000 cases ([`EXPECTED_PARSE_ONLY`]):
//!   `CommitChangeRequest`'s `account_state` is a fixed-length signed statement, and this
//!   fixture's placeholder bytes never match that length, so every mutation of it still fails
//!   deserialization before any domain call. `devices/web-certificate` and the three
//!   `healing/*` endpoints (ADR 0032) take bundle chains, kind-4 certificates and self-grants
//!   this fixture never signs too, but the same measurement shows their placeholder bodies do
//!   parse and do reach a domain refusal (a `403`/`404`/`413`, never a `2xx`) — real coverage
//!   on the auth, method and authorization dimensions, just not on a body a real client's
//!   crypto would ever produce.
//! - Log-stream scanning (INV-48) is not attempted, though a hook does exist: this harness's
//!   own stderr carries the server's access log (`http/mod.rs::access_log`), since nothing
//!   forks a subprocess. Piping `bulk_fuzz_nightly`'s stderr to a file at
//!   `RIZZY_ATTACK_MULTIPLIER=5` (~9,000 cases) shows every line is that access log's fixed
//!   `{method, route, status, duration_ms}` schema, which cannot carry a secret by
//!   construction, and that neither `auth_failure` nor `vault_failure` (`api.rs`, logged only
//!   for a storage or internal failure, never a domain refusal) fired even once across those
//!   cases. Scanning the stream itself, rather than reasoning about its schema from one
//!   captured run, is the gap this harness still leaves open. [`canary`] covers exactly what
//!   the task names, "the DB files and a backup".
//! - No multi-process or real-socket SSRF/DNS-rebinding surface (`icons` role, §7.11) is
//!   exercised: this harness drives the router in-process, and the `icons` role is not part of
//!   `api`/`web`/`worker`.
//! - Duplicate header lines (`Authorization`, `Content-Length`, `Rizzy-Request-Counter`) are
//!   not a case axis: the production router's `single()` extractor rejects more than one
//!   field line for these before `handle()` is reached, and no test here constructs a request
//!   with a repeated header to confirm that rejection in this harness's own fixture.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::{Rng as _, SeedableRng as _};
use proptest::prelude::RngCore as _;
use proptest::test_runner::{Config as ProptestConfig, TestRng, TestRunner};
use rizzy_client::device::UnlockedDevice;
use rizzy_client::rizzy_core::ids::{AccountId, DeviceId, VaultId};
use rizzy_client::session::DeviceSession;
use rizzy_client::signup::DeviceKind;
use rizzy_domain_auth::ServerSecrets;
use rizzy_domain_auth::types::{SIGNATURE_CONTAINER_LEN, SessionToken, paths};
use rizzy_server::config::Config;
use rizzy_server::http::api::{BODY_LIMIT, Endpoint, HttpMethod};
use rizzy_server::secrets_file;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::common::{Reply, Server, TempDir, block_on, config_in, send_from};
use crate::rotation::{
    Auth, Client, PASSWORD, call, copy_token, device_session, login_named, now_ms, post_empty,
    request, signup_named,
};

/// Cases of [`bulk_fuzz_pr_budget`], proptest's deterministic RNG: never flaky in CI. Sized to
/// land well under the task's ~60 s PR budget (measured ~20 ms/case on the author's machine,
/// dominated by the oversized-body and deep-nesting mutations' allocations).
const PR_CASES: u32 = 1_800;

/// The default multiplier of [`bulk_fuzz_nightly`] over [`PR_CASES`], on fresh seeds. The
/// owner's scale-up run (20x, split into chunks under this harness's time limit) overrides it
/// with `RIZZY_ATTACK_MULTIPLIER`.
const NIGHTLY_MULTIPLIER: u32 = 20;

/// The three fixture accounts' login names.
const NAMES: [&str; 3] = ["atk-alice", "atk-bob", "atk-carol"];

/// Where a batch's seeds come from (mirrors `rizzy-sync`'s private `convergence::generate::Seeds`
/// — module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seeds {
    /// Proptest's deterministic RNG: the same cases on every run.
    Fixed,
    /// Fresh OS randomness (or `PROPTEST_RNG_SEED`, read by proptest itself).
    Fresh,
}

/// `cases` seeds drawn as `seeds` says.
fn draw_seeds(cases: u32, seeds: Seeds) -> Vec<u64> {
    let cfg = ProptestConfig::default();
    match seeds {
        Seeds::Fixed => {
            let mut rng = TestRng::deterministic_rng(cfg.rng_algorithm);
            (0..cases).map(|_| rng.next_u64()).collect()
        }
        Seeds::Fresh => {
            let mut runner = TestRunner::new(cfg);
            (0..cases).map(|_| runner.rng().next_u64()).collect()
        }
    }
}

// ============================================================================================
// Oracle: pure checks against THREAT_MODEL.md, never against the implementation.
// ============================================================================================

mod oracle {
    //! Each predicate's doc comment names the invariant or ADR clause it enforces, and takes
    //! only the response (or file bytes): it never reads `rizzy-server`'s source to decide what
    //! counts as a violation. [`positive_controls`] is the harness's proof that these actually
    //! fire, run against synthetic data a real server never has to produce.

    use axum::http::{HeaderMap, StatusCode};
    use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding as _};

    /// One oracle finding.
    #[derive(Debug, Clone)]
    pub(crate) struct Violation {
        /// The invariant or ADR clause violated.
        pub(crate) rule: &'static str,
        /// What was observed.
        pub(crate) detail: String,
    }

    impl std::fmt::Display for Violation {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[{}] {}", self.rule, self.detail)
        }
    }

    fn violation(rule: &'static str, detail: impl Into<String>) -> Violation {
        Violation {
            rule,
            detail: detail.into(),
        }
    }

    /// INV-49 / §7.7 "E": every response carries the frame, transport and sniffing headers,
    /// whatever its status — a `404`, a `405` and a `HEAD` included.
    pub(crate) fn security_headers(headers: &HeaderMap) -> Option<Violation> {
        const WANT: &[(&str, Option<&str>)] = &[
            ("strict-transport-security", None),
            ("x-content-type-options", Some("nosniff")),
            ("x-frame-options", Some("DENY")),
            ("referrer-policy", Some("no-referrer")),
        ];
        for (name, expected) in WANT {
            match headers.get(*name) {
                None => return Some(violation("INV-49", format!("missing {name}"))),
                Some(value) => {
                    if let Some(expected) = expected
                        && value.to_str().is_ok_and(|v| v != *expected)
                    {
                        return Some(violation("INV-49", format!("{name} = {value:?}")));
                    }
                }
            }
        }
        if headers.get("content-security-policy").is_none() {
            return Some(violation("INV-49", "missing content-security-policy"));
        }
        None
    }

    /// ADR 0028 item 3 / INV-7: a non-`2xx` body is exactly `{"error":"<code>"}` — JSON, one
    /// field, nothing echoed back — and carries `Cache-Control: no-store`.
    pub(crate) fn uniform_error(
        status: StatusCode,
        body: &[u8],
        headers: &HeaderMap,
    ) -> Option<Violation> {
        if status.is_success() {
            return None;
        }
        let value: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return Some(violation(
                    "ADR-0028-3",
                    format!("error body is not JSON: {e}"),
                ));
            }
        };
        let serde_json::Value::Object(map) = &value else {
            return Some(violation(
                "ADR-0028-3",
                format!("error body is not an object: {value}"),
            ));
        };
        if map.len() != 1 || !matches!(map.get("error"), Some(serde_json::Value::String(_))) {
            return Some(violation(
                "ADR-0028-3",
                format!("error body is not exactly {{\"error\":...}}: {value}"),
            ));
        }
        if headers.get("cache-control").and_then(|v| v.to_str().ok()) != Some("no-store") {
            return Some(violation(
                "ADR-0028-3",
                "error body missing Cache-Control: no-store",
            ));
        }
        None
    }

    /// ADR 0028 item 3: every refusal this build defines has its own `4xx`/`409`/`410` code
    /// (`api::status`); a `5xx` is never a deliberate answer to a client request, however
    /// malformed — only an unhandled internal failure.
    pub(crate) fn no_server_error(status: StatusCode) -> Option<Violation> {
        status
            .is_server_error()
            .then(|| violation("no-5xx", format!("status {status}")))
    }

    /// §7.6 "D": "A panic in any role writes a core dump with in-memory secrets." A request
    /// must never crash the task handling it.
    pub(crate) fn no_panic(detail: impl Into<String>) -> Violation {
        violation("no-panic", detail.into())
    }

    /// A1 / INV-7 "authorization check ... for every endpoint and resource type": a response to
    /// one account never carries bytes that identify another account's real resource id, raw
    /// or as the base64url the wire format encodes every id in (CRYPTO.md §9.6).
    pub(crate) fn no_foreign_bytes(body: &[u8], foreign: &[u8], label: &str) -> Option<Violation> {
        if foreign.len() < 8 {
            // Too short to be a meaningful marker (would false-positive on common bytes).
            return None;
        }
        if contains(body, foreign) {
            return Some(violation(
                "A1-idor",
                format!("response body contains {label}'s id, raw"),
            ));
        }
        let encoded = Base64UrlUnpadded::encode_string(foreign);
        contains(body, encoded.as_bytes()).then(|| {
            violation(
                "A1-idor",
                format!("response body contains {label}'s id, base64url"),
            )
        })
    }

    /// Byte substring search, independent of UTF-8 validity on either side.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Lowercase hex of `bytes`.
    fn hex_lower(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// INV-15 / A1: `secret` appears nowhere in `haystack`, raw, as hex (either case) or as
    /// base64 (standard and url-safe, padded and unpadded) — "the weaker half: it only finds
    /// what the test knows to look for" (`password_equivalents.rs`, INV-15's own words).
    pub(crate) fn find_canary(haystack: &[u8], label: &str, secret: &[u8]) -> Option<Violation> {
        if secret.len() < 6 {
            // Too short to search meaningfully without false positives (e.g. a 1-byte "secret").
            return None;
        }
        if contains(haystack, secret) {
            return Some(violation("INV-15", format!("{label}: raw bytes found")));
        }
        let hex = hex_lower(secret);
        if contains(haystack, hex.as_bytes()) || contains(haystack, hex.to_uppercase().as_bytes()) {
            return Some(violation("INV-15", format!("{label}: hex-encoded")));
        }
        let encodings: [String; 4] = [
            Base64::encode_string(secret),
            Base64Unpadded::encode_string(secret),
            Base64Url::encode_string(secret),
            Base64UrlUnpadded::encode_string(secret),
        ];
        for encoded in encodings {
            if contains(haystack, encoded.as_bytes()) {
                return Some(violation("INV-15", format!("{label}: base64-encoded")));
            }
        }
        None
    }

    #[cfg(test)]
    mod positive_controls {
        //! The task's positive control: a deliberately planted bad case each predicate must
        //! flag, proving the oracle can detect a violation and is not a vacuous pass.

        use axum::http::{HeaderMap, HeaderValue, StatusCode};
        use base64ct::{Base64, Base64Url, Base64UrlUnpadded, Encoding as _};

        use super::{
            find_canary, hex_lower, no_foreign_bytes, no_server_error, security_headers,
            uniform_error,
        };

        #[test]
        fn flags_a_5xx() {
            assert!(no_server_error(StatusCode::INTERNAL_SERVER_ERROR).is_some());
            assert!(no_server_error(StatusCode::BAD_GATEWAY).is_some());
            assert!(no_server_error(StatusCode::BAD_REQUEST).is_none());
            assert!(no_server_error(StatusCode::OK).is_none());
        }

        #[test]
        fn flags_a_missing_security_header() {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
            headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
            headers.insert(
                "content-security-policy",
                HeaderValue::from_static("default-src 'none'"),
            );
            // strict-transport-security is missing: must be flagged.
            assert!(security_headers(&headers).is_some());
            headers.insert(
                "strict-transport-security",
                HeaderValue::from_static("max-age=1"),
            );
            assert!(
                security_headers(&headers).is_none(),
                "a complete set passes"
            );
            // A weakened frame-ancestors-equivalent header must be flagged too (INV-49).
            headers.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
            assert!(security_headers(&headers).is_some());
        }

        #[test]
        fn flags_a_non_uniform_error_body() {
            let mut headers = HeaderMap::new();
            headers.insert("cache-control", HeaderValue::from_static("no-store"));
            // Echoes the input back: a real server never does this (ADR 0028 item 3).
            let echoing = br#"{"error":"invalid_request","received":"the attacker's own input"}"#;
            assert!(uniform_error(StatusCode::BAD_REQUEST, echoing, &headers).is_some());
            // Missing Cache-Control: no-store.
            let clean = br#"{"error":"invalid_request"}"#;
            assert!(uniform_error(StatusCode::BAD_REQUEST, clean, &HeaderMap::new()).is_some());
            assert!(uniform_error(StatusCode::BAD_REQUEST, clean, &headers).is_none());
        }

        #[test]
        fn flags_another_accounts_id_in_a_response_body() {
            let victim_id = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00";
            let encoded = Base64UrlUnpadded::encode_string(victim_id);
            let leaking = [
                b"{\"ok\":true,\"device_id\":\"".as_slice(),
                encoded.as_bytes(),
                b"\"}".as_slice(),
            ]
            .concat();
            assert!(no_foreign_bytes(&leaking, victim_id, "victim").is_some());
            assert!(no_foreign_bytes(b"{\"error\":\"not_found\"}", victim_id, "victim").is_none());
        }

        #[test]
        fn flags_a_canary_secret_in_every_encoding() {
            let secret = b"the-master-password-must-never-appear";
            assert!(find_canary(secret, "raw", secret).is_some());
            let hex = hex_lower(secret);
            assert!(find_canary(hex.as_bytes(), "hex", secret).is_some());
            assert!(
                find_canary(Base64::encode_string(secret).as_bytes(), "b64-std", secret).is_some()
            );
            assert!(
                find_canary(
                    Base64Url::encode_string(secret).as_bytes(),
                    "b64-url",
                    secret
                )
                .is_some()
            );
            assert!(
                find_canary(
                    Base64UrlUnpadded::encode_string(secret).as_bytes(),
                    "b64-url-unpadded",
                    secret
                )
                .is_some()
            );
            assert!(find_canary(b"nothing interesting here at all", "clean", secret).is_none());
        }
    }
}

// ============================================================================================
// Scenario: the shared 3-account fixture.
// ============================================================================================

/// One fixture account: a durable device, its vault and the secrets its Emergency Kit held.
/// Two devices (`client`'s and `second_*`): `device.rs::revoker`'s suspension rule needs a
/// fresh OPAQUE session naming "another device in the set" and refuses one that names itself
/// (`own == target` is `InvalidRequest`), so a self-control that suspends and unsuspends a
/// device for real (`idor_matrix_across_three_accounts`) needs two (CRYPTO.md §11.8 step 0).
struct Account {
    /// The login name.
    name: String,
    /// The primary device: state, unlocked keys, device session (CRYPTO.md §5.10).
    client: Client,
    /// A second, bearer-only OPAQUE session (no device signature) over the same account.
    bare_bearer: SessionToken,
    /// The second device's unlocked keys.
    second_unlocked: UnlockedDevice,
    /// The second device's session (CRYPTO.md §5.10).
    second_session: DeviceSession,
    /// The personal vault.
    vault_id: VaultId,
    /// The Emergency Kit's Secret Key, as shown to the user.
    secret_key: String,
    /// The Emergency Kit's recovery code, as shown to the user.
    recovery_code: String,
}

impl Account {
    fn device_id(&self) -> DeviceId {
        self.client.state.device_id()
    }

    fn account_id(&self) -> AccountId {
        self.client.state.account_id()
    }
}

/// The server, its configuration (kept so [`canary`] can take a real backup after the server
/// stops) and three signed-up accounts, each with one synced item.
struct Scenario {
    server: Server,
    config: Config,
    accounts: Vec<Account>,
}

impl Scenario {
    /// Builds the fixture: a server, three accounts signed up with a recovery code, each
    /// writing and syncing one item (so `vault/fetch` has something to answer and `vault_id` is
    /// known).
    async fn build(seed: u64) -> Self {
        let dir = TempDir::new();
        let config = config_in(&dir, &[]);
        let secrets = ServerSecrets::generate(&mut ChaCha20Rng::seed_from_u64(seed));
        std::fs::write(
            &config.secrets_file,
            secrets_file::serialize(&secrets).unwrap(),
        )
        .unwrap();
        let server = Server::open(dir, &config, |_| {}).await;

        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0xA77A_C1C0);
        let mut accounts = Vec::with_capacity(NAMES.len());
        for name in NAMES {
            let (up, sk, code) = signup_named(&server, &mut rng, name, true).await;
            let mut client = Client::signed_up(&server, up).await;
            let _item = client.create(&mut rng, "seed-value");
            let rejected = client.sync(&server, &mut rng).await;
            assert!(rejected.is_empty(), "{name}: {rejected:?}");
            // Boxed, and the answer dropped at once: a verified account answer is large.
            let vault_id = Box::pin(client.refresh(&server))
                .await
                .vault_ids()
                .next()
                .unwrap();
            let logged_in = login_named(&server, &mut rng, name, &sk, None).await;
            let bare_bearer = copy_token(logged_in.bearer_token());

            // A second durable device (`Account`'s own struct docs explain why).
            let enrolling = login_named(&server, &mut rng, name, &sk, None).await;
            let enrol_token = copy_token(enrolling.bearer_token());
            let (pending, enrol_request) = enrolling
                .enrol(&mut rng, DeviceKind::DesktopCli, now_ms())
                .unwrap();
            post_empty(
                &server,
                "/api/v1/devices/enrol",
                &enrol_request,
                Auth::Bearer(&enrol_token),
            )
            .await;
            let enrolled = pending.finalize();
            let second = enrolled.device;
            let second_unlocked = enrolled.unlocked;
            let second_session = device_session(&server, &second, &second_unlocked)
                .await
                .unwrap();

            accounts.push(Account {
                name: name.to_owned(),
                client,
                bare_bearer,
                second_unlocked,
                second_session,
                vault_id,
                secret_key: sk,
                recovery_code: code.unwrap(),
            });
        }
        Self {
            server,
            config,
            accounts,
        }
    }

    /// Every secret the fixture holds, labelled, for the canary scan. The master password is
    /// shared across accounts (`rotation::PASSWORD`, by this fixture's own design, same as
    /// every other HTTP test), so it is listed once.
    fn canaries(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = vec![("master-password".to_owned(), PASSWORD.as_bytes().to_vec())];
        for account in &self.accounts {
            out.push((
                format!("{}-secret-key", account.name),
                account.secret_key.as_bytes().to_vec(),
            ));
            out.push((
                format!("{}-recovery-code", account.name),
                account.recovery_code.as_bytes().to_vec(),
            ));
        }
        out
    }
}

/// A peer address spread across the whole private range, derived from `seed`, so that no two
/// unrelated cases share a rate-limit bucket by accident (module docs: "one case's rate-limit
/// backoff never swallows the next one's answer").
fn peer_for(seed: u64) -> IpAddr {
    let bytes = seed.to_le_bytes();
    IpAddr::V4(Ipv4Addr::new(10, bytes[0], bytes[1], bytes[2].max(1)))
}

/// base64url (unpadded) of `bytes` (CRYPTO.md §9.6's wire encoding, used by every id field).
fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

// ============================================================================================
// Seed bodies: one schema-shaped JSON value per endpoint, from the wire field names
// (`rizzy-proto`'s request structs), never from a real OPAQUE/signature computation. The
// generator mutates these; the IDOR matrix substitutes a foreign id into them.
// ============================================================================================

/// A placeholder base64 string of `len` zero bytes, standing in for an opaque cryptographic
/// field (an `OpaqueMessage`, `AccountStatement` or similar) this fixture does not compute.
fn opaque(len: usize) -> String {
    b64(&vec![0u8; len])
}

/// A schema-shaped seed body for `endpoint`, using `me`'s own real ids where the field names
/// are resource ids (module docs "Not covered" for the endpoints with no real seed, module docs
/// above for the field-name sources).
#[expect(
    clippy::too_many_lines,
    reason = "one flat table of seed bodies, one arm per endpoint, reads best as one match"
)]
fn seed_value(endpoint: Endpoint, me: &Account) -> Value {
    match endpoint {
        Endpoint::RegisterStart => json!({
            "account_id": b64(&[0u8; 16]),
            "login_name": format!("{}-reg-attempt", me.name),
            "registration_request": opaque(32),
        }),
        Endpoint::RegisterFinish => json!({
            "registration_upload": opaque(192),
            "setup_id": 1,
            "account_key_server_wrap": opaque(64),
            "identity_secret_keys": opaque(64),
            "bundle": opaque(64),
            "account_state": opaque(64),
            "vault_self_grant": opaque(64),
            "recovery": Value::Null,
        }),
        Endpoint::LoginStart => json!({
            "login_name": me.name,
            "ke1": opaque(96),
        }),
        Endpoint::LoginFinish => json!({
            "login_id": b64(&[0u8; 16]),
            "ke3": opaque(64),
        }),
        Endpoint::DeviceAuthStart => json!({
            "account_id": b64(&me.account_id().to_bytes()),
            "device_id": b64(&me.device_id().to_bytes()),
        }),
        Endpoint::DeviceAuthFinish => json!({
            "account_id": b64(&me.account_id().to_bytes()),
            "device_id": b64(&me.device_id().to_bytes()),
            "challenge": opaque(32),
            "signature": opaque(SIGNATURE_CONTAINER_LEN),
        }),
        Endpoint::AccountState => json!({
            "known_bundle_seq": 0,
            "known_settings_seq": 0,
        }),
        Endpoint::EnrolDevice => json!({
            "device_certificate": opaque(96),
            "account_state": opaque(64),
        }),
        Endpoint::WebCertificate => json!({
            "device_certificate": opaque(96),
        }),
        Endpoint::AckDeviceGrants => json!({ "account_key_epoch": 0 }),
        Endpoint::PublishBundles => json!({ "bundles": [] }),
        Endpoint::PublishAccountState => json!({
            "account_state": opaque(64),
            "device_certificates": [],
            "device_revocations": [],
        }),
        Endpoint::PublishGrants => json!({
            "vault_self_grants": [],
            "device_grants": [],
        }),
        Endpoint::ReregisterStart => json!({ "registration_request": opaque(32) }),
        Endpoint::CommitChange => json!({
            "account_state": opaque(64),
            "device_certificates": [],
            "device_revocations": [],
            "account_key_server_wrap": opaque(64),
            "registration_upload": opaque(192),
            "setup_id": 1,
        }),
        Endpoint::SuspendDevice | Endpoint::UnsuspendDevice => json!({
            "device_id": b64(&me.device_id().to_bytes()),
        }),
        Endpoint::RecoveryStart | Endpoint::RecoveryComplete => json!({
            "login_name": me.name,
            "recovery_auth_token": opaque(32),
        }),
        // GET with no body (`DeviceGrants`) or a 0 body-limit endpoint (`RecoveryCancel`,
        // `TotpEnrolStart`): no body at all.
        Endpoint::DeviceGrants
        | Endpoint::RecoveryCancel
        | Endpoint::TotpEnrolStart
        | Endpoint::WebauthnEnrolStart
        | Endpoint::WebauthnList => Value::Null,
        // The empty-body `sessions` endpoints (ADR 0075 §2): no body either.
        Endpoint::SessionsList | Endpoint::SessionsCurrentEnd | Endpoint::SessionsOthersEnd => {
            Value::Null
        }
        // A well-formed id that names no session: the lookup runs and answers `404`.
        Endpoint::SessionsEnd => json!({ "session_id": b64(&[0u8; 16]) }),
        Endpoint::TotpEnrolConfirm => json!({ "totp_credential_seq": 1, "code": "123456" }),
        Endpoint::TotpDisable => json!({ "code": "123456" }),
        Endpoint::WebauthnEnrolConfirm => json!({
            "enrolment_id": b64(&[0u8; 16]),
            "label": "key",
            "credential": "{}",
        }),
        Endpoint::WebauthnRemove => json!({ "credential_id": b64(&[0u8; 32]) }),
        Endpoint::WebauthnLoginChallenge => json!({ "pending_id": b64(&[0u8; 16]) }),
        Endpoint::WebauthnLoginFinish => json!({
            "pending_id": b64(&[0u8; 16]),
            "credential": "{}",
        }),
        Endpoint::Upload => json!({
            "vault_id": b64(&me.vault_id.to_bytes()),
            "records": [],
        }),
        Endpoint::Fetch => json!({
            "vault_id": b64(&me.vault_id.to_bytes()),
            "cursor": [],
        }),
        Endpoint::Heal => json!({
            "vault_id": b64(&me.vault_id.to_bytes()),
            "item_key_wraps": [],
            "records": [],
        }),
        // ADR 0054 §6. The wrap and the chunk are opaque to the server, so zero bytes of the
        // right lengths reach the domain: a create in the account's own vault, and the other
        // four on an id nobody declared (`not_found`) unless a create case declared it first.
        Endpoint::AttachmentCreate => json!({
            "attachment_id": b64(&[0xa7; 16]),
            "vault_id": b64(&me.vault_id.to_bytes()),
            "item_id": b64(&[0u8; 16]),
            "attachment_key_wrap": opaque(122),
            "total_plaintext_len": 10,
        }),
        Endpoint::AttachmentGet | Endpoint::AttachmentDelete => json!({
            "attachment_id": b64(&[0xa7; 16]),
        }),
        Endpoint::AttachmentUploadChunk => json!({
            "attachment_id": b64(&[0xa7; 16]),
            "chunk_index": 0,
            "envelope": opaque(100),
        }),
        Endpoint::AttachmentDownloadChunk => json!({
            "attachment_id": b64(&[0xa7; 16]),
            "chunk_index": 0,
        }),
    }
}

/// `seed_value` as bytes, or an empty body for the endpoints whose body limit is 0.
fn seed_bytes(endpoint: Endpoint, me: &Account) -> Vec<u8> {
    match seed_value(endpoint, me) {
        Value::Null => Vec::new(),
        value => serde_json::to_vec(&value).unwrap(),
    }
}

fn method_str(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
    }
}

// ============================================================================================
// Sending a case: per-case panic isolation (no shared-task unwind) and the oracle.
// ============================================================================================

/// One run's outcome.
enum Outcome {
    Replied(Reply),
    Panicked(String),
}

/// Sends `request` from `peer` on its own task, so a panic inside the router is caught as a
/// `JoinError` instead of unwinding this test's loop (§7.6 "D": "A panic ... must never crash
/// the handling task" is exactly what this proves — a real panic here is a real finding, not a
/// harness crash).
async fn send_case(server: &Server, peer: IpAddr, request: Request<Body>) -> Outcome {
    let router = server.router.clone();
    match tokio::spawn(async move { send_from(router, peer, request).await }).await {
        Ok(reply) => Outcome::Replied(reply),
        Err(join_error) => Outcome::Panicked(join_error.to_string()),
    }
}

/// Runs the universal oracle over `outcome` and appends any findings to `findings`, prefixed
/// with `label`. `foreign` lists (account label, id bytes) that must not leak into the body.
/// `uniform_error` is checked only when `is_api` — ADR 0028's `{"error":"<code>"}` convention
/// is `/api/`'s own; the `web` role's 404 is deliberately a plain page (`http/mod.rs` module
/// docs: "any other path with no `web` role answers a plain `404`";
/// `headers.rs::web_role_serves_the_placeholder_under_its_csp` pins its non-JSON body).
fn check_outcome(
    label: &str,
    outcome: Outcome,
    is_api: bool,
    foreign: &[(&str, &[u8])],
    findings: &mut Vec<String>,
) -> Option<Reply> {
    match outcome {
        Outcome::Panicked(detail) => {
            findings.push(format!("{label}: {}", oracle::no_panic(detail)));
            None
        }
        Outcome::Replied(reply) => {
            if let Some(v) = oracle::no_server_error(reply.status) {
                findings.push(format!("{label}: {v}"));
            }
            if let Some(v) = oracle::security_headers(&reply.headers) {
                findings.push(format!("{label}: {v}"));
            }
            if is_api
                && let Some(v) = oracle::uniform_error(reply.status, &reply.body, &reply.headers)
            {
                findings.push(format!("{label}: {v}"));
            }
            for (who, id) in foreign {
                if let Some(v) = oracle::no_foreign_bytes(&reply.body, id, who) {
                    findings.push(format!("{label}: {v}"));
                }
            }
            Some(reply)
        }
    }
}

// ============================================================================================
// The random generator: body mutation x auth mode x endpoint.
// ============================================================================================

mod generator {
    //! [`Mutation`] and [`AuthChoice`]: the two axes the bulk tests draw combinatorially.

    /// A body mutation. `MAX_NESTING` bounds [`Mutation::DeepNesting`] (module docs "Not
    /// covered": past a safe margin, `serde_json`'s recursive-descent parser would overflow
    /// this test process's own stack, which Rust cannot catch).
    pub(crate) const MAX_NESTING: usize = 4_000;

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Mutation {
        /// No body at all.
        Empty,
        /// A random prefix of the seed.
        Truncated,
        /// One bit flipped somewhere in the seed.
        BitFlipped,
        /// The whole body replaced by a JSON value of the wrong top-level type.
        WrongTopLevelType,
        /// A random field's value replaced with `null`.
        NullField,
        /// A random field's value replaced with a mismatched JSON type.
        WrongTypeField,
        /// An unknown field added.
        ExtraField,
        /// Just over the generic body-size limit.
        Oversized,
        /// Bounded deep array nesting.
        DeepNested,
        /// A control character or a Unicode override spliced into a string field.
        ControlChars,
        /// Bytes that are not JSON at all.
        NotJson,
    }

    /// Every mutation, for a case index to pick from.
    pub(crate) const ALL: &[Mutation] = &[
        Mutation::Empty,
        Mutation::Truncated,
        Mutation::BitFlipped,
        Mutation::WrongTopLevelType,
        Mutation::NullField,
        Mutation::WrongTypeField,
        Mutation::ExtraField,
        Mutation::Oversized,
        Mutation::DeepNested,
        Mutation::ControlChars,
        Mutation::NotJson,
    ];

    /// How the case authenticates.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum AuthChoice {
        /// No `Authorization` header.
        None,
        /// 32 random-looking bytes that name no session.
        Forged,
        /// A header that is not a bearer token at all.
        Malformed,
        /// Another fixture account's real bearer token (no device signature).
        OtherBearer,
        /// Another fixture account's real, fully signed device session.
        OtherSigned,
        /// This account's bearer-only session (no device signature).
        OwnBearer,
        /// This account's fully signed device session: the positive control proving a mutated
        /// body still fails on its own after auth succeeds.
        OwnSigned,
    }

    /// Every auth mode, for a case index to pick from.
    pub(crate) const AUTH: &[AuthChoice] = &[
        AuthChoice::None,
        AuthChoice::Forged,
        AuthChoice::Malformed,
        AuthChoice::OtherBearer,
        AuthChoice::OtherSigned,
        AuthChoice::OwnBearer,
        AuthChoice::OwnSigned,
    ];
}

/// Applies `mutation` to `seed`, using `rng` for the randomised choices.
fn apply_mutation(seed: &[u8], mutation: generator::Mutation, rng: &mut ChaCha20Rng) -> Vec<u8> {
    use generator::Mutation;
    match mutation {
        Mutation::Empty => Vec::new(),
        Mutation::NotJson => {
            let len = 1 + (rng.next_u32() as usize % 64);
            let mut bytes = vec![0u8; len];
            rng.fill_bytes(&mut bytes);
            bytes
        }
        Mutation::Truncated => {
            if seed.is_empty() {
                return Vec::new();
            }
            let cut = rng.next_u32() as usize % seed.len();
            seed[..cut].to_vec()
        }
        Mutation::BitFlipped => {
            let mut bytes = seed.to_vec();
            let len = bytes.len();
            let bit = rng.next_u32() % 8;
            if len > 0
                && let Some(byte) = bytes.get_mut(rng.next_u32() as usize % len)
            {
                *byte ^= 1 << bit;
            }
            bytes
        }
        Mutation::WrongTopLevelType => {
            const CHOICES: &[&[u8]] =
                &[b"null", b"true", b"42", b"\"a string\"", b"[]", b"[1,2,3]"];
            CHOICES[rng.next_u32() as usize % CHOICES.len()].to_vec()
        }
        Mutation::Oversized => {
            let extra = rng.next_u32() as usize % 4096;
            vec![b' '; BODY_LIMIT + 1 + extra]
        }
        Mutation::DeepNested => {
            let depth = 8 + (rng.next_u32() as usize % generator::MAX_NESTING);
            let mut bytes = Vec::with_capacity(depth * 2);
            bytes.extend(std::iter::repeat_n(b'[', depth));
            bytes.extend(std::iter::repeat_n(b']', depth));
            bytes
        }
        Mutation::NullField | Mutation::WrongTypeField | Mutation::ExtraField => {
            mutate_field(seed, mutation, rng)
        }
        Mutation::ControlChars => {
            if let Ok(mut value) = serde_json::from_slice::<Value>(seed) {
                poison_first_string(&mut value);
                serde_json::to_vec(&value).unwrap_or_else(|_| seed.to_vec())
            } else {
                let mut bytes = seed.to_vec();
                bytes.extend_from_slice("\0\u{202e}\u{feff}\r\n".as_bytes());
                bytes
            }
        }
    }
}

/// [`generator::Mutation::NullField`], [`WrongTypeField`](generator::Mutation::WrongTypeField)
/// and [`ExtraField`](generator::Mutation::ExtraField): picks a field of `seed`'s top-level
/// object (if any) and mutates it.
fn mutate_field(seed: &[u8], mutation: generator::Mutation, rng: &mut ChaCha20Rng) -> Vec<u8> {
    use generator::Mutation;
    let Ok(Value::Object(mut map)) = serde_json::from_slice::<Value>(seed) else {
        return seed.to_vec();
    };
    if matches!(mutation, Mutation::ExtraField) {
        map.insert("__attack_extra_field__".to_owned(), json!("x"));
        return serde_json::to_vec(&Value::Object(map)).unwrap();
    }
    if map.is_empty() {
        return seed.to_vec();
    }
    let keys: Vec<String> = map.keys().cloned().collect();
    let key = keys[rng.next_u32() as usize % keys.len()].clone();
    let replacement = match mutation {
        Mutation::NullField => Value::Null,
        Mutation::WrongTypeField => match map.get(&key) {
            Some(Value::String(_)) => json!(12_345),
            Some(Value::Number(_)) => json!("not-a-number"),
            Some(Value::Array(_)) => json!("not-an-array"),
            Some(Value::Bool(_)) => json!("not-a-bool"),
            _ => json!([1, 2, 3]),
        },
        _ => unreachable!("guarded above"),
    };
    map.insert(key, replacement);
    serde_json::to_vec(&Value::Object(map)).unwrap()
}

/// Replaces the first string value found in `value`'s tree with control characters and a
/// Unicode right-to-left override, in place.
fn poison_first_string(value: &mut Value) -> bool {
    match value {
        Value::String(s) => {
            *s = "\0\u{202e}\u{feff}attacker-controlled-\u{0}-text".repeat(4);
            true
        }
        Value::Array(items) => items.iter_mut().any(poison_first_string),
        Value::Object(map) => map.values_mut().any(poison_first_string),
        _ => false,
    }
}

/// Builds the request for one generated case.
fn build_case_request(
    accounts: &mut [Account],
    acting: usize,
    endpoint: Endpoint,
    body: Vec<u8>,
    auth: generator::AuthChoice,
) -> Request<Body> {
    use generator::AuthChoice;
    let method = method_str(endpoint.method());
    let path = endpoint.path();
    match auth {
        AuthChoice::None => request(method, path, body, Auth::None),
        AuthChoice::OtherBearer => {
            let other = (acting + 1) % accounts.len();
            let token = copy_token(&accounts[other].bare_bearer);
            request(method, path, body, Auth::Bearer(&token))
        }
        AuthChoice::OtherSigned => {
            let other = (acting + 1) % accounts.len();
            let mut request_built = {
                let token = copy_token(accounts[other].client.session.bearer_token());
                request(method, path, body.clone(), Auth::Bearer(&token))
            };
            let signature = accounts[other]
                .client
                .session
                .sign_request(&accounts[other].client.unlocked, method, path, &body)
                .unwrap();
            request_built.headers_mut().insert(
                "rizzy-request-counter",
                HeaderValue::from_str(&signature.request_counter.to_string()).unwrap(),
            );
            request_built.headers_mut().insert(
                "rizzy-request-signature",
                HeaderValue::from_str(signature.signature.to_b64url().as_str()).unwrap(),
            );
            request_built
        }
        AuthChoice::OwnBearer => {
            let token = copy_token(&accounts[acting].bare_bearer);
            request(method, path, body, Auth::Bearer(&token))
        }
        AuthChoice::OwnSigned => {
            let client = &mut accounts[acting].client;
            request(
                method,
                path,
                body,
                Auth::Device(&mut client.session, &client.unlocked),
            )
        }
        AuthChoice::Forged | AuthChoice::Malformed => {
            let mut request_built = request(method, path, body, Auth::None);
            let value = match auth {
                AuthChoice::Forged => {
                    let token = SessionToken::new(Zeroizing::new([0x42; 32]));
                    format!("Bearer {}", token.to_b64url().as_str())
                }
                AuthChoice::Malformed => "Bearer not-a-valid-token-at-all!!".to_owned(),
                _ => unreachable!("guarded above"),
            };
            request_built
                .headers_mut()
                .insert("authorization", HeaderValue::from_str(&value).unwrap());
            request_built
        }
    }
}

/// The endpoints that end sessions (ADR 0075 R2–R4). A generated case on one of them may end
/// the fixture's own sessions, after which every later case would answer `401` and the bulk
/// run would test nothing past authentication. They are drawn instead by
/// [`session_ending_routes_under_generated_cases`], which re-opens what a case ended.
const SESSION_ENDING: &[Endpoint] = &[
    Endpoint::SessionsCurrentEnd,
    Endpoint::SessionsEnd,
    Endpoint::SessionsOthersEnd,
];

/// The endpoints the shared-fixture bulk runs draw from: every one but [`SESSION_ENDING`].
fn drawable_endpoints() -> Vec<Endpoint> {
    Endpoint::ALL
        .iter()
        .copied()
        .filter(|e| !SESSION_ENDING.contains(e))
        .collect()
}

/// Runs one generated case, checks it, and returns its endpoint and status (`None` on a
/// caught panic), for [`the_generator_reaches_past_the_parse_boundary`]'s reach histogram.
async fn run_case(
    scenario: &mut Scenario,
    seed: u64,
    findings: &mut Vec<String>,
) -> Option<(&'static str, StatusCode)> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let drawable = drawable_endpoints();
    let endpoint = drawable[rng.next_u32() as usize % drawable.len()];
    let mutation = generator::ALL[rng.next_u32() as usize % generator::ALL.len()];
    let auth = generator::AUTH[rng.next_u32() as usize % generator::AUTH.len()];
    let acting = rng.next_u32() as usize % scenario.accounts.len();

    let seed_body = seed_bytes(endpoint, &scenario.accounts[acting]);
    let body = apply_mutation(&seed_body, mutation, &mut rng);
    let request = build_case_request(&mut scenario.accounts, acting, endpoint, body, auth);
    let peer = peer_for(seed);
    let label = format!(
        "seed {seed:#x} ({:?}, {mutation:?}, {auth:?}, acting {acting})",
        endpoint.path()
    );
    let outcome = send_case(&scenario.server, peer, request).await;
    let status = match &outcome {
        Outcome::Replied(reply) => Some(reply.status),
        Outcome::Panicked(_) => None,
    };
    check_outcome(&label, outcome, true, &[], findings);
    status.map(|status| (endpoint.path(), status))
}

/// Runs `cases` generated cases on `seeds`, appending every finding to `findings`. Returns how
/// many cases actually ran, so a caller can assert it against what it asked for: a wall-clock
/// budget alone cannot tell a scaled-up run from a knob that silently stopped scaling
/// (`draw_seeds` cannot itself under-produce — `(0..cases).map(..).collect()` always has
/// `cases` elements — but this makes that fact checked at the only call sites that matter,
/// rather than assumed from timing).
async fn run_generator(
    scenario: &mut Scenario,
    cases: u32,
    seeds: Seeds,
    findings: &mut Vec<String>,
) -> usize {
    let mut ran = 0usize;
    for seed in draw_seeds(cases, seeds) {
        let _status = run_case(scenario, seed, findings).await;
        ran += 1;
    }
    ran
}

/// Endpoints whose seed body ([`seed_value`]) is a placeholder for signed or encrypted
/// material this fixture never computes (its own module docs' "Not covered"): their domain
/// call past `parse()` is realistically never reached by a generic mutation, whatever the
/// mutation. Named here, checked by [`the_generator_reaches_past_the_parse_boundary`], not
/// silently assumed.
const EXPECTED_PARSE_ONLY: &[&str] = &[paths::ACCOUNT_COMMIT];

/// The task's oracle must be falsifiable: a case whose mutated body always fails
/// deserialization proves nothing past "the router dispatches" (`api.rs::handle` parses the
/// body, inside the session check, before any domain or authorization logic runs). This test
/// measures, per endpoint, whether at least one generated case reaches a status other than
/// `400`/`401` — a `403`, `404`, `409`, `413`, `429` or `2xx` — which only happens once the
/// body parses and a domain call actually runs. Every endpoint not in [`EXPECTED_PARSE_ONLY`]
/// must clear that bar, or the generator's claimed coverage for it is unfalsifiable.
#[test]
fn the_generator_reaches_past_the_parse_boundary() {
    block_on(async {
        let mut scenario = Scenario::build(7).await;
        let mut findings = Vec::new();
        let mut histogram: BTreeMap<(&'static str, u16), usize> = BTreeMap::new();
        for seed in draw_seeds(20_000, Seeds::Fixed) {
            if let Some((path, status)) = run_case(&mut scenario, seed, &mut findings).await {
                *histogram.entry((path, status.as_u16())).or_insert(0) += 1;
            }
        }
        assert!(
            findings.is_empty(),
            "{} findings while measuring reach:\n{}",
            findings.len(),
            findings.join("\n")
        );

        let mut shallow = Vec::new();
        for endpoint in drawable_endpoints() {
            let path = endpoint.path();
            let reached_past_parse = histogram
                .keys()
                .any(|&(p, status)| p == path && status != 400 && status != 401);
            if !reached_past_parse && !EXPECTED_PARSE_ONLY.contains(&path) {
                shallow.push(path);
            }
        }
        assert!(
            shallow.is_empty(),
            "endpoints the generator never got past 400/401 on, and that are not listed in \
             EXPECTED_PARSE_ONLY: {shallow:?}\nfull histogram: {histogram:#?}"
        );
    });
}

// ============================================================================================
// IDOR matrix: every ordered pair of the three accounts, for every resource route.
// ============================================================================================

mod idor {
    //! Threat model A15 "IDOR attempts against other users' ciphertext, shares and device
    //! lists"; INV-7 "authorization check and test for every endpoint and resource type". Every
    //! case authenticates as the real acting account and names a real resource id that belongs
    //! to a different real account.
}

/// Overwrites `field` in `value` (which must be a JSON object) with `replacement`.
fn with_field(mut value: Value, field: &str, replacement: Value) -> Vec<u8> {
    if let Value::Object(map) = &mut value {
        map.insert(field.to_owned(), replacement);
    }
    serde_json::to_vec(&value).unwrap()
}

/// The IDOR matrix test (module docs [`idor`]).
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one story per resource family, matching rotation.rs's own exception"
)]
fn idor_matrix_across_three_accounts() {
    block_on(async {
        let mut scenario = Scenario::build(1).await;
        let mut rng = ChaCha20Rng::seed_from_u64(0x1D0A);
        let mut findings = Vec::new();
        let n = scenario.accounts.len();

        for acting in 0..n {
            // Self-control (advisor review): prove these bodies are not simply malformed by
            // having the acting account suspend, then immediately unsuspend, its *primary*
            // device, authenticated by a fresh OPAQUE re-authentication bound to its *second*
            // device (`device.rs::revoker`: the suspension rule needs a fresh OPAQUE session
            // naming "another device in the set", and refuses a device that names itself —
            // CRYPTO.md §11.8 step 0 — so this cannot be done with one device alone, and
            // `Account::second` exists for exactly this). A cross-account attempt below that
            // produced the *same* status as this self-success would prove nothing.
            let own_primary = scenario.accounts[acting].device_id().to_bytes();
            let name = scenario.accounts[acting].name.clone();
            let sk = scenario.accounts[acting].secret_key.clone();
            let suspend_self = with_field(
                seed_value(Endpoint::SuspendDevice, &scenario.accounts[acting]),
                "device_id",
                json!(b64(&own_primary)),
            );
            let account = &mut scenario.accounts[acting];
            let reauth = login_named(
                &scenario.server,
                &mut rng,
                &name,
                &sk,
                Some((&mut account.second_session, &account.second_unlocked)),
            )
            .await;
            let fresh = copy_token(reauth.bearer_token());
            let req = request(
                "POST",
                Endpoint::SuspendDevice.path(),
                suspend_self,
                Auth::Bearer(&fresh),
            );
            let outcome = send_case(&scenario.server, peer_for(0x5E1F), req).await;
            let self_suspend_status = check_outcome(
                &format!("idor self-control suspend acting={acting}"),
                outcome,
                true,
                &[],
                &mut findings,
            )
            .map(|reply| reply.status);
            assert_eq!(
                self_suspend_status,
                Some(StatusCode::OK),
                "acting={acting}: suspending the primary device from the second must succeed as a control"
            );
            let unsuspend_self = with_field(
                seed_value(Endpoint::UnsuspendDevice, &scenario.accounts[acting]),
                "device_id",
                json!(b64(&own_primary)),
            );
            let account = &mut scenario.accounts[acting];
            let reauth = login_named(
                &scenario.server,
                &mut rng,
                &name,
                &sk,
                Some((&mut account.second_session, &account.second_unlocked)),
            )
            .await;
            let fresh = copy_token(reauth.bearer_token());
            let req = request(
                "POST",
                Endpoint::UnsuspendDevice.path(),
                unsuspend_self,
                Auth::Bearer(&fresh),
            );
            let outcome = send_case(&scenario.server, peer_for(0x5E1F), req).await;
            let self_unsuspend_status = check_outcome(
                &format!("idor self-control unsuspend acting={acting}"),
                outcome,
                true,
                &[],
                &mut findings,
            )
            .map(|reply| reply.status);
            assert_eq!(
                self_unsuspend_status,
                Some(StatusCode::NO_CONTENT),
                "acting={acting}: unsuspending one's own device must succeed as a control"
            );
            // Suspending the primary device, even if immediately lifted, ends its sessions
            // (`device.rs::suspend_device`: "ends its sessions") — `client.session`'s bearer
            // token above does not come back on its own. Re-authenticate the primary device
            // so the vault and device-auth checks below, which use it, are not collateral
            // damage from this self-control.
            let account = &mut scenario.accounts[acting];
            account.client.session = device_session(
                &scenario.server,
                &account.client.state,
                &account.client.unlocked,
            )
            .await
            .unwrap();
            // Same control for device-auth/start: the acting account's own, correctly paired
            // (account_id, device_id) must start a challenge; a mismatched pair below must not
            // answer the same way. (`device-auth/finish` has no comparable self-control: its
            // seed body's `challenge`/`signature` are placeholders no account could ever sign
            // correctly, so it never succeeds regardless of whose ids it names — the cross-
            // account check there still holds it to "never a 2xx", just without this
            // reinforcement.)
            let start_body = serde_json::to_vec(&seed_value(
                Endpoint::DeviceAuthStart,
                &scenario.accounts[acting],
            ))
            .unwrap();
            let req = request(
                "POST",
                Endpoint::DeviceAuthStart.path(),
                start_body,
                Auth::None,
            );
            let outcome = send_case(&scenario.server, peer_for(0x5E1F), req).await;
            let self_device_auth_start_status = check_outcome(
                &format!("idor self-control device-auth/start acting={acting}"),
                outcome,
                true,
                &[],
                &mut findings,
            )
            .map(|reply| reply.status);
            assert_eq!(
                self_device_auth_start_status,
                Some(StatusCode::OK),
                "acting={acting}: a correctly paired device-auth/start must succeed as a control"
            );

            let self_status_of = |endpoint: Endpoint| match endpoint {
                Endpoint::SuspendDevice => self_suspend_status,
                Endpoint::UnsuspendDevice => self_unsuspend_status,
                Endpoint::DeviceAuthStart => self_device_auth_start_status,
                _ => None,
            };

            for victim in 0..n {
                if acting == victim {
                    continue;
                }
                let victim_device = scenario.accounts[victim].device_id().to_bytes();
                let victim_vault = scenario.accounts[victim].vault_id.to_bytes();
                let victim_account = scenario.accounts[victim].account_id().to_bytes();

                // devices/suspend and devices/unsuspend: the same fresh-OPAQUE-over-the-
                // second-device session the self-control above used (otherwise the request
                // fails on session kind alone, `fresh_session_required`, and never reaches the
                // ownership check this matrix exists to test), naming the victim's real
                // primary device id instead of the acting account's own.
                for endpoint in [Endpoint::SuspendDevice, Endpoint::UnsuspendDevice] {
                    let seed = seed_value(endpoint, &scenario.accounts[acting]);
                    let body = with_field(seed, "device_id", json!(b64(&victim_device)));
                    let account = &mut scenario.accounts[acting];
                    let reauth = login_named(
                        &scenario.server,
                        &mut rng,
                        &name,
                        &sk,
                        Some((&mut account.second_session, &account.second_unlocked)),
                    )
                    .await;
                    let fresh = copy_token(reauth.bearer_token());
                    let req = request(
                        method_str(endpoint.method()),
                        endpoint.path(),
                        body,
                        Auth::Bearer(&fresh),
                    );
                    let label =
                        format!("idor {:?} acting={acting} victim={victim}", endpoint.path());
                    let outcome = send_case(&scenario.server, peer_for(0xD00D), req).await;
                    if let Some(reply) = check_outcome(
                        &label,
                        outcome,
                        true,
                        &[("victim-device", &victim_device)],
                        &mut findings,
                    ) {
                        // `device.rs::revoker`: a device not in the acting account's own set
                        // is `AuthError::NotFound`. The self-control above proves the fresh-
                        // OPAQUE-over-the-second-device mechanics reach this far at all
                        // (`self_suspend_status`/`self_unsuspend_status` are both successes,
                        // not this `404`), so this is a real ownership check, not a session
                        // mismatch answering "not success" for an unrelated reason.
                        if reply.status != StatusCode::NOT_FOUND {
                            findings.push(format!(
                                "{label}: expected not_found for another account's device, got {} {}",
                                reply.status,
                                String::from_utf8_lossy(&reply.body)
                            ));
                        }
                        debug_assert_ne!(Some(reply.status), self_status_of(endpoint));
                    }
                }

                // vault/upload, vault/fetch, vault/heal: the acting account's real device
                // session, naming the victim's real vault id.
                for endpoint in [Endpoint::Upload, Endpoint::Fetch, Endpoint::Heal] {
                    let seed = seed_value(endpoint, &scenario.accounts[acting]);
                    let body = with_field(seed, "vault_id", json!(b64(&victim_vault)));
                    let client = &mut scenario.accounts[acting].client;
                    let req = request(
                        method_str(endpoint.method()),
                        endpoint.path(),
                        body,
                        Auth::Device(&mut client.session, &client.unlocked),
                    );
                    let label =
                        format!("idor {:?} acting={acting} victim={victim}", endpoint.path());
                    let outcome = send_case(&scenario.server, peer_for(0xFEED), req).await;
                    if let Some(reply) = check_outcome(
                        &label,
                        outcome,
                        true,
                        &[("victim-vault", &victim_vault)],
                        &mut findings,
                    ) {
                        // Threat model: "NotFound for a vault ... that belongs to another
                        // account": a cross-account vault id is never anything but a refusal.
                        if reply.status != StatusCode::NOT_FOUND {
                            findings.push(format!(
                                "{label}: expected not_found for another account's vault, got {} {}",
                                reply.status,
                                String::from_utf8_lossy(&reply.body)
                            ));
                        }
                    }
                }

                // device-auth/start and device-auth/finish: a mismatched (account, device)
                // pair across two real accounts.
                for endpoint in [Endpoint::DeviceAuthStart, Endpoint::DeviceAuthFinish] {
                    let mut body_value = seed_value(endpoint, &scenario.accounts[acting]);
                    if let Value::Object(map) = &mut body_value {
                        map.insert("account_id".to_owned(), json!(b64(&victim_account)));
                    }
                    let body = serde_json::to_vec(&body_value).unwrap();
                    let req = request(
                        method_str(endpoint.method()),
                        endpoint.path(),
                        body,
                        Auth::None,
                    );
                    let label = format!(
                        "idor {:?} account={acting} device={acting} claimed-account={victim}",
                        endpoint.path()
                    );
                    let outcome = send_case(&scenario.server, peer_for(0xACE0), req).await;
                    if let Some(reply) = check_outcome(&label, outcome, true, &[], &mut findings) {
                        if reply.status.is_success() {
                            findings.push(format!(
                                "{label}: device-auth accepted a device under another account's id"
                            ));
                        } else if Some(reply.status) == self_status_of(endpoint) {
                            findings.push(format!(
                                "{label}: answered the same as the self-control success \
                                 ({}), which proves nothing distinguishes ownership",
                                reply.status
                            ));
                        }
                    }
                }
            }
        }

        assert!(
            findings.is_empty(),
            "{} IDOR findings:\n{}",
            findings.len(),
            findings.join("\n")
        );
    });
}

// ============================================================================================
// Method confusion.
// ============================================================================================

/// Every endpoint against every method it does not serve (module docs [`method_confusion`]).
mod method_confusion {}

/// Every HTTP method the test tries against each endpoint.
const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

#[test]
fn method_confusion_across_every_endpoint() {
    block_on(async {
        let mut scenario = Scenario::build(2).await;
        let mut findings = Vec::new();

        for endpoint in Endpoint::ALL {
            let acting = 0usize;
            let body = seed_bytes(*endpoint, &scenario.accounts[acting]);
            for &method in METHODS {
                if method == method_str(endpoint.method()) {
                    continue;
                }
                let client = &mut scenario.accounts[acting].client;
                let req = request(
                    method,
                    endpoint.path(),
                    body.clone(),
                    Auth::Device(&mut client.session, &client.unlocked),
                );
                let label = format!("method-confusion {method} {:?}", endpoint.path());
                let outcome = send_case(&scenario.server, peer_for(0x3E7), req).await;
                if let Some(reply) = check_outcome(&label, outcome, true, &[], &mut findings)
                    && reply.status != StatusCode::METHOD_NOT_ALLOWED
                {
                    findings.push(format!(
                        "{label}: expected 405, got {} {}",
                        reply.status,
                        String::from_utf8_lossy(&reply.body)
                    ));
                }
            }
        }

        assert!(
            findings.is_empty(),
            "{} method-confusion findings:\n{}",
            findings.len(),
            findings.join("\n")
        );
    });
}

// ============================================================================================
// Web role: path traversal and odd paths (§7.7 "E").
// ============================================================================================

mod web_paths {}

/// Path traversal, odd encodings and null bytes tried against the `web` role.
const PATHS: &[&str] = &[
    "/../../etc/passwd",
    "/..%2f..%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/etc/passwd",
    "//etc/passwd",
    "/./../../secrets.json",
    "/\0",
    "/a/../../b",
    "/%00",
    "/api/../api/meta",
    "/web-vault/../../../../etc/passwd",
];

#[test]
fn web_role_rejects_traversal_and_odd_paths() {
    block_on(async {
        let scenario = Scenario::build(3).await;
        let mut findings = Vec::new();
        for &path in PATHS {
            let Ok(req) = Request::get(path).body(Body::empty()) else {
                continue; // an unconstructible target: skipped, not a finding.
            };
            let label = format!("web-path {path:?}");
            let outcome = send_case(&scenario.server, peer_for(0x7EA), req).await;
            if let Some(reply) = check_outcome(&label, outcome, false, &[], &mut findings) {
                // The web role never serves 2xx for a traversal attempt, and never leaks a
                // filesystem path outside the embedded asset set.
                if reply.status.is_success() {
                    findings.push(format!("{label}: served 2xx for a traversal attempt"));
                }
                if contains_sentinel(&reply.body, b"root:") {
                    findings.push(format!("{label}: response body looks like /etc/passwd"));
                }
            }
        }
        assert!(
            findings.is_empty(),
            "{} web-path findings:\n{}",
            findings.len(),
            findings.join("\n")
        );
    });
}

fn contains_sentinel(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ============================================================================================
// Replay and cross-endpoint signature reuse.
// ============================================================================================

mod replay {}

#[test]
fn signed_requests_cannot_be_replayed_or_retargeted() {
    block_on(async {
        let mut scenario = Scenario::build(4).await;
        let mut findings = Vec::new();

        // A legitimate, signed account/state request succeeds once.
        let body = seed_bytes(Endpoint::AccountState, &scenario.accounts[0]);
        let first = {
            let client = &mut scenario.accounts[0].client;
            request(
                "POST",
                Endpoint::AccountState.path(),
                body.clone(),
                Auth::Device(&mut client.session, &client.unlocked),
            )
        };
        let (authorization, counter, signature) = {
            let h = first.headers();
            (
                h.get("authorization").unwrap().clone(),
                h.get("rizzy-request-counter").unwrap().clone(),
                h.get("rizzy-request-signature").unwrap().clone(),
            )
        };
        let outcome = send_case(&scenario.server, peer_for(0x1), first).await;
        if let Some(reply) = check_outcome("replay: first send", outcome, true, &[], &mut findings)
            && reply.status != StatusCode::OK
        {
            findings.push(format!(
                "replay: the first, honest send did not succeed: {} {}",
                reply.status,
                String::from_utf8_lossy(&reply.body)
            ));
        }

        // The exact same signed request, resent byte for byte: must not be honoured twice.
        let resend = Request::post(Endpoint::AccountState.path())
            .header("authorization", authorization.clone())
            .header("rizzy-request-counter", counter.clone())
            .header("rizzy-request-signature", signature.clone())
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap();
        let outcome = send_case(&scenario.server, peer_for(0x2), resend).await;
        if let Some(reply) = check_outcome("replay: resend", outcome, true, &[], &mut findings)
            && reply.status == StatusCode::OK
        {
            findings
                .push("replay: an exact resend of a signed request was honoured twice".to_owned());
        }

        // The same signature, counter and body, retargeted at a different endpoint: the
        // signed bytes no longer match what was sent, so this must fail too.
        let retargeted = Request::post(Endpoint::RecoveryCancel.path())
            .header("authorization", authorization)
            .header("rizzy-request-counter", counter)
            .header("rizzy-request-signature", signature)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let outcome = send_case(&scenario.server, peer_for(0x3), retargeted).await;
        if let Some(reply) = check_outcome(
            "replay: cross-endpoint retarget",
            outcome,
            true,
            &[],
            &mut findings,
        ) && reply.status == StatusCode::OK
        {
            findings
                .push("replay: a signature made for one endpoint verified on another".to_owned());
        }

        assert!(
            findings.is_empty(),
            "{} replay findings:\n{}",
            findings.len(),
            findings.join("\n")
        );
    });
}

// ============================================================================================
// INV-7's lockout-protection exemption.
// ============================================================================================

mod lockout {}

#[test]
fn an_unauthenticated_flood_never_blocks_the_real_accounts_reauth() {
    block_on(async {
        let mut scenario = Scenario::build(5).await;
        let target_name = scenario.accounts[0].name.clone();
        let sk = scenario.accounts[0].secret_key.clone();

        // Flood OPAQUE login attempts against the real name, from one source, well past the
        // (name, source) backoff (conventions.rs: five lets through, twelve exhausts it).
        let mut rng = ChaCha20Rng::seed_from_u64(0x5100D);
        let mut saw_rate_limited = false;
        for _ in 0..30 {
            let body = json!({ "login_name": target_name, "ke1": opaque(96) });
            let req = request(
                "POST",
                Endpoint::LoginStart.path(),
                serde_json::to_vec(&body).unwrap(),
                Auth::None,
            );
            let reply = match send_case(&scenario.server, peer_for(0x5EED), req).await {
                Outcome::Replied(reply) => reply,
                Outcome::Panicked(detail) => panic!("lockout flood panicked: {detail}"),
            };
            if reply.status == StatusCode::TOO_MANY_REQUESTS {
                saw_rate_limited = true;
                break;
            }
            rng.next_u32(); // keep the seed stream distinct from other tests, no other effect.
        }
        assert!(saw_rate_limited, "the flood never reached rate_limited");

        // The account's own device re-authenticates over its existing session regardless
        // (INV-7: "OPAQUE attempts that arrive inside a device-authenticated session therefore
        // use their own bucket, which unauthenticated floods cannot exhaust").
        let client = &mut scenario.accounts[0].client;
        let logged_in = login_named(
            &scenario.server,
            &mut rng,
            &target_name,
            &sk,
            Some((&mut client.session, &client.unlocked)),
        )
        .await;
        drop(logged_in); // reaching this line without panicking is the assertion: see rotation.rs.
    });
}

// ============================================================================================
// X-Forwarded-For spoofing from an untrusted peer.
// ============================================================================================

mod xff {}

/// [ADR 0028] item 11 / INV-7 / threat model §7.6 "S" ("XFF trusted only from configured
/// proxies"). The fixture's server is given no `TRUSTED_PROXIES` ([`config_in`]), so an
/// attacker forging `X-Forwarded-For` must never (a) escape its own rate-limit bucket by
/// rotating the header, and must never (b) get its flood attributed to a real client's own
/// bucket by naming that client's address in the header.
///
/// `conventions.rs`'s `a_trusted_proxy_without_a_client_address_is_refused` and
/// `the_rate_limit_source_is_the_forwarded_client` already pin this rule end to end against a
/// real configured proxy (both the trusted and the untrusted side); this test is the same
/// untrusted-peer property, against the bulk fixture's own accounts, so the attack module does
/// not rely on `conventions.rs` alone for an attacker-model row it otherwise exercises.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
#[test]
fn x_forwarded_for_from_an_untrusted_peer_is_never_attributed() {
    block_on(async {
        let scenario = Scenario::build(11).await;
        let victim_name = scenario.accounts[0].name.clone();
        let victim_peer = peer_for(0x0A01); // the victim's own, real source address.
        let attacker_peer = peer_for(0x0A02); // an unrelated attacker, a different real peer.
        let control_peer = peer_for(0x0A03); // a third peer, never named by any forged header.
        let mut findings = Vec::new();

        // The attacker floods the victim's login name from a DIFFERENT real peer, forging
        // `X-Forwarded-For` as the victim's own address on every request — hoping the server
        // attributes the abuse to the victim's bucket instead of the attacker's own.
        let mut attacker_rate_limited = false;
        for i in 0..30 {
            let body = json!({ "login_name": victim_name, "ke1": opaque(96) });
            let forged = format!("{victim_peer}, 203.0.113.{i}");
            let req = Request::builder()
                .method("POST")
                .uri(Endpoint::LoginStart.path())
                .header("content-type", "application/json")
                .header("x-forwarded-for", forged)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            let outcome = send_case(&scenario.server, attacker_peer, req).await;
            let Some(reply) = check_outcome("xff forged flood", outcome, true, &[], &mut findings)
            else {
                continue;
            };
            if reply.status == StatusCode::TOO_MANY_REQUESTS {
                attacker_rate_limited = true;
                break;
            }
        }
        assert!(findings.is_empty(), "{}", findings.join("\n"));
        assert!(
            attacker_rate_limited,
            "the forged-XFF flood from the attacker's own peer never hit a rate limit: either \
             the server is not bucketing by the real peer, or the forged header is being read \
             from an untrusted peer"
        );

        // Drain the victim's OWN real bucket (no forged header at all) and an untouched
        // control peer's bucket for the SAME login name, both from a clean start, counting
        // attempts to the first `429` each. If even one count from the attacker's forged-XFF
        // flood above landed in the victim's bucket, its drain is shorter than the control's
        // by that many; if the header was correctly ignored, the two match exactly. This pins
        // the property against no hardcoded limiter constant, so it survives that limit
        // changing later.
        let victim_attempts =
            drain_login_bucket(&scenario.server, victim_peer, &victim_name, &mut findings).await;
        let control_attempts =
            drain_login_bucket(&scenario.server, control_peer, &victim_name, &mut findings).await;
        assert!(findings.is_empty(), "{}", findings.join("\n"));
        assert_eq!(
            victim_attempts, control_attempts,
            "the victim's own bucket allows {victim_attempts} attempts before a 429, a real \
             peer untouched by the attack allows {control_attempts}: the attacker's forged-XFF \
             flood leaked into the victim's bucket, keyed on its real address"
        );
    });
}

/// How many clean `login/start` attempts [`drain_login_bucket`] will send before concluding the
/// limiter is broken rather than counting forever.
const XFF_DRAIN_CAP: u32 = 30;

/// Sends unauthenticated `login/start` attempts for `login_name` from `peer`, with no
/// `X-Forwarded-For` header, until the first `429` or [`XFF_DRAIN_CAP`] is reached. Returns the
/// number of attempts that were NOT `429` (so a clean, untouched bucket and this one can be
/// compared by that count alone, with no assumption about what the limit's actual number is).
async fn drain_login_bucket(
    server: &Server,
    peer: IpAddr,
    login_name: &str,
    findings: &mut Vec<String>,
) -> u32 {
    for attempt in 0..XFF_DRAIN_CAP {
        let body = json!({ "login_name": login_name, "ke1": opaque(96) });
        let req = request(
            "POST",
            Endpoint::LoginStart.path(),
            serde_json::to_vec(&body).unwrap(),
            Auth::None,
        );
        let outcome = send_case(server, peer, req).await;
        let Some(reply) = check_outcome("xff drain", outcome, true, &[], findings) else {
            continue;
        };
        if reply.status == StatusCode::TOO_MANY_REQUESTS {
            return attempt;
        }
    }
    panic!(
        "{peer}'s bucket for {login_name:?} never hit a rate limit within {XFF_DRAIN_CAP} \
         attempts: the drain helper or the fixture is broken, not just the property under test"
    );
}

// ============================================================================================
// Canary scan: the quiesced database, the secrets file and a real backup.
// ============================================================================================

mod canary {}

/// Recursively collects every regular file under `root`.
fn files_under(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// What [`scan_for_canaries`] actually examined, so a clean result can be told apart from one
/// that silently touched nothing (a `std::fs::read` failure used to be swallowed with no count).
#[derive(Default, Clone, Copy)]
struct ScanStats {
    files: usize,
    bytes: usize,
}

/// Scans every file under `root` for `secrets`, appending findings to `findings`. Returns how
/// many files and bytes were actually read, so a caller can assert the scan was not vacuous.
fn scan_for_canaries(
    root: &Path,
    secrets: &[(String, Vec<u8>)],
    findings: &mut Vec<String>,
) -> ScanStats {
    let mut files = Vec::new();
    files_under(root, &mut files);
    let mut stats = ScanStats::default();
    for file in files {
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        stats.files += 1;
        stats.bytes += bytes.len();
        for (name, secret) in secrets {
            if let Some(v) = oracle::find_canary(&bytes, name, secret) {
                findings.push(format!("{}: {v}", file.display()));
            }
        }
    }
    stats
}

#[test]
fn canary_scan_finds_no_secrets_after_a_bulk_run() {
    block_on(async {
        let mut scenario = Scenario::build(6).await;
        let secrets = scenario.canaries();

        // A representative slice of the bulk generator, so the database holds a realistic
        // amount of adversarial traffic before the scan (task: "after a full bulk run").
        let mut findings = Vec::new();
        let ran = run_generator(&mut scenario, 300, Seeds::Fixed, &mut findings).await;
        assert_eq!(
            ran, 300,
            "the canary fixture's own generator slice did not run every case"
        );
        assert!(
            findings.is_empty(),
            "the canary fixture's own generator slice found violations:\n{}",
            findings.join("\n")
        );

        let data_dir = scenario.config.data_dir.clone();
        let secrets_path = scenario.config.secrets_file.clone();
        let backup_path = scenario
            .config
            .data_dir
            .with_file_name("attack-canary.backup");

        let dir = scenario.server.stop().await;
        rizzy_server::admin::backup(&scenario.config, &backup_path, false)
            .await
            .expect(
                "the canary fixture's own backup must succeed, or the backup-file check below \
                 is vacuous",
            );

        // Positive control: plant one of the fixture's real canaries into the data dir and
        // confirm the SAME walker the clean assertion below trusts flags it. The oracle's own
        // unit positive controls (`oracle::positive_controls`) only prove `find_canary` works on
        // a buffer handed to it directly; this proves the file-walking machinery reaches the
        // real data dir.
        let planted_path = data_dir.join("attack-canary-plant.tmp");
        let (plant_name, plant_secret) = secrets
            .first()
            .expect("the fixture always has at least one account's canaries");
        std::fs::write(&planted_path, plant_secret).expect("can write the planted-canary file");
        let mut plant_findings = Vec::new();
        let plant_stats = scan_for_canaries(&data_dir, &secrets, &mut plant_findings);
        std::fs::remove_file(&planted_path).expect("can remove the planted-canary file");
        assert!(
            plant_findings
                .iter()
                .any(|f| f.contains(plant_name.as_str()) && f.contains("attack-canary-plant.tmp")),
            "the walker did not flag a planted canary ({plant_name}) under {}; it is not \
             reaching the real data dir",
            data_dir.display()
        );

        let mut leaks = Vec::new();
        let stats = scan_for_canaries(&data_dir, &secrets, &mut leaks);
        assert!(
            stats.files > 0 && stats.bytes > 0,
            "the data-dir scan examined {} files / {} bytes under {}: the clean result below \
             would be vacuous",
            stats.files,
            stats.bytes,
            data_dir.display()
        );
        assert_eq!(
            stats.files,
            plant_stats.files - 1,
            "the real scan ({} files, plant removed) should see exactly one fewer file than the \
             plant scan ({} files)",
            stats.files,
            plant_stats.files
        );

        let secrets_bytes =
            std::fs::read(&secrets_path).expect("the secrets file must exist and be readable");
        assert!(
            !secrets_bytes.is_empty(),
            "the secrets file must not be empty"
        );
        for (name, secret) in &secrets {
            if let Some(v) = oracle::find_canary(&secrets_bytes, name, secret) {
                leaks.push(format!("{}: {v}", secrets_path.display()));
            }
        }

        let backup_bytes =
            std::fs::read(&backup_path).expect("the backup file must exist and be readable");
        assert!(
            !backup_bytes.is_empty(),
            "the backup file must not be empty"
        );
        for (name, secret) in &secrets {
            if let Some(v) = oracle::find_canary(&backup_bytes, name, secret) {
                leaks.push(format!("{}: {v}", backup_path.display()));
            }
        }

        std::fs::remove_file(&backup_path).expect("can remove the canary-run backup file");
        drop(dir);

        assert!(
            leaks.is_empty(),
            "{} canary leaks:\n{}",
            leaks.len(),
            leaks.join("\n")
        );
    });
}

// ============================================================================================
// The two budgets.
// ============================================================================================

/// The PR budget: [`PR_CASES`] on proptest's deterministic RNG, plus one run each of the
/// exhaustive sub-suites, all against one shared fixture.
#[test]
fn bulk_fuzz_pr_budget() {
    block_on(async {
        let mut scenario = Scenario::build(42).await;
        let mut findings = Vec::new();
        let ran = run_generator(&mut scenario, PR_CASES, Seeds::Fixed, &mut findings).await;
        assert_eq!(
            ran, PR_CASES as usize,
            "the PR-budget run did not actually run every requested case"
        );
        assert!(
            findings.is_empty(),
            "{} bulk-fuzz findings (PR budget):\n{}",
            findings.len(),
            findings.join("\n")
        );
    });
}

/// The nightly budget: [`NIGHTLY_MULTIPLIER`] (or `RIZZY_ATTACK_MULTIPLIER`) times
/// [`PR_CASES`], on fresh seeds. No CI job runs it yet (`.github/workflows/` is the owner's to
/// change, CLAUDE.md); the job it needs is `cargo test -p rizzy-server --locked -- --ignored
/// bulk_fuzz_nightly`, on a schedule.
#[test]
#[ignore = "nightly budget: RIZZY_ATTACK_MULTIPLIER (default 20) times the PR cases, fresh seeds"]
fn bulk_fuzz_nightly() {
    block_on(async {
        let multiplier: u32 = std::env::var("RIZZY_ATTACK_MULTIPLIER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(NIGHTLY_MULTIPLIER);
        let mut scenario = Scenario::build(43).await;
        let mut findings = Vec::new();
        let requested = PR_CASES * multiplier;
        let ran = run_generator(&mut scenario, requested, Seeds::Fresh, &mut findings).await;
        assert_eq!(
            ran, requested as usize,
            "the nightly run (x{multiplier}) did not actually run every requested case: a \
             dead RIZZY_ATTACK_MULTIPLIER or a generator that stops early would still finish \
             fast and green without this"
        );
        assert!(
            findings.is_empty(),
            "{} bulk-fuzz findings (nightly, x{multiplier}):\n{}",
            findings.len(),
            findings.join("\n")
        );
    });
}

/// The generated cases of [`run_case`] on the [`SESSION_ENDING`] endpoints, each followed by
/// re-opening every fixture session the case ended (a device session by device
/// authentication, the bearer-only one by a new login), so the next case starts from the same
/// fixture. The oracle is the bulk runs' own.
#[test]
fn session_ending_routes_under_generated_cases() {
    block_on(async {
        let mut scenario = Scenario::build(75).await;
        let mut findings = Vec::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0x0075_5E55);
        let mut reached = BTreeMap::<&'static str, usize>::new();
        for seed in draw_seeds(240, Seeds::Fixed) {
            let mut case_rng = ChaCha20Rng::seed_from_u64(seed);
            let endpoint = SESSION_ENDING[case_rng.next_u32() as usize % SESSION_ENDING.len()];
            let mutation = generator::ALL[case_rng.next_u32() as usize % generator::ALL.len()];
            let auth = generator::AUTH[case_rng.next_u32() as usize % generator::AUTH.len()];
            let acting = case_rng.next_u32() as usize % scenario.accounts.len();
            let seed_body = seed_bytes(endpoint, &scenario.accounts[acting]);
            let body = apply_mutation(&seed_body, mutation, &mut case_rng);
            let request = build_case_request(&mut scenario.accounts, acting, endpoint, body, auth);
            let label = format!(
                "seed {seed:#x} ({:?}, {mutation:?}, {auth:?}, acting {acting})",
                endpoint.path()
            );
            let outcome = send_case(&scenario.server, peer_for(seed), request).await;
            if let Outcome::Replied(reply) = &outcome
                && reply.status != StatusCode::BAD_REQUEST
                && reply.status != StatusCode::UNAUTHORIZED
            {
                *reached.entry(endpoint.path()).or_insert(0) += 1;
            }
            check_outcome(&label, outcome, true, &[], &mut findings);
            scenario.reopen_sessions(&mut rng).await;
        }
        assert!(
            findings.is_empty(),
            "{} findings on the session-ending routes:\n{}",
            findings.len(),
            findings.join("\n")
        );
        for endpoint in SESSION_ENDING {
            assert!(
                reached.contains_key(endpoint.path()),
                "never past 400/401: {:?}; reached {reached:?}",
                endpoint.path()
            );
        }
    });
}

impl Scenario {
    /// Re-opens every fixture session a [`SESSION_ENDING`] case ended.
    async fn reopen_sessions(&mut self, rng: &mut ChaCha20Rng) {
        for account in &mut self.accounts {
            let alive = call(
                &self.server,
                "POST",
                paths::SESSIONS_LIST,
                Vec::new(),
                Auth::Bearer(&copy_token(&account.bare_bearer)),
            )
            .await;
            if alive.status == StatusCode::UNAUTHORIZED {
                let logged_in =
                    login_named(&self.server, rng, &account.name, &account.secret_key, None).await;
                account.bare_bearer = copy_token(logged_in.bearer_token());
            }
            let client = &mut account.client;
            let alive = call(
                &self.server,
                "POST",
                paths::SESSIONS_LIST,
                Vec::new(),
                Auth::Device(&mut client.session, &client.unlocked),
            )
            .await;
            if alive.status == StatusCode::UNAUTHORIZED {
                client.session = device_session(&self.server, &client.state, &client.unlocked)
                    .await
                    .unwrap();
            }
        }
    }
}

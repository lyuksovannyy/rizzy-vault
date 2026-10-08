//! Fuzzes rizzy-wasm's readers of what JavaScript hands in (ADR 0013 §3 rule 8: "Host input is
//! untrusted"): never panic, and every accepted value is what it claims to be.
//!
//! The first two bytes are a status code, the rest a response body, then, read as UTF-8 and
//! split at NUL, four strings:
//!
//! - `checkMeta` and `expectNoContent` on the status and body: an error or success, never a
//!   panic; a success of `expectNoContent` is a `204` with no body.
//! - `parse_id` on each string: an accepted id is 32 hex digits and formats back to the same
//!   digits in lower case.
//! - An `ItemDraft` fed every string through every entry kind: it never holds more than
//!   `MAX_DRAFT_ENTRIES` entries.
//! - `LoginFlow::start` and `SignupFlow::start` on the strings as origin, login name, Secret
//!   Key and password: a flow that starts has its first request outstanding, to the right path,
//!   with a JSON body. No answer is passed in, so no Argon2id runs. The Secret Key and password
//!   arrays hold zeroes after the call, whatever its outcome.
//! - `EnrolFlow::start` on the same four strings: as `LoginFlow::start` above.
//! - `DeviceSession::unlock` on a `KvRow` built from the four strings and the body (the
//!   byte-blob cache dump a host's `IndexedDB` adapter hands in, ADR 0026 §3; `d` as the
//!   password): never a panic, whatever the store name, key or value.
//! - `decideMatchCandidates`/`normalizePageUrl` on the same strings as a page URL, a frame
//!   origin and one saved URI's value: never a panic for any `MatchMode` wire value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_wasm::items::{MAX_DRAFT_ENTRIES, hex, parse_id};
use rizzy_wasm::matching::{UriInput, decide_match_candidates, normalize_page_url};
use rizzy_wasm::store::KvRow;
use rizzy_wasm::{
    DeviceSession, EnrolFlow, ItemDraft, LoginFlow, SignupFlow, check_meta, expect_no_content,
};

fuzz_target!(|data: &[u8]| {
    let (head, body) = data.split_at(data.len().min(2));
    let status = match head {
        [a, b] => u16::from_be_bytes([*a, *b]),
        _ => 0,
    };
    let _ = check_meta(status, body);
    if expect_no_content(status, body).is_ok() {
        assert!(status == 204 && body.is_empty());
    }
    let Ok(text) = core::str::from_utf8(body) else {
        return;
    };
    let mut parts = text.split('\0');
    let mut next = || parts.next().unwrap_or("");
    let (a, b, c, d) = (next(), next(), next(), next());

    for s in [a, b, c, d] {
        if let Ok(id) = parse_id(s) {
            assert_eq!(hex(&id), s.to_ascii_lowercase());
        }
    }

    let mut draft = ItemDraft::new();
    for _ in 0..2 {
        for s in [a, b, c, d] {
            let _ = draft.set(s, b);
            let _ = draft.clear(s);
            let _ = draft.tag(s);
            let _ = draft.untag(s);
            let _ = draft.add_uri(s, d);
            let _ = draft.add_custom_field(s, a, c, d);
            let _ = draft.move_element(s, a, c, Some(d.to_owned()));
            let _ = draft.remove_element(s, d);
        }
    }
    assert!(draft.length() <= MAX_DRAFT_ENTRIES);

    // The secrets cross as byte arrays the call zeroes, whatever its outcome.
    let mut secret_key = c.as_bytes().to_vec();
    let mut password = d.as_bytes().to_vec();
    let login = LoginFlow::start(a, b, &mut secret_key, &mut password, None);
    assert!(secret_key.iter().chain(&password).all(|&byte| byte == 0));
    if let Ok(flow) = login {
        assert_eq!(flow.state(), "request");
        let request = flow.request().expect("a started login has a request");
        assert_eq!(request.path(), "/api/v1/login/start");
        let body = request.body().expect("login/start has a body");
        assert!(serde_json::from_slice::<serde_json::Value>(&body).is_ok());
    }
    let mut password = d.as_bytes().to_vec();
    let signup = SignupFlow::start(a, b, &mut password, None, true, 0);
    assert!(password.iter().all(|&byte| byte == 0));
    if let Ok(flow) = signup {
        assert_eq!(flow.state(), "request");
        let request = flow.request().expect("a started signup has a request");
        assert_eq!(request.path(), "/api/v1/register/start");
    }

    let mut secret_key = c.as_bytes().to_vec();
    let mut password = d.as_bytes().to_vec();
    let enrol = EnrolFlow::start(a, b, &mut secret_key, &mut password, None);
    assert!(secret_key.iter().chain(&password).all(|&byte| byte == 0));
    if let Ok(flow) = enrol {
        assert_eq!(flow.state(), "request");
        let request = flow.request().expect("a started enrolment has a request");
        assert_eq!(request.path(), "/api/v1/login/start");
    }

    // The byte-blob cache dump a host's IndexedDB adapter hands in (ADR 0026 §3): never a
    // panic for any store name, key or value, and never a success from a single arbitrary row
    // (a complete, consistent cache needs every row cache format 1 defines).
    let rows = vec![KvRow::from_js(a.to_owned(), c.as_bytes().to_vec(), body.to_vec())];
    let mut password = d.as_bytes().to_vec();
    let unlocked = DeviceSession::unlock(rows, &mut password, 0);
    assert!(password.iter().all(|&byte| byte == 0));
    assert!(unlocked.is_err());

    // The matcher (ADR 0037): never a panic for any page URL, frame origin, saved URI or wire
    // mode value, including one `decide_match_candidates` does not recognise.
    let _ = normalize_page_url(a);
    let mode = u16::from(data.first().copied().unwrap_or(0));
    let uris = vec![UriInput::new(a.to_owned(), b.to_owned(), c.to_owned(), mode)];
    let _ = decide_match_candidates(a, true, b, mode, uris.clone());
    let _ = decide_match_candidates(a, false, b, mode, uris);
});

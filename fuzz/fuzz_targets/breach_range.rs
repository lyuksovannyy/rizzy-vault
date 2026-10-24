// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes the breach-check range parser (CRYPTO.md §11.16; ADR 0053): the upstream's
//! `SUFFIX:COUNT` body is untrusted twice, once in the `icons` role (from the upstream) and
//! once in the client (from the server).
//!
//! On arbitrary bytes: `RangeBody::from_bytes` and `parse_range` never panic and agree; an
//! accepted body is at most `MAX_BREACH_RANGE_LEN` bytes with at most
//! `MAX_BREACH_RANGE_ENTRIES` entries, each a 35-character uppercase hex suffix; the client's
//! constant-time verdict over it never panics and only reports a count the body holds. The
//! same bytes as a JSON `BreachRangeResponse` and `BreachRangeRequest` never panic either.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::breach::{BreachCheck, BreachVerdict};
use rizzy_proto::breach::{
    BreachRangeRequest, BreachRangeResponse, RangeBody, SUFFIX_LEN, parse_range,
};
use rizzy_proto::limits::{MAX_BREACH_RANGE_ENTRIES, MAX_BREACH_RANGE_LEN};

fuzz_target!(|data: &[u8]| {
    let body = RangeBody::from_bytes(data);
    let parsed = core::str::from_utf8(data).ok().map(parse_range);
    match (&body, parsed) {
        (Ok(body), Some(Ok(entries))) => {
            assert!(data.len() <= MAX_BREACH_RANGE_LEN);
            assert!(entries.len() <= MAX_BREACH_RANGE_ENTRIES);
            assert_eq!(body.entries(), entries);
            for e in &entries {
                assert_eq!(e.suffix.len(), SUFFIX_LEN);
                assert!(
                    e.suffix
                        .iter()
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(b))
                );
            }
            let response = BreachRangeResponse {
                range: body.clone(),
            };
            let (check, _) = BreachCheck::start("password").expect("a check");
            if let BreachVerdict::Found { count } = check.finish(&response) {
                assert!(count > 0 && entries.iter().any(|e| e.count == count));
            }
        }
        (Err(_), None | Some(Err(_))) => {}
        _ => panic!("RangeBody::from_bytes and parse_range disagree"),
    }
    let _ = serde_json::from_slice::<BreachRangeResponse>(data);
    let _ = serde_json::from_slice::<BreachRangeRequest>(data);
});

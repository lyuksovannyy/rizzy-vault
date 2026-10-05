# ADR 0033: Protocol Buffers encoding for client–server messages

- Status: Proposed
- Date: 2026-10-05
- Deciders: project owner
- Milestone: M1 (JSON stays the only `/api/v1` encoding) / M3 (the trigger below is checked again when `rizzy-ffi` lands)

## Context

The owner asked for an ADR "for supporting protobuf between clients". Clients never talk to each other: every client message goes to the server and back, so this ADR reads the request as the `/api/v1` bodies that all clients exchange with the server. [ROADMAP](../ROADMAP.md) has no row for a second wire encoding; adopting one would need a ROADMAP edit the owner approves.

Today (V, e60d7be):

- [ADR 0002](0002-own-protocol.md) point 3 fixes "JSON over HTTPS", binary fields as base64url without padding ([CRYPTO.md §9.6](../CRYPTO.md#96-encoding-for-transport-and-storage)), one definition of the types in `rizzy-proto`, and a generated, checked-in OpenAPI 3.1 file whose generator is not chosen yet ([ADR 0028](0028-api-v1-http-conventions.md) open question 4). ADR 0002's alternatives already rejected "gRPC or another binary RPC": harder from a browser and from `curl`, and "ciphertext dominates message size either way".
- [ADR 0028](0028-api-v1-http-conventions.md) item 2 answers `200` with `Content-Type: application/json`; item 3 makes every error `{"error":"<code>"}`; item 9 forbids response compression under `/api/` (BREACH-style length oracles), so base64url's 4/3 overhead is never compressed away.
- `rizzy-proto` types carry their limits in the type (`wire::Bytes<MAX>`, `Text`, `List` with a count cap checked while parsing and at most 64 elements reserved up front), refuse unknown fields in every request type (so no field can carry `E_dev`, CRYPTO.md §11.1 step 8), and ignore unknown fields in responses (additive changes). The `proto_json` fuzz target parses all 42 types from arbitrary bytes and requires one JSON form per accepted value.
- **The encoding is under the signature.** The `device-request` statement signs `str(method) ‖ str(path_and_query) ‖ SHA-256(request body)` ([CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication), §10.2; `rizzy-core` `DeviceRequest::body_hash`), over the raw bytes as sent; the server hashes the body as received (ADR 0028 item 6 (f)) before it parses it (g). `Content-Type` and every other header are outside the signed message (ADR 0028 item 5). So the body bytes, not the decoded value, are what a device key vouches for, and today the server reads them one way only.
- **All clients share Rust.** `rv`, the web vault (`rizzy-wasm`; `packages/core` and `apps/web` only carry bytes to `fetch`, JS never parses an API body) and the M3/M7 native apps (`rizzy-ffi`, `rizzy-ffi-cpp`, [ADR 0019](0019-native-clients.md)) all build and parse bodies in `rizzy-client` with the `rizzy-proto` types ([ADR 0013](0013-shared-client-core.md)). Protobuf's main benefit, generated types for many languages, buys nothing here.
- Idempotent repeats compare carried fields (statements, envelopes, grants), not request bodies (V, `rizzy-domain-vault` `store.rs`, `rizzy-domain-auth` `ports.rs`), so a body's encoding does not affect them.

Crate facts (V unless marked; local registry and RustSec DB at 2026-10-01, a scratch edit to `crates/rizzy-proto/Cargo.toml` that was reverted, `git status` clean afterwards):

- `prost` 0.14.4 with `default-features = false, features = ["derive"]` adds `prost`, `prost-derive`, `anyhow`, `itertools` (and `either`, `bytes` already locked) to `rizzy-proto`'s wasm32 closure. Licences: prost Apache-2.0; bytes MIT; anyhow, itertools MIT OR Apache-2.0. Maintained under `tokio-rs/prost` (authors listed: Dan Burkert, Lucio Franco, Casper Meijn; current maintainer set U). MSRV 1.85.
- `prost-build` 0.14.4 as a build dependency adds 17 crates to `Cargo.lock` (petgraph, multimap, prettyplease, regex, tempfile, a third `hashbrown`, …) and needs the `protoc` binary at build time (`PROTOC` or `PATH`, `prost-build` `config.rs`); `protoc` is a C++ binary outside cargo, cargo-deny and our pins.
- `cargo deny check` passed in both scratch states with no `deny.toml` change (a `version = "*"` first failed `bans` as a wildcard; an exact pin passed).
- RustSec: RUSTSEC-2020-0002 (prost < 0.6.1, stack overflow on crafted input), RUSTSEC-2021-0073 (prost-types < 0.8), RUSTSEC-2026-0007 (bytes < 1.11.1, `BytesMut::reserve` overflow); none affects the versions above. The `protobuf` crate (not prost) has RUSTSEC-2019-0003 and RUSTSEC-2024-0437.
- `unsafe`: `prost` has 13 source lines mentioning `unsafe` (`encoding.rs`, `varint.rs`), `bytes` about 150; `bytes` is already in the lock file today.
- Decoder behaviour: `prost` limits nesting to 100 (`RECURSION_LIMIT`) unless the `no-recursion-limit` feature is on; derived decoders **skip unknown fields** (`prost-derive` `lib.rs`, `skip_field`) with no option to refuse them; repeated fields `push` per element with **no count cap**; derived fields must be prost's own types, not `wire::Bytes<MAX>`.
- wasm size: not measured. The `prost` runtime is small (U, tens of KiB), but `serde_json` stays in `rizzy-wasm` for `/api/meta`, errors, exports and imports, so the bundle grows and nothing is removed (L).

## Decision

1. **Not now.** `/api/v1` keeps JSON as its only body encoding. No `application/protobuf` (or `application/x-protobuf`) content type, `.proto` file, `prost`, `prost-build` or `protoc` enters the workspace in M1. ADR 0002 point 3 and ADR 0028 item 2 stand unchanged.
2. **Why.** For an all-Rust client set the only gain is size and parse time: about 25 % of a body dominated by base64url ciphertext (L: 4/3 inflation, arithmetic). Against it: a second parser over hostile input on both sides; prost cannot refuse unknown request fields (the rule that keeps device-only secrets off the wire); no count caps during decode (a 32 MiB `vault/upload` body could expand into millions of small structs before validation, U how many); a non-canonical encoding under a signature; `protoc` as an unpinned build-time binary; a second set of vectors and fuzz targets; and nothing removed from the bundle.
3. **Revisit trigger** (any one): (a) on the M3 reference desktop or the M7 reference phone, JSON encoding, decoding and base64url together take ≥ 20 % of client wall time of a full `vault/fetch` of a 5,000-item account, measured with the `rizzy-client` benchmark that ADR would add; (b) a single maximal record no longer fits the default upload limit only because of base64url (today a 16 MiB envelope with a 1.5 MiB statement is about 23.4 MiB of JSON under 32 MiB); (c) the owner puts a non-Rust client or a third-party SDK in ROADMAP scope. The trigger is checked when `rizzy-ffi` lands (M3).
4. **Binding constraints on any later ADR** that adopts protobuf, so the work is not redone:
   - **Beside JSON, never replacing it** within `v1`; JSON remains the default for `curl`, `/api/meta` and every error body (ADR 0028 item 3).
   - **The encoding is signed.** A body must have one meaning under a device signature. The encoding is chosen by the **path** (for example a parallel `/api/v1/pb/…` tree), which is already signed, not by `Content-Type`, which is not; or else by a new `device-request` statement version that binds the content type (a CRYPTO.md change with vectors). Disjointness of the two parsers (a JSON body starts with `{`, which protobuf reads as field 15, start-group) must not be relied on.
   - **Never re-encode signed or hashed bytes.** The server hashes the received body and the client hashes the exact bytes it sends; neither decodes and re-encodes a body before hashing. Statements, envelopes, OPAQUE messages and AAD stay `bytes` fields with CRYPTO.md §2's fixed layouts; protobuf is transport only, like JSON today. No protobuf encoding is ever stored or signed.
   - **Source of truth** stays the `rizzy-proto` Rust types (ADR 0002 point 3): `prost` derive on wire structs inside `rizzy-proto`, converted by `TryFrom` into the bounded types; no `prost-build`, no `protoc`, no `build.rs`. A `.proto` file, if third parties need one, is generated or checked against the Rust types in CI, never hand-maintained as a second definition.
   - **Bounds:** body limits of ADR 0028 item 7 first; nesting ≤ 100 with `no-recursion-limit` banned; list counts checked **during** decode (a hand-written `merge_field` for list wrappers or a counting pre-pass), never after; request types refuse unknown fields by a decoder that errors on an unknown tag; responses may skip them; duplicate singular fields refused.
   - **Tests:** a `proto_pb` fuzz target over all types (no panic, no allocation past the limits, `decode(encode(decode(x))) == decode(x)`), JSON↔protobuf equivalence vectors for every type, and `device-request` vectors over protobuf bodies.

## Consequences

### Positive

- One parser per side over hostile bodies, one fuzz target, one set of vectors; the unknown-field and count-cap rules keep working as written.
- No `protoc`, no new build script, no new crates in the R1 allow-list ([ADR 0016](0016-workspace-layout.md)).
- The constraints in point 4 make a later adoption a bounded change, with the signing question answered up front.

### Negative

- Bodies stay about a third larger than their binary content, and the web vault and native apps pay base64url and JSON costs on every sync.
- No ready schema for a third-party client in another language.

### Risks

- Large vaults on phones may make JSON parsing a visible cost; trigger (a) is the signal.
- A path-based encoding is additive to `v1` (new endpoints, ADR 0002 point 3) before or after v1.0, but it doubles the route table of ADR 0028 item 1 and its tests.

## Alternatives considered

- **Protobuf beside JSON now, by `Content-Type`/`Accept`.** Puts the body's meaning under an unsigned header (point 4), adds a second hostile-input parser that cannot refuse unknown request fields, for a size gain no current client needs.
- **Protobuf replacing JSON.** Same parser issues; loses `curl` debugging and the OpenAPI document ADR 0002 requires; every client and the server change at once under ADR 0002 point 5.
- **`.proto` files and `prost-build` as the source of truth.** A second definition beside `rizzy-proto`, generated types without our bounded fields, and `protoc` as an unpinned C++ build input on every developer and CI machine.
- **A hand-written protobuf codec.** Avoids prost's gaps, but is our own parser for a format we do not need yet.
- **Other binary formats (CBOR, MessagePack, bincode).** Same signing and canonicality questions; not requested; no gain over protobuf for this client set.
- **Shrinking base64url costs only for large blobs** (for example a raw `application/octet-stream` upload of one record). Narrower, and may be the better answer if trigger (b) fires; out of scope here.

## Open questions for the owner

1. **Accept "not now" with the trigger of point 3?** Recommendation: yes.
2. **If adopted later, bind the encoding by path or by a new `device-request` statement version?** Recommendation: by path; it needs no CRYPTO.md change and fails closed.
3. **Publish a `.proto` file for third parties?** Recommendation: no, until a non-Rust client is in ROADMAP scope (trigger (c)).
4. **Did "between clients" mean something other than client–server bodies** (for example a device-to-device channel, which no ADR defines)? Recommendation: confirm the reading in Context; a device-to-device channel would be its own ADR.
5. **ROADMAP.** Recommendation: no row now; add one in the change that adopts protobuf.

## References

- [ADR 0002](0002-own-protocol.md) point 3 and "Alternatives considered"; [ADR 0013](0013-shared-client-core.md); [ADR 0016](0016-workspace-layout.md) §3, R1; [ADR 0019](0019-native-clients.md) §5; [ADR 0028](0028-api-v1-http-conventions.md) items 2, 3, 5–7, 9, open question 4.
- [CRYPTO.md](../CRYPTO.md) §2, §5.10, §9.6, §10.2, §11.1 step 8; [THREAT_MODEL.md](../THREAT_MODEL.md) §7.6, INV-48; [ROADMAP.md](../ROADMAP.md).
- Code (V, e60d7be): `crates/rizzy-proto/src/{lib,wire,limits}.rs`; `crates/rizzy-core/src/sign/statements.rs` (`DeviceRequest`); `crates/rizzy-server/src/http/api.rs`; `crates/rizzy-wasm/src/http.rs`; `apps/web/src/bounded-fetch.ts`; `fuzz/fuzz_targets/proto_json.rs`.
- prost 0.14.4, prost-derive 0.14.4, prost-build 0.14.4 sources in the local cargo registry (V); RustSec advisory DB, commit of 2026-10-01: RUSTSEC-2020-0002, RUSTSEC-2021-0073, RUSTSEC-2026-0007, RUSTSEC-2019-0003, RUSTSEC-2024-0437 (V).
- Protocol Buffers encoding guide: non-canonical serialisation, last-one-wins for repeated singular fields, groups (L: general knowledge, not re-read for this ADR).

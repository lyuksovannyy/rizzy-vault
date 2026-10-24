# ADR 0083: Erratum to ADR 0071: `plaintext_len` is bound by the canonical reader's framing, not by chunk AAD

- Status: Proposed
- Date: 2026-10-24
- Deciders: project owner
- Milestone: M8 (`rizzy-server` `db_backup`; documentation only, no format or code change)
- Supersedes: [ADR 0071](0071-encrypted-db-backup-format.md) ("Container (format_version 2)" in part: the second sentence of its "Ordering and completeness" paragraph), on acceptance. §3 below gives the exact part and its replacement.

## Context

**The owner's words, verbatim (2026-10-24):** "A minor erratum/amendment to ADR 0071 strikes plaintext_len from that specific sentence, clarifying that protection relies on the reader's chunk_count derivation and exact length verification rather than chunk AAD."

**The sentence.** [ADR 0071](0071-encrypted-db-backup-format.md) (Accepted 2026-10-11, implemented) says, in the paragraph "**Ordering and completeness.**" of its Decision, second sentence:

> Because `chunk_count` and `i` sit in every chunk's AAD, reordering, duplicating, dropping a chunk, or editing the clear `chunk_count`/`plaintext_len` fields fails every surviving chunk's commitment check, not only the edited one.

The `plaintext_len` half of that claim is false for the construction the same paragraph fixes. Chunk *i*'s ctx is `backup_id ‖ u64(created_at_ms) ‖ u32(backup_key_id) ‖ u32(i) ‖ u32(chunk_count)`; `plaintext_len` is not in it, and the `0x01` commitment covers only the key, the nonce and the AAD ([CRYPTO.md §9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)). An edit to `plaintext_len` leaves every commitment intact (V: ADR 0071, and `crates/rizzy-server/src/db_backup.rs` lines 23 and 41–49).

**What actually refuses such an edit** (V, code and docs read at `f20ad1d`):

- The implementation's module docs say so: "**`plaintext_len` is in no AAD.** ADR 0071 says an edit to it "fails every surviving chunk's commitment check"; for the construction as written it does not … What refuses such an edit here is the framing" (`db_backup.rs` lines 41–49). They leave "whether `plaintext_len` should be bound in the ctx" to the owner. The owner's words above answer it: it is not, and the framing is the protection.
- `parse_header_with` (`db_backup.rs` lines 280–323) checks, in this order and before any crypto: the input is at most `MAX_BACKUP_FILE_LEN` (else `TooLarge`); the magic; `format_version` = 2; the 64-byte header (`HEADER_LEN`) is complete; `plaintext_len` ≠ 0 (`"plaintext_len is 0"`); `plaintext_len` ≤ `MAX_BACKUP_FILE_LEN` (else `LENGTH_MISMATCH`, so no later arithmetic overflows); `chunk_count = ceil(plaintext_len / CHUNK_LEN)` (`"chunk_count is not ceil(plaintext_len / CHUNK_LEN)"`); and the input is exactly `sealed_len(plaintext_len)` = `HEADER_LEN + plaintext_len + 90 × chunk_count` bytes (`LENGTH_MISMATCH` = `"the file length does not match plaintext_len and chunk_count"`). `open` (lines 334–380) then cuts each chunk's envelope at the length derived from `plaintext_len` alone (`min(CHUNK_LEN, remaining) + 90`), opens the chunks in order and stops at the first failure, and checks again that exactly `plaintext_len` bytes came out and no input is left.
- [CRYPTO.md §9.8](../CRYPTO.md#98-chunked-db-backup-format_version-2-m8) already describes this reader. Its "Ordering and completeness" bullet names only `i` and `chunk_count` as AAD-bound. Its "**Reader**" bullet says: "The reader accepts exactly what the writer produces. Before any crypto it requires `plaintext_len > 0` and the chunk-count rule above. The input must also be exactly `header + plaintext_len + 90 × chunk_count` bytes long … `plaintext_len` is in no chunk's ctx, so a commitment does not bind it. This exact framing does: an edit that keeps the chunk count consistent misframes the file, or, with the last envelope cut to fit, fails that chunk's tag." CRYPTO.md describes; no Accepted ADR says a reader **must** be this strict.
- Behind the chunk tags, the reassembled bytes are a format_version 1 file, whose trailing SHA-256 the format_version 1 reader verifies over the whole file before it parses anything ([ADR 0023](0023-logical-backup-format.md) §2). `restore` hands the opened bytes to that reader (`crates/rizzy-server/src/admin.rs`, `restore_into`: "a format version 2 file is opened first … the format version 1 bytes inside continue at this step").

**Why the reader's strictness matters.** A `0x01` envelope carries no length of its own ([CRYPTO.md §9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01): the layout has no length field, and the ciphertext runs to 16 bytes before wherever the envelope ends), so chunk boundaries exist only as the reader computes them. A lax reader would take "the rest of the file" as the last envelope, ignore trailing bytes, or open whatever envelopes it finds and truncate their concatenation to `plaintext_len`. Such a reader accepts a `plaintext_len` lowered inside the last chunk's 8 MiB bucket and silently drops the tail of the payload, leaving only the format_version 1 digest to notice. The canonical reader refuses that file before any crypto. The corrected sentence is true only for the canonical reader, so the reader's rules have to be normative, not a property of today's code.

**Tests that already exist** (V, read at `f20ad1d`):

- Committed vector **`db-backup/reject/10`** (`crates/rizzy-core/tests/vectors/db_backup.json`): base `db-backup/single-chunk/0` (a 1000-byte payload), mutation `{"op":"set_header","field":"plaintext_len","value":"999"}` (`chunk_count` stays 1), expected error `{"kind":"malformed","rule":"the file length does not match plaintext_len and chunk_count"}`. Replayed by `committed_vectors_replay` in `crates/rizzy-server/tests/db_backup.rs`; the mutation is generated by `reject_mutations` in the same file.
- Committed vector **`db-backup/reject/11`**: base `db-backup/three-chunk/0` (`2 × CHUNK_LEN + 1000` bytes), `plaintext_len` set one higher, to `16778217` (`chunk_count` stays 3), the same expected error.
- Committed vector `db-backup/reject/9`: `chunk_count` set to 2 on the single-chunk file, expected `"chunk_count is not ceil(plaintext_len / CHUNK_LEN)"`.
- Unit test `a_plaintext_len_edit_is_refused_by_the_framing_not_the_commitment` (`db_backup.rs` lines 719–741): a shorter and a longer `plaintext_len` inside the same `ceil()` bucket are both `Malformed(LENGTH_MISMATCH)`; the shorter one with the last envelope also cut by one ciphertext byte, so that the framing fits, fails that chunk's tag (`Authentication { chunk_index: 2 }`) while every earlier chunk opens.
- The property tests `prop_any_truncation_fails`, `prop_any_single_bit_flip_fails` and `prop_arbitrary_bytes_never_panic` (`db_backup.rs` lines 763–790), and the fuzz target `db_backup_container` (`fuzz/Cargo.toml`).

**Rules this ADR works within.** [ADR 0020](0020-partial-supersession.md) point 9: the smallest part that can be superseded is a whole sentence, a change to a few words names the whole sentence, and the replacement is written out in full. CLAUDE.md: an Accepted ADR is never edited, and an Accepted ADR wins over CRYPTO.md on a mechanism.

## Decision

### 1. The corrected sentence

`plaintext_len` is struck from ADR 0071's AAD claim. It is in no chunk's ctx, and no commitment binds it. A `plaintext_len` edit is refused by the canonical reader of §2, through the `chunk_count` derivation and the exact length check. If an attacker also re-cuts the last envelope to fit, that chunk's AEAD tag refuses it. The format_version 1 digest stands behind both. The construction, the ctx, the container layout and every byte of the format are unchanged.

### 2. The canonical reader is normative

A format_version 2 reader **must** accept exactly the files the writer produces. Before any crypto, and before any allocation sized by a declared length, it **must** check:

1. the input is at most `MAX_BACKUP_FILE_LEN` ([ADR 0023](0023-logical-backup-format.md) §3) and at least the 64-byte header long;
2. the magic, and `format_version` = 2;
3. `plaintext_len` > 0 and `plaintext_len` ≤ `MAX_BACKUP_FILE_LEN`;
4. `chunk_count = ceil(plaintext_len / CHUNK_LEN)`;
5. the input is exactly `header + plaintext_len + 90 × chunk_count` bytes long.

It then **must** derive every chunk's envelope length from `plaintext_len` alone: chunk *i* < `chunk_count − 1` is `CHUNK_LEN + 90` bytes, and the last chunk is `plaintext_len − (chunk_count − 1) × CHUNK_LEN + 90` bytes, with no chunk padded. It opens the chunks in order under their ctx, refuses the file at the first failure, and hands the concatenation, which is then exactly `plaintext_len` bytes, to the format_version 1 reader, which verifies its digest (ADR 0023 §2).

A reader is **non-conforming** if it takes "the rest of the file" as the last chunk, tolerates trailing or missing bytes, finds chunk boundaries any other way, or relies on truncating a longer concatenation to `plaintext_len`. The words "truncating to `plaintext_len`" in ADR 0071's "Container" paragraph stay binding as written: under this reader the truncation removes nothing.

`rizzy-server`'s `db_backup::parse_header` and `db_backup::open` are the reader, and they conform today (Context). Any later reader of the format, such as another restore tool or an implementation in another language, is held to the same rules and must replay the committed `db-backup` vectors with the same errors.

### 3. What this ADR supersedes

One Accepted part ([ADR 0020](0020-partial-supersession.md) point 9). The rest of ADR 0071 stays binding unchanged, including the rest of its "Ordering and completeness" paragraph: the first sentence (the ctx) and the third ("A reader refuses a file where `chunk_count != ceil(plaintext_len / CHUNK_LEN)` before opening any chunk.").

1. **[ADR 0071](0071-encrypted-db-backup-format.md) Decision, subsection "Container (format_version 2)", paragraph "Ordering and completeness", second sentence**, word for word: "Because `chunk_count` and `i` sit in every chunk's AAD, reordering, duplicating, dropping a chunk, or editing the clear `chunk_count`/`plaintext_len` fields fails every surviving chunk's commitment check, not only the edited one."

   Replacement, in full:

   > Because `chunk_count` and `i` sit in every chunk's AAD, reordering, duplicating, dropping a chunk, or editing the clear `chunk_count` field fails every surviving chunk's commitment check, not only the edited one. `plaintext_len` sits in no chunk's ctx, so no commitment binds it; the canonical reader binds it instead. Before any crypto, that reader refuses the file unless `plaintext_len` > 0, `chunk_count = ceil(plaintext_len / CHUNK_LEN)`, and the file is exactly `header + plaintext_len + 90 × chunk_count` bytes long, and it derives every chunk's exact envelope length from `plaintext_len` (each chunk but the last `CHUNK_LEN + 90` bytes, the last the rest plus 90, none padded). A `plaintext_len` edit that keeps `chunk_count` consistent therefore misframes the file and is refused before any chunk is opened; an attacker who also re-cuts the last envelope to fit the edited length makes that chunk fail its AEAD tag; and the format_version 1 file's trailing SHA-256 ([ADR 0023](0023-logical-backup-format.md) §2), verified after the chunks open, stands behind both. A reader that takes the rest of the file as the last chunk, tolerates trailing or missing bytes, or relies on truncating a longer concatenation to `plaintext_len` is non-conforming ([ADR 0083](0083-db-backup-plaintext-len-erratum.md) §2).

### 4. Tests

No new test is needed. `db-backup/reject/10` (a `plaintext_len` edit with `chunk_count` consistent), `db-backup/reject/11` (the same on a three-chunk file), `db-backup/reject/9` and the unit test `a_plaintext_len_edit_is_refused_by_the_framing_not_the_commitment` (the re-cut last envelope) already pin every clause of §1 and §2 (Context). They stay committed and replayed. Regenerating them stays deliberate (`cargo test -p rizzy-server --test db_backup -- --ignored generate`, then review the diff). A change that makes any of them fail with a different error, or with none, contradicts this ADR.

## Consequences

### Positive

- ADR 0071's Decision no longer contains a false security claim. The M8 audit (CRYPTO.md §1 rule 2, target 12) reviews a stated property that matches the code.
- The reader's strictness becomes a requirement, so nobody can relax it as a "simplification" without a new ADR.
- No format, vector, code or migration change. Every format_version 2 file written so far stays valid.

### Negative

- The integrity of `plaintext_len` rests on reader discipline (exact framing), not on the construction's AAD. A second reader has to reproduce §2 exactly to be safe; a reviewer has to check that, rather than get it for free.

### Risks

- **A future relaxed reader** (streaming restore, partial restore, a tool in another language). Signal: a reader that does not replay `db-backup/reject/9` to `/11` with the same errors. Mitigation: §2 makes it non-conforming, and the vectors are the test.
- **A future format that needs `plaintext_len` bound cryptographically** (for example random-access or streaming reads that cannot check the file length up front). That is a new `format_version` and a new ADR, not a reinterpretation of this one.

## Alternatives considered

- **Bind `plaintext_len` into every chunk's ctx.** That would make the original sentence true. The owner's words of 2026-10-24 rule it out ("rather than chunk AAD"). It is also a format change: new vectors, and either a new `format_version` or every existing format_version 2 file unreadable, for no gain over the exact framing the reader already enforces.
- **Leave ADR 0071 as written, and rely on CRYPTO.md §9.8 and the code.** Rejected: an Accepted ADR wins over CRYPTO.md on a mechanism (CLAUDE.md), so the false sentence would stay the binding text, and the strict reader would stay an implementation detail.
- **Supersede the whole "Ordering and completeness" paragraph.** Rejected: its first and third sentences are correct, and ADR 0020 point 9 asks for the smallest part that changes.

## Open questions for the owner

None.

## On acceptance

The accepting change makes these edits; none is made now ([ADR 0020](0020-partial-supersession.md) point 9).

1. **Status lines.** [ADR 0071](0071-encrypted-db-backup-format.md), now "Accepted": set to "Partially superseded by [ADR 0083](0083-db-backup-plaintext-len-erratum.md) (Container (format_version 2) in part)". Its [index](README.md) row follows, and this ADR's row and status line move to Accepted.
2. **[CRYPTO.md §9.8](../CRYPTO.md#98-chunked-db-backup-format_version-2-m8), "Reader" bullet:** append "Any other reader is non-conforming: one that takes the rest of the file as the last chunk, tolerates trailing or missing bytes, or relies on truncating a longer concatenation to `plaintext_len` ([ADR 0083](adr/0083-db-backup-plaintext-len-erratum.md))." No other CRYPTO.md text changes: §9.8's "Ordering and completeness" bullet already names only `i` and `chunk_count`.
3. **A code comment, no behaviour change.** In `crates/rizzy-server/src/db_backup.rs`, the module docs' "`plaintext_len` is in no AAD" bullet (lines 41–49) drops its quote of ADR 0071's superseded wording and its last sentence ("Whether `plaintext_len` should be bound in the ctx is a construction question for the owner, not answered here"), and cites this ADR instead.
4. **[docs/HANDOFF.md](../HANDOFF.md):** the open item "the 0071 `plaintext_len` sentence" is closed.

## References

- [ADR 0071](0071-encrypted-db-backup-format.md): the superseded sentence; "Container", "Size", "Commands and restore".
- [ADR 0023](0023-logical-backup-format.md) §2 (the format_version 1 trailing SHA-256), §3 (`MAX_BACKUP_FILE_LEN`).
- [ADR 0020](0020-partial-supersession.md) point 9.
- [CRYPTO.md §9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01) (the 90-byte `0x01` overhead; the commitment covers key, nonce and AAD), [§9.8](../CRYPTO.md#98-chunked-db-backup-format_version-2-m8) ("Ordering and completeness", "Reader").
- [THREAT_MODEL.md](../THREAT_MODEL.md) INV-98 (the backup key; unchanged).
- Code (V, read at `f20ad1d`): `crates/rizzy-server/src/db_backup.rs` (`parse_header_with`, `sealed_len_with`, `open_with`, the unit test `a_plaintext_len_edit_is_refused_by_the_framing_not_the_commitment`); `crates/rizzy-server/tests/db_backup.rs` (`reject_mutations`, `committed_vectors_replay`); `crates/rizzy-core/tests/vectors/db_backup.json` (`db-backup/reject/9`, `/10`, `/11`); `crates/rizzy-server/src/admin.rs` (`restore_into`, format_version 2).

# Committed fuzz seeds

`fuzz/corpus/` is git-ignored: it is the working corpus `cargo fuzz` grows on each machine. This
directory holds the few inputs that are committed on purpose, as starting points. Pass a target's
seed directory as a second, read-only corpus after the working one:

```sh
cargo fuzz run equivalence_list fuzz/corpus/equivalence_list fuzz/seeds/equivalence_list
```

libFuzzer writes new inputs only to the first directory, so the seeds stay as committed.

## `equivalence_list/`

- `adr0080-seed-test-key-v1.bin`: the ADR 0080 default site groups
  (`data/equivalence/groups.txt` as committed with that change: 22 groups, 184 domains, 3,226
  bytes) compiled and signed by `cargo xtask equivalence-list` with `list_version` 1 and
  `published_at_ms` 1700000000000 (ADR 0080 §8). It is signed with the **test** seed `0x55`
  repeated 32 times, the same public test fixture the `equivalence_list` fuzz target and
  `rizzy-match`'s known-answer test use, so the target's parser sees a full-size, correctly
  signed list. It is not signed with, and says nothing about, the owner's list-signing key, and
  no client accepts it: the pinned key in `crates/rizzy-match/src/compiled.rs` is a different
  key, set by the owner. Regenerate it after a change to `groups.txt` with the same command and
  the same test seed. When the owner ships a signed list, add it here too
  (`docs/equivalence-list.md` §4).

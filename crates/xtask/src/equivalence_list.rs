//! `cargo xtask equivalence-list` (ADR 0038 §3): compiles the human-editable source
//! (`data/equivalence/groups.txt`) into the canonical `rizzy-match` equivalence-list bytes and
//! signs them with the owner's offline Ed25519 key.
//!
//! **Source format.** ADR 0038 §1 asks for "a human-editable source file ... using only crates
//! already in the workspace for parsing — if none fits, a minimal hand-written line format
//! documented in the file." No TOML (or any other structured-text) crate is in
//! `[workspace.dependencies]`, and adding one is out of scope for this change (CLAUDE.md
//! "Dependencies": a new crate is justified and reviewed on its own, not bundled into an
//! unrelated feature) — so the source is the hand-written line format `data/equivalence/
//! groups.txt`'s own header documents: one group per non-comment, non-blank line,
//! `group_id (32 hex chars) | third_party_hostable (0 or 1) | domain1,domain2,...`.
//!
//! **Signing.** The key file is the raw 32-byte Ed25519 seed (`docs/equivalence-list.md`
//! "Generating the offline key" says how the owner makes one). Never checked in, never typed
//! on this command line, never logged by this tool (CLAUDE.md "Never log secrets").

use std::fs;
use std::path::Path;

use rizzy_core::labels;
use rizzy_match::equivalence::{EquivalenceGroup, EquivalenceList, GroupId};

/// Parses one line's three `|`-separated fields into a group id, its PSL-split flag and its
/// domain list.
fn parse_line(lineno: usize, line: &str) -> Result<EquivalenceGroup, String> {
    let fields: Vec<&str> = line.split('|').map(str::trim).collect();
    let [id_hex, flag_str, domains_str] = fields.as_slice() else {
        return Err(format!(
            "line {lineno}: expected 3 fields separated by '|' (group_id | flag | domains), found {}",
            fields.len()
        ));
    };
    let group_id = decode_group_id(id_hex)
        .ok_or_else(|| format!("line {lineno}: group id must be exactly 32 hex characters"))?;
    let third_party_hostable = match *flag_str {
        "0" => false,
        "1" => true,
        other => {
            return Err(format!(
                "line {lineno}: flag must be 0 or 1, found {other:?}"
            ));
        }
    };
    let domains: Vec<&str> = domains_str
        .split(',')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .collect();
    EquivalenceGroup::new(group_id, domains, third_party_hostable)
        .map_err(|e| format!("line {lineno}: {e}"))
}

/// Decodes a 32-hex-character group id (16 bytes).
fn decode_group_id(hex: &str) -> Option<GroupId> {
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(GroupId::from_bytes(bytes))
}

/// Parses the whole source text into its groups, skipping blank lines and `#` comments.
///
/// # Errors
/// A `String` naming the first bad line and why, 1-indexed as a text editor shows it.
pub(crate) fn parse_source(text: &str) -> Result<Vec<EquivalenceGroup>, String> {
    let mut groups = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        groups.push(parse_line(index + 1, line)?);
    }
    Ok(groups)
}

/// Runs `cargo xtask equivalence-list <source-file> <key-file> <list-version>
/// <published-at-ms>`: reads the source and the raw 32-byte signing seed, builds and signs the
/// list, and returns its wire bytes (ADR 0038 §1) for the caller to write out, typically with
/// `> data/equivalence/list.bin` (never committed until the owner has a real key: see
/// `crates/rizzy-match/src/compiled.rs`).
///
/// # Errors
/// A `String` describing the first problem: the source or key file could not be read, the key
/// is not exactly 32 bytes, the source does not parse, the list does not build (a duplicate
/// `group_id`, or too many groups — [`EquivalenceList::new`] sorts groups by id itself, so the
/// source file's line order never matters and is never an error), or encoding overflows
/// (unreachable in practice, every bound is checked well below `u32::MAX`).
pub(crate) fn run(
    source_path: &Path,
    key_path: &Path,
    list_version: u32,
    published_at_ms: u64,
) -> Result<Vec<u8>, String> {
    let source = fs::read_to_string(source_path)
        .map_err(|e| format!("reading {}: {e}", source_path.display()))?;
    let groups = parse_source(&source)?;
    let list = EquivalenceList::new(list_version, published_at_ms, groups)
        .map_err(|e| format!("building the list: {e}"))?;
    let ctx = list
        .encode_ctx()
        .map_err(|e| format!("encoding the list: {e}"))?;

    let seed_bytes =
        fs::read(key_path).map_err(|e| format!("reading key {}: {e}", key_path.display()))?;
    let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "key file {} must be exactly 32 bytes (a raw Ed25519 seed), found {}",
            key_path.display(),
            seed_bytes.len()
        )
    })?;
    let signature = rizzy_core::sign::sign_detached(labels::SIG_EQUIVALENCE_LIST, &ctx, &seed)
        .map_err(|e| format!("signing: {e}"))?;

    list.encode_signed(&signature)
        .map_err(|e| format!("encoding the signed list: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_source() {
        let text = "\
# the youtube group
f1e2d3c4b5a697887766554433221100 | 0 | youtube.com,youtu.be,youtube-nocookie.com
";
        let groups = parse_source(text).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].domains(),
            ["youtu.be", "youtube-nocookie.com", "youtube.com"]
        );
        assert!(!groups[0].third_party_hostable());
    }

    #[test]
    fn rejects_a_short_group_id() {
        let err = parse_source("00 | 0 | a.example,b.example\n").unwrap_err();
        assert!(err.contains("line 1"), "{err}");
    }

    #[test]
    fn rejects_a_bad_flag() {
        let err = parse_source("f1e2d3c4b5a697887766554433221100 | 2 | a.example,b.example\n")
            .unwrap_err();
        assert!(err.contains("flag must be 0 or 1"), "{err}");
    }

    #[test]
    fn blank_lines_and_comments_are_skipped() {
        let groups = parse_source(
            "\n  \n# comment\nf1e2d3c4b5a697887766554433221100 | 0 | a.example,b.example\n",
        )
        .unwrap();
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn run_produces_a_verifiable_wire_list() {
        let dir = std::env::temp_dir().join(format!(
            "rizzy-match-equivalence-list-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let source_path = dir.join("groups.txt");
        let key_path = dir.join("key.bin");
        fs::write(
            &source_path,
            "f1e2d3c4b5a697887766554433221100 | 0 | apple.com,icloud.com\n",
        )
        .unwrap();
        fs::write(&key_path, [0x77u8; 32]).unwrap();

        let wire = run(&source_path, &key_path, 1, 1_700_000_000_000).unwrap();

        // Independent known answer for the seed `0x77` repeated 32 times (Python
        // `cryptography` 50.0.2's `Ed25519PrivateKey`, not this code): its public key.
        let public_key: [u8; 32] =
            *hex("c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7")
                .first_chunk()
                .unwrap();
        let list = EquivalenceList::verify(&wire, &public_key, 0).unwrap();
        assert_eq!(list.list_version(), 1);
        assert_eq!(list.groups().len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .map(|b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => u8::MAX,
            })
            .collect();
        digits.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
    }
}

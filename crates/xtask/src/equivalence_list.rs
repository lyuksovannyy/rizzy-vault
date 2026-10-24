// SPDX-License-Identifier: AGPL-3.0-only

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
//! **Checks beyond `EquivalenceGroup::new`** (ADR 0080 §2, §6, §8): an error names the line,
//! the member and the rule it breaks; no domain may be in two groups and no group id on two
//! lines; `list_version` 0 is refused. The tests parse the committed `groups.txt`, so a PSL
//! bump that breaks a member fails `cargo test`.
//!
//! **Signing.** The key file is the raw 32-byte Ed25519 seed (`docs/equivalence-list.md`
//! "Generating the offline key" says how the owner makes one). Never checked in, never typed
//! on this command line, never logged by this tool (CLAUDE.md "Never log secrets").

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rizzy_core::labels;
use rizzy_match::equivalence::{
    EquivalenceGroup, EquivalenceList, GroupId, MemberRuleViolation, member_rule_violation,
};
use rizzy_match::error::MAX_GROUP_DOMAINS;
use rizzy_match::normalize_domain;

/// Why one source member is refused, naming the member and the rule (ADR 0080 §8: the bare
/// "equivalence list is malformed" of `EquivalenceGroup::new` names neither).
fn diagnose_members(domains: &[&str]) -> Option<String> {
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for raw in domains {
        let normalised = match normalize_domain(raw) {
            Ok(normalised) => normalised,
            Err(e) => {
                return Some(format!(
                    "member {raw:?} does not normalise to a domain ({e})"
                ));
            }
        };
        if let Some(violation) = member_rule_violation(&normalised) {
            let why = match violation {
                MemberRuleViolation::NotADomain => {
                    "is an IP literal or not a domain (ADR 0044 rule 1)".to_owned()
                }
                MemberRuleViolation::PublicSuffix => {
                    "is a public suffix under the compiled-in PSL, which anyone can register \
                     beneath (ADR 0044 rule 2)"
                        .to_owned()
                }
                MemberRuleViolation::NotRegistrable { registrable } => format!(
                    "is not its own registrable domain: under the compiled-in PSL its \
                     registrable domain is {registrable:?} (ADR 0044 rule 2)"
                ),
            };
            return Some(format!("member {raw:?} {why}"));
        }
        if let Some(earlier) = seen.insert(normalised.clone(), raw) {
            return Some(format!(
                "members {earlier:?} and {raw:?} both normalise to {normalised:?} (ADR 0038 §1: \
                 no duplicates)"
            ));
        }
    }
    if domains.len() < 2 || domains.len() > usize::from(MAX_GROUP_DOMAINS) {
        return Some(format!(
            "a group needs 2 to {MAX_GROUP_DOMAINS} members (ADR 0038 §1), found {}",
            domains.len()
        ));
    }
    None
}

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
    if let Some(why) = diagnose_members(&domains) {
        return Err(format!("line {lineno}: {why}"));
    }
    // `EquivalenceGroup::new` stays the authority; the diagnosis above only names the rule.
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
/// Two source-level review rules no single line can check, enforced here rather than in the
/// wire format (ADR 0038 §1 is untouched): a group id is used by one line only (ADR 0038 §1,
/// "assigned once"), and **no domain is in two global groups** (ADR 0080 §2: overlap makes
/// "turn this group off" misleading, because the other group still matches).
///
/// # Errors
/// A `String` naming the first bad line and why, 1-indexed as a text editor shows it.
pub(crate) fn parse_source(text: &str) -> Result<Vec<EquivalenceGroup>, String> {
    let mut groups = Vec::new();
    let mut id_lines: BTreeMap<GroupId, usize> = BTreeMap::new();
    let mut member_lines: BTreeMap<String, usize> = BTreeMap::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = index + 1;
        let group = parse_line(lineno, line)?;
        if let Some(earlier) = id_lines.insert(group.id(), lineno) {
            return Err(format!(
                "line {lineno}: group id is already used on line {earlier} (ADR 0038 §1: an id \
                 is assigned once and never reused)"
            ));
        }
        for domain in group.domains() {
            if let Some(earlier) = member_lines.insert(domain.clone(), lineno) {
                return Err(format!(
                    "line {lineno}: member {domain:?} is already in the group on line {earlier} \
                     (ADR 0080 §2: no domain may appear in more than one global group)"
                ));
            }
        }
        groups.push(group);
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
    if list_version == 0 {
        return Err(
            "list-version 0 is reserved and never published (ADR 0080 §6: a client's floor 0 \
             means \"nothing accepted yet\"); the first list is version 1"
                .to_owned(),
        );
    }
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
    fn rejects_an_ip_literal_or_a_non_registrable_member() {
        // ADR 0044: `EquivalenceGroup::new` refuses these, so the line fails before signing.
        for bad in [
            "192.168.1.1",
            "2130706433",
            "[::1]",
            "co.uk",
            "github.io",
            "mail.example.com",
        ] {
            let line = format!("f1e2d3c4b5a697887766554433221100 | 0 | {bad},example.com\n");
            let err = parse_source(&format!("# ok\n{line}")).unwrap_err();
            assert!(err.contains("line 2"), "{bad}: {err}");
        }
        // A dotless intranet name is its own registrable domain and is accepted.
        assert!(parse_source("f1e2d3c4b5a697887766554433221100 | 0 | nas,example.com\n").is_ok());
    }

    /// ADR 0080 §8: the error names the member and the rule, not only the line.
    #[test]
    fn an_error_names_the_member_and_the_rule() {
        let id = "f1e2d3c4b5a697887766554433221100";
        let cases = [
            (
                "amazon.com,amazon.com.be",
                "\"amazon.com.be\"",
                "\"com.be\"",
            ),
            ("alibaba.com,net.cn", "\"net.cn\"", "public suffix"),
            (
                "example.com,192.168.1.1",
                "\"192.168.1.1\"",
                "ADR 0044 rule 1",
            ),
            (
                "example.com,mail.example.org",
                "\"mail.example.org\"",
                "ADR 0044 rule 2",
            ),
            (
                "example.com,a b.example",
                "\"a b.example\"",
                "does not normalise",
            ),
            (
                "Example.com.,example.com",
                "\"example.com\"",
                "no duplicates",
            ),
            ("example.com", "2 to 64", "found 1"),
        ];
        for (domains, member, rule) in cases {
            let err = parse_source(&format!("{id} | 0 | {domains}\n")).unwrap_err();
            assert!(err.starts_with("line 1: "), "{err}");
            assert!(err.contains(member), "{domains}: {err}");
            assert!(err.contains(rule), "{domains}: {err}");
        }
        let too_many: Vec<String> = (0..65).map(|i| format!("d{i}.example")).collect();
        let err = parse_source(&format!("{id} | 0 | {}\n", too_many.join(","))).unwrap_err();
        assert!(err.contains("found 65"), "{err}");
    }

    /// ADR 0080 §2: no domain may be in two global groups, whatever its spelling.
    #[test]
    fn a_domain_in_two_groups_is_refused() {
        let err = parse_source(
            "\
f1e2d3c4b5a697887766554433221100 | 0 | youtube.com,youtu.be
# another group
00112233445566778899aabbccddeeff | 0 | google.com,YouTube.com.
",
        )
        .unwrap_err();
        assert!(err.contains("line 3"), "{err}");
        assert!(err.contains("\"youtube.com\""), "{err}");
        assert!(err.contains("on line 1"), "{err}");
        assert!(err.contains("ADR 0080 §2"), "{err}");
    }

    #[test]
    fn a_group_id_on_two_lines_is_refused() {
        let err = parse_source(
            "\
f1e2d3c4b5a697887766554433221100 | 0 | a.example,b.example
F1E2D3C4B5A697887766554433221100 | 0 | c.example,d.example
",
        )
        .unwrap_err();
        assert!(err.contains("line 2") && err.contains("line 1"), "{err}");
    }

    /// ADR 0080 §6: version 0 is reserved and never published; the tool refuses it before it
    /// reads the key.
    #[test]
    fn run_refuses_list_version_zero() {
        let err = run(
            Path::new("/nonexistent/groups.txt"),
            Path::new("/nonexistent/key"),
            0,
            0,
        )
        .unwrap_err();
        assert!(err.contains("reserved"), "{err}");
    }

    /// The committed source (ADR 0080 §8): it parses under this build's PSL, so a PSL bump that
    /// turns a member into a suffix fails `cargo test` in the pull request that makes it (ADR
    /// 0044 "A PSL bump ...": "Mitigation is process, not code"). It is the ADR 0080 seed: 22
    /// groups, 184 domains, none flagged, without the removed members or the retired id.
    #[test]
    fn the_committed_groups_txt_parses_and_is_the_adr_0080_seed() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/equivalence/groups.txt");
        let text = fs::read_to_string(&path).unwrap();
        let groups = parse_source(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(groups.len(), 22);
        let members: Vec<&String> = groups.iter().flat_map(EquivalenceGroup::domains).collect();
        assert_eq!(members.len(), 184);
        assert!(groups.iter().all(|g| !g.third_party_hostable()));
        for removed in [
            "amazon.com.be",
            "net.cn",
            "atlassian.net",
            "statuspage.io",
            "jira.com",
            "yandex.ua",
        ] {
            assert!(!members.iter().any(|m| *m == removed), "{removed}");
        }
        let retired = decode_group_id("8ce962df007bc44d8d1bb3817570df24").unwrap();
        assert!(groups.iter().all(|g| g.id() != retired));
        // The starter ids ADR 0080 §2 keeps.
        for (kept, member) in [
            ("ad39c37cee45d28736adc53bcafa8db2", "youtu.be"),
            ("1e683ea6d91b48d95a602cf7e6b71747", "icloud.com"),
        ] {
            let id = decode_group_id(kept).unwrap();
            let group = groups.iter().find(|g| g.id() == id).unwrap();
            assert!(group.contains(member), "{kept}");
        }
        // Every line points at its evidence section (ADR 0080 §4).
        let evidence = fs::read_to_string(path.with_file_name("EVIDENCE.md")).unwrap();
        for line in text.lines().filter(|l| l.starts_with("# upstream: ")) {
            let anchor = line.rsplit("EVIDENCE.md#").next().unwrap();
            let heading = anchor.rsplit_once("-type-").unwrap();
            assert!(
                evidence
                    .to_lowercase()
                    .contains(&format!("## {} (type {})", heading.0, heading.1)),
                "{anchor}"
            );
        }
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("# upstream: "))
                .count(),
            22
        );
    }

    /// The committed source builds and signs (here with a TEST key, never the owner's) into a
    /// list every client accepts at floor 0 and again at its own version (ADR 0080 §5–§6).
    #[test]
    fn the_committed_groups_txt_signs_into_a_list_accepted_at_its_own_version() {
        let dir = std::env::temp_dir().join(format!(
            "rizzy-match-equivalence-seed-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("test-key.bin");
        fs::write(&key_path, [0x77u8; 32]).unwrap();
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/equivalence/groups.txt");
        let wire = run(&source, &key_path, 1, 1_700_000_000_000).unwrap();
        let _ = fs::remove_dir_all(&dir);

        // ADR 0080 §2: "signs it into 3,226 wire bytes".
        assert_eq!(wire.len(), 3_226);
        let public_key: [u8; 32] =
            *hex("c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7")
                .first_chunk()
                .unwrap();
        let first = EquivalenceList::verify(&wire, &public_key, 0).unwrap();
        assert_eq!(first.groups().len(), 22);
        assert_eq!(
            EquivalenceList::verify(&wire, &public_key, 1).unwrap(),
            first
        );
    }

    /// The committed fuzz seed (`fuzz/seeds/equivalence_list/`, ADR 0080 §8) is a list signed
    /// with the public TEST seed `0x55` × 32 (the fuzz target's own fixture), never the owner's
    /// key: it verifies under that test key, at version 1, with the seed's 22 groups.
    #[test]
    fn the_committed_fuzz_seed_is_signed_with_the_test_key() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/seeds/equivalence_list/adr0080-seed-test-key-v1.bin");
        let wire = fs::read(&path).unwrap();
        let test_public_key: [u8; 32] =
            *hex("c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242")
                .first_chunk()
                .unwrap();
        let list = EquivalenceList::verify(&wire, &test_public_key, 0).unwrap();
        assert_eq!(list.list_version(), 1);
        assert_eq!(list.groups().len(), 22);
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

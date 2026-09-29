//! The DCO sign-off check of ADR 0017 Decision 4, run by `cargo xtask check-signoff`.
//!
//! ADR 0017 §4 asks CI for two things: that the commits of a pull request carry the
//! `Signed-off-by:` trailers, and that "the squash commit on `main` keeps the trailers". The
//! two modes below check one each.
//!
//! **Pull-request mode** (`check-signoff <base>..<head>`, CI on `pull_request`). Every commit in
//! the range must carry a `Signed-off-by:` trailer whose name and email are the commit's
//! author: the trailer is the author's certification of the Developer Certificate of Origin
//! 1.1 for that commit (CONTRIBUTING.md, "Sign-off"). [`crate::check_signoff`] runs `git log`
//! with [`LOG_FORMAT`], hands its stdout to [`parse_log`], and checks the hashes it read
//! against a separate `git rev-list` of the same range ([`same_commits`]). Git itself finds the
//! trailers (`%(trailers:key=Signed-off-by,...)`), so only the trailer block at the end of the
//! message counts, as in `git interpret-trailers`; a `Signed-off-by:` line quoted in the middle
//! of the body does not. Git matches the key without regard to case.
//!
//! Matching, the conservative reading where ADR 0017 does not spell it out:
//!
//! - A trailer matches when its name equals the author name exactly (after trimming outer
//!   whitespace) and its email equals the author email ignoring ASCII case. A sign-off by
//!   someone else, such as a maintainer who amended the commit, does not stand in for the
//!   author's own.
//! - Every commit in the range is checked, merge commits included: ADR 0017 §4 says "every
//!   commit", and a merge can carry conflict resolutions. A contributor updates a branch by
//!   rebasing, or signs off the merge commit.
//! - An empty range is a failure: a pull request always has a commit, so an empty range means
//!   the range is wrong, and passing it would check nothing.
//!
//! **Squash mode** (`check-signoff --squash <before>..<after>`, CI on a push to `main`). GitHub
//! writes the squash commit: its author is the merger's GitHub identity (often a
//! `users.noreply.github.com` address), and with the "commit messages" squash format the PR
//! commits' `Signed-off-by:` lines sit in the body, above a final `Co-authored-by:` paragraph,
//! so git's trailer parser does not return them. Neither the author rule nor the trailer block
//! fits that commit, so this mode reads the whole message ([`squash_signoffs`]) and requires at
//! least one well-formed `Signed-off-by: Name <email>` line anywhere in it. That is what can be
//! checked from the squash commit alone; it catches the settings ADR 0017 §4 forbids ("Pull
//! request title" and "Pull request title and description" drop every trailer) and merge
//! commits made through the web interface. It cannot prove that *every* PR trailer survived:
//! the PR's commits are not part of a push event's history. The pull-request mode, which ran
//! before the merge, is what checks each commit's author. A stricter squash rule (for example
//! one `Signed-off-by:` per `Co-authored-by:` identity) depends on how GitHub fills those
//! lines, which is not verified here; it is left to the owner.
//!
//! **Untrusted input.** Commit metadata in a pull request is written by its author, so no free
//! text goes into the delimited `git log` stream except the fields the check needs: no subject,
//! no body. Every field is still treated as hostile: git keeps the separator bytes 0x1E and
//! 0x1F in names and messages, so [`parse_log`] rejects any record whose name, email or
//! sign-off line holds a control character, and [`same_commits`] requires the hashes read to be
//! exactly the commits `git rev-list` lists, so a smuggled terminator that forges an extra
//! record fails the check even when every field count is right. The squash mode reads one
//! commit's message per `git log -1` call, with no delimiter to forge. The parsers never index
//! and never panic, fail closed on anything they cannot read, and cap the input at
//! [`MAX_LOG_BYTES`], [`MAX_COMMITS`] and [`MAX_MESSAGE_BYTES`]. Names and sign-offs are
//! printed through [`str::escape_debug`], so crafted text cannot start a new output line, which
//! is where GitHub Actions reads workflow commands (`::...::`), and cannot carry terminal
//! escape sequences. The range argument is checked by [`check_range`] before it reaches git,
//! and git receives it after `--end-of-options`, so it can never be read as an option.
//!
//! xtask is never shipped, so these parsers have no fuzz target (the `fuzz/` workspace builds
//! library crates only); the unit tests below cover the malformed and forged shapes instead.

use std::collections::BTreeSet;
use std::fmt;

/// The `git log --format` string [`parse_log`] reads: hash, author name, author email, and one
/// unfolded `Signed-off-by` value per line. Fields are separated by the ASCII unit separator
/// (0x1F) and records end with the record separator (0x1E); `tformat` adds a newline after
/// each record. The subject is deliberately left out: it is free text the author controls.
pub(crate) const LOG_FORMAT: &str =
    "%H%x1f%an%x1f%ae%x1f%(trailers:key=Signed-off-by,valueonly,unfold)%x1e";

/// The largest `git log` or `git rev-list` output read, in bytes (64 MiB). A pull request
/// comes nowhere near it.
pub(crate) const MAX_LOG_BYTES: usize = 64 * 1024 * 1024;

/// The most commits one run checks.
pub(crate) const MAX_COMMITS: usize = 10_000;

/// The longest commit message the squash mode reads, in bytes (1 MiB).
pub(crate) const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// The longest revision on either side of the range, in bytes.
const MAX_REV_LEN: usize = 256;

/// Field separator in [`LOG_FORMAT`] (`%x1f`).
const FIELD_SEP: char = '\u{1f}';

/// Record terminator in [`LOG_FORMAT`] (`%x1e`).
const RECORD_SEP: char = '\u{1e}';

/// The trailer key the squash mode looks for, compared without regard to ASCII case.
const SIGNOFF_KEY: &str = "signed-off-by:";

/// One commit as [`LOG_FORMAT`] prints it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Commit {
    /// The full commit hash, lowercase hex (40 characters for SHA-1, 64 for SHA-256).
    pub(crate) sha: String,
    /// The author name, as recorded (`%an`, no mailmap).
    pub(crate) author_name: String,
    /// The author email, as recorded (`%ae`, no mailmap).
    pub(crate) author_email: String,
    /// The value of every `Signed-off-by` trailer, such as `Jane Doe <jane@example.com>`.
    pub(crate) signoffs: Vec<String>,
}

/// A commit without a matching sign-off.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Missing<'a> {
    /// The commit.
    pub(crate) commit: &'a Commit,
}

impl fmt::Display for Missing<'_> {
    /// `<sha12>: no Signed-off-by trailer matches the author "<name> <email>"`, with the name
    /// and email escaped ([`str::escape_debug`]) and the sign-offs found.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = self.commit;
        write!(
            f,
            "{}: no Signed-off-by trailer matches the author \"{} <{}>\"",
            short(&c.sha),
            c.author_name.escape_debug(),
            c.author_email.escape_debug(),
        )?;
        if c.signoffs.is_empty() {
            write!(f, " (the commit has no Signed-off-by trailer)")
        } else {
            write!(f, " (found:")?;
            for s in &c.signoffs {
                write!(f, " \"{}\"", s.escape_debug())?;
            }
            write!(f, ")")
        }
    }
}

/// The first 12 characters of a hash, or all of it when shorter.
pub(crate) fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

/// Checks the `<base>..<head>` argument before it is given to git: exactly one `..`, and on
/// each side 1 to [`MAX_REV_LEN`] bytes of ASCII letters, digits, `/`, `_`, `-` and `.`, not
/// starting with `-` or `.` and containing no `..`. That admits commit hashes and branch names
/// such as `origin/main`, and rejects options, `...` ranges and revision expressions.
///
/// # Errors
///
/// Returns a message saying what is wrong with the argument.
pub(crate) fn check_range(range: &str) -> Result<(), String> {
    let Some((base, head)) = range.split_once("..") else {
        return Err("expected a range `<base>..<head>`".to_owned());
    };
    for (side, rev) in [("base", base), ("head", head)] {
        if rev.is_empty() || rev.len() > MAX_REV_LEN {
            return Err(format!(
                "the {side} revision must be 1 to {MAX_REV_LEN} bytes long"
            ));
        }
        if rev.starts_with(['-', '.']) || rev.contains("..") {
            return Err(format!(
                "the {side} revision must not start with `-` or `.` or contain `..`"
            ));
        }
        if !rev
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
        {
            return Err(format!(
                "the {side} revision may contain only ASCII letters, digits, `/`, `_`, `-` and `.`"
            ));
        }
    }
    Ok(())
}

/// Parses `git log --format=`[`LOG_FORMAT`] output, newest commit first as git prints it.
///
/// # Errors
///
/// Returns a message when the output is larger than [`MAX_LOG_BYTES`], lists more than
/// [`MAX_COMMITS`] commits, or has a record that [`parse_record`] rejects, or text after the
/// last record terminator.
pub(crate) fn parse_log(out: &str) -> Result<Vec<Commit>, String> {
    if out.len() > MAX_LOG_BYTES {
        return Err(format!(
            "git log printed more than {MAX_LOG_BYTES} bytes; refusing to check"
        ));
    }
    let mut commits = Vec::new();
    let mut rest = out;
    loop {
        // `tformat` ends each record with a newline after our terminator.
        rest = rest.trim_start_matches('\n');
        if rest.is_empty() {
            break;
        }
        let Some((record, tail)) = rest.split_once(RECORD_SEP) else {
            return Err("git log output ends inside a record".to_owned());
        };
        rest = tail;
        if commits.len() >= MAX_COMMITS {
            return Err(format!(
                "the range has more than {MAX_COMMITS} commits; refusing to check"
            ));
        }
        commits.push(parse_record(record)?);
    }
    Ok(commits)
}

/// Whether `s` is a full commit hash: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
fn is_sha(s: &str) -> bool {
    matches!(s.len(), 40 | 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parses one record: hash, author name, author email, sign-off lines.
///
/// # Errors
///
/// Returns a message when the record does not have exactly four fields, the hash is not 40 or
/// 64 lowercase hex digits, or the name, the email or a sign-off line holds a control
/// character (such as a smuggled 0x1E or 0x1F separator, see the module docs).
fn parse_record(record: &str) -> Result<Commit, String> {
    let fields: Vec<&str> = record.split(FIELD_SEP).collect();
    let [sha, name, email, trailers] = fields.as_slice() else {
        return Err(format!(
            "a git log record has {} fields instead of 4 (a separator byte in commit metadata?)",
            fields.len()
        ));
    };
    if !is_sha(sha) {
        return Err(format!(
            "git log printed a malformed commit hash \"{}\"",
            sha.escape_debug()
        ));
    }
    let signoffs: Vec<String> = trailers
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    if [*name, *email]
        .into_iter()
        .chain(signoffs.iter().map(String::as_str))
        .any(|s| s.chars().any(char::is_control))
    {
        return Err(format!(
            "commit {} has a control character in its author name, author email or a \
             Signed-off-by trailer; refusing to check",
            short(sha)
        ));
    }
    Ok(Commit {
        sha: (*sha).to_owned(),
        author_name: (*name).to_owned(),
        author_email: (*email).to_owned(),
        signoffs,
    })
}

/// Parses `git rev-list <range>` output: one full commit hash per line.
///
/// # Errors
///
/// Returns a message when the output is larger than [`MAX_LOG_BYTES`], lists more than
/// [`MAX_COMMITS`] commits, or has a line that is not a full hash.
pub(crate) fn parse_rev_list(out: &str) -> Result<Vec<String>, String> {
    if out.len() > MAX_LOG_BYTES {
        return Err(format!(
            "git rev-list printed more than {MAX_LOG_BYTES} bytes; refusing to check"
        ));
    }
    let mut shas = Vec::new();
    for line in out.lines().filter(|l| !l.is_empty()) {
        if !is_sha(line) {
            return Err(format!(
                "git rev-list printed a malformed commit hash \"{}\"",
                line.escape_debug()
            ));
        }
        if shas.len() >= MAX_COMMITS {
            return Err(format!(
                "the range has more than {MAX_COMMITS} commits; refusing to check"
            ));
        }
        shas.push(line.to_owned());
    }
    Ok(shas)
}

/// Checks that the commits [`parse_log`] read are exactly the commits `git rev-list` lists for
/// the same range: the same number, no hash twice, the same set. A record forged by separator
/// bytes in commit metadata adds a hash that is not in the range, or repeats one that is.
///
/// # Errors
///
/// Returns a message naming the mismatch.
pub(crate) fn same_commits(commits: &[Commit], listed: &[String]) -> Result<(), String> {
    let read: BTreeSet<&str> = commits.iter().map(|c| c.sha.as_str()).collect();
    let want: BTreeSet<&str> = listed.iter().map(String::as_str).collect();
    if read.len() != commits.len() || want.len() != listed.len() || read != want {
        return Err(format!(
            "git log printed {} record(s) ({} distinct) but git rev-list lists {} commit(s) \
             ({} distinct) or a different set; commit metadata may hold forged separator \
             bytes. Refusing to pass",
            commits.len(),
            read.len(),
            listed.len(),
            want.len()
        ));
    }
    Ok(())
}

/// Splits a sign-off value `Name <email>` into its trimmed name and its email. The email is
/// what lies between the last `<` and a final `>`.
fn identity(value: &str) -> Option<(&str, &str)> {
    let value = value.trim();
    let inner = value.strip_suffix('>')?;
    let (name, email) = inner.rsplit_once('<')?;
    Some((name.trim(), email))
}

/// Whether one of `commit`'s sign-offs names its author (see the module docs, "Matching").
pub(crate) fn signed_off_by_author(commit: &Commit) -> bool {
    let author_name = commit.author_name.trim();
    commit.signoffs.iter().any(|s| {
        identity(s).is_some_and(|(name, email)| {
            !email.is_empty()
                && name == author_name
                && email.eq_ignore_ascii_case(&commit.author_email)
        })
    })
}

/// Every commit whose author did not sign it off, in `commits` order.
pub(crate) fn missing(commits: &[Commit]) -> Vec<Missing<'_>> {
    commits
        .iter()
        .filter(|c| !signed_off_by_author(c))
        .map(|commit| Missing { commit })
        .collect()
}

/// The squash mode's reading of one commit message (`%B`): the value of every well-formed
/// `Signed-off-by: Name <email>` line anywhere in it, not only in the final trailer block (see
/// the module docs, "Squash mode"). A line counts when, after trimming, it starts with the key
/// (any ASCII case) and its value has a non-empty name, a non-empty email and no control
/// character. The squash mode passes a commit when this is not empty.
///
/// # Errors
///
/// Returns a message when the message is larger than [`MAX_MESSAGE_BYTES`].
pub(crate) fn squash_signoffs(message: &str) -> Result<Vec<&str>, String> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(format!(
            "a commit message is larger than {MAX_MESSAGE_BYTES} bytes; refusing to check"
        ));
    }
    Ok(message
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let key = line.get(..SIGNOFF_KEY.len())?;
            if !key.eq_ignore_ascii_case(SIGNOFF_KEY) {
                return None;
            }
            let value = line.get(SIGNOFF_KEY.len()..)?.trim();
            let (name, email) = identity(value)?;
            let ok = !name.is_empty() && !email.is_empty() && !value.chars().any(char::is_control);
            ok.then_some(value)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "1387df9c4c4f1f70c43f142b57b3713dac7edbce";
    const SHA_B: &str = "d18b058a46b82d283651f950561b56904b2099f4";

    fn record(sha: &str, name: &str, email: &str, trailers: &str) -> String {
        format!("{sha}\u{1f}{name}\u{1f}{email}\u{1f}{trailers}\u{1e}\n")
    }

    fn commit(name: &str, email: &str, signoffs: &[&str]) -> Commit {
        Commit {
            sha: SHA_A.to_owned(),
            author_name: name.to_owned(),
            author_email: email.to_owned(),
            signoffs: signoffs.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn listed(shas: &[&str]) -> Vec<String> {
        shas.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_git_log_output() {
        let out = record(
            SHA_A,
            "Jane Doe",
            "jane@example.com",
            "Jane Doe <jane@example.com>\nBob <bob@example.com>\n",
        ) + &record(SHA_B, "Bob", "bob@example.com", "");
        let commits = parse_log(&out).unwrap();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].sha, SHA_A);
        assert_eq!(commits[0].author_name, "Jane Doe");
        assert_eq!(
            commits[0].signoffs,
            ["Jane Doe <jane@example.com>", "Bob <bob@example.com>"]
        );
        assert!(commits[1].signoffs.is_empty());
        assert_eq!(same_commits(&commits, &listed(&[SHA_B, SHA_A])), Ok(()));
    }

    #[test]
    fn empty_output_is_no_commits() {
        assert_eq!(parse_log("").unwrap(), []);
        assert_eq!(parse_log("\n\n").unwrap(), []);
        assert_eq!(parse_rev_list("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn malformed_output_fails_closed() {
        // A field separator smuggled into the name.
        let smuggled = record(SHA_A, "A\u{1f}B", "a@x", "");
        assert!(parse_log(&smuggled).is_err());
        // Too few fields.
        assert!(parse_log(&format!("{SHA_A}\u{1f}A\u{1e}\n")).is_err());
        // No terminator after the last record.
        assert!(parse_log(&format!("{SHA_A}\u{1f}A\u{1f}a@x\u{1f}")).is_err());
        // Hashes that are not 40 or 64 lowercase hex digits.
        for sha in [
            "",
            "1387df9",
            SHA_A.to_uppercase().as_str(),
            format!("{SHA_A}0").as_str(),
        ] {
            assert!(parse_log(&record(sha, "A", "a@x", "")).is_err(), "{sha}");
            if !sha.is_empty() {
                assert!(parse_rev_list(&format!("{sha}\n")).is_err(), "{sha}");
            }
        }
        // A SHA-256 repository's hash is accepted.
        let sha256 = "ab".repeat(32);
        assert!(parse_log(&record(&sha256, "A", "a@x", "")).is_ok());
        assert!(parse_rev_list(&format!("{sha256}\n")).is_ok());
        // Stray bytes and multi-byte text never panic.
        for junk in [
            "\u{1e}",
            "\u{1f}\u{1e}",
            "é\u{1e}",
            "\u{1f}\u{1f}\u{1f}\u{1e}",
        ] {
            assert!(parse_log(junk).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn control_characters_in_metadata_fail_closed() {
        for (name, email, trailers) in [
            ("A\u{7}", "a@x", "A <a@x>"),
            ("A", "a@x\u{1b}", "A <a@x>"),
            ("A", "a@x", "A <a@x>\u{0}"),
            ("A", "a@x", "A\rB <a@x>"),
            ("A\u{85}", "a@x", "A <a@x>"),
        ] {
            assert!(
                parse_log(&record(SHA_A, name, email, trailers)).is_err(),
                "{name:?} {email:?} {trailers:?}"
            );
        }
    }

    /// The forgery the review reproduced, moved to the fields that are still printed: separator
    /// bytes in commit metadata end the real record early (with a field count that stays
    /// right) and start a fake one that matches its own "author". Only the `git rev-list`
    /// cross-check sees it.
    #[test]
    fn a_forged_record_fails_the_rev_list_cross_check() {
        let fake = "a".repeat(40);
        // Author name `X\x1fX <a@x>... ` built so that record 1 reads (SHA_A, X, a@x, "X <a@x>")
        // and record 2 reads (fake, Mallory, m@x, "Mallory <m@x>").
        let out = format!(
            "{SHA_A}\u{1f}X\u{1f}a@x\u{1f}X <a@x>\u{1e}{fake}\u{1f}Mallory\u{1f}m@x\u{1f}Mallory <m@x>\u{1e}\n"
        );
        let commits = parse_log(&out).unwrap();
        assert_eq!(commits.len(), 2);
        // Each forged record "matches its author"...
        assert!(missing(&commits).is_empty());
        // ...but the range holds one commit, so the check refuses.
        assert!(same_commits(&commits, &listed(&[SHA_A])).is_err());
        // The fake record reusing a real hash is a duplicate, also refused.
        let dup = format!(
            "{SHA_A}\u{1f}X\u{1f}a@x\u{1f}X <a@x>\u{1e}{SHA_A}\u{1f}M\u{1f}m@x\u{1f}M <m@x>\u{1e}\n"
        );
        let commits = parse_log(&dup).unwrap();
        assert!(same_commits(&commits, &listed(&[SHA_A, SHA_B])).is_err());
        assert!(same_commits(&commits, &listed(&[SHA_A])).is_err());
        // A different set of the same size.
        let commits = parse_log(&record(SHA_A, "A", "a@x", "A <a@x>")).unwrap();
        assert!(same_commits(&commits, &listed(&[SHA_B])).is_err());
        // rev-list listing a hash twice.
        assert!(same_commits(&commits, &listed(&[SHA_A, SHA_A])).is_err());
    }

    #[test]
    fn caps_the_number_of_commits() {
        let one = record(SHA_A, "A", "a@x", "A <a@x>");
        assert_eq!(
            parse_log(&one.repeat(MAX_COMMITS)).unwrap().len(),
            MAX_COMMITS
        );
        assert!(parse_log(&one.repeat(MAX_COMMITS + 1)).is_err());
        let line = format!("{SHA_A}\n");
        assert_eq!(
            parse_rev_list(&line.repeat(MAX_COMMITS)).unwrap().len(),
            MAX_COMMITS
        );
        assert!(parse_rev_list(&line.repeat(MAX_COMMITS + 1)).is_err());
    }

    #[test]
    fn author_sign_off_matches() {
        let c = commit(
            "Jane Doe",
            "jane@example.com",
            &["Jane Doe <jane@example.com>"],
        );
        assert!(signed_off_by_author(&c));
        // The email ignores ASCII case, and outer whitespace is trimmed.
        let c = commit(
            "Jane Doe",
            "Jane@Example.com",
            &["  Jane Doe   <jane@example.COM> "],
        );
        assert!(signed_off_by_author(&c));
        // One matching trailer among others is enough.
        let c = commit(
            "Jane Doe",
            "jane@example.com",
            &["Maintainer <m@example.com>", "Jane Doe <jane@example.com>"],
        );
        assert!(signed_off_by_author(&c));
    }

    #[test]
    fn other_sign_offs_do_not_match() {
        for signoffs in [
            &[][..],
            &["Maintainer <m@example.com>"],
            &["Jane Doe <jane@example.org>"],
            &["jane doe <jane@example.com>"],
            &["Jane <jane@example.com>"],
            &["Jane Doe jane@example.com"],
            &["Jane Doe <jane@example.com"],
            &["Jane Doe <>"],
            &["<jane@example.com>"],
        ] {
            let c = commit("Jane Doe", "jane@example.com", signoffs);
            assert!(!signed_off_by_author(&c), "{signoffs:?}");
        }
        // An author with an empty email is never matched by an empty one.
        assert!(!signed_off_by_author(&commit("Jane", "", &["Jane <>"])));
    }

    #[test]
    fn missing_lists_unsigned_commits_in_order() {
        let signed = commit("A", "a@x", &["A <a@x>"]);
        let mut unsigned = commit("B", "b@x", &["A <a@x>"]);
        unsigned.sha = SHA_B.to_owned();
        let commits = [signed, unsigned];
        let found = missing(&commits);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].commit.sha, SHA_B);
    }

    #[test]
    fn report_escapes_untrusted_text() {
        let c = commit(
            "Eve\n::error::x",
            "e@x\u{1b}[31m",
            &["a\n::set-output name=x::y"],
        );
        let line = Missing { commit: &c }.to_string();
        assert!(!line.contains('\n'), "{line}");
        assert!(!line.contains('\u{1b}'), "{line}");
        assert!(line.starts_with(&SHA_A[..12]), "{line}");
        assert!(line.contains("no Signed-off-by trailer"), "{line}");
        let c = commit("A", "a@x", &["B <b@x>"]);
        assert!(
            Missing { commit: &c }
                .to_string()
                .ends_with("(found: \"B <b@x>\")")
        );
    }

    /// A squash commit in GitHub's "Pull request title and commit details" format with two
    /// authors: the sign-offs sit in the body and the final paragraph is `Co-authored-by:`, so
    /// git's trailer block would not return them. The squash mode finds them anywhere.
    #[test]
    fn squash_mode_reads_sign_offs_anywhere_in_the_message() {
        let msg = "feat(core): x (#12)\n\
                   \n\
                   * feat(core): first\n\
                   \n\
                   Signed-off-by: Jane Doe <jane@example.com>\n\
                   \n\
                   * fix(core): second\n\
                   \n\
                   Signed-off-by: Bob <bob@example.com>\n\
                   \n\
                   ---------\n\
                   \n\
                   Co-authored-by: Bob <bob@example.com>\n";
        assert_eq!(
            squash_signoffs(msg).unwrap(),
            ["Jane Doe <jane@example.com>", "Bob <bob@example.com>"]
        );
        // Key case and indentation do not matter.
        assert_eq!(
            squash_signoffs("t\n\n  signed-OFF-by:  A <a@x> \n").unwrap(),
            ["A <a@x>"]
        );
    }

    #[test]
    fn squash_mode_rejects_messages_without_a_well_formed_sign_off() {
        for msg in [
            // "Pull request title": every trailer dropped.
            "feat(core): x (#12)\n",
            // "Pull request title and description", or a web merge commit.
            "Merge pull request #12 from a/b\n\nSome description.\n",
            // Only authorship, no certification.
            "feat: x\n\nCo-authored-by: Bob <bob@example.com>\n",
            // Malformed values.
            "t\n\nSigned-off-by: Bob\n",
            "t\n\nSigned-off-by: <bob@x>\n",
            "t\n\nSigned-off-by: Bob <>\n",
            "t\n\nSigned-off-by: Bob <b@x\n",
            "t\n\nSigned-off-by: B\u{1f}ob <b@x>\n",
            "t\n\nSigned-off-by Bob <b@x>\n",
            "t\n\nNot-Signed-off-by: Bob <b@x>\n",
            "",
            "é",
        ] {
            assert!(squash_signoffs(msg).unwrap().is_empty(), "{msg:?}");
        }
        let big = "a".repeat(MAX_MESSAGE_BYTES + 1);
        assert!(squash_signoffs(&big).is_err());
    }

    #[test]
    fn range_argument() {
        for ok in [
            "1387df9c4c4f1f70c43f142b57b3713dac7edbce..d18b058a46b82d283651f950561b56904b2099f4",
            "origin/main..HEAD",
            "v0.1.0..feature/x_y-z",
        ] {
            assert_eq!(check_range(ok), Ok(()), "{ok}");
        }
        let long = "a".repeat(MAX_REV_LEN + 1);
        for bad in [
            "",
            "HEAD",
            "..HEAD",
            "main..",
            "main...HEAD",
            "main..HEAD..x",
            "--output=x..HEAD",
            "main..-p",
            "main..HEAD^",
            "main..HEAD~1",
            "main..@{u}",
            "main..HEAD:x",
            "main ..HEAD",
            "main..HÉAD",
            format!("{long}..HEAD").as_str(),
        ] {
            assert!(check_range(bad).is_err(), "{bad}");
        }
    }
}

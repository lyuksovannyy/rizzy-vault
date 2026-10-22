// SPDX-License-Identifier: AGPL-3.0-only

//! The SPDX header check of [ADR 0017] Decision 6, run by `cargo xtask check-spdx` (reports
//! every missing or wrong header) and `cargo xtask check-spdx --fix` (writes them).
//!
//! Decision 6 requires every source file we write to start with
//!
//! ```text
//! // SPDX-License-Identifier: AGPL-3.0-only
//! ```
//!
//! on its first line, or on the line after a shebang, in the language's own comment syntax, with
//! no per-file copyright line or year. [`EXPRESSION`] is plain `AGPL-3.0-only` (Decision 2, owner
//! decision 1): Decision 3's App Store additional permission is not committed yet (§3 "Not done
//! yet"), so there is no custom addition to fold in, and Decision 6 says the expression "follows
//! Decision 2 and 3".
//!
//! # Which files
//!
//! Decision 6 names the covered languages: Rust, TypeScript/JavaScript, Swift, Kotlin, shell, CSS
//! and HTML templates ([`Lang`]; no Swift or Kotlin source exists in this repository yet). It
//! does not name TOML, JSON, YAML or Markdown, and its own closing sentence treats manifests
//! separately ("Crate manifests keep `license.workspace = true`. A crate never overrides it."),
//! so `Cargo.toml` and other config files get no header here. That is a scope reading for the
//! owner to overrule in one line, not an oversight.
//!
//! Candidates come from `git ls-files --cached --others --exclude-standard` under the workspace
//! root ([`candidates`]), the listing [`crate::rust_sources`] also uses for the `unsafe` scan, so
//! a new untracked file is checked before it is committed and build output under `target/` never
//! is. [`excluded`] then drops:
//!
//! - `.claude/` and `.github/`: CLAUDE.md forbids editing either without an explicit ask, and
//!   wiring this check into CI (`.github/workflows/ci.yml`) is a separate ask the owner has not
//!   given yet. The one shell script in the repository, `.claude/hooks/session-start.sh`, is
//!   excluded on this ground alone — it is otherwise a plain candidate.
//! - [`crate::rules::GENERATED_RUST`] (`crates/rizzy-wasm/generated/`): wasm-bindgen's emitted
//!   glue, reviewed as third-party code (ADR 0019 §4.1), never hand-edited.
//!
//! Nothing else is vendored or generated under a covered extension today: the PSL snapshot and
//! the crypto test vectors are `.txt`/`.json`, already outside Decision 6's list.
//!
//! # Shebang handling
//!
//! A real shebang (`#!/usr/bin/env node`, `#!/bin/bash`) moves the header to line 2
//! ([`is_shebang`]). A Rust inner attribute on line 1 (`#![forbid(unsafe_code)]`) is not a
//! shebang: it starts `#![`, never `#!/` or a bare interpreter name, so [`is_shebang`] reads it as
//! ordinary line-1 content and the header is inserted above it, which is legal because a line
//! comment may precede an inner attribute. Every first-party `.rs` file in this repository in
//! fact starts with a `//!` module doc comment, not an attribute, so this case does not arise
//! today; it is still handled and tested because a future file could start either way.
//!
//! # HTML
//!
//! Decision 6 gives HTML templates no exception, so the header goes on line 1, before
//! `<!doctype html>`. This was not just assumed: the task report for HANDOFF gap 40 records a
//! browser check of the built web vault's `document.compatMode` after `--fix` ran, confirming
//! standards mode, because the historical IE-era rule ("anything before DOCTYPE forces quirks
//! mode") is not what the HTML5 tree-construction "initial" insertion mode does — a leading
//! comment is inserted as a child of the document and the DOCTYPE that follows still decides the
//! mode on its own content.
//!
//! # Fixing
//!
//! [`fixed_text`] either inserts a new header line (truly missing: [`Status::Missing`]) or
//! replaces an existing line that already looks like an SPDX attempt but has the wrong text
//! (wrong identifier, a typo: [`Status::Wrong`]), never both. An insertion adds exactly one blank
//! line after the header, before any existing content, so a `//!` module doc comment's first
//! paragraph never starts on the same line as a plain comment; a replacement changes only that
//! one line. Either way the file's own line terminator (`\n` or `\r\n`) is kept, and a file
//! already correct is returned unchanged, so `--fix` is idempotent.
//!
//! [ADR 0017]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0017-licensing.md

use std::path::Path;
use std::process::Command;

/// The plain SPDX license expression (ADR 0017 Decision 2, owner decision 1; see the module
/// docs for why no Decision 3 addition is folded in).
pub(crate) const EXPRESSION: &str = "AGPL-3.0-only";

/// A language Decision 6 covers, keyed by its comment syntax. No Swift or Kotlin source exists
/// in this repository yet, so they have no variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lang {
    /// `.rs`: a Rust line comment.
    Rust,
    /// `.ts`, `.tsx`, `.js`, `.mjs`, `.jsx`, `.cjs`, `.mts`, `.cts`: the same line-comment syntax.
    TsJs,
    /// `.sh`, `.bash`: a shell line comment.
    Shell,
    /// `.css`: a block comment (CSS has no line comment).
    Css,
    /// `.html`, `.htm`: an HTML comment.
    Html,
}

impl Lang {
    /// The language for `path`'s extension, matched case-insensitively — a case-insensitive file
    /// system can open `X.RS` for `mod x;`, as [`crate::unsafe_scan::first_party`] notes — or
    /// `None` for an extension Decision 6 does not cover.
    pub(crate) fn of(path: &str) -> Option<Self> {
        let ext = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "rs" => Self::Rust,
            "ts" | "tsx" | "js" | "mjs" | "jsx" | "cjs" | "mts" | "cts" => Self::TsJs,
            "sh" | "bash" => Self::Shell,
            "css" => Self::Css,
            "html" | "htm" => Self::Html,
            _ => return None,
        })
    }

    /// The exact expected header line for this language, with no trailing newline.
    pub(crate) fn header(self) -> String {
        match self {
            Self::Rust | Self::TsJs => format!("// SPDX-License-Identifier: {EXPRESSION}"),
            Self::Shell => format!("# SPDX-License-Identifier: {EXPRESSION}"),
            Self::Css => format!("/* SPDX-License-Identifier: {EXPRESSION} */"),
            Self::Html => format!("<!-- SPDX-License-Identifier: {EXPRESSION} -->"),
        }
    }

    /// This language's comment-opening token, for [`looks_like_attempt`].
    fn comment_open(self) -> &'static str {
        match self {
            Self::Rust | Self::TsJs => "//",
            Self::Shell => "#",
            Self::Css => "/*",
            Self::Html => "<!--",
        }
    }
}

/// Whether `line` is a real shebang (`#!/usr/bin/env node`, `#!/bin/bash`, `#!perl`), not a Rust
/// inner attribute (`#![attr]`), which also starts `#!` but is first-line code, not a shebang.
/// Decision 6 moves the header past a real shebang only.
pub(crate) fn is_shebang(line: &str) -> bool {
    line.starts_with("#!") && !line.starts_with("#![")
}

/// The 0-based line index where the header belongs: 1 when `lines` starts with a real shebang
/// ([`is_shebang`]), 0 otherwise.
pub(crate) fn header_index(lines: &[&str]) -> usize {
    usize::from(lines.first().is_some_and(|l| is_shebang(l)))
}

/// Whether `line` already looks like an attempt at `lang`'s SPDX header: it opens with the
/// language's comment token and mentions `SPDX-License-Identifier`, whatever the rest says. Used
/// only to decide how [`fixed_text`] fixes the line: in place (a wrong identifier, a typo) versus
/// inserting a new one above it (truly missing, pushing existing content down a line).
fn looks_like_attempt(lang: Lang, line: &str) -> bool {
    line.starts_with(lang.comment_open()) && line.contains("SPDX-License-Identifier")
}

/// The result of checking one file's header against [`Lang::header`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// The expected header is exactly at the expected line.
    Ok,
    /// No line at the expected index looks like an SPDX header attempt: either the line holds
    /// other content (a module doc comment, a blank line), or the file is too short to have a
    /// line there at all (empty, or only a shebang).
    Missing,
    /// A line at the expected index looks like an SPDX header attempt, but is not the expected
    /// text exactly.
    Wrong {
        /// The line as found.
        found: String,
    },
}

/// Checks `text` against `lang`'s expected header (module docs, "Which files" and "Shebang
/// handling").
pub(crate) fn check_text(lang: Lang, text: &str) -> Status {
    let lines: Vec<&str> = text.lines().collect();
    let expected = lang.header();
    match lines.get(header_index(&lines)) {
        Some(line) if *line == expected => Status::Ok,
        Some(line) if looks_like_attempt(lang, line) => Status::Wrong {
            found: (*line).to_owned(),
        },
        _ => Status::Missing,
    }
}

/// Splits `text` into (content, terminator) pairs, one pair per line: terminator is `"\r\n"`,
/// `"\n"`, or `""` for a final line with no trailing newline. Empty `text` yields no pairs.
fn split_lines(text: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        match rest.find('\n') {
            Some(i) if rest[..i].ends_with('\r') => {
                out.push((&rest[..i - 1], "\r\n"));
                rest = &rest[i + 1..];
            }
            Some(i) => {
                out.push((&rest[..i], "\n"));
                rest = &rest[i + 1..];
            }
            None => {
                out.push((rest, ""));
                rest = "";
            }
        }
    }
    out
}

/// The reverse of [`split_lines`].
fn join_lines(lines: &[(&str, &str)]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (content, terminator) in lines {
        let _ = write!(out, "{content}{terminator}");
    }
    out
}

/// `lines`' dominant line terminator: its first line's, or `"\n"` if that line has none (a
/// one-line file with no trailing newline) or there are no lines at all.
fn dominant_terminator(lines: &[(&str, &str)]) -> &'static str {
    match lines.first() {
        Some((_, "\r\n")) => "\r\n",
        _ => "\n",
    }
}

/// Replaces line `index` of `text` with `new_line`, keeping its own terminator (or the file's
/// dominant one if, somehow, it had none). Every other line is unchanged. Used for
/// [`Status::Wrong`].
fn replace_line(text: &str, index: usize, new_line: &str) -> String {
    let mut lines = split_lines(text);
    let terminator = dominant_terminator(&lines);
    if let Some((content, t)) = lines.get_mut(index) {
        *content = new_line;
        if t.is_empty() {
            *t = terminator;
        }
    }
    join_lines(&lines)
}

/// Inserts `new_line` as a new line at `index`, pushing the line that was there (and everything
/// after it), if any, down by one line, separated from it by exactly one blank line. Nothing
/// before `index` (a shebang) moves. If `index` is at or past the end, `new_line` is simply
/// appended, with a terminator added to the previous last line if it had none ([`insert_final_newline`
/// in `.editorconfig`]). Used for [`Status::Missing`].
///
/// [`insert_final_newline` in `.editorconfig`]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/.editorconfig
fn insert_line(text: &str, index: usize, new_line: &str) -> String {
    let mut lines = split_lines(text);
    let terminator = dominant_terminator(&lines);
    if let Some(last) = lines.last_mut().filter(|(_, t)| t.is_empty()) {
        last.1 = terminator;
    }
    let at = index.min(lines.len());
    let had_content_after = at < lines.len();
    let mut out = Vec::with_capacity(lines.len() + 2);
    out.extend_from_slice(&lines[..at]);
    out.push((new_line, terminator));
    if had_content_after {
        out.push(("", terminator));
    }
    out.extend_from_slice(&lines[at..]);
    join_lines(&out)
}

/// Fixes `text`'s header for `lang` (module docs, "Fixing"): unchanged if already
/// [`Status::Ok`], [`replace_line`] for [`Status::Wrong`], [`insert_line`] for
/// [`Status::Missing`]. Applying this again to its own output always returns that output
/// unchanged.
pub(crate) fn fixed_text(lang: Lang, text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let index = header_index(&lines);
    let header = lang.header();
    match check_text(lang, text) {
        Status::Ok => text.to_owned(),
        Status::Wrong { .. } => replace_line(text, index, &header),
        Status::Missing => insert_line(text, index, &header),
    }
}

/// Whether `path` (relative to the workspace root, `/` separators, as git prints it) lies at or
/// under directory `dir`: equal, or `dir` is a proper prefix ending at a `/` boundary.
fn under(path: &str, dir: &str) -> bool {
    let dir = dir.trim_end_matches('/');
    path == dir
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Directories excluded from this check for reasons that have nothing to do with file type
/// (module docs, "Which files"): CLAUDE.md forbids editing either without an explicit ask.
const EXCLUDED_DIRS: &[&str] = &[".claude", ".github"];

/// Whether `path` is excluded regardless of its extension: [`EXCLUDED_DIRS`], or
/// [`crate::rules::GENERATED_RUST`].
pub(crate) fn excluded(path: &str) -> bool {
    EXCLUDED_DIRS.iter().any(|d| under(path, d))
        || crate::rules::GENERATED_RUST.iter().any(|d| under(path, d))
}

/// Runs `cmd`, returning stdout, or a message with stderr (the small local copy every xtask
/// module keeps, for example `bindings::run`).
fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("running {cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("{cmd:?} printed invalid UTF-8: {e}"))
}

/// Every candidate file under `root`: tracked files and untracked-but-not-ignored files
/// (`git ls-files --cached --others --exclude-standard`), filtered to a covered [`Lang`] and not
/// [`excluded`], as (path, language) pairs sorted by path.
///
/// # Errors
///
/// Returns a message when git fails, or lists a path that is not UTF-8.
fn candidates(root: &Path) -> Result<Vec<(String, Lang)>, String> {
    let listing = run(Command::new("git").current_dir(root).args([
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ]))?;
    let mut out: Vec<(String, Lang)> = listing
        .split('\0')
        .filter(|p| !p.is_empty() && !excluded(p))
        .filter_map(|p| Lang::of(p).map(|lang| (p.to_owned(), lang)))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The file's contents, or `None` if it does not exist. [`candidates`] lists tracked files too,
/// and a tracked file can be deleted from the working tree; it is skipped, as
/// [`crate::rust_sources`] does for the same reason ("there is nothing left to compile" —
/// nothing left to check or fix, here).
///
/// # Errors
///
/// Returns a message naming the path for any read error other than "not found".
fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// Describes where the header belongs, for a message: `"line 1"`, or `"line 2 (after the
/// shebang)"` when `index` is 1.
fn describe_index(index: usize) -> &'static str {
    if index == 0 {
        "line 1"
    } else {
        "line 2 (after the shebang)"
    }
}

/// `cargo xtask check-spdx`: every [`candidates`] file whose header is not [`Status::Ok`], as one
/// message per file, sorted by path.
///
/// # Errors
///
/// Returns a message when git fails or a candidate file cannot be read.
pub(crate) fn check(root: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (path, lang) in candidates(root)? {
        let Some(text) = read_optional(&root.join(&path))? else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let at = describe_index(header_index(&lines));
        match check_text(lang, &text) {
            Status::Ok => {}
            Status::Missing => out.push(format!(
                "{path}: missing the SPDX header on {at} (expected `{}`)",
                lang.header()
            )),
            Status::Wrong { found } => out.push(format!(
                "{path}: {at} is `{found}`, expected `{}`",
                lang.header()
            )),
        }
    }
    Ok(out)
}

/// `cargo xtask check-spdx --fix`: writes [`fixed_text`] to every [`candidates`] file whose
/// content changes, and returns the paths it wrote to, sorted.
///
/// # Errors
///
/// Returns a message when git fails, a candidate file cannot be read, or a fixed file cannot be
/// written.
pub(crate) fn fix(root: &Path) -> Result<Vec<String>, String> {
    let mut written = Vec::new();
    for (path, lang) in candidates(root)? {
        let full = root.join(&path);
        let Some(text) = read_optional(&full)? else {
            continue;
        };
        let new_text = fixed_text(lang, &text);
        if new_text != text {
            std::fs::write(&full, new_text).map_err(|e| format!("writing {path}: {e}"))?;
            written.push(path);
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lang_of_recognizes_covered_extensions_case_insensitively() {
        assert_eq!(Lang::of("crates/x/src/lib.rs"), Some(Lang::Rust));
        assert_eq!(Lang::of("crates/x/src/LIB.RS"), Some(Lang::Rust));
        assert_eq!(Lang::of("apps/web/src/main.tsx"), Some(Lang::TsJs));
        assert_eq!(Lang::of("apps/web/src/x.ts"), Some(Lang::TsJs));
        assert_eq!(Lang::of("eslint.config.mjs"), Some(Lang::TsJs));
        assert_eq!(Lang::of("x.jsx"), Some(Lang::TsJs));
        assert_eq!(Lang::of("x.cjs"), Some(Lang::TsJs));
        assert_eq!(Lang::of("x.mts"), Some(Lang::TsJs));
        assert_eq!(Lang::of("x.cts"), Some(Lang::TsJs));
        assert_eq!(
            Lang::of(".claude/hooks/session-start.sh"),
            Some(Lang::Shell)
        );
        assert_eq!(Lang::of("x.bash"), Some(Lang::Shell));
        assert_eq!(Lang::of("apps/web/src/app.css"), Some(Lang::Css));
        assert_eq!(Lang::of("apps/web/index.html"), Some(Lang::Html));
        assert_eq!(Lang::of("x.HTM"), Some(Lang::Html));
        // Not covered by Decision 6 (module docs, "Which files").
        for path in [
            "Cargo.toml",
            "x.json",
            "x.yaml",
            "x.yml",
            "README.md",
            "x.lock",
            "x",
        ] {
            assert_eq!(Lang::of(path), None, "{path}");
        }
    }

    #[test]
    fn is_shebang_distinguishes_rust_attributes() {
        assert!(is_shebang("#!/usr/bin/env node"));
        assert!(is_shebang("#!/bin/bash"));
        assert!(is_shebang("#!perl"));
        assert!(!is_shebang("#![forbid(unsafe_code)]"));
        assert!(!is_shebang("#![warn(clippy::indexing_slicing)]"));
        assert!(!is_shebang("// a comment"));
        assert!(!is_shebang(""));
    }

    #[test]
    fn header_text_per_language() {
        assert_eq!(
            Lang::Rust.header(),
            "// SPDX-License-Identifier: AGPL-3.0-only"
        );
        assert_eq!(
            Lang::TsJs.header(),
            "// SPDX-License-Identifier: AGPL-3.0-only"
        );
        assert_eq!(
            Lang::Shell.header(),
            "# SPDX-License-Identifier: AGPL-3.0-only"
        );
        assert_eq!(
            Lang::Css.header(),
            "/* SPDX-License-Identifier: AGPL-3.0-only */"
        );
        assert_eq!(
            Lang::Html.header(),
            "<!-- SPDX-License-Identifier: AGPL-3.0-only -->"
        );
    }

    #[test]
    fn check_text_reports_ok() {
        assert_eq!(
            check_text(
                Lang::Rust,
                "// SPDX-License-Identifier: AGPL-3.0-only\n\n//! doc\n"
            ),
            Status::Ok
        );
        assert_eq!(
            check_text(
                Lang::Shell,
                "#!/bin/bash\n# SPDX-License-Identifier: AGPL-3.0-only\nset -e\n"
            ),
            Status::Ok
        );
    }

    #[test]
    fn check_text_reports_missing() {
        // The common real case: real content on line 1, no SPDX attempt at all.
        assert_eq!(
            check_text(Lang::Rust, "//! `rizzy-core` crate docs.\n"),
            Status::Missing
        );
        // Empty file.
        assert_eq!(check_text(Lang::Css, ""), Status::Missing);
        // A shebang with nothing else: no line 2 to hold the header.
        assert_eq!(check_text(Lang::Shell, "#!/bin/bash\n"), Status::Missing);
        assert_eq!(check_text(Lang::Shell, "#!/bin/bash"), Status::Missing);
        // The correct line exists, but on line 2 with no shebang on line 1: Decision 6 requires
        // line 1, so this is still missing, not ok.
        assert_eq!(
            check_text(Lang::Rust, "\n// SPDX-License-Identifier: AGPL-3.0-only\n"),
            Status::Missing
        );
    }

    #[test]
    fn check_text_reports_wrong() {
        assert_eq!(
            check_text(Lang::Rust, "// SPDX-License-Identifier: MIT\n//! doc\n"),
            Status::Wrong {
                found: "// SPDX-License-Identifier: MIT".to_owned()
            }
        );
        assert_eq!(
            check_text(
                Lang::Rust,
                "// SPDX-License-Identifier: AGPL-3.0-or-later\n"
            ),
            Status::Wrong {
                found: "// SPDX-License-Identifier: AGPL-3.0-or-later".to_owned()
            }
        );
        // Wrong, after a shebang.
        assert_eq!(
            check_text(Lang::Shell, "#!/bin/bash\n# SPDX-License-Identifier: MIT\n"),
            Status::Wrong {
                found: "# SPDX-License-Identifier: MIT".to_owned()
            }
        );
    }

    #[test]
    fn fixed_text_inserts_when_missing() {
        let fixed = fixed_text(Lang::Rust, "//! `rizzy-core` crate docs.\n");
        assert_eq!(
            fixed,
            "// SPDX-License-Identifier: AGPL-3.0-only\n\n//! `rizzy-core` crate docs.\n"
        );
    }

    #[test]
    fn fixed_text_inserts_after_a_shebang() {
        let fixed = fixed_text(Lang::Shell, "#!/bin/bash\nset -euo pipefail\n");
        assert_eq!(
            fixed,
            "#!/bin/bash\n# SPDX-License-Identifier: AGPL-3.0-only\n\nset -euo pipefail\n"
        );
        // A shebang with nothing else: no blank line is added after (nothing to separate).
        assert_eq!(
            fixed_text(Lang::Shell, "#!/bin/bash\n"),
            "#!/bin/bash\n# SPDX-License-Identifier: AGPL-3.0-only\n"
        );
    }

    #[test]
    fn fixed_text_handles_the_empty_file() {
        assert_eq!(
            fixed_text(Lang::Css, ""),
            "/* SPDX-License-Identifier: AGPL-3.0-only */\n"
        );
    }

    #[test]
    fn fixed_text_replaces_in_place_when_wrong() {
        assert_eq!(
            fixed_text(Lang::Rust, "// SPDX-License-Identifier: MIT\n//! doc\n"),
            "// SPDX-License-Identifier: AGPL-3.0-only\n//! doc\n"
        );
    }

    #[test]
    fn fixed_text_leaves_an_already_correct_file_untouched() {
        let text = "// SPDX-License-Identifier: AGPL-3.0-only\n\n//! doc\n";
        assert_eq!(fixed_text(Lang::Rust, text), text);
    }

    #[test]
    fn fixed_text_is_idempotent() {
        for (lang, text) in [
            (Lang::Rust, "//! a crate doc\nfn f() {}\n"),
            (Lang::Rust, ""),
            (Lang::Shell, "#!/bin/bash\nset -e\n"),
            (Lang::Rust, "// SPDX-License-Identifier: MIT\n"),
            (Lang::Html, "<!doctype html>\n<html></html>\n"),
        ] {
            let once = fixed_text(lang, text);
            let twice = fixed_text(lang, &once);
            assert_eq!(once, twice, "{text:?}");
        }
    }

    #[test]
    fn fixed_text_preserves_crlf() {
        let fixed = fixed_text(Lang::Rust, "//! doc\r\nfn f() {}\r\n");
        assert_eq!(
            fixed,
            "// SPDX-License-Identifier: AGPL-3.0-only\r\n\r\n//! doc\r\nfn f() {}\r\n"
        );
    }

    #[test]
    fn fixed_text_adds_a_missing_final_newline_when_appending() {
        // No trailing newline at all: the header is still appended cleanly, and a terminator is
        // added to the line before it (.editorconfig: insert_final_newline).
        assert_eq!(
            fixed_text(Lang::Shell, "#!/bin/bash"),
            "#!/bin/bash\n# SPDX-License-Identifier: AGPL-3.0-only\n"
        );
    }

    #[test]
    fn excluded_paths() {
        assert!(excluded(".claude/hooks/session-start.sh"));
        assert!(excluded(".claude"));
        assert!(excluded(".github/workflows/ci.yml"));
        assert!(excluded("crates/rizzy-wasm/generated/expanded.rs"));
        assert!(excluded("crates/rizzy-wasm/generated/counts.txt"));
        assert!(!excluded("crates/rizzy-wasm/src/lib.rs"));
        assert!(!excluded("crates/rizzy-core/src/lib.rs"));
        assert!(!excluded("apps/web/src/main.tsx"));
        // A path that merely starts with the same characters is not "under" the directory.
        assert!(!excluded(".githubx/x.rs"));
        assert!(!excluded(".claudex/x.rs"));
    }

    #[test]
    fn under_matches_exactly_or_at_a_slash_boundary() {
        assert!(under(".claude/hooks/x.sh", ".claude"));
        assert!(under(".claude", ".claude"));
        assert!(!under(".claudex/x", ".claude"));
        assert!(!under("x/.claude/y", ".claude"));
    }
}

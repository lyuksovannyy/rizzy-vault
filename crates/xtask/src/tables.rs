// SPDX-License-Identifier: AGPL-3.0-only

//! The table-ownership check of [ADR 0011] point 7 and [ADR 0016] R4, run by
//! `cargo xtask check-tables` (ADR 0016 §5, row "R4, tables", M1).
//!
//! # What it enforces, and where each rule comes from
//!
//! - **Each domain's tables carry its prefix, and a domain queries only its own tables.**
//!   ADR 0011 point 5: "Table names carry the domain prefix: `auth_`, `vault_`, …" and "A domain
//!   crate queries only its own tables." ADR 0016 R4: "Each domain queries only its own tables".
//! - **What is read.** ADR 0011 point 7: the check "scans migration and query files. It reads
//!   the table names after `FROM`, `JOIN`, `INTO`, `UPDATE`, `TABLE` and `REFERENCES`."
//!   [`KEYWORDS`] is exactly that list.
//! - **When it fails.** ADR 0011 point 7: "It fails when a prefix does not match the owning
//!   crate. The one allowed foreign key is the only exception." Every table name read in a file
//!   must start with its owner's prefix ([`DOMAINS`]). An unquoted name is compared after SQL's
//!   folding to lower case; a quoted name is compared as written.
//! - **The one exception.** ADR 0011 point 6: "One cross-domain reference is allowed: a foreign
//!   key to `auth_accounts(id)` with `ON DELETE CASCADE`, so that deleting an account is one
//!   transaction. No other foreign key crosses a domain." So `REFERENCES auth_accounts (id)`,
//!   followed by `ON DELETE CASCADE` in the same constraint, is accepted in a file another
//!   domain owns. Anything else that names `auth_accounts` there, a query included, is a
//!   violation.
//!
//! # Which files, and who owns them
//!
//! - **Query files:** every `.sql` file under `crates/rizzy-domain-*/queries/`, recursively
//!   (ADR 0011 point 7: "Queries live in `.sql` files under each domain crate's `queries/`
//!   directory"). The owner is the crate. A domain crate with a `queries/` directory but no row
//!   in [`DOMAINS`] is a violation: its prefix is unknown, and ADR 0016 (Consequences) has the
//!   xtask rules updated whenever a crate is added.
//! - **Migration files:** every `.sql` file directly in [`MIGRATION_DIRS`] (ADR 0011 point 8).
//!   The owner is the domain the file name carries, `NNNN_<domain>_<what>.sql` (point 8: "Each
//!   file name carries the owning domain"). A name that carries none, or a domain with no row in
//!   [`DOMAINS`], is a violation.
//!
//! # Out of scope until the owner decides
//!
//! The `storage_` tables and the backup queries are not checked. Whether this check covers them
//! is an open owner question (docs/HANDOFF.md §5, gap 19). So migrations whose file name carries
//! the `storage` domain ([`NOT_CHECKED_MIGRATION_DOMAINS`]) are counted as not checked and
//! skipped, and `rizzy-storage`'s own `queries/` directory (backup, storage and engine-specific
//! queries) is not read: `rizzy-storage` is not a domain crate. A domain crate's file that names
//! a `storage_` table is still a violation, because that name does not carry the domain's own
//! prefix.
//!
//! # Narrowest readings
//!
//! Where the ADRs leave room, the check takes the narrowest reading and goes no further:
//!
//! - Only the names right after the six keywords are read. A comma-separated `FROM` list counts:
//!   each of its items is a name "after `FROM`". Names in other positions, such as
//!   `CREATE INDEX … ON t`, `ALTER TABLE … RENAME TO t` or `TRUNCATE t`, are not read.
//! - A keyword that does not introduce a table is skipped: `UPDATE` after `DO` (upsert), `ON`
//!   (foreign-key action), `FOR` or `KEY` (row locks), and `FROM` in `IS [NOT] DISTINCT FROM`.
//!   A keyword followed by `(` opens a subquery, whose own keywords are read where they stand.
//!   Any other token where a name should be (a literal, the end of the file) is reported, never
//!   skipped, so SQL the reader does not understand fails the check instead of passing it.
//! - SQL outside the files above (a string literal in a `.rs` file, a `.sql` file elsewhere) is
//!   not read: ADR 0011 point 7 names migration and query files only.
//!
//! Every violation in a file's SQL names `file:line`; a file-level one (an owner the check
//! cannot tell) names the file. The listing is sorted, so the output is deterministic, and
//! nothing touches the network.
//!
//! [ADR 0011]: ../../../docs/adr/0011-storage.md
//! [ADR 0016]: ../../../docs/adr/0016-workspace-layout.md

use std::fs;
use std::path::{Path, PathBuf};

/// A domain the check knows: its name in migration file names, its crate and its prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Domain {
    /// The owning domain a migration file name carries (ADR 0011 point 8).
    name: &'static str,
    /// The crate whose `queries/` directory holds the domain's query files.
    krate: &'static str,
    /// The table-name prefix (ADR 0011 point 5).
    prefix: &'static str,
}

/// The ownership table: the domains with a crate today (ADR 0016 §3). The other prefixes of
/// ADR 0011 point 5 (`relay_`, `share_`, `mail_`, `org_`) get a row when their crate is added.
const DOMAINS: [Domain; 2] = [
    Domain {
        name: "auth",
        krate: "rizzy-domain-auth",
        prefix: "auth_",
    },
    Domain {
        name: "vault",
        krate: "rizzy-domain-vault",
        prefix: "vault_",
    },
];

/// Migration domains this check does not read (module doc, "Out of scope until the owner
/// decides").
const NOT_CHECKED_MIGRATION_DOMAINS: [&str; 1] = ["storage"];

/// The two migration sequences, one per engine (ADR 0011 point 8).
const MIGRATION_DIRS: [&str; 2] = [
    "crates/rizzy-storage/migrations/sqlite",
    "crates/rizzy-storage/migrations/postgres",
];

/// The directory the crates live in (ADR 0016 §7).
const CRATES_DIR: &str = "crates";

/// The name prefix of the domain crates (ADR 0016 §3).
const DOMAIN_CRATE_PREFIX: &str = "rizzy-domain-";

/// The keywords whose following table names are read (ADR 0011 point 7).
const KEYWORDS: [&str; 6] = ["FROM", "JOIN", "INTO", "UPDATE", "TABLE", "REFERENCES"];

/// The one cross-domain foreign-key target (ADR 0011 point 6).
const SHARED_TABLE: &str = "auth_accounts";

/// The column that foreign key references (ADR 0011 point 6).
const SHARED_COLUMN: &str = "id";

/// Words that end a `FROM` item instead of being its alias, so a comma after them belongs to
/// another clause (`ORDER BY a, b`).
const CLAUSE_WORDS: [&str; 29] = [
    "WHERE",
    "GROUP",
    "ORDER",
    "LIMIT",
    "OFFSET",
    "JOIN",
    "INNER",
    "LEFT",
    "RIGHT",
    "FULL",
    "CROSS",
    "NATURAL",
    "OUTER",
    "ON",
    "USING",
    "UNION",
    "EXCEPT",
    "INTERSECT",
    "HAVING",
    "WINDOW",
    "RETURNING",
    "SET",
    "VALUES",
    "FOR",
    "FETCH",
    "INDEXED",
    "NOT",
    "DEFAULT",
    "SELECT",
];

/// Runs the check on the tree at `root`. `Ok` is the success line. `Err` is every violation
/// and a summary, or the error that kept the check from reading its inputs.
pub(crate) fn run(root: &Path) -> Result<String, String> {
    let report = check(root).map_err(|e| format!("check-tables: error: {e}"))?;
    if report.violations.is_empty() {
        let crates: Vec<&str> = DOMAINS.iter().map(|d| d.krate).collect();
        return Ok(format!(
            "check-tables: ok ({} query file(s) of {}, {} migration file(s): every table name \
             after FROM, JOIN, INTO, UPDATE, TABLE and REFERENCES carries its owner's prefix, \
             apart from the one foreign key REFERENCES auth_accounts (id) ON DELETE CASCADE; \
             ADR 0011 points 5-7, ADR 0016 R4). Not checked, pending the owner (HANDOFF §5 gap \
             19): {} storage migration file(s) and rizzy-storage's queries",
            report.query_files,
            crates.join(", "),
            report.migration_files,
            report.not_checked,
        ));
    }
    let mut lines: Vec<String> = report
        .violations
        .iter()
        .map(|v| format!("error: {v}"))
        .collect();
    lines.push(format!(
        "check-tables: {} violation(s) of the table-ownership rules (ADR 0011 points 5-7, \
         ADR 0016 R4). The ownership table is crates/xtask/src/tables.rs.",
        report.violations.len()
    ));
    Err(lines.join("\n"))
}

/// What [`check`] found.
#[derive(Debug, Default, PartialEq, Eq)]
struct Report {
    /// Every violation, in file order and then in line order.
    violations: Vec<String>,
    /// The domain query files checked.
    query_files: usize,
    /// The migration files checked.
    migration_files: usize,
    /// The migration files skipped as out of scope (the `storage` domain).
    not_checked: usize,
}

/// Reads every covered file under `root` and checks it. `Err` only when an input cannot be read,
/// a missing migration directory included; rule violations go into the report.
fn check(root: &Path) -> Result<Report, String> {
    let mut report = Report::default();
    for name in dir_names(&root.join(CRATES_DIR), CRATES_DIR)? {
        if !name.starts_with(DOMAIN_CRATE_PREFIX) {
            continue;
        }
        let queries = root.join(CRATES_DIR).join(&name).join("queries");
        if !queries.is_dir() {
            continue;
        }
        let rel_dir = format!("{CRATES_DIR}/{name}/queries");
        let Some(domain) = DOMAINS.iter().find(|d| d.krate == name) else {
            report.violations.push(format!(
                "{rel_dir}: crate {name} has a queries/ directory but no row in the ownership \
                 table (crates/xtask/src/tables.rs), so its table prefix cannot be checked \
                 (ADR 0011 point 7; ADR 0016, Consequences)"
            ));
            continue;
        };
        let owner = format!("crate {}", domain.krate);
        for (rel, path) in sql_files(&queries, &rel_dir, true)? {
            report.query_files += 1;
            let sql = read(&path, &rel)?;
            report
                .violations
                .extend(check_sql(&rel, &sql, domain, &owner));
        }
    }
    for dir in MIGRATION_DIRS {
        let abs = root.join(dir);
        if !abs.is_dir() {
            return Err(format!(
                "{dir}: not a directory; ADR 0011 point 8 puts the migrations there"
            ));
        }
        for (rel, path) in sql_files(&abs, dir, false)? {
            let file_name = rel.rsplit('/').next().unwrap_or_default();
            let Some(name) = migration_domain(file_name) else {
                report.violations.push(format!(
                    "{rel}: the file name carries no owning domain; expected \
                     NNNN_<domain>_<what>.sql (ADR 0011 points 7 and 8)"
                ));
                continue;
            };
            if NOT_CHECKED_MIGRATION_DOMAINS.contains(&name) {
                report.not_checked += 1;
                continue;
            }
            let Some(domain) = DOMAINS.iter().find(|d| d.name == name) else {
                report.violations.push(format!(
                    "{rel}: the file name carries the domain {name:?}, which has no row in the \
                     ownership table (crates/xtask/src/tables.rs), so its table prefix cannot \
                     be checked (ADR 0011 points 7 and 8)"
                ));
                continue;
            };
            report.migration_files += 1;
            let sql = read(&path, &rel)?;
            let owner = format!("the {} domain its file name carries", domain.name);
            report
                .violations
                .extend(check_sql(&rel, &sql, domain, &owner));
        }
    }
    Ok(report)
}

/// The owning domain a migration file name carries: `auth` for `0001_auth_initial.sql`. `None`
/// unless the name is `<digits>_<domain>[_<what>].sql`.
fn migration_domain(file_name: &str) -> Option<&str> {
    let stem = file_name.strip_suffix(".sql")?;
    let (seq, rest) = stem.split_once('_')?;
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let domain = rest.split('_').next().unwrap_or_default();
    (!domain.is_empty()).then_some(domain)
}

/// The names of the subdirectories of `dir`, sorted.
fn dir_names(dir: &Path, rel: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("{rel}: {e}"))? {
        let entry = entry.map_err(|e| format!("{rel}: {e}"))?;
        if entry.path().is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// Every `.sql` file in `dir` (and, with `recursive`, in its subdirectories) as its path
/// relative to the root, with `/` separators, and its full path; sorted by the relative path.
fn sql_files(dir: &Path, rel: &str, recursive: bool) -> Result<Vec<(String, PathBuf)>, String> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("{rel}: {e}"))? {
        let entry = entry.map_err(|e| format!("{rel}: {e}"))?;
        entries.push((
            entry.file_name().to_string_lossy().into_owned(),
            entry.path(),
        ));
    }
    entries.sort();
    let mut files = Vec::new();
    for (name, path) in entries {
        let child = format!("{rel}/{name}");
        if path.is_dir() {
            if recursive {
                files.extend(sql_files(&path, &child, true)?);
            }
        } else if path.extension().is_some_and(|e| e == "sql") {
            files.push((child, path));
        }
    }
    files.sort();
    Ok(files)
}

/// Reads one SQL file as UTF-8.
fn read(path: &Path, rel: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{rel}: {e}"))
}

/// One SQL token.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    /// An unquoted identifier or keyword, as written.
    Word(String),
    /// A quoted identifier (double quotes or backticks), without its quotes.
    Quoted(String),
    /// One punctuation character.
    Punct(char),
    /// A string or number literal or a bind parameter: never a name.
    Literal,
}

/// A token and the 1-based line it starts on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    /// The token.
    tok: Tok,
    /// The 1-based line it starts on.
    line: usize,
}

/// Splits SQL into tokens and drops `--` and `/* */` comments. `Err` names the line of an
/// unterminated comment, string or quoted identifier.
fn tokenize(sql: &str) -> Result<Vec<Token>, (usize, &'static str)> {
    let chars: Vec<char> = sql.chars().collect();
    let mut toks = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '-' && next == Some('-') {
            while chars.get(i).is_some_and(|&c| c != '\n') {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let start = line;
            i += 2;
            loop {
                match chars.get(i) {
                    None => return Err((start, "unterminated /* comment")),
                    Some('*') if chars.get(i + 1) == Some(&'/') => {
                        i += 2;
                        break;
                    }
                    Some('\n') => {
                        line += 1;
                        i += 1;
                    }
                    Some(_) => i += 1,
                }
            }
        } else if c == '\'' || c == '"' || c == '`' {
            let start = line;
            let Some((text, end)) = quoted(&chars, i, c) else {
                return Err((start, "unterminated quoted string or identifier"));
            };
            line += text.matches('\n').count();
            let tok = if c == '\'' {
                Tok::Literal
            } else {
                Tok::Quoted(text)
            };
            toks.push(Token { tok, line: start });
            i = end;
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while chars
                .get(i)
                .is_some_and(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            {
                i += 1;
            }
            let word: String = chars.get(start..i).unwrap_or_default().iter().collect();
            toks.push(Token {
                tok: Tok::Word(word),
                line,
            });
        } else if c.is_ascii_digit() || (c == '$' && next.is_some_and(|n| n.is_ascii_digit())) {
            i += 1;
            while chars
                .get(i)
                .is_some_and(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            {
                i += 1;
            }
            toks.push(Token {
                tok: Tok::Literal,
                line,
            });
        } else {
            toks.push(Token {
                tok: Tok::Punct(c),
                line,
            });
            i += 1;
        }
    }
    Ok(toks)
}

/// The text of the quoted token that opens at `open` with the quote `q` (a doubled quote stands
/// for one) and the index after its closing quote; `None` if it is never closed.
fn quoted(chars: &[char], open: usize, q: char) -> Option<(String, usize)> {
    let mut text = String::new();
    let mut i = open + 1;
    loop {
        let c = *chars.get(i)?;
        if c == q {
            if chars.get(i + 1) == Some(&q) {
                text.push(q);
                i += 2;
                continue;
            }
            return Some((text, i + 1));
        }
        text.push(c);
        i += 1;
    }
}

/// Whether `t` is the unquoted word `kw`, in any case.
fn is_word(t: Option<&Token>, kw: &str) -> bool {
    matches!(t.map(|t| &t.tok), Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw))
}

/// Whether the token at `j` is the punctuation `c`.
fn is_punct(toks: &[Token], j: usize, c: char) -> bool {
    toks.get(j).is_some_and(|t| t.tok == Tok::Punct(c))
}

/// One part of a table name: an unquoted word folded to lower case, as SQL folds it, or a
/// quoted identifier as written.
fn name_part(t: &Token) -> Option<String> {
    match &t.tok {
        Tok::Word(w) => Some(w.to_ascii_lowercase()),
        Tok::Quoted(q) => Some(q.clone()),
        Tok::Punct(_) | Tok::Literal => None,
    }
}

/// The table name at `j`, any `schema.` qualifier kept, and the index after it.
fn name_at(toks: &[Token], j: usize) -> Option<(String, usize)> {
    let mut name = name_part(toks.get(j)?)?;
    let mut k = j + 1;
    while is_punct(toks, k, '.') {
        let Some(part) = toks.get(k + 1).and_then(name_part) else {
            break;
        };
        name.push('.');
        name.push_str(&part);
        k += 2;
    }
    Some((name, k))
}

/// Whether the keyword `kw` at `i` introduces a table name (module doc, "Narrowest readings").
fn introduces_table(toks: &[Token], i: usize, kw: &str) -> bool {
    let prev = i.checked_sub(1).and_then(|p| toks.get(p));
    match kw {
        "UPDATE" => !["DO", "ON", "FOR", "KEY"].iter().any(|w| is_word(prev, w)),
        "FROM" => {
            let before = i.checked_sub(2).and_then(|p| toks.get(p));
            !(is_word(prev, "DISTINCT") && (is_word(before, "IS") || is_word(before, "NOT")))
        }
        _ => true,
    }
}

/// Skips the modifiers that may stand between a keyword and its table name: `IF [NOT] EXISTS`,
/// `ONLY`, and the `OR <conflict action>` of `SQLite` after `UPDATE`.
fn skip_modifiers(toks: &[Token], mut j: usize) -> usize {
    loop {
        if is_word(toks.get(j), "IF") && is_word(toks.get(j + 1), "EXISTS") {
            j += 2;
        } else if is_word(toks.get(j), "IF")
            && is_word(toks.get(j + 1), "NOT")
            && is_word(toks.get(j + 2), "EXISTS")
        {
            j += 3;
        } else if is_word(toks.get(j), "ONLY") {
            j += 1;
        } else if is_word(toks.get(j), "OR")
            && matches!(toks.get(j + 1).map(|t| &t.tok), Some(Tok::Word(_)))
        {
            j += 2;
        } else {
            return j;
        }
    }
}

/// The index after the parenthesised group that opens at `j`, or the end of the tokens.
fn after_parens(toks: &[Token], mut j: usize) -> usize {
    let mut depth = 0usize;
    while let Some(t) = toks.get(j) {
        j += 1;
        match t.tok {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    j
}

/// Skips the alias of a `FROM` item: `AS name`, a quoted name, or an unquoted word that is not
/// a clause word.
fn skip_alias(toks: &[Token], j: usize) -> usize {
    if is_word(toks.get(j), "AS") {
        return j + 2;
    }
    match toks.get(j).map(|t| &t.tok) {
        Some(Tok::Quoted(_)) => j + 1,
        Some(Tok::Word(w)) if !CLAUSE_WORDS.iter().any(|c| w.eq_ignore_ascii_case(c)) => j + 1,
        _ => j,
    }
}

/// What stands where a keyword's table name should be.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Item {
    /// A table name.
    Table {
        /// The name, as [`name_at`] reads it.
        name: String,
        /// The line it stands on.
        line: usize,
        /// The token index after it.
        end: usize,
    },
    /// Something that is no name.
    Unreadable {
        /// The line it stands on.
        line: usize,
        /// What it is, for the message.
        found: String,
    },
}

/// The table names after the keyword at `i`; with `list` (for `FROM`), every item of a
/// comma-separated list. A parenthesised subquery is stepped over: its own keywords are read
/// where they stand.
fn items_after(toks: &[Token], i: usize, list: bool) -> Vec<Item> {
    let mut items = Vec::new();
    let mut j = skip_modifiers(toks, i + 1);
    loop {
        match toks.get(j) {
            Some(t) if t.tok == Tok::Punct('(') => {
                if !list {
                    break;
                }
                j = after_parens(toks, j);
            }
            Some(t) => {
                let Some((name, end)) = name_at(toks, j) else {
                    let found = match &t.tok {
                        Tok::Punct(c) => format!("`{c}`"),
                        Tok::Literal => "a literal".to_owned(),
                        Tok::Word(w) | Tok::Quoted(w) => format!("`{w}`"),
                    };
                    items.push(Item::Unreadable {
                        line: t.line,
                        found,
                    });
                    break;
                };
                items.push(Item::Table {
                    name,
                    line: t.line,
                    end,
                });
                j = end;
            }
            None => {
                items.push(Item::Unreadable {
                    line: toks.last().map_or(1, |t| t.line),
                    found: "the end of the file".to_owned(),
                });
                break;
            }
        }
        if !list {
            break;
        }
        j = skip_alias(toks, j);
        if !is_punct(toks, j, ',') {
            break;
        }
        j = skip_modifiers(toks, j + 1);
    }
    items
}

/// Whether `REFERENCES auth_accounts`, whose name ends at `end`, is the one foreign key ADR 0011
/// point 6 allows: column `(id)`, and `ON DELETE CASCADE` before the constraint ends (at a `,`
/// or `)` outside parentheses, or at `;`).
fn is_shared_foreign_key(toks: &[Token], end: usize) -> bool {
    let column_is_id = is_punct(toks, end, '(')
        && toks.get(end + 1).and_then(name_part).as_deref() == Some(SHARED_COLUMN)
        && is_punct(toks, end + 2, ')');
    if !column_is_id {
        return false;
    }
    let mut depth = 0usize;
    let mut j = end + 3;
    while let Some(t) = toks.get(j) {
        match t.tok {
            Tok::Punct(';') => return false,
            Tok::Punct(',' | ')') if depth == 0 => return false,
            Tok::Punct(')') => depth -= 1,
            Tok::Punct('(') => depth += 1,
            _ => {}
        }
        if depth == 0
            && is_word(Some(t), "ON")
            && is_word(toks.get(j + 1), "DELETE")
            && is_word(toks.get(j + 2), "CASCADE")
        {
            return true;
        }
        j += 1;
    }
    false
}

/// Checks one file's SQL against its owner's prefix. `path` is shown in each violation; `owner`
/// says who owns the file and why.
fn check_sql(path: &str, sql: &str, domain: &Domain, owner: &str) -> Vec<String> {
    let toks = match tokenize(sql) {
        Ok(toks) => toks,
        Err((line, what)) => {
            return vec![format!(
                "{path}:{line}: {what}; the table names cannot be read (ADR 0011 point 7)"
            )];
        }
    };
    let mut violations = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        let Some(kw) = KEYWORDS.iter().copied().find(|k| is_word(Some(t), k)) else {
            continue;
        };
        if !introduces_table(&toks, i, kw) {
            continue;
        }
        for item in items_after(&toks, i, kw == "FROM") {
            match item {
                Item::Table { name, line, end } => {
                    if name.starts_with(domain.prefix) {
                        continue;
                    }
                    let shared = name == SHARED_TABLE;
                    if shared && kw == "REFERENCES" && is_shared_foreign_key(&toks, end) {
                        continue;
                    }
                    let hint = if shared {
                        "; the one cross-domain reference ADR 0011 point 6 allows is the foreign \
                         key REFERENCES auth_accounts (id) ON DELETE CASCADE"
                    } else {
                        ""
                    };
                    violations.push(format!(
                        "{path}:{line}: {kw} {name}: the table does not carry the prefix `{}` of \
                         its owner, {owner} (ADR 0011 points 5 and 7, ADR 0016 R4){hint}",
                        domain.prefix
                    ));
                }
                Item::Unreadable { line, found } => violations.push(format!(
                    "{path}:{line}: expected a table name after {kw}, found {found}; the check \
                     cannot read it (ADR 0011 point 7)"
                )),
            }
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH: &Domain = &DOMAINS[0];
    const VAULT: &Domain = &DOMAINS[1];

    /// The violations of `sql` as a vault-owned file.
    fn vault(sql: &str) -> Vec<String> {
        check_sql("q.sql", sql, VAULT, "crate rizzy-domain-vault")
    }

    #[test]
    fn the_ownership_table_matches_the_adr_prefixes() {
        assert_eq!(AUTH.prefix, "auth_");
        assert_eq!(AUTH.krate, "rizzy-domain-auth");
        assert_eq!(VAULT.prefix, "vault_");
        assert_eq!(VAULT.krate, "rizzy-domain-vault");
        for d in DOMAINS {
            assert_eq!(format!("{}_", d.name), d.prefix);
            assert_eq!(format!("{DOMAIN_CRATE_PREFIX}{}", d.name), d.krate);
        }
    }

    #[test]
    fn migration_domain_reads_the_owner_from_the_file_name() {
        assert_eq!(migration_domain("0001_auth_initial.sql"), Some("auth"));
        assert_eq!(
            migration_domain("0007_vault_add_snapshots.sql"),
            Some("vault")
        );
        assert_eq!(
            migration_domain("0003_storage_restore.sql"),
            Some("storage")
        );
        assert_eq!(migration_domain("0008_vault.sql"), Some("vault"));
        assert_eq!(migration_domain("initial.sql"), None);
        assert_eq!(migration_domain("x1_auth_initial.sql"), None);
        assert_eq!(migration_domain("_auth_initial.sql"), None);
        assert_eq!(migration_domain("0001__initial.sql"), None);
        assert_eq!(migration_domain("0001_auth_initial.txt"), None);
    }

    #[test]
    fn tokenize_drops_comments_and_keeps_lines() {
        let toks = tokenize("-- FROM auth_x\n/* JOIN\nauth_y */ SELECT 'FROM auth_z'\n\"a\"\"b\"")
            .unwrap();
        assert_eq!(
            toks,
            vec![
                Token {
                    tok: Tok::Word("SELECT".to_owned()),
                    line: 3
                },
                Token {
                    tok: Tok::Literal,
                    line: 3
                },
                Token {
                    tok: Tok::Quoted("a\"b".to_owned()),
                    line: 4
                },
            ]
        );
        assert_eq!(tokenize("SELECT $1, 42, x.y").unwrap().len(), 8);
    }

    #[test]
    fn tokenize_reports_unterminated_input_by_line() {
        assert_eq!(
            tokenize("SELECT\n/* open").unwrap_err(),
            (2, "unterminated /* comment")
        );
        assert_eq!(tokenize("\n\nSELECT 'open").unwrap_err().0, 3);
        assert_eq!(tokenize("SELECT \"open").unwrap_err().0, 1);
    }

    #[test]
    fn own_tables_pass() {
        let sql = "SELECT a FROM vault_items WHERE id = $1;\n\
                   INSERT INTO vault_items (a) VALUES ($1) ON CONFLICT (a) DO UPDATE SET a = excluded.a;\n\
                   UPDATE vault_items SET a = 1;\n\
                   DELETE FROM vault_items;\n\
                   SELECT x FROM vault_a AS a JOIN vault_b b ON a.id = b.id;\n\
                   CREATE TABLE IF NOT EXISTS vault_c (id BLOB REFERENCES vault_a (id) ON UPDATE CASCADE);\n\
                   ALTER TABLE vault_c ADD x INTEGER;\n\
                   SELECT 1 FROM vault_a FOR UPDATE;\n\
                   SELECT a IS DISTINCT FROM b FROM vault_a;\n\
                   SELECT x FROM VAULT_ITEMS ORDER BY a, b;\n\
                   SELECT max(x) FROM (SELECT x FROM vault_a) GROUP BY y, z;";
        assert_eq!(vault(sql), Vec::<String>::new());
        assert_eq!(
            check_sql(
                "a.sql",
                "SELECT * FROM auth_accounts",
                AUTH,
                "crate rizzy-domain-auth"
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn every_keyword_reports_a_foreign_table_with_file_and_line() {
        let sql = "SELECT a\nFROM auth_x;\n\
                   SELECT 1 FROM vault_a JOIN auth_y ON 1;\n\
                   INSERT INTO auth_z (a) VALUES (1);\n\
                   UPDATE auth_w SET a = 1;\n\
                   CREATE TABLE items (id BLOB);\n\
                   CREATE TABLE vault_t (id BLOB REFERENCES auth_devices (id) ON DELETE CASCADE);";
        let v = vault(sql);
        assert_eq!(v.len(), 6, "{v:#?}");
        assert!(v[0].starts_with("q.sql:2: FROM auth_x: "), "{}", v[0]);
        assert!(v[0].contains("prefix `vault_` of its owner, crate rizzy-domain-vault"));
        assert!(v[0].contains("ADR 0011 points 5 and 7, ADR 0016 R4"));
        assert!(v[1].starts_with("q.sql:3: JOIN auth_y: "), "{}", v[1]);
        assert!(v[2].starts_with("q.sql:4: INTO auth_z: "), "{}", v[2]);
        assert!(v[3].starts_with("q.sql:5: UPDATE auth_w: "), "{}", v[3]);
        assert!(v[4].starts_with("q.sql:6: TABLE items: "), "{}", v[4]);
        assert!(
            v[5].starts_with("q.sql:7: REFERENCES auth_devices: "),
            "{}",
            v[5]
        );
    }

    #[test]
    fn the_one_shared_foreign_key_is_the_only_exception() {
        // ADR 0011 point 6, column and table constraint forms.
        let ok = "CREATE TABLE vault_v (\n  account_id BLOB NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,\n  x INTEGER\n);\n\
                  CREATE TABLE vault_w (a BLOB, FOREIGN KEY (a) REFERENCES \"auth_accounts\"(\"id\") ON DELETE CASCADE);";
        assert_eq!(vault(ok), Vec::<String>::new());
        for bad in [
            "CREATE TABLE vault_v (a BLOB REFERENCES auth_accounts (id));",
            "CREATE TABLE vault_v (a BLOB REFERENCES auth_accounts (id) ON DELETE SET NULL, b INTEGER CHECK (b > 0) ON DELETE CASCADE);",
            "CREATE TABLE vault_v (a BLOB REFERENCES auth_accounts (login_name) ON DELETE CASCADE);",
            "CREATE TABLE vault_v (a BLOB REFERENCES auth_accounts ON DELETE CASCADE);",
            "SELECT 1 FROM auth_accounts WHERE id = $1;",
            "DELETE FROM auth_accounts;",
        ] {
            let v = vault(bad);
            assert_eq!(v.len(), 1, "{bad}: {v:#?}");
            assert!(v[0].contains("auth_accounts"), "{}", v[0]);
            assert!(
                v[0].contains("REFERENCES auth_accounts (id) ON DELETE CASCADE"),
                "{}",
                v[0]
            );
        }
    }

    #[test]
    fn subqueries_and_from_lists_are_read() {
        let v = vault("SELECT 1 FROM vault_a WHERE id IN (SELECT id FROM auth_b);");
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("FROM auth_b"));
        let v = vault("SELECT 1 FROM vault_a a, auth_b AS b, \"auth_c\" c, ONLY auth_d");
        assert_eq!(v.len(), 3, "{v:#?}");
        assert!(v[0].contains("FROM auth_b"));
        assert!(v[1].contains("FROM auth_c"));
        assert!(v[2].contains("FROM auth_d"));
        let v = vault("SELECT 1 FROM (SELECT 1 FROM vault_a) x, auth_e");
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("FROM auth_e"));
    }

    #[test]
    fn names_are_compared_as_sql_reads_them() {
        assert_eq!(vault("SELECT 1 FROM Vault_Items"), Vec::<String>::new());
        // A quoted name keeps its case, and a schema qualifier is part of the name.
        assert_eq!(vault("SELECT 1 FROM \"VAULT_items\"").len(), 1);
        assert_eq!(vault("SELECT 1 FROM main.vault_items").len(), 1);
        // A storage_ table is not the domain's own (module doc, "Out of scope …").
        assert_eq!(vault("SELECT 1 FROM storage_meta").len(), 1);
        // Neither comments nor string literals are SQL.
        assert_eq!(
            vault("-- FROM auth_x\nSELECT 'JOIN auth_y' /* INTO auth_z */ FROM vault_a"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_unreadable_name_fails_instead_of_passing() {
        let v = vault("SELECT 1 FROM\n'vault_a'");
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(
            v[0].starts_with("q.sql:2: expected a table name after FROM, found a literal"),
            "{}",
            v[0]
        );
        let v = vault("DELETE FROM");
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("found the end of the file"), "{}", v[0]);
        let v = vault("INSERT INTO ;");
        assert!(v[0].contains("found `;`"), "{}", v[0]);
        let v = vault("SELECT 1\n/* never closed");
        assert_eq!(
            v,
            vec![
                "q.sql:2: unterminated /* comment; the table names cannot be read (ADR 0011 \
                 point 7)"
                    .to_owned()
            ]
        );
    }

    /// A fresh scratch directory under the OS temp dir, removed by the caller.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rizzy-xtask-tables-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// Writes `text` to `root/rel`, creating its directories.
    fn put(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// A tree that passes: one query per domain crate, an auth, a vault and a storage migration
    /// per engine, and rizzy-storage queries that read every domain (not checked).
    fn clean_tree(name: &str) -> PathBuf {
        let root = scratch_dir(name);
        put(
            &root,
            "crates/rizzy-domain-auth/queries/a.sql",
            "SELECT 1 FROM auth_accounts",
        );
        put(
            &root,
            "crates/rizzy-domain-vault/queries/sub/v.sql",
            "SELECT 1 FROM vault_vaults",
        );
        put(
            &root,
            "crates/rizzy-domain-vault/queries/notes.txt",
            "FROM auth_x",
        );
        put(
            &root,
            "crates/rizzy-core/queries/x.sql",
            "SELECT 1 FROM auth_x",
        );
        put(
            &root,
            "crates/rizzy-storage/queries/backup/all.sql",
            "SELECT 1 FROM auth_accounts JOIN vault_vaults ON 1",
        );
        for engine in ["sqlite", "postgres"] {
            let dir = format!("crates/rizzy-storage/migrations/{engine}");
            put(
                &root,
                &format!("{dir}/0001_auth_initial.sql"),
                "CREATE TABLE auth_accounts (id BLOB PRIMARY KEY);",
            );
            put(
                &root,
                &format!("{dir}/0002_vault_initial.sql"),
                "CREATE TABLE vault_vaults (id BLOB, account_id BLOB REFERENCES auth_accounts (id) ON DELETE CASCADE);",
            );
            put(
                &root,
                &format!("{dir}/0003_storage_restore.sql"),
                "CREATE TABLE storage_meta (id INTEGER);",
            );
        }
        root
    }

    #[test]
    fn check_passes_a_clean_tree_and_skips_what_is_out_of_scope() {
        let root = clean_tree("clean");
        let report = check(&root).unwrap();
        assert_eq!(
            report,
            Report {
                violations: Vec::new(),
                query_files: 2,
                migration_files: 4,
                not_checked: 2,
            }
        );
        let ok = run(&root).unwrap();
        assert!(ok.starts_with("check-tables: ok (2 query file(s)"), "{ok}");
        assert!(ok.contains("2 storage migration file(s)"), "{ok}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn check_reports_every_violation_in_file_order() {
        let root = clean_tree("dirty");
        put(
            &root,
            "crates/rizzy-domain-vault/queries/sub/v.sql",
            "SELECT 1\nFROM auth_sessions",
        );
        put(
            &root,
            "crates/rizzy-domain-mail/queries/m.sql",
            "SELECT 1 FROM mail_x",
        );
        put(
            &root,
            "crates/rizzy-storage/migrations/sqlite/0004_vault_more.sql",
            "-- adds\nALTER TABLE auth_accounts ADD x INTEGER;",
        );
        put(
            &root,
            "crates/rizzy-storage/migrations/sqlite/0005_relay_init.sql",
            "",
        );
        put(
            &root,
            "crates/rizzy-storage/migrations/postgres/extra.sql",
            "",
        );
        let err = run(&root).unwrap_err();
        let lines: Vec<&str> = err.lines().collect();
        assert_eq!(lines.len(), 6, "{err}");
        assert!(lines[0].starts_with("error: crates/rizzy-domain-mail/queries: crate rizzy-domain-mail has a queries/ directory but no row"), "{err}");
        assert!(
            lines[1].starts_with(
                "error: crates/rizzy-domain-vault/queries/sub/v.sql:2: FROM auth_sessions: "
            ),
            "{err}"
        );
        assert!(lines[2].starts_with("error: crates/rizzy-storage/migrations/sqlite/0004_vault_more.sql:2: TABLE auth_accounts: "), "{err}");
        assert!(
            lines[2].contains("the vault domain its file name carries"),
            "{err}"
        );
        assert!(lines[3].starts_with("error: crates/rizzy-storage/migrations/sqlite/0005_relay_init.sql: the file name carries the domain \"relay\""), "{err}");
        assert!(lines[4].starts_with("error: crates/rizzy-storage/migrations/postgres/extra.sql: the file name carries no owning domain"), "{err}");
        assert!(
            lines[5].starts_with("check-tables: 5 violation(s)"),
            "{err}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn check_fails_without_the_migration_directories() {
        let root = scratch_dir("no-migrations");
        put(
            &root,
            "crates/rizzy-domain-auth/queries/a.sql",
            "SELECT 1 FROM auth_accounts",
        );
        let err = run(&root).unwrap_err();
        assert!(
            err.starts_with(
                "check-tables: error: crates/rizzy-storage/migrations/sqlite: not a directory"
            ),
            "{err}"
        );
        let _ = fs::remove_dir_all(&root);
    }
}

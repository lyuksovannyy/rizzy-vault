//! A reader for the subset of TOML that Cargo manifests, `.cargo/config.toml` and `clippy.toml`
//! use, enough for the R7 and R8 checks, the `check-wasm` alias and the R1 clippy lists.
//! `cargo metadata` reports resolved values, but not whether `publish` and `license` were
//! inherited, nor the `[lints]` table.
//!
//! Every `key = value` becomes one entry with its full dotted key (`package.publish.workspace`,
//! `lints.workspace`, `workspace.lints.rust.unsafe_code`) and its value with the whitespace
//! outside strings removed (`{workspace=true}`). Arrays and inline tables may span lines.
//! [`parse_value`] reads such a normalised value into strings, arrays and inline tables.
//!
//! **Fail closed.** A line this reader does not understand is recorded in
//! [`Manifest::errors`], and the checks report it as a violation instead of guessing. That
//! includes every line with a multi-line string delimiter (`"""` or `'''`), even in a comment:
//! Cargo reads escapes and `#` inside a multi-line string differently from a line-based reader,
//! so a crafted one could show this reader a `[lints]` table that Cargo reads as string content.
//! No manifest in the workspace uses one.
//!
//! Keys and table headers must be **bare dotted keys** (`a.b-c.d_e`); a quoted key segment
//! (`"lints.workspace"`, `'x'`) is an error. Cargo reads `"lints.workspace" = true` as one
//! unknown top-level key and only warns about it, while a reader that splits on `.` would see
//! `lints.workspace = true`: the crate would pass R7 with no `[lints]` table at all. No
//! committed file uses a quoted key. A future manifest that needs one (a
//! `[target.'cfg(..)'.dependencies]` table) extends this reader first, with a test.

/// A parsed manifest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Manifest {
    /// `(dotted key, normalised value)`, in file order.
    pub(crate) entries: Vec<(String, String)>,
    /// Lines that could not be read.
    pub(crate) errors: Vec<String>,
}

impl Manifest {
    /// Parses `text`.
    pub(crate) fn parse(text: &str) -> Self {
        let mut out = Self::default();
        // `None` after a header this reader could not read: its keys are skipped (the header's
        // error already fails the check) rather than filed under the wrong table.
        let mut table = Some(String::new());
        let mut lines = text.lines().enumerate();
        while let Some((index, raw)) = lines.next() {
            if has_multi_line_delimiter(raw) {
                out.errors.push(multi_line_error(index));
                continue;
            }
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let header = if let Some(h) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]"))
            {
                Some(normalise_key(h).map(|t| format!("{t}[]")))
            } else {
                line.strip_prefix('[')
                    .and_then(|l| l.strip_suffix(']'))
                    .map(normalise_key)
            };
            if let Some(header) = header {
                table = match header {
                    Ok(t) => Some(t),
                    Err(e) => {
                        out.errors
                            .push(format!("line {}: table header {e}", index + 1));
                        None
                    }
                };
                continue;
            }
            let Some(eq) = find_outside_strings(line, '=') else {
                out.errors
                    .push(format!("line {}: not `key = value`", index + 1));
                continue;
            };
            let (key, value) = line.split_at(eq);
            let key = normalise_key(key);
            let mut value = value.get(1..).unwrap_or_default().trim().to_owned();
            // Continue a multi-line array or inline table.
            while !is_complete(&value) {
                let Some((next_index, next)) = lines.next() else {
                    out.errors
                        .push(format!("line {}: unterminated value", index + 1));
                    break;
                };
                if has_multi_line_delimiter(next) {
                    out.errors.push(multi_line_error(next_index));
                    break;
                }
                value.push('\n');
                value.push_str(strip_comment(next));
            }
            let key = match key {
                Ok(key) => key,
                Err(e) => {
                    out.errors.push(format!("line {}: key {e}", index + 1));
                    continue;
                }
            };
            let Some(table) = &table else { continue };
            let full = if table.is_empty() {
                key
            } else {
                format!("{table}.{key}")
            };
            out.entries.push((full, normalise_value(&value)));
        }
        out
    }

    /// The value of `key`, if present.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every entry whose key is `prefix` or starts with `prefix.`.
    pub(crate) fn under<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.entries
            .iter()
            .filter(move |(k, _)| {
                k == prefix
                    || k.strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('.'))
            })
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Whether `table.field` is inherited from the workspace: `field.workspace = true` or
    /// `field = { workspace = true }`.
    pub(crate) fn inherits(&self, table: &str, field: &str) -> bool {
        let key = format!("{table}.{field}");
        let entries: Vec<(&str, &str)> = self.under(&key).collect();
        matches!(
            entries.as_slice(),
            [(k, "true")] if k.ends_with(".workspace")
        ) || matches!(entries.as_slice(), [(_, "{workspace=true}")])
    }
}

/// The byte offset of the first `needle` outside a quoted string.
fn find_outside_strings(line: &str, needle: char) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == needle => return Some(i),
            _ => {}
        }
    }
    None
}

/// The line without a trailing `# comment` (a `#` inside a string is kept).
fn strip_comment(line: &str) -> &str {
    match find_outside_strings(line, '#') {
        Some(i) => line.get(..i).unwrap_or(line),
        None => line,
    }
}

/// `a . b .c` → `a.b.c`. Every segment must be a non-empty bare key (ASCII letters, digits, `-`
/// and `_`), with only spaces and tabs around it. Anything else, a quoted segment above all, is
/// an error: splitting `"lints.workspace"` on `.` would read one key as two (module docs).
fn normalise_key(key: &str) -> Result<String, String> {
    let mut parts = Vec::new();
    for part in key.split('.') {
        let part = part.trim_matches([' ', '\t']);
        let bare = part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if part.is_empty() || !bare {
            return Err(format!(
                "`{}` is not a bare dotted key; quoted keys are not read",
                key.trim()
            ));
        }
        parts.push(part);
    }
    Ok(parts.join("."))
}

/// Whether `line` contains a multi-line string delimiter anywhere, comments included.
fn has_multi_line_delimiter(line: &str) -> bool {
    line.contains("\"\"\"") || line.contains("'''")
}

fn multi_line_error(index: usize) -> String {
    format!(
        "line {}: multi-line string (`\"\"\"` or `'''`), which this reader does not read",
        index + 1
    )
}

/// Whether brackets and braces outside strings balance. (Multi-line strings never get here.)
fn is_complete(value: &str) -> bool {
    let mut depth = 0i64;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in value.chars() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '\'' => quote = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                _ => {}
            },
        }
    }
    depth <= 0
}

/// The value with every whitespace character outside strings removed.
fn normalise_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in value.chars() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c.is_whitespace() => continue,
            _ => {}
        }
        out.push(c);
    }
    out
}

/// A normalised value, read by [`parse_value`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TomlValue {
    /// A basic or literal string, without its quotes. Escapes are kept as written, so a string
    /// with an escape never equals a plain one (fail closed).
    Str(String),
    /// Anything else that is not an array or a table (a number, a boolean), as written.
    Bare(String),
    /// An array.
    Array(Vec<TomlValue>),
    /// An inline table, in file order. Keys are bare or quoted, never dotted.
    Table(Vec<(String, TomlValue)>),
}

/// Reads a value as [`Manifest`] stores it (whitespace outside strings removed).
pub(crate) fn parse_value(normalised: &str) -> Result<TomlValue, String> {
    let mut rest = normalised;
    let value = value(&mut rest)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(format!("unexpected `{rest}` after a value"))
    }
}

fn value(rest: &mut &str) -> Result<TomlValue, String> {
    let mut chars = rest.chars();
    match chars.next() {
        Some(q @ ('"' | '\'')) => Ok(TomlValue::Str(string(rest, q)?)),
        Some('[') => {
            *rest = chars.as_str();
            let mut items = Vec::new();
            loop {
                if let Some(after) = rest.strip_prefix(']') {
                    *rest = after;
                    return Ok(TomlValue::Array(items));
                }
                items.push(value(rest)?);
                if let Some(after) = rest.strip_prefix(',') {
                    *rest = after;
                } else if !rest.starts_with(']') {
                    return Err("expected `,` or `]` in an array".to_owned());
                }
            }
        }
        Some('{') => {
            *rest = chars.as_str();
            let mut items = Vec::new();
            loop {
                if let Some(after) = rest.strip_prefix('}') {
                    *rest = after;
                    return Ok(TomlValue::Table(items));
                }
                let key = if let Some(q @ ('"' | '\'')) = rest.chars().next() {
                    string(rest, q)?
                } else {
                    let end = rest
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                        .unwrap_or(rest.len());
                    let (key, after) = rest.split_at(end);
                    *rest = after;
                    key.to_owned()
                };
                *rest = rest
                    .strip_prefix('=')
                    .filter(|_| !key.is_empty())
                    .ok_or("expected `key = value` in an inline table")?;
                items.push((key, value(rest)?));
                if let Some(after) = rest.strip_prefix(',') {
                    *rest = after;
                } else if !rest.starts_with('}') {
                    return Err("expected `,` or `}` in an inline table".to_owned());
                }
            }
        }
        Some(_) => {
            let end = rest.find([',', ']', '}']).unwrap_or(rest.len());
            let (bare, after) = rest.split_at(end);
            if bare.contains(['[', '{', '"', '\'', '=']) {
                return Err(format!("cannot read `{bare}`"));
            }
            *rest = after;
            Ok(TomlValue::Bare(bare.to_owned()))
        }
        None => Err("missing value".to_owned()),
    }
}

/// Reads the string that `rest` starts with (quote `q`), leaving `rest` after its closing quote.
fn string(rest: &mut &str, q: char) -> Result<String, String> {
    let body = rest.get(1..).unwrap_or_default();
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if q == '"' => escaped = true,
            _ if c == q => {
                let (content, after) = body.split_at(i);
                *rest = after.get(1..).unwrap_or_default();
                return Ok(content.to_owned());
            }
            _ => {}
        }
    }
    Err("unterminated string".to_owned())
}

/// The review's desynchronisation, for the tests: Cargo reads `\"` as an escape and `#` as
/// string content, so everything from `description` to the last `"""` is one string to Cargo,
/// and the crate has no `[lints]` table. A reader that counts `"""` substrings closes the string
/// after the second line and sees `[lints] workspace = true`.
#[cfg(test)]
pub(crate) const HIDDEN_LINTS: &str = "[package]\nname = \"rizzy-sync\"\n\
    license.workspace = true\npublish.workspace = true\nrust-version.workspace = true\n\
    description = \"\"\"\n\\\"\"\"\n[lints]\nworkspace = true #\"\"\"\n";

#[cfg(test)]
mod tests {
    use super::*;

    const CRATE: &str = r#"
[package]
name = "rizzy-core" # the name
description = "x = y # not a comment"
version.workspace = true
license = { workspace = true }
publish.workspace = true

[dependencies]
argon2.workspace = true
thing = { version = "1", features = [
    "a",   # first
    "b=c",
] }

[[bin]]
name = "tool"

[lints]
workspace = true
"#;

    #[test]
    fn reads_keys_tables_and_multi_line_values() {
        let m = Manifest::parse(CRATE);
        assert!(m.errors.is_empty(), "{:?}", m.errors);
        assert_eq!(m.get("package.name"), Some("\"rizzy-core\""));
        assert_eq!(
            m.get("package.description"),
            Some("\"x = y # not a comment\"")
        );
        assert_eq!(
            m.get("dependencies.thing"),
            Some("{version=\"1\",features=[\"a\",\"b=c\",]}")
        );
        assert_eq!(m.get("bin[].name"), Some("\"tool\""));
        assert_eq!(
            m.under("lints").collect::<Vec<_>>(),
            [("lints.workspace", "true")]
        );
        assert!(m.inherits("package", "license"));
        assert!(m.inherits("package", "publish"));
        assert!(!m.inherits("package", "rust-version"));
        assert!(!m.inherits("package", "name"));
    }

    #[test]
    fn a_value_that_is_not_inheritance_does_not_count() {
        let m = Manifest::parse("[package]\nlicense = \"MIT\"\npublish = true\n");
        assert!(!m.inherits("package", "license"));
        assert!(!m.inherits("package", "publish"));
        let m = Manifest::parse("[package]\nlicense.workspace = false\n");
        assert!(!m.inherits("package", "license"));
    }

    #[test]
    fn unknown_lines_are_errors() {
        let m = Manifest::parse("[package]\nthis is not toml\n");
        assert_eq!(m.errors.len(), 1);
        let m = Manifest::parse("[package]\nfeatures = [\n\"a\",\n");
        assert_eq!(m.errors.len(), 1);
    }

    #[test]
    fn under_matches_whole_segments_only() {
        let m = Manifest::parse("[lints]\nworkspace = true\n[lintsx]\na = 1\n");
        assert_eq!(m.under("lints").count(), 1);
    }

    #[test]
    fn multi_line_strings_fail_closed() {
        let m = Manifest::parse(HIDDEN_LINTS);
        assert_eq!(m.errors.len(), 3, "{:?}", m.errors);
        assert!(m.errors[0].contains("line 6: multi-line string"), "{m:?}");
        assert_eq!(m.under("lints").count(), 0, "{m:?}");
        // Literal multi-line strings, a delimiter in a comment, and one inside an array.
        for text in [
            "[package]\ndescription = '''\nx\n'''\n",
            "[package]\nname = \"x\" # '''\n",
            "[package]\nkeywords = [\n\"a\",\n\"\"\"b\"\"\",\n]\n",
        ] {
            let m = Manifest::parse(text);
            assert!(!m.errors.is_empty(), "{text}");
        }
    }

    #[test]
    fn quoted_and_malformed_keys_fail_closed() {
        // tooling#3, second form: Cargo reads each of these as one unknown key (and only warns),
        // so none of them may read as `lints.workspace`, `publish.workspace` or the lint level.
        for text in [
            "\"lints.workspace\" = true\n",
            "'lints.workspace' = true\n",
            "lints.\"workspace\" = true\n",
            "[package]\n\"publish.workspace\" = true\n",
            "[workspace]\n\"lints.rust.unsafe_code\" = \"forbid\"\n",
            "[\"lints\"]\nworkspace = true\n",
            "['lints']\nworkspace = true\n",
            "[[\"bin\"]]\nname = \"x\"\n",
            "[lints.]\nworkspace = true\n",
            "lints..workspace = true\n",
            "lints workspace = true\n",
            "lints.workspace\u{a0}= true\n",
            "= true\n",
        ] {
            let m = Manifest::parse(text);
            assert!(!m.errors.is_empty(), "{text:?}");
            assert_eq!(m.under("lints").count(), 0, "{text:?}: {m:?}");
            assert!(!m.inherits("package", "publish"), "{text:?}: {m:?}");
            assert_eq!(m.under("workspace.lints").count(), 0, "{text:?}: {m:?}");
        }
        // Keys under an unreadable header are skipped, not filed under the table before it.
        let m = Manifest::parse("[lints]\n[\"x\"]\nworkspace = true\n");
        assert_eq!(m.errors.len(), 1, "{m:?}");
        assert!(m.entries.is_empty(), "{m:?}");
        // Spaces and tabs around the dots are TOML, and read as Cargo reads them.
        let m = Manifest::parse("[ lints ]\nrust . unsafe_code\t= \"forbid\"\n");
        assert!(m.errors.is_empty(), "{m:?}");
        assert_eq!(m.get("lints.rust.unsafe_code"), Some("\"forbid\""));
    }

    #[test]
    fn the_committed_files_read_cleanly() {
        for (name, text) in [
            ("Cargo.toml", include_str!("../../../Cargo.toml")),
            (
                ".cargo/config.toml",
                include_str!("../../../.cargo/config.toml"),
            ),
            ("clippy.toml", include_str!("../../../clippy.toml")),
            ("rizzy-core", include_str!("../../rizzy-core/Cargo.toml")),
            (
                "rizzy-core clippy",
                include_str!("../../rizzy-core/clippy.toml"),
            ),
            ("rizzy-sync", include_str!("../../rizzy-sync/Cargo.toml")),
            (
                "rizzy-sync clippy",
                include_str!("../../rizzy-sync/clippy.toml"),
            ),
            (
                "rizzy-server",
                include_str!("../../rizzy-server/Cargo.toml"),
            ),
            ("rizzy-cli", include_str!("../../rizzy-cli/Cargo.toml")),
            ("xtask", include_str!("../Cargo.toml")),
        ] {
            let m = Manifest::parse(text);
            assert!(m.errors.is_empty(), "{name}: {:?}", m.errors);
            for (key, value) in &m.entries {
                assert!(parse_value(value).is_ok(), "{name}: {key} = {value}");
            }
        }
    }

    #[test]
    fn values_parse_into_strings_arrays_and_tables() {
        let s = |v: &str| TomlValue::Str(v.to_owned());
        assert_eq!(parse_value("\"a\\\"b\""), Ok(s("a\\\"b")));
        assert_eq!(parse_value("'a\\'"), Ok(s("a\\")));
        assert_eq!(parse_value("-1"), Ok(TomlValue::Bare("-1".to_owned())));
        assert_eq!(
            parse_value("[\"a\",{path=\"b\",'reason'=\"c,}\"},]"),
            Ok(TomlValue::Array(vec![
                s("a"),
                TomlValue::Table(vec![
                    ("path".to_owned(), s("b")),
                    ("reason".to_owned(), s("c,}")),
                ]),
            ]))
        );
        assert_eq!(parse_value("[]"), Ok(TomlValue::Array(Vec::new())));
        for bad in [
            "",
            "\"open",
            "[\"a\"",
            "[\"a\"\"b\"]",
            "{a.b=1}",
            "{=1}",
            "{a=1",
            "\"a\"x",
            "[a[b]]",
        ] {
            assert!(parse_value(bad).is_err(), "{bad}");
        }
    }
}

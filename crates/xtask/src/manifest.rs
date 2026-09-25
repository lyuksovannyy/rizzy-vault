//! A reader for the subset of TOML that Cargo manifests and `.cargo/config.toml` use, enough
//! for the R7 and R8 checks and the `check-wasm` alias. `cargo metadata` reports resolved
//! values, but not whether `publish` and `license` were inherited, nor the `[lints]` table.
//!
//! Every `key = value` becomes one entry with its full dotted key (`package.publish.workspace`,
//! `lints.workspace`, `workspace.lints.rust.unsafe_code`) and its value with the whitespace
//! outside strings removed (`{workspace=true}`). Arrays and inline tables may span lines.
//!
//! **Fail closed.** A line this reader does not understand is recorded in
//! [`Manifest::errors`], and the checks report it as a violation instead of guessing.

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
        let mut table = String::new();
        let mut lines = text.lines().enumerate();
        while let Some((index, raw)) = lines.next() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(header) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
                table = format!("{}[]", normalise_key(header));
                continue;
            }
            if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                table = normalise_key(header);
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
            // Continue a multi-line array, inline table or string.
            while !is_complete(&value) {
                let Some((_, next)) = lines.next() else {
                    out.errors
                        .push(format!("line {}: unterminated value", index + 1));
                    break;
                };
                value.push('\n');
                value.push_str(strip_comment(next));
            }
            if key.is_empty() {
                out.errors.push(format!("line {}: empty key", index + 1));
                continue;
            }
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

/// `a . "b" .c` → `a.b.c`.
fn normalise_key(key: &str) -> String {
    key.split('.')
        .map(|part| part.trim().trim_matches('"').trim_matches('\''))
        .collect::<Vec<_>>()
        .join(".")
}

/// Whether brackets and braces outside strings balance and no triple-quoted string is open.
fn is_complete(value: &str) -> bool {
    for delimiter in ["\"\"\"", "'''"] {
        if value.matches(delimiter).count() % 2 == 1 {
            return false;
        }
    }
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
}

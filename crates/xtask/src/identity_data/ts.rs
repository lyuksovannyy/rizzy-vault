// SPDX-License-Identifier: AGPL-3.0-only

//! The narrow faker-js `.ts` reader of `cargo xtask identity-data` (ADR 0079 §6: "A narrow
//! hand-written extractor reads faker-js's `.ts` files ... Any other shape is an error, never a
//! guess").
//!
//! [`tokenize`] turns a file into tokens of a small TypeScript subset: identifiers, decimal
//! integers, single- or double-quoted strings (escapes `\\`, `\'` and `\"` only), template
//! literals (kept raw), and punctuation. `//` and `/* */` comments are skipped. Anything else,
//! such as a regular-expression literal or a non-ASCII character outside a string, is an
//! error.
//!
//! Two kinds of file are accepted:
//!
//! - **Literal data**, read by [`parse_default`]: the whole file is `export default` followed
//!   by a string list (`[ '…', … ]`) or an object literal whose values are strings, string
//!   lists or template literals (`{ female: [ … ], male: [ … ] }`), and an optional `;`.
//! - **Code shapes**, read by [`match_template`]: the whole file must equal a template, token
//!   for token, apart from typed holes (`$num`, `$str`, `$strs`, `$obj`) whose values are
//!   captured. Each template is one exact, reviewed shape (`super::shapes`); a file that differs
//!   anywhere is an error.
//!
//! The locale entry files (`src/locale/<locale>.ts`) have their own reader,
//! [`locale_chain`].

/// One token of the accepted subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Tok {
    /// An identifier, including `$`-prefixed template holes.
    Ident(String),
    /// A decimal integer literal.
    Num(u64),
    /// A quoted string, decoded.
    Str(String),
    /// A template literal's raw text between the backquotes.
    Template(String),
    /// Punctuation.
    Punct(&'static str),
}

/// Punctuation, longest first so that `...` wins over `.`.
const PUNCTS: &[&str] = &[
    "...", "===", "!==", "=>", "&&", "||", "(", ")", "[", "]", "{", "}", ",", ";", ":", ".", "=",
    "+", "-", "*", "/", "<", ">", "!", "?", "&", "|",
];

/// The largest file the reader accepts, in bytes (the largest pinned input is about 45 KB).
pub(super) const MAX_FILE: usize = 1 << 20;

/// Tokenizes `src`.
///
/// # Errors
///
/// On a character outside the subset, an unterminated string, comment or template, an escape
/// other than `\\`, `\'` and `\"`, an integer that does not fit `u64`, or a file over
/// [`MAX_FILE`].
pub(super) fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    if src.len() > MAX_FILE {
        return Err(format!("file is {} bytes, over {MAX_FILE}", src.len()));
    }
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(&ch) = chars.get(pos) {
        let next = chars.get(pos + 1).copied();
        if matches!(ch, ' ' | '\n' | '\r' | '\t') {
            pos += 1;
        } else if ch == '/' && next == Some('/') {
            while chars.get(pos).is_some_and(|&x| x != '\n') {
                pos += 1;
            }
        } else if ch == '/' && next == Some('*') {
            let close = (pos + 2..chars.len().saturating_sub(1))
                .find(|&k| chars[k] == '*' && chars[k + 1] == '/')
                .ok_or_else(|| format!("line {}: unterminated comment", line_of(&chars, pos)))?;
            pos = close + 2;
        } else if ch == '\'' || ch == '"' {
            let (s, after) = quoted(&chars, pos)?;
            out.push(Tok::Str(s));
            pos = after;
        } else if ch == '\x60' {
            let (s, after) = template(&chars, pos)?;
            out.push(Tok::Template(s));
            pos = after;
        } else if ch.is_ascii_digit() {
            let end = (pos..chars.len())
                .find(|&k| !chars[k].is_ascii_digit())
                .unwrap_or(chars.len());
            if chars.get(end).is_some_and(|&x| is_ident_char(x)) {
                return Err(format!("line {}: malformed number", line_of(&chars, pos)));
            }
            let text: String = chars[pos..end].iter().collect();
            let n = text
                .parse::<u64>()
                .map_err(|e| format!("line {}: number {text}: {e}", line_of(&chars, pos)))?;
            out.push(Tok::Num(n));
            pos = end;
        } else if is_ident_char(ch) {
            let end = (pos..chars.len())
                .find(|&k| !is_ident_char(chars[k]))
                .unwrap_or(chars.len());
            out.push(Tok::Ident(chars[pos..end].iter().collect()));
            pos = end;
        } else if let Some(p) = PUNCTS.iter().find(|p| {
            p.chars()
                .enumerate()
                .all(|(k, pc)| chars.get(pos + k) == Some(&pc))
        }) {
            pos += p.chars().count();
            out.push(Tok::Punct(p));
        } else {
            return Err(format!(
                "line {}: character {ch:?} outside the accepted subset",
                line_of(&chars, pos)
            ));
        }
    }
    Ok(out)
}

/// The 1-based line of character index `at`.
fn line_of(chars: &[char], at: usize) -> usize {
    chars[..at.min(chars.len())]
        .iter()
        .filter(|&&x| x == '\n')
        .count()
        + 1
}

/// Whether `ch` may continue an identifier (ASCII letters, digits, `_` and `$`).
fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'
}

/// Scans the quoted string that starts at `start`; returns it decoded and the index after it.
fn quoted(chars: &[char], start: usize) -> Result<(String, usize), String> {
    let quote = chars[start];
    let line = line_of(chars, start);
    let mut pos = start + 1;
    let mut s = String::new();
    loop {
        let Some(&ch) = chars.get(pos) else {
            return Err(format!("line {line}: unterminated string"));
        };
        pos += 1;
        match ch {
            _ if ch == quote => return Ok((s, pos)),
            '\n' | '\r' => return Err(format!("line {line}: newline in a string")),
            '\\' => {
                match chars.get(pos) {
                    Some(&e @ ('\\' | '\'' | '"')) => s.push(e),
                    _ => {
                        return Err(format!(
                            "line {line}: escape other than \\\\, \\' or \\\" in a string"
                        ));
                    }
                }
                pos += 1;
            }
            _ => s.push(ch),
        }
    }
}

/// Scans the template literal that starts at `start`; returns its raw text and the index after
/// it. A backslash in a template is an error.
fn template(chars: &[char], start: usize) -> Result<(String, usize), String> {
    let line = line_of(chars, start);
    let mut s = String::new();
    for (k, &ch) in chars.iter().enumerate().skip(start + 1) {
        match ch {
            '\x60' => return Ok((s, k + 1)),
            '\\' => return Err(format!("line {line}: escape in a template literal")),
            _ => s.push(ch),
        }
    }
    Err(format!("line {line}: unterminated template"))
}

/// A value of an object literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Value {
    /// `'…'`.
    Str(String),
    /// `[ '…', … ]`.
    List(Vec<String>),
    /// A template literal, raw.
    Template(String),
}

/// The literal after `export default`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Literal {
    /// A string list.
    List(Vec<String>),
    /// An object literal, keys in source order (duplicates are rejected).
    Object(Vec<(String, Value)>),
}

/// A cursor over tokens.
struct Cursor<'a> {
    /// The tokens.
    toks: &'a [Tok],
    /// The next token's index.
    pos: usize,
}

impl Cursor<'_> {
    /// The next token, without consuming it.
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    /// Consumes and returns the next token.
    fn bump(&mut self) -> Result<&Tok, String> {
        let t = self
            .toks
            .get(self.pos)
            .ok_or_else(|| "unexpected end of file".to_owned())?;
        self.pos += 1;
        Ok(t)
    }

    /// Whether the next token is the punctuation `p` (consumed if so).
    fn eat(&mut self, p: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Punct(q)) if *q == p) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consumes the punctuation `p` or fails.
    fn expect(&mut self, p: &str) -> Result<(), String> {
        if self.eat(p) {
            Ok(())
        } else {
            Err(format!(
                "expected `{p}` at token {}, found {:?}",
                self.pos,
                self.peek()
            ))
        }
    }

    /// Consumes the identifier `name` or fails.
    fn keyword(&mut self, name: &str) -> Result<(), String> {
        match self.bump()? {
            Tok::Ident(s) if s == name => Ok(()),
            other => Err(format!("expected `{name}`, found {other:?}")),
        }
    }

    /// Consumes any identifier.
    fn ident(&mut self) -> Result<String, String> {
        match self.bump()? {
            Tok::Ident(s) => Ok(s.clone()),
            other => Err(format!("expected an identifier, found {other:?}")),
        }
    }

    /// Consumes a quoted string.
    fn string(&mut self) -> Result<String, String> {
        match self.bump()? {
            Tok::Str(s) => Ok(s.clone()),
            other => Err(format!("expected a string, found {other:?}")),
        }
    }

    /// Whether every token was consumed.
    fn at_end(&self) -> bool {
        self.pos == self.toks.len()
    }

    /// `[ '…', … ]` with an optional trailing comma.
    fn list(&mut self) -> Result<Vec<String>, String> {
        self.expect("[")?;
        let mut out = Vec::new();
        loop {
            if self.eat("]") {
                return Ok(out);
            }
            out.push(self.string()?);
            if !self.eat(",") {
                self.expect("]")?;
                return Ok(out);
            }
        }
    }

    /// `{ key: value, … }` with an optional trailing comma; keys are identifiers or strings.
    fn object(&mut self) -> Result<Vec<(String, Value)>, String> {
        self.expect("{")?;
        let mut out: Vec<(String, Value)> = Vec::new();
        loop {
            if self.eat("}") {
                return Ok(out);
            }
            let key = match self.bump()? {
                Tok::Ident(s) | Tok::Str(s) => s.clone(),
                other => return Err(format!("expected an object key, found {other:?}")),
            };
            if out.iter().any(|(k, _)| *k == key) {
                return Err(format!("duplicate object key `{key}`"));
            }
            self.expect(":")?;
            let value = match self.peek() {
                Some(Tok::Str(_)) => Value::Str(self.string()?),
                Some(Tok::Template(_)) => match self.bump()? {
                    Tok::Template(s) => Value::Template(s.clone()),
                    other => return Err(format!("expected a template, found {other:?}")),
                },
                Some(Tok::Punct("[")) => Value::List(self.list()?),
                other => {
                    return Err(format!(
                        "object value of `{key}` is not a string, list or template: {other:?}"
                    ));
                }
            };
            out.push((key, value));
            if !self.eat(",") {
                self.expect("}")?;
                return Ok(out);
            }
        }
    }
}

/// Reads a literal-data file: `export default <list or object> ;?` and nothing else.
///
/// # Errors
///
/// On any other shape (see the module docs).
pub(super) fn parse_default(src: &str) -> Result<Literal, String> {
    let toks = tokenize(src)?;
    let mut c = Cursor {
        toks: &toks,
        pos: 0,
    };
    c.keyword("export")?;
    c.keyword("default")?;
    let lit = match c.peek() {
        Some(Tok::Punct("[")) => Literal::List(c.list()?),
        Some(Tok::Punct("{")) => Literal::Object(c.object()?),
        other => {
            return Err(format!(
                "`export default` of {other:?}, not a list or object"
            ));
        }
    };
    c.eat(";");
    if !c.at_end() {
        return Err(format!(
            "unexpected tokens after the default export: {:?}",
            c.peek()
        ));
    }
    Ok(lit)
}

/// A value captured by a template hole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Capture {
    /// `$num`.
    Num(u64),
    /// `$str`.
    Str(String),
    /// `$strs`: a string list.
    Strs(Vec<String>),
    /// `$obj`: an object literal.
    Obj(Vec<(String, Value)>),
}

/// Matches the whole of `src` against `template`, token for token, and returns the holes'
/// captures in order.
///
/// # Errors
///
/// When `src` differs from the template anywhere (the first difference is reported).
pub(super) fn match_template(src: &str, template: &str) -> Result<Vec<Capture>, String> {
    let toks = tokenize(src)?;
    let want = tokenize(template).map_err(|e| format!("template: {e}"))?;
    let mut c = Cursor {
        toks: &toks,
        pos: 0,
    };
    let mut caps = Vec::new();
    for w in &want {
        match w {
            Tok::Ident(h) if h == "$num" => match c.bump()? {
                Tok::Num(n) => caps.push(Capture::Num(*n)),
                other => return Err(format!("expected a number, found {other:?}")),
            },
            Tok::Ident(h) if h == "$str" => caps.push(Capture::Str(c.string()?)),
            Tok::Ident(h) if h == "$strs" => caps.push(Capture::Strs(c.list()?)),
            Tok::Ident(h) if h == "$obj" => caps.push(Capture::Obj(c.object()?)),
            _ => {
                let at = c.pos;
                let got = c.bump().map_err(|e| format!("{e}; expected {w:?}"))?;
                if got != w {
                    return Err(format!(
                        "the file differs from the accepted shape at token {at}: found {got:?}, \
                         expected {w:?}"
                    ));
                }
            }
        }
    }
    if !c.at_end() {
        return Err(format!(
            "the file continues past the accepted shape: {:?}",
            c.peek()
        ));
    }
    Ok(caps)
}

/// Reads a locale entry file, `src/locale/<locale>.ts`, and returns its fallback chain without
/// `base`, most specific first (for `de_AT`: `de_AT`, `de`, `en`).
///
/// The accepted shape is faker's generated one: `import { Faker } from '../faker';`, then one
/// `import <name> from '../locales/<name>';` per locale, then
/// `export const faker = new Faker({ locale: [<names>], });`. Every name in the list must have
/// been imported, and the list must end with `base`.
///
/// # Errors
///
/// On any other shape.
pub(super) fn locale_chain(src: &str) -> Result<Vec<String>, String> {
    let toks = tokenize(src)?;
    let mut c = Cursor {
        toks: &toks,
        pos: 0,
    };
    c.keyword("import")?;
    c.expect("{")?;
    c.keyword("Faker")?;
    c.expect("}")?;
    c.keyword("from")?;
    if c.string()? != "../faker" {
        return Err("`Faker` is not imported from '../faker'".to_owned());
    }
    c.expect(";")?;
    let mut imported = Vec::new();
    while matches!(c.peek(), Some(Tok::Ident(s)) if s == "import") {
        c.keyword("import")?;
        let name = c.ident()?;
        c.keyword("from")?;
        let path = c.string()?;
        if path != format!("../locales/{name}") {
            return Err(format!("`{name}` is imported from {path:?}"));
        }
        c.expect(";")?;
        imported.push(name);
    }
    c.keyword("export")?;
    c.keyword("const")?;
    c.keyword("faker")?;
    c.expect("=")?;
    c.keyword("new")?;
    c.keyword("Faker")?;
    c.expect("(")?;
    c.expect("{")?;
    c.keyword("locale")?;
    c.expect(":")?;
    c.expect("[")?;
    let mut chain = Vec::new();
    loop {
        if c.eat("]") {
            break;
        }
        let name = c.ident()?;
        if !imported.contains(&name) {
            return Err(format!("`{name}` is used but not imported"));
        }
        chain.push(name);
        if !c.eat(",") {
            c.expect("]")?;
            break;
        }
    }
    c.eat(",");
    c.expect("}")?;
    c.expect(")")?;
    c.eat(";");
    if !c.at_end() {
        return Err("unexpected tokens after the Faker constructor".to_owned());
    }
    if chain.last().map(String::as_str) != Some("base") {
        return Err("the locale chain does not end with `base`".to_owned());
    }
    chain.pop();
    if chain.is_empty() || chain.iter().any(|l| l == "base") {
        return Err("malformed locale chain".to_owned());
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::{
        Capture, Literal, Tok, Value, locale_chain, match_template, parse_default, tokenize,
    };

    #[test]
    fn accepts_a_plain_list_with_comments() {
        let src =
            "// leading\nexport default [\n  'Anna', // one\n  \"Jürgen\",\n  'O\\'Brien',\n];\n";
        assert_eq!(
            parse_default(src).unwrap(),
            Literal::List(vec!["Anna".into(), "Jürgen".into(), "O'Brien".into()])
        );
        assert_eq!(
            parse_default("/* c */ export default ['a', 'b']").unwrap(),
            Literal::List(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn accepts_a_sexed_object() {
        let src =
            "export default {\n  generic: ['Kim'],\n  female: ['Anna'],\n  male: ['Max',],\n};";
        let Literal::Object(o) = parse_default(src).unwrap() else {
            panic!("not an object")
        };
        assert_eq!(
            o,
            vec![
                ("generic".into(), Value::List(vec!["Kim".into()])),
                ("female".into(), Value::List(vec!["Anna".into()])),
                ("male".into(), Value::List(vec!["Max".into()])),
            ]
        );
    }

    #[test]
    fn rejects_other_shapes() {
        for src in [
            "export default [...a, 'b'];",
            "export default ['a'].map((x) => x);",
            "const a = ['x'];\nexport default a;",
            "export default { female: names };",
            "export default ['a\\n'];",
            "export default ['a'] extra",
            "export default { a: ['x'], a: ['y'] };",
            "export default [/re/];",
            "export default ['unterminated];",
            "export default [ 'a' 'b' ];",
            "module.exports = ['a'];",
            "export default [1, 2];",
        ] {
            assert!(parse_default(src).is_err(), "accepted {src:?}");
        }
    }

    #[test]
    fn rejects_unknown_characters_outside_strings() {
        assert!(tokenize("export default ['a'] @").is_err());
        assert!(tokenize("export default ['a'] é").is_err());
        assert!(tokenize("/* open").is_err());
        assert!(tokenize("`a\\`b`").is_err());
        assert!(tokenize("12ab").is_err());
    }

    #[test]
    fn templates_capture_holes_and_reject_differences() {
        let tpl = "const a = $strs; export default a.map((x) => `${x}#`).slice($num, $str);";
        let src =
            "const a = ['A', 'B'];\n// note\nexport default a.map((x) => `${x}#`).slice(3, 'z');";
        assert_eq!(
            match_template(src, tpl).unwrap(),
            vec![
                Capture::Strs(vec!["A".into(), "B".into()]),
                Capture::Num(3),
                Capture::Str("z".into())
            ]
        );
        let changed = src.replace("${x}#", "${x}##");
        assert!(match_template(&changed, tpl).is_err());
        assert!(match_template(&format!("{src};"), tpl).is_err());
        assert!(match_template("const a = ['A'];", tpl).is_err());
    }

    #[test]
    fn reads_a_locale_chain() {
        let src = "/*\n * generated\n */\n\nimport { Faker } from '../faker';\nimport base from \
                   '../locales/base';\nimport de from '../locales/de';\nimport de_AT from \
                   '../locales/de_AT';\nimport en from '../locales/en';\n\nexport const faker = \
                   new Faker({\n  locale: [de_AT, de, en, base],\n});\n";
        assert_eq!(locale_chain(src).unwrap(), vec!["de_AT", "de", "en"]);
        assert!(locale_chain(&src.replace(", base]", "]")).is_err());
        assert!(locale_chain(&src.replace("'../locales/de'", "'../locales/fr'")).is_err());
        assert!(locale_chain(&src.replace("de_AT, de", "de_AT, xx, de")).is_err());
    }

    #[test]
    fn punctuation_prefers_the_longest_match() {
        assert_eq!(
            tokenize("...a=>b").unwrap(),
            vec![
                Tok::Punct("..."),
                Tok::Ident("a".into()),
                Tok::Punct("=>"),
                Tok::Ident("b".into())
            ]
        );
    }
}

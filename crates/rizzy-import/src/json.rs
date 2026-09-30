//! A bounded JSON reader (RFC 8259) into a tree of zeroizing strings, for the Bitwarden JSON
//! export, 1PUX's `export.data` and rizzy-vault's own plaintext JSON export.
//!
//! **Why not `serde_json`.** Its strings and maps are plain `String`s, so every password of the
//! export would stay in freed memory. Here every string, number and member name is copied
//! once, into a zeroizing buffer sized to its raw text, which unescaping only shortens, so it
//! never reallocates (CRYPTO.md §12.2). It also keeps R1's allow-list at `rizzy-core`'s.
//!
//! **Bounds** (threat model A16): the input cap is the caller's; nesting is capped at
//! [`MAX_DEPTH`] and the number of values at [`MAX_NODES`], both checked before the value is
//! built. The reader never panics and never indexes out of bounds.
//!
//! **Strictness.** RFC 8259 grammar only: no comments, no trailing commas, no single quotes, no
//! `NaN`, no leading zeros, no raw control characters in strings, no lone surrogates in
//! `\u` escapes, nothing after the top-level value but whitespace. A duplicate member name is
//! kept; [`Json::get`] returns the first (RFC 8259 leaves duplicates to the reader; real
//! exports have none).

use core::fmt;

use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::limits::{MAX_DEPTH, MAX_NODES};
use crate::text;

/// One JSON value. Strings, numbers and member names are zeroizing; `Debug` prints only the
/// value's kind.
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as its source text (it may be a card expiry or a PIN).
    Number(Zeroizing<String>),
    /// A string, unescaped.
    String(Zeroizing<String>),
    /// An array.
    Array(Vec<Json>),
    /// An object's members, in source order.
    Object(Vec<(Zeroizing<String>, Json)>),
}

impl fmt::Debug for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "Json::Null",
            Self::Bool(_) => "Json::Bool([REDACTED])",
            Self::Number(_) => "Json::Number([REDACTED])",
            Self::String(_) => "Json::String([REDACTED])",
            Self::Array(_) => "Json::Array([REDACTED])",
            Self::Object(_) => "Json::Object([REDACTED])",
        })
    }
}

impl Json {
    /// The first member named `name`, if this is an object that has one.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(key, _)| key.as_str() == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The members, if this is an object.
    #[must_use]
    pub fn members(&self) -> Option<&[(Zeroizing<String>, Json)]> {
        match self {
            Self::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The string, if this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The string, or a number's source text: exporters write some fields (card expiry,
    /// PINs) either way.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::String(s) | Self::Number(s) => Some(s),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// A non-negative integer: a number written as plain digits, or a string of them.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.as_text().and_then(text::parse_u64)
    }

    /// A signed integer: a number written as an optional `-` and plain digits, or a string of
    /// them.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.as_text().and_then(text::parse_i64)
    }
}

/// Parses one JSON document. The caller has already applied its size cap.
///
/// # Errors
/// [`ImportError::Encoding`] if it is not UTF-8 (a leading byte-order mark is allowed),
/// [`ImportError::Malformed`] on a syntax error, [`ImportError::TooDeep`] and
/// [`ImportError::TooMany`] past [`MAX_DEPTH`] and [`MAX_NODES`].
pub fn parse(input: &[u8], max_len: usize) -> Result<Json, ImportError> {
    let source = text::utf8_input(input, max_len)?;
    let mut parser = Parser {
        src: source,
        bytes: source.as_bytes(),
        pos: 0,
        nodes: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(ImportError::Malformed);
    }
    Ok(value)
}

/// The reader's state: the source and a cursor into it.
struct Parser<'a> {
    /// The document, known to be UTF-8.
    src: &'a str,
    /// The same bytes.
    bytes: &'a [u8],
    /// The next byte to read.
    pos: usize,
    /// Values built so far.
    nodes: usize,
}

impl Parser<'_> {
    /// The byte at the cursor, if any.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Skips JSON whitespace.
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// Consumes `byte` or fails.
    fn expect(&mut self, byte: u8) -> Result<(), ImportError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(ImportError::Malformed)
        }
    }

    /// Consumes the literal `word` or fails.
    fn literal(&mut self, word: &[u8]) -> Result<(), ImportError> {
        let end = self
            .pos
            .checked_add(word.len())
            .ok_or(ImportError::Malformed)?;
        if self.bytes.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(())
        } else {
            Err(ImportError::Malformed)
        }
    }

    /// Counts one value against [`MAX_NODES`].
    fn count(&mut self) -> Result<(), ImportError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            Err(ImportError::TooMany)
        } else {
            Ok(())
        }
    }

    /// Reads one value at nesting `depth`.
    fn value(&mut self, depth: usize) -> Result<Json, ImportError> {
        self.count()?;
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Json::String),
            Some(b't') => self.literal(b"true").map(|()| Json::Bool(true)),
            Some(b'f') => self.literal(b"false").map(|()| Json::Bool(false)),
            Some(b'n') => self.literal(b"null").map(|()| Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number().map(Json::Number),
            _ => Err(ImportError::Malformed),
        }
    }

    /// Reads an array; the cursor is on `[`.
    fn array(&mut self, depth: usize) -> Result<Json, ImportError> {
        if depth > MAX_DEPTH {
            return Err(ImportError::TooDeep);
        }
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(ImportError::Malformed),
            }
        }
    }

    /// Reads an object; the cursor is on `{`.
    fn object(&mut self, depth: usize) -> Result<Json, ImportError> {
        if depth > MAX_DEPTH {
            return Err(ImportError::TooDeep);
        }
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            let name = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth)?;
            members.push((name, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(members));
                }
                _ => return Err(ImportError::Malformed),
            }
        }
    }

    /// Reads a number's text; the cursor is on `-` or a digit.
    fn number(&mut self) -> Result<Zeroizing<String>, ImportError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(ImportError::Malformed),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.required_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.required_digits()?;
        }
        let number = self
            .src
            .get(start..self.pos)
            .ok_or(ImportError::Malformed)?;
        Ok(text::copy(number))
    }

    /// Skips ASCII digits.
    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    /// Skips one or more ASCII digits.
    fn required_digits(&mut self) -> Result<(), ImportError> {
        let start = self.pos;
        self.digits();
        if self.pos == start {
            Err(ImportError::Malformed)
        } else {
            Ok(())
        }
    }

    /// Reads a string; the cursor is on its opening quote.
    fn string(&mut self) -> Result<Zeroizing<String>, ImportError> {
        self.expect(b'"')?;
        let start = self.pos;
        // First pass: find the closing quote, so the buffer is allocated once at the raw
        // length, which unescaping never exceeds.
        let mut end = start;
        loop {
            match self.bytes.get(end) {
                None => return Err(ImportError::Malformed),
                Some(b'"') => break,
                Some(b'\\') => end += 2,
                Some(b) if *b < 0x20 => return Err(ImportError::Malformed),
                Some(_) => end += 1,
            }
        }
        let mut out = text::with_capacity(end - start);
        let mut run = start;
        while self.pos < end {
            if self.peek() != Some(b'\\') {
                self.pos += 1;
                continue;
            }
            // The run before the escape: it starts and ends next to ASCII bytes, so it is on
            // character boundaries.
            out.push_str(self.src.get(run..self.pos).ok_or(ImportError::Malformed)?);
            self.pos += 1;
            let escaped = self.peek().ok_or(ImportError::Malformed)?;
            self.pos += 1;
            let c = match escaped {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => self.unicode_escape()?,
                _ => return Err(ImportError::Malformed),
            };
            out.push(c);
            run = self.pos;
        }
        out.push_str(self.src.get(run..end).ok_or(ImportError::Malformed)?);
        self.pos = end + 1;
        Ok(out)
    }

    /// Reads the four hex digits after `\u`, and a low surrogate's `\uXXXX` after a high one.
    fn unicode_escape(&mut self) -> Result<char, ImportError> {
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                self.literal(b"\\u")?;
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(ImportError::Malformed);
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(ImportError::Malformed),
            _ => first,
        };
        char::from_u32(code).ok_or(ImportError::Malformed)
    }

    /// Reads four hex digits.
    fn hex4(&mut self) -> Result<u32, ImportError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = self
                .peek()
                .and_then(|b| char::from(b).to_digit(16))
                .ok_or(ImportError::Malformed)?;
            value = (value << 4) | digit;
            self.pos += 1;
        }
        Ok(value)
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    use super::*;

    /// Parses with a generous cap.
    fn p(s: &str) -> Result<Json, ImportError> {
        parse(s.as_bytes(), 1 << 20)
    }

    #[test]
    fn values() {
        let doc = p(r#" {"a": [1, -2.5e3, true, false, null, "x"], "b": {"c": "d"}} "#).unwrap();
        let a = doc.get("a").unwrap().as_array().unwrap();
        assert_eq!(a.len(), 6);
        assert_eq!(a[0].as_u64(), Some(1));
        assert_eq!(a[1].as_text(), Some("-2.5e3"));
        assert_eq!(a[1].as_u64(), None);
        assert_eq!(a[2].as_bool(), Some(true));
        assert!(matches!(a[4], Json::Null));
        assert_eq!(a[5].as_str(), Some("x"));
        assert_eq!(doc.get("b").unwrap().get("c").unwrap().as_str(), Some("d"));
        assert!(doc.get("z").is_none());
    }

    #[test]
    fn escapes() {
        let doc = p(r#""a\"b\\c\/d\b\f\n\r\t\u00e9\ud83d\ude00é""#).unwrap();
        assert_eq!(doc.as_str(), Some("a\"b\\c/d\u{8}\u{c}\n\r\té\u{1F600}é"));
    }

    #[test]
    fn first_duplicate_wins() {
        let doc = p(r#"{"k": "1", "k": "2"}"#).unwrap();
        assert_eq!(doc.get("k").unwrap().as_str(), Some("1"));
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            "1e",
            "-",
            "'a'",
            "\"\\x\"",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "\"\\ud800\\u0041\"",
            "\"a\nb\"",
            "\"abc",
            "tru",
            "nul",
            "[1] 2",
            "NaN",
            "{\"a\" 1}",
            "{1:2}",
            "\"\\u12\"",
        ] {
            assert_eq!(p(bad).unwrap_err(), ImportError::Malformed, "{bad:?}");
        }
        assert_eq!(parse(b"\"\xff\"", 10).unwrap_err(), ImportError::Encoding);
        assert_eq!(parse(b"[1, 2]", 3).unwrap_err(), ImportError::TooLarge);
    }

    #[test]
    fn depth_cap() {
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(p(&ok).is_ok());
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(p(&deep).unwrap_err(), ImportError::TooDeep);
        let deep_obj = format!(
            "{}1{}",
            "{\"a\":".repeat(MAX_DEPTH + 1),
            "}".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(p(&deep_obj).unwrap_err(), ImportError::TooDeep);
    }

    #[test]
    fn bom_is_skipped() {
        assert_eq!(parse(b"\xEF\xBB\xBF\"x\"", 10).unwrap().as_str(), Some("x"));
    }

    #[test]
    fn debug_is_redacted() {
        let doc = p(r#"{"password": "hunter2"}"#).unwrap();
        let shown = format!("{doc:?}");
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("password"));
    }
}

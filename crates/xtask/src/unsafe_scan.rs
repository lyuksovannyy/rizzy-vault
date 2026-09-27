//! The first-party `unsafe` token scan of ADR 0019 §4.1, run by `cargo xtask check-deps`.
//!
//! `unsafe_code = "forbid"` (ADR 0016 R7) does not see everything: rustc drops an `unsafe_code`
//! diagnostic whose span lies in an external macro expansion, so `unsafe` written inside a
//! proc-macro input can escape the lint if the macro re-spans or consumes those tokens (ADR 0019,
//! Context). This scan reads the source instead. It lexes each first-party `.rs` file and
//! reports every `unsafe` keyword token. Comments, and string, byte-string, C-string, raw-string
//! and character literals, are excluded. Our code gets no `unsafe` exception (ADR 0013 owner
//! decision 1, ADR 0019 owner decision 7), so every token is a violation. The scan makes spike
//! S1's one-time "no `unsafe` token in our source" a standing check.
//!
//! **Which files.** Every `.rs` file that `git ls-files --cached --others --exclude-standard`
//! lists under the workspace root: tracked files, and untracked files that are not ignored, so a
//! new file is scanned before it is committed. That is the workspace crates, `fuzz/` and
//! `spikes/`. Only the generated Rust of [`crate::rules::GENERATED_RUST`] is skipped
//! ([`first_party`]).
//!
//! **Fail closed.** An unterminated block comment, string or character literal would hide the
//! rest of the file, so it is an error, which the check reports as a violation. A file that is
//! not UTF-8 fails the load.
//!
//! **Limits.** A raw identifier (`r#unsafe`) is an identifier, not the keyword, and is not
//! reported. The scan does not see `unsafe` that a proc macro builds from a string, Rust that
//! `include!` or a `#[path]` attribute takes from a file whose name does not end in `.rs`, or
//! code that a build script writes to `OUT_DIR`. `unsafe` that a binding generator emits is not
//! first party: §4.1's baseline diff reviews it.

/// Where a token starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Position {
    /// Line, from 1.
    pub(crate) line: usize,
    /// Column, from 1, counted in characters.
    pub(crate) column: usize,
}

/// Whether `path`, relative to the workspace root with `/` separators as git prints it, is a
/// first-party Rust file: its extension is `rs` in any case (on a case-insensitive file system,
/// `mod x;` can open `X.RS`), and it lies in none of the `generated` directories.
pub(crate) fn first_party(path: &str, generated: &[&str]) -> bool {
    std::path::Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
        && !generated.iter().any(|dir| {
            path.strip_prefix(dir.trim_end_matches('/'))
                .is_some_and(|rest| rest.starts_with('/'))
        })
}

/// The position of every `unsafe` keyword token in `source`, in order.
///
/// # Errors
///
/// Returns a message with the position when a block comment, string or character literal is
/// not terminated, because the rest of the file could not be scanned.
pub(crate) fn unsafe_tokens(source: &str) -> Result<Vec<Position>, String> {
    let mut cur = Cursor::new(source);
    let mut found = Vec::new();
    while let Some(c) = cur.peek(0) {
        let start = cur.at;
        match (c, cur.peek(1)) {
            ('/', Some('/')) => cur.line_comment(),
            ('/', Some('*')) => cur.block_comment(start)?,
            ('"', _) => cur.string(start)?,
            ('\'', _) => cur.quote(start)?,
            _ if is_word(c) => match cur.word().as_str() {
                "unsafe" => found.push(start),
                prefix @ ("r" | "br" | "cr") => cur.raw(prefix == "r", start)?,
                _ => {}
            },
            _ => cur.advance(),
        }
    }
    Ok(found)
}

/// Whether `c` belongs to a word: an identifier, keyword or number. A word is read whole, so
/// `unsafe_code` is one word, never the keyword.
fn is_word(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// The error for a construct opened at `start` that never ends.
fn unterminated(what: &str, start: Position) -> String {
    format!(
        "unterminated {what} at line {}, column {}",
        start.line, start.column
    )
}

/// A source text, read one character at a time.
struct Cursor {
    /// The text.
    chars: Vec<char>,
    /// Index of the next character.
    index: usize,
    /// Position of the next character.
    at: Position,
}

impl Cursor {
    /// A cursor at the start of `source`.
    fn new(source: &str) -> Self {
        Self {
            chars: source.chars().collect(),
            index: 0,
            at: Position { line: 1, column: 1 },
        }
    }

    /// The character `ahead` places after the next one (0 is the next one), if any.
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.index + ahead).copied()
    }

    /// Moves past the next character, if there is one.
    fn advance(&mut self) {
        let Some(c) = self.peek(0) else { return };
        self.index += 1;
        if c == '\n' {
            self.at.line += 1;
            self.at.column = 1;
        } else {
            self.at.column += 1;
        }
    }

    /// Moves past the next `n` characters, or to the end.
    fn advance_by(&mut self, n: usize) {
        for _ in 0..n {
            self.advance();
        }
    }

    /// Reads a word ([`is_word`]).
    fn word(&mut self) -> String {
        let mut word = String::new();
        while let Some(c) = self.peek(0).filter(|&c| is_word(c)) {
            word.push(c);
            self.advance();
        }
        word
    }

    /// At `//`: skips a line comment, doc comments (`///`, `//!`) included.
    fn line_comment(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.advance();
        }
    }

    /// At `/*`: skips a block comment, doc comments (`/**`, `/*!`) included. Block comments
    /// nest.
    fn block_comment(&mut self, start: Position) -> Result<(), String> {
        self.advance_by(2);
        let mut depth = 1_usize;
        while depth > 0 {
            match (self.peek(0), self.peek(1)) {
                (None, _) => return Err(unterminated("block comment", start)),
                (Some('/'), Some('*')) => {
                    depth += 1;
                    self.advance_by(2);
                }
                (Some('*'), Some('/')) => {
                    depth -= 1;
                    self.advance_by(2);
                }
                _ => self.advance(),
            }
        }
        Ok(())
    }

    /// At `"`: skips a string literal, or the body of a byte or C string whose `b` or `c` was
    /// read as a word. `\` escapes the next character.
    fn string(&mut self, start: Position) -> Result<(), String> {
        self.advance();
        loop {
            match self.peek(0) {
                None => return Err(unterminated("string literal", start)),
                Some('\\') => self.advance_by(2),
                Some('"') => {
                    self.advance();
                    return Ok(());
                }
                Some(_) => self.advance(),
            }
        }
    }

    /// At `'`: skips a character or byte literal (`'a'`, `'"'`, `'\''`, `'\u{2028}'`), or only
    /// the `'` of a lifetime or label, whose name is then read as a word.
    fn quote(&mut self, start: Position) -> Result<(), String> {
        match (self.peek(1), self.peek(2)) {
            (Some('\\'), _) => {
                // `'`, `\` and the escaped character, then up to the closing `'`.
                self.advance_by(3);
                loop {
                    match self.peek(0) {
                        None | Some('\n') => {
                            return Err(unterminated("character literal", start));
                        }
                        Some('\'') => {
                            self.advance();
                            return Ok(());
                        }
                        Some(_) => self.advance(),
                    }
                }
            }
            (Some(_), Some('\'')) => self.advance_by(3),
            _ => self.advance(),
        }
        Ok(())
    }

    /// After the word `r`, `br` or `cr`: skips a raw string literal (`r"…"`, `r#"…"#`, with any
    /// number of `#`), which ends only at a `"` followed by as many `#`. After `r` alone, also
    /// skips a raw identifier (`r#name`), which is never the keyword. Anything else is left to
    /// the main loop.
    fn raw(&mut self, may_be_identifier: bool, start: Position) -> Result<(), String> {
        let mut hashes = 0;
        while self.peek(hashes) == Some('#') {
            hashes += 1;
        }
        if self.peek(hashes) == Some('"') {
            self.advance_by(hashes + 1);
            loop {
                match self.peek(0) {
                    None => return Err(unterminated("raw string literal", start)),
                    Some('"') if (1..=hashes).all(|n| self.peek(n) == Some('#')) => {
                        self.advance_by(hashes + 1);
                        return Ok(());
                    }
                    Some(_) => self.advance(),
                }
            }
        }
        if may_be_identifier && hashes == 1 && self.peek(1).is_some_and(is_word) {
            self.advance();
            self.word();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(line: usize, column: usize) -> Position {
        Position { line, column }
    }

    fn scan(source: &str) -> Vec<Position> {
        unsafe_tokens(source).unwrap()
    }

    #[test]
    fn the_keyword_is_found_in_every_position() {
        assert_eq!(scan("unsafe fn f() {}"), [at(1, 1)]);
        assert_eq!(scan("fn f() {\n    unsafe { g() }\n}\n"), [at(2, 5)]);
        assert_eq!(
            scan(
                "#[unsafe(no_mangle)]\nunsafe impl Send for X {}\nunsafe extern \"C\" {}\n\
                 pub unsafe trait T {}\n"
            ),
            [at(1, 3), at(2, 1), at(3, 1), at(4, 5)]
        );
        // Macro input, which the lint may not see (ADR 0019, Context).
        assert_eq!(
            scan("m! { unsafe { x } }\nquote! { unsafe {} }"),
            [at(1, 6), at(2, 10)]
        );
        assert_eq!(scan("x=unsafe{y}"), [at(1, 3)]);
        assert_eq!(scan("unsafe"), [at(1, 1)]);
        // Columns count characters, not bytes.
        assert_eq!(scan("é unsafe"), [at(1, 3)]);
    }

    #[test]
    fn other_words_are_not_the_keyword() {
        for source in [
            "#![forbid(unsafe_code)]",
            "my_unsafe",
            "Unsafe",
            "UNSAFE",
            "unsafe1",
            "unsafeé",
            "r#unsafe",
            "x.r#unsafe()",
            "",
        ] {
            assert_eq!(scan(source), [], "{source}");
        }
    }

    #[test]
    fn comments_are_skipped() {
        for source in [
            "// unsafe",
            "/// unsafe { }",
            "//! unsafe",
            "/* unsafe */",
            "/** unsafe */",
            "/*! unsafe */",
            "/***/",
            "/* outer /* nested unsafe */ still unsafe */",
            "/* \" is no string */",
            "// \" is no string\n",
            "// ' is no char\n",
        ] {
            assert_eq!(scan(source), [], "{source}");
        }
        assert_eq!(scan("/* a /* b */ c */ unsafe"), [at(1, 19)]);
        assert_eq!(scan("// x\nunsafe"), [at(2, 1)]);
        assert_eq!(scan("x // \"\nunsafe"), [at(2, 1)]);
    }

    #[test]
    fn literals_are_skipped() {
        for source in [
            r#""unsafe""#,
            r#""a \" unsafe""#,
            r#"b"unsafe""#,
            r#"c"unsafe""#,
            r#"br"unsafe""#,
            r#"cr"unsafe""#,
            r#"r"unsafe \""#,
            r##"r#"a "unsafe" b"#"##,
            r###"r##"a "# unsafe"##"###,
            r###"br##"unsafe"##"###,
            r##"cr#"unsafe"#"##,
            r#"#[doc = r"unsafe"] fn f() {}"#,
            r#"'"' "unsafe""#,
            r#"b'"' "unsafe""#,
            r"'\'' '\\' '\u{75}' b'\x75'",
            r#"let s: &'static str = "unsafe";"#,
            "'outer: loop { break 'outer; }",
            "impl X<'_> for Y {}",
        ] {
            assert_eq!(scan(source), [], "{source}");
        }
        // What follows a literal is scanned again.
        assert_eq!(scan(r#""\\" unsafe"#), [at(1, 6)]);
        assert_eq!(scan("\"a\nb\" unsafe"), [at(2, 4)]);
        assert_eq!(scan(r#"'"' unsafe"#), [at(1, 5)]);
        assert_eq!(scan(r"'\'' unsafe"), [at(1, 6)]);
        assert_eq!(scan(r##"r#"x"# unsafe"##), [at(1, 8)]);
        assert_eq!(scan("fn f<'a>(x: &'a str) { unsafe {} }"), [at(1, 24)]);
    }

    #[test]
    fn unterminated_constructs_fail_closed() {
        for (source, what) in [
            (
                r#""unsafe"#,
                "unterminated string literal at line 1, column 1",
            ),
            (
                "/* unsafe",
                "unterminated block comment at line 1, column 1",
            ),
            (
                "x\n  /* /* */ unsafe",
                "unterminated block comment at line 2, column 3",
            ),
            (
                r#"r#"unsafe""#,
                "unterminated raw string literal at line 1, column 1",
            ),
            (r#"b"\""#, "unterminated string literal at line 1, column 2"),
            (r"'\", "unterminated character literal at line 1, column 1"),
            (
                "'\\u{75\n",
                "unterminated character literal at line 1, column 1",
            ),
        ] {
            assert_eq!(unsafe_tokens(source), Err(what.to_owned()), "{source}");
        }
    }

    /// The Rust files of this crate hold `unsafe` only in comments and literals, many of them
    /// raw strings with `"` and `#` inside (above): none is reported.
    #[test]
    fn xtask_sources_pass() {
        for source in [
            include_str!("unsafe_scan.rs"),
            include_str!("main.rs"),
            include_str!("check.rs"),
            include_str!("check/tests.rs"),
            include_str!("rules.rs"),
            include_str!("manifest.rs"),
            include_str!("metadata.rs"),
            include_str!("../tests/cli.rs"),
        ] {
            assert_eq!(unsafe_tokens(source), Ok(vec![]));
        }
    }

    #[test]
    fn generated_directories_are_not_first_party() {
        let generated = ["crates/rizzy-ffi/generated", "crates/rizzy-wasm/generated/"];
        assert!(first_party("crates/rizzy-ffi/src/lib.rs", &generated));
        assert!(first_party("crates/rizzy-ffi/generated.rs", &generated));
        assert!(first_party("crates/rizzy-ffi/generated2/x.rs", &generated));
        assert!(!first_party(
            "crates/rizzy-ffi/generated/expanded.rs",
            &generated
        ));
        assert!(!first_party(
            "crates/rizzy-wasm/generated/a/b.rs",
            &generated
        ));
        assert!(first_party("fuzz/fuzz_targets/normalize.rs", &[]));
        assert!(first_party("crates/x/src/Y.RS", &[]));
        assert!(!first_party("crates/rizzy-ffi/generated/rizzy.swift", &[]));
        assert!(!first_party("README.md", &[]));
        assert!(!first_party("crates/x/src/lib.rs.bk", &[]));
    }
}

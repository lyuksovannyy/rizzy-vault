// SPDX-License-Identifier: AGPL-3.0-only

//! The committed transliteration table ([`super::TRANSLIT`]) and the ascii column it computes
//! (ADR 0079 §5 "The ascii column"; the exact rules are in the format contract the xtask and the
//! `rizzy-client` parser share).
//!
//! The table has two sections. `[general]` folds Latin diacritics for every country
//! (`é` → `e`, `ß` → `ss`). `[de]` overrides it for the countries whose names follow
//! German spelling conventions (DE, AT, CH: `ü` → `ue`). A rule is one lower-case character, a
//! space and its replacement of 1–3 ASCII lower-case letters. `#` starts a comment line; blank
//! lines are ignored.

use std::collections::BTreeMap;

/// The parsed table.
#[derive(Debug, Default)]
pub(super) struct Translit {
    /// `[general]`.
    general: BTreeMap<char, String>,
    /// `[de]`, consulted first for German-convention countries.
    german: BTreeMap<char, String>,
}

/// The longest ascii form, in bytes.
pub(super) const MAX_ASCII: usize = 32;

impl Translit {
    /// Parses the table.
    ///
    /// # Errors
    ///
    /// On a rule outside a section, an unknown section, a malformed rule, a key that is ASCII or
    /// not lower case, or a key repeated within a section.
    pub(super) fn parse(src: &str) -> Result<Self, String> {
        let mut t = Self::default();
        let mut section: Option<bool> = None;
        for (n, line) in src.lines().enumerate() {
            let err = |m: &str| format!("translit line {}: {m}", n + 1);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line {
                "[general]" => section = Some(false),
                "[de]" => section = Some(true),
                _ => {
                    let german = section.ok_or_else(|| err("rule before any section"))?;
                    let mut chars = line.chars();
                    let key = chars.next().ok_or_else(|| err("empty rule"))?;
                    if chars.next() != Some(' ') {
                        return Err(err("expected <char> <replacement>"));
                    }
                    let rep: String = chars.collect();
                    if key.is_ascii() || key.to_lowercase().ne(std::iter::once(key)) {
                        return Err(err("the key must be a non-ASCII lower-case character"));
                    }
                    if rep.is_empty()
                        || rep.len() > 3
                        || !rep.bytes().all(|b| b.is_ascii_lowercase())
                    {
                        return Err(err("the replacement must be 1-3 of [a-z]"));
                    }
                    let map = if german {
                        &mut t.german
                    } else {
                        &mut t.general
                    };
                    if map.insert(key, rep).is_some() {
                        return Err(err("key repeated in its section"));
                    }
                }
            }
        }
        Ok(t)
    }

    /// The ascii form of a display form, or `None` when a character has no rule or the result
    /// breaks the ascii rules (1–[`MAX_ASCII`] bytes of `[a-z-]`, no leading, trailing or
    /// doubled hyphen).
    ///
    /// Each character is lower-cased first; `a`–`z` and `-` stay, a space becomes `-`, an
    /// apostrophe is removed, anything else goes through the table.
    pub(super) fn ascii(&self, display: &str, german: bool) -> Option<String> {
        let mut out = String::new();
        for c in display.chars() {
            for l in c.to_lowercase() {
                match l {
                    'a'..='z' | '-' => out.push(l),
                    ' ' => out.push('-'),
                    '\'' => {}
                    _ => {
                        let rep = german
                            .then(|| self.german.get(&l))
                            .flatten()
                            .or_else(|| self.general.get(&l))?;
                        out.push_str(rep);
                    }
                }
            }
        }
        let ok = !out.is_empty()
            && out.len() <= MAX_ASCII
            && !out.starts_with('-')
            && !out.ends_with('-')
            && !out.contains("--");
        ok.then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::Translit;

    const TABLE: &str = "# comment\n[general]\nü u\né e\nß ss\nø o\n\n[de]\nü ue\n";

    #[test]
    fn folds_with_the_german_override() {
        let t = Translit::parse(TABLE).unwrap();
        assert_eq!(t.ascii("Jürgen", true).unwrap(), "juergen");
        assert_eq!(t.ascii("Jürgen", false).unwrap(), "jurgen");
        assert_eq!(t.ascii("Strauß", true).unwrap(), "strauss");
        assert_eq!(t.ascii("Ü", true).unwrap(), "ue");
        assert_eq!(t.ascii("O'Brien", false).unwrap(), "obrien");
        assert_eq!(t.ascii("Anne Marie", false).unwrap(), "anne-marie");
        assert_eq!(t.ascii("Jean-Luc", false).unwrap(), "jean-luc");
        assert_eq!(t.ascii("Søren", false).unwrap(), "soren");
    }

    #[test]
    fn rejects_unmapped_and_malformed_results() {
        let t = Translit::parse(TABLE).unwrap();
        assert_eq!(t.ascii("Łukasz", false), None);
        assert_eq!(t.ascii("'", false), None);
        assert_eq!(t.ascii("a - b", false), None);
        assert_eq!(t.ascii(&"a".repeat(33), false), None);
        assert_eq!(t.ascii("-a", false), None);
    }

    #[test]
    fn rejects_malformed_tables() {
        for bad in [
            "ü u\n",
            "[general]\nü\n",
            "[general]\nüu\n",
            "[general]\nu u\n",
            "[general]\nÜ ue\n",
            "[general]\nü U\n",
            "[general]\nü uuuu\n",
            "[general]\nü u\nü v\n",
            "[other]\n",
        ] {
            assert!(Translit::parse(bad).is_err(), "accepted {bad:?}");
        }
    }
}

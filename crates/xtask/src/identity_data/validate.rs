// SPDX-License-Identifier: AGPL-3.0-only

//! An independent re-check of a rendered data file against the format contract (ADR 0079 §5
//! content rules), run on every output before it is written and by the unit tests. It mirrors
//! what the `rizzy-client` parser enforces, so a writer bug fails here, not in the client.

use std::collections::BTreeSet;

use super::{
    HEADER, LIMITS, MAX_LINE, MAX_OUTPUT, MAX_PHONES, MAX_POSTCODES, MAX_SUB_POSTCODES,
    MAX_SUBDIVISIONS, display_ok, phone_ok, postcode_ok, title_ok, translit::MAX_ASCII,
};

/// A cursor over the file's lines.
struct Lines<'a> {
    /// The lines (without their LF).
    lines: Vec<&'a str>,
    /// The next line's index.
    pos: usize,
}

impl<'a> Lines<'a> {
    /// The next line, without consuming it.
    fn peek(&self) -> Option<&'a str> {
        self.lines.get(self.pos).copied()
    }

    /// Consumes a line that starts with `prefix` and returns the rest.
    fn directive(&mut self, prefix: &str) -> Result<&'a str, String> {
        let line = self
            .peek()
            .ok_or_else(|| format!("expected {prefix:?}, found the end"))?;
        let rest = line
            .strip_prefix(prefix)
            .ok_or_else(|| format!("line {}: expected {prefix:?}", self.pos + 1))?;
        self.pos += 1;
        Ok(rest)
    }

    /// Consumes every following line that starts with `prefix`.
    fn repeated(&mut self, prefix: &str) -> Vec<&'a str> {
        let mut out = Vec::new();
        while let Some(rest) = self.peek().and_then(|l| l.strip_prefix(prefix)) {
            out.push(rest);
            self.pos += 1;
        }
        out
    }

    /// Consumes the entry lines of a section (until the next `[` or `@` line or the end).
    fn entries(&mut self, header: &str) -> Result<Vec<&'a str>, String> {
        if self.peek() != Some(header) {
            return Err(format!("line {}: expected {header}", self.pos + 1));
        }
        self.pos += 1;
        let mut out = Vec::new();
        while let Some(l) = self.peek() {
            if l.starts_with('[') || l.starts_with('@') {
                break;
            }
            out.push(l);
            self.pos += 1;
        }
        Ok(out)
    }
}

/// Whether `s` is a valid ascii form.
fn ascii_ok(s: &str) -> bool {
    (1..=MAX_ASCII).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
}

/// Checks that `items` are strictly ascending (so sorted and unique).
fn ascending<T: Ord + std::fmt::Debug>(what: &str, items: &[T]) -> Result<(), String> {
    match items.windows(2).find(|w| w[0] >= w[1]) {
        Some(w) => Err(format!("{what}: {:?} is not before {:?}", w[0], w[1])),
        None => Ok(()),
    }
}

/// A name list: `display|ascii` lines.
fn names(what: &str, lines: &[&str], cap: usize, min: usize) -> Result<(), String> {
    let mut displays = Vec::new();
    for l in lines {
        let (d, a) = l
            .split_once('|')
            .ok_or_else(|| format!("{what}: {l:?} is not display|ascii"))?;
        if !display_ok(d) || !ascii_ok(a) {
            return Err(format!("{what}: {l:?} breaks a content rule"));
        }
        displays.push(d);
    }
    count(what, displays.len(), min, cap)?;
    ascending(what, &displays)
}

/// A street or city list.
fn plain(what: &str, lines: &[&str], cap: usize, min: usize) -> Result<(), String> {
    if let Some(bad) = lines.iter().find(|l| !display_ok(l)) {
        return Err(format!("{what}: {bad:?} breaks a content rule"));
    }
    count(what, lines.len(), min, cap)?;
    ascending(what, lines)
}

/// Checks a list length.
fn count(what: &str, n: usize, min: usize, cap: usize) -> Result<(), String> {
    if n < min || n > cap {
        return Err(format!("{what}: {n} entries, outside {min}..={cap}"));
    }
    Ok(())
}

/// Checks the whole file.
///
/// # Errors
///
/// On the first rule it breaks.
pub(crate) fn validate(text: &str, min_list: usize) -> Result<(), String> {
    if text.len() > MAX_OUTPUT {
        return Err(format!("{} bytes, over {MAX_OUTPUT}", text.len()));
    }
    let body = text
        .strip_suffix('\n')
        .ok_or("the file does not end with LF")?;
    if text.starts_with('\u{feff}') || text.contains('\r') || text.contains('\t') {
        return Err("BOM, CR or tab".to_owned());
    }
    let all: Vec<&str> = body.split('\n').collect();
    for (n, l) in all.iter().enumerate() {
        if l.is_empty() || l.len() > MAX_LINE || l.ends_with(' ') || (n > 0 && l.starts_with('#')) {
            return Err(format!(
                "line {}: empty, too long, trailing space or comment",
                n + 1
            ));
        }
    }
    if all.first() != Some(&HEADER) {
        return Err("line 1 is not the header".to_owned());
    }
    let mut lines = Lines { lines: all, pos: 1 };
    let mut previous = String::new();
    while lines.peek().is_some() {
        let code = lines.directive("@country ")?;
        if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) || *code <= *previous {
            return Err(format!("country {code:?} is malformed or out of order"));
        }
        code.clone_into(&mut previous);
        country(&mut lines, code, min_list).map_err(|e| format!("{code}: {e}"))?;
    }
    Ok(())
}

/// One country block after its `@country` line.
fn country(lines: &mut Lines<'_>, code: &str, min: usize) -> Result<(), String> {
    let name = lines.directive("@name ")?;
    let male = lines.directive("@title.male ")?;
    let female = lines.directive("@title.female ")?;
    let address = lines.directive("@address ")?;
    let number = lines.directive("@number ")?;
    if !display_ok(name) || !title_ok(male) || !title_ok(female) {
        return Err("name or title".to_owned());
    }
    let rest = address
        .replacen("{street}", "", 1)
        .replacen("{number}", "", 1);
    if address.matches("{street}").count() != 1
        || address.matches("{number}").count() != 1
        || !rest
            .chars()
            .all(|c| c.is_alphabetic() || c == ' ' || c == ',')
    {
        return Err(format!("@address {address:?}"));
    }
    let nums: Vec<u32> = number
        .split(' ')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| "@number")?;
    match nums.as_slice() {
        [lo, hi] if (1..=*hi).contains(lo) && *hi <= 9999 => {}
        _ => return Err(format!("@number {number:?}")),
    }
    let postcodes = lines.repeated("@postcode ");
    count("@postcode", postcodes.len(), 1, MAX_POSTCODES)?;
    ascending("@postcode", &postcodes)?;
    if let Some(bad) = postcodes.iter().find(|p| !postcode_ok(p)) {
        return Err(format!("@postcode {bad:?}"));
    }
    let phones = lines.repeated("@phone ");
    count("@phone", phones.len(), 0, MAX_PHONES)?;
    ascending("@phone", &phones)?;
    if let Some(bad) = phones.iter().find(|p| !phone_ok(p)) {
        return Err(format!("@phone {bad:?}"));
    }
    names(
        "[first.female]",
        &lines.entries("[first.female]")?,
        LIMITS.first,
        min,
    )?;
    names(
        "[first.male]",
        &lines.entries("[first.male]")?,
        LIMITS.first,
        min,
    )?;
    if lines.peek() == Some("[last]") {
        names("[last]", &lines.entries("[last]")?, LIMITS.last, min)?;
    } else {
        names(
            "[last.female]",
            &lines.entries("[last.female]")?,
            LIMITS.last,
            min,
        )?;
        names(
            "[last.male]",
            &lines.entries("[last.male]")?,
            LIMITS.last,
            min,
        )?;
    }
    plain("[street]", &lines.entries("[street]")?, LIMITS.street, min)?;
    plain("[city]", &lines.entries("[city]")?, LIMITS.city, min)?;
    let subs = subdivisions(code, &lines.entries("[subdivision]")?)?;
    if lines.peek() == Some("[postcode]") {
        let mut pairs = Vec::new();
        for l in lines.entries("[postcode]")? {
            let (c, p) = l
                .split_once('|')
                .ok_or_else(|| format!("[postcode] {l:?}"))?;
            if !subs.contains(c) || !postcode_ok(p) {
                return Err(format!("[postcode] {l:?}"));
            }
            pairs.push((c, p));
        }
        count("[postcode]", pairs.len(), 1, MAX_SUB_POSTCODES)?;
        ascending("[postcode]", &pairs)?;
    }
    match lines.peek() {
        None => Ok(()),
        Some(l) if l.starts_with("@country ") => Ok(()),
        Some(l) => Err(format!("unexpected line {l:?}")),
    }
}

/// The `[subdivision]` lines; returns the codes.
fn subdivisions<'a>(country: &str, lines: &[&'a str]) -> Result<BTreeSet<&'a str>, String> {
    let mut codes = Vec::new();
    let mut forms = BTreeSet::new();
    for l in lines {
        let (c, f) = l
            .split_once('|')
            .ok_or_else(|| format!("[subdivision] {l:?}"))?;
        let suffix = c
            .strip_prefix(country)
            .and_then(|s| s.strip_prefix('-'))
            .unwrap_or("");
        let code_ok = (1..=3).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
        if !code_ok || !display_ok(f) || !forms.insert(f) {
            return Err(format!("[subdivision] {l:?}"));
        }
        codes.push(c);
    }
    count("[subdivision]", codes.len(), 1, MAX_SUBDIVISIONS)?;
    ascending("[subdivision]", &codes)?;
    Ok(codes.into_iter().collect())
}

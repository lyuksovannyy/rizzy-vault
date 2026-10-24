// SPDX-License-Identifier: AGPL-3.0-only

//! The narrow Unicode CLDR reader of `cargo xtask identity-data` (ADR 0079 §6).
//!
//! It reads three kinds of element, each on one line, as CLDR's own files write them:
//!
//! - `<territory type="DE">Germany</territory>` in `common/main/en.xml` ([`territory_name`]);
//! - `<subgroup type="DE" contains="debb debe …"/>` in `common/supplemental/subdivisions.xml`
//!   ([`containment`]);
//! - `<subdivision type="deby" draft="…">Bayern</subdivision>` in
//!   `common/subdivisions/<lang>.xml` ([`subdivision_names`]).
//!
//! Elements with an `alt` attribute (variant names) are skipped. Text may use the five XML
//! entities; any other `&`, a nested tag, an attribute other than `type`, `draft`, `alt`
//! (and `contains` for `subgroup`) or a second unqualified element for the same `type` is
//! an error, never a guess.

use std::collections::BTreeMap;

/// One parsed element: its attributes and its text (empty for a self-closing element).
#[derive(Debug)]
struct Element {
    /// Attribute name and decoded value, in source order.
    attrs: Vec<(String, String)>,
    /// The decoded text content.
    text: String,
}

impl Element {
    /// The value of attribute `name`, if present.
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Decodes the five predefined XML entities.
///
/// # Errors
///
/// On any other `&` sequence or a raw `<`.
fn decode(s: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(['&', '<']) {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if rest.starts_with('<') {
            return Err(format!("markup inside text: {s:?}"));
        }
        let (rep, len) = [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&apos;", '\''),
        ]
        .iter()
        .find(|(e, _)| rest.starts_with(e))
        .map(|(e, c)| (*c, e.len()))
        .ok_or_else(|| format!("unknown entity in {s:?}"))?;
        out.push(rep);
        rest = &rest[len..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Finds every `<tag …>text</tag>` or `<tag …/>` element that starts a line (after
/// indentation), checking that its attributes are in `allowed`.
///
/// # Errors
///
/// When such an element is malformed or not on one line.
fn elements(src: &str, tag: &str, allowed: &[&str]) -> Result<Vec<Element>, String> {
    let open = format!("<{tag} ");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    for (n, line) in src.lines().enumerate() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(&open) else {
            continue;
        };
        let err = |m: &str| format!("line {}: <{tag}>: {m}", n + 1);
        let gt = rest.find('>').ok_or_else(|| err("no '>'"))?;
        let (head, self_closing) = match rest[..gt].strip_suffix('/') {
            Some(h) => (h, true),
            None => (&rest[..gt], false),
        };
        let mut attrs = Vec::new();
        let mut h = head.trim();
        while !h.is_empty() {
            let eq = h.find("=\"").ok_or_else(|| err("malformed attribute"))?;
            let name = h[..eq].trim().to_owned();
            if !allowed.contains(&name.as_str()) {
                return Err(err(&format!("unexpected attribute {name:?}")));
            }
            let after = &h[eq + 2..];
            let end = after
                .find('"')
                .ok_or_else(|| err("unterminated attribute"))?;
            if attrs.iter().any(|(k, _): &(String, String)| *k == name) {
                return Err(err("duplicate attribute"));
            }
            attrs.push((name, decode(&after[..end]).map_err(|e| err(&e))?));
            h = after[end + 1..].trim_start();
        }
        let tail = &rest[gt + 1..];
        let text = if self_closing {
            String::new()
        } else {
            let end = tail
                .find(&close)
                .ok_or_else(|| err("the element does not close on its line"))?;
            decode(&tail[..end]).map_err(|e| err(&e))?
        };
        out.push(Element { attrs, text });
    }
    Ok(out)
}

/// The English name of territory `code` (upper case) from `common/main/en.xml`: the element
/// without `alt`.
///
/// # Errors
///
/// When there is none, or more than one.
pub(super) fn territory_name(src: &str, code: &str) -> Result<String, String> {
    let mut found = Vec::new();
    for e in elements(src, "territory", &["type", "alt", "draft"])? {
        if e.attr("type") == Some(code) && e.attr("alt").is_none() {
            found.push(e.text);
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!("no territory name for {code}")),
        _ => Err(format!("more than one territory name for {code}")),
    }
}

/// The subdivision containment: group type (a country code such as `DE`, or a subdivision
/// such as `iec`) to its members, in source order.
///
/// # Errors
///
/// On a malformed element or a repeated group.
pub(super) fn containment(src: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut out = BTreeMap::new();
    for e in elements(src, "subgroup", &["type", "contains"])? {
        let group = e.attr("type").ok_or("subgroup without type")?.to_owned();
        let members: Vec<String> = e
            .attr("contains")
            .ok_or_else(|| format!("subgroup {group} without contains"))?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if out.insert(group.clone(), members).is_some() {
            return Err(format!("subgroup {group} appears twice"));
        }
    }
    Ok(out)
}

/// Subdivision names from a `common/subdivisions/<lang>.xml`: CLDR id (lower case, such as
/// `deby`) to name, skipping `alt` variants.
///
/// # Errors
///
/// On a malformed element or two unqualified names for one id.
pub(super) fn subdivision_names(src: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for e in elements(src, "subdivision", &["type", "draft", "alt"])? {
        if e.attr("alt").is_some() {
            continue;
        }
        let id = e.attr("type").ok_or("subdivision without type")?.to_owned();
        if out.insert(id.clone(), e.text).is_some() {
            return Err(format!("subdivision {id} has two names"));
        }
    }
    Ok(out)
}

/// The ISO 3166-2 code of CLDR subdivision id `id` in country `country`: `deby` → `DE-BY`.
///
/// # Errors
///
/// When `id` does not start with the country or its suffix is not 1–3 ASCII letters or
/// digits.
pub(super) fn iso_code(country: &str, id: &str) -> Result<String, String> {
    let lower = country.to_ascii_lowercase();
    let suffix = id
        .strip_prefix(&lower)
        .ok_or_else(|| format!("subdivision {id} is not in {country}"))?;
    if suffix.is_empty()
        || suffix.len() > 3
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(format!("subdivision {id}: unexpected code shape"));
    }
    Ok(format!("{country}-{}", suffix.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::{containment, iso_code, subdivision_names, territory_name};

    const MAIN: &str = r#"<ldml>
			<territory type="DE">Germany</territory>
			<territory type="GB">United Kingdom</territory>
			<territory type="GB" alt="short">UK</territory>
			<territory type="BA">Bosnia &amp; Herzegovina</territory>
</ldml>"#;

    #[test]
    fn reads_territory_names_without_alt() {
        assert_eq!(territory_name(MAIN, "GB").unwrap(), "United Kingdom");
        assert_eq!(territory_name(MAIN, "BA").unwrap(), "Bosnia & Herzegovina");
        assert!(territory_name(MAIN, "FR").is_err());
        let twice = MAIN.replace(
            "</ldml>",
            "<territory type=\"DE\">Deutschland</territory>\n</ldml>",
        );
        assert!(territory_name(&twice, "DE").is_err());
    }

    #[test]
    fn reads_containment_and_names() {
        let sup = "\t\t<subgroup type=\"IE\" contains=\"iec iel\"/>\n\t\t<subgroup type=\"iec\" \
                   contains=\"ieg iemo\"/>\n";
        let c = containment(sup).unwrap();
        assert_eq!(c["IE"], vec!["iec", "iel"]);
        assert_eq!(c["iec"], vec!["ieg", "iemo"]);
        assert!(containment(&format!("{sup}{sup}")).is_err());
        let names = "\t\t\t<subdivision type=\"deby\">Bayern</subdivision>\n\t\t\t<subdivision \
                     type=\"chsg\" draft=\"contributed\">St. Gallen</subdivision> <!-- x -->\n\t\t\t\
                     <subdivision type=\"deby\" alt=\"variant\">Bavaria</subdivision>\n";
        let n = subdivision_names(names).unwrap();
        assert_eq!(n["deby"], "Bayern");
        assert_eq!(n["chsg"], "St. Gallen");
    }

    #[test]
    fn rejects_malformed_elements() {
        assert!(subdivision_names("<subdivision type=\"x\" foo=\"1\">a</subdivision>").is_err());
        assert!(subdivision_names("<subdivision type=\"x\">a &nbsp; b</subdivision>").is_err());
        assert!(subdivision_names("<subdivision type=\"x\">a <b>c</b></subdivision>").is_err());
        assert!(subdivision_names("<subdivision type=\"x\">open\n</subdivision>").is_err());
        assert!(
            subdivision_names(
                "<subdivision type=\"x\">a</subdivision>\n<subdivision type=\"x\">b</subdivision>"
            )
            .is_err()
        );
    }

    #[test]
    fn maps_iso_codes() {
        assert_eq!(iso_code("DE", "deby").unwrap(), "DE-BY");
        assert_eq!(iso_code("FR", "fr20r").unwrap(), "FR-20R");
        assert_eq!(iso_code("AT", "at1").unwrap(), "AT-1");
        assert!(iso_code("DE", "atby").is_err());
        assert!(iso_code("DE", "de").is_err());
        assert!(iso_code("DE", "debyxx").is_err());
    }
}

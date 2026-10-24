// SPDX-License-Identifier: AGPL-3.0-only

//! Icon discovery in a page ([ADR 0052] point 3): a bounded substring scan for
//! `<link rel="icon">` and `<link rel="shortcut icon">`, not an HTML parser, to keep the
//! attack surface small.
//!
//! - **Bounds.** Only the first [`MAX_HTML_SCAN`] bytes are read (the caller reads no more
//!   from the network either). At most [`MAX_LINK_TAGS`] `<link` tags are looked at, each at
//!   most [`MAX_TAG_LEN`] bytes up to its `>` and at most [`MAX_ATTRIBUTES`] attributes; a
//!   tag past a bound ends the scan. At most [`MAX_CANDIDATES`] `href`s are returned, each
//!   at most [`crate::target::MAX_REFERENCE_LEN`] bytes. Every loop advances, so the scan is
//!   linear in its input.
//! - **What counts.** A `<link` tag (tag name case-insensitive) whose `rel` has the token
//!   `icon` (so `icon` and `shortcut icon`, but not `apple-touch-icon` or `mask-icon`), with a
//!   non-empty `href`. A candidate whose `type` names SVG, or whose `href` path ends in
//!   `.svg`, is skipped: SVG is never fetched or served (INV-51). Comments (`<!-- … -->`)
//!   are skipped.
//! - **Attribute values** are double-quoted, single-quoted or unquoted. In an `href`, the
//!   character references `&amp;`, `&#38;` and `&#x26;` read as `&`; any other byte is left
//!   as written, and a value that is not ASCII is skipped (the resolver would refuse it).
//! - **The result is untrusted.** The caller resolves each `href` against the page request
//!   ([`crate::target::Target::resolve`]), and every fetch it leads to goes through the
//!   allow-list again.
//!
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md

use crate::target::MAX_REFERENCE_LEN;

/// The most of a page that is scanned, in bytes (ADR 0052 point 3: 64 KiB).
pub const MAX_HTML_SCAN: usize = 64 * 1024;

/// The most `<link` tags looked at.
pub const MAX_LINK_TAGS: usize = 64;

/// The longest `<link` tag, in bytes, from `<` to `>`.
pub const MAX_TAG_LEN: usize = 4096;

/// The most attributes read from one tag.
pub const MAX_ATTRIBUTES: usize = 32;

/// The most candidate `href`s returned.
pub const MAX_CANDIDATES: usize = 4;

/// The attributes of one tag that matter here.
#[derive(Default)]
struct LinkAttributes<'a> {
    /// `rel`.
    rel: Option<&'a [u8]>,
    /// `href`.
    href: Option<&'a [u8]>,
    /// `type`.
    kind: Option<&'a [u8]>,
}

/// The position of `needle` in `haystack` at or after `from`.
fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let rest = haystack.get(from..)?;
    rest.windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

/// Whether `haystack` at `at` starts with `prefix`, ASCII case-insensitively.
fn starts_with_ci(haystack: &[u8], at: usize, prefix: &[u8]) -> bool {
    haystack
        .get(at..at.saturating_add(prefix.len()))
        .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
}

/// The `href`s of icon links in `html`, in document order (module docs).
#[must_use]
pub fn icon_hrefs(html: &[u8]) -> Vec<String> {
    let html = html.get(..MAX_HTML_SCAN).unwrap_or(html);
    let mut out = Vec::new();
    let mut tags = 0usize;
    let mut at = 0usize;
    while let Some(open) = html
        .get(at..)
        .and_then(|s| s.iter().position(|b| *b == b'<'))
    {
        let open = open + at;
        if starts_with_ci(html, open, b"<!--") {
            match find(html, b"-->", open + 4) {
                Some(end) => {
                    at = end + 3;
                    continue;
                }
                None => break,
            }
        }
        let is_link = starts_with_ci(html, open, b"<link")
            && html
                .get(open + 5)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'/' || *b == b'>');
        if !is_link {
            at = open + 1;
            continue;
        }
        tags += 1;
        if tags > MAX_LINK_TAGS {
            break;
        }
        let Some((attributes, end)) = parse_tag(html, open + 5) else {
            break;
        };
        at = end;
        if let Some(href) = candidate(&attributes) {
            out.push(href);
            if out.len() >= MAX_CANDIDATES {
                break;
            }
        }
    }
    out
}

/// Reads the attributes of a tag from `start` (just after the tag name) to its `>`. Returns
/// them and the index after the `>`, or `None` when the tag passes a bound or never ends.
fn parse_tag(html: &[u8], start: usize) -> Option<(LinkAttributes<'_>, usize)> {
    let limit = start.saturating_add(MAX_TAG_LEN).min(html.len());
    let tag = html.get(..limit)?;
    let mut attributes = LinkAttributes::default();
    let mut i = start;
    let mut count = 0usize;
    loop {
        while tag
            .get(i)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'/')
        {
            i += 1;
        }
        match tag.get(i) {
            None => return None,
            Some(b'>') => return Some((attributes, i + 1)),
            Some(_) => {}
        }
        count += 1;
        if count > MAX_ATTRIBUTES {
            return None;
        }
        let name_start = i;
        while tag
            .get(i)
            .is_some_and(|b| !b.is_ascii_whitespace() && !matches!(b, b'=' | b'>' | b'/'))
        {
            i += 1;
        }
        let name = tag.get(name_start..i)?;
        while tag.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        let mut value: &[u8] = b"";
        if tag.get(i) == Some(&b'=') {
            i += 1;
            while tag.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            match tag.get(i) {
                Some(quote @ (b'"' | b'\'')) => {
                    let close = tag.get(i + 1..)?.iter().position(|b| b == quote)?;
                    value = tag.get(i + 1..i + 1 + close)?;
                    i = i + 2 + close;
                }
                Some(_) => {
                    let value_start = i;
                    while tag
                        .get(i)
                        .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'>')
                    {
                        i += 1;
                    }
                    value = tag.get(value_start..i)?;
                }
                None => return None,
            }
        }
        if name.eq_ignore_ascii_case(b"rel") {
            attributes.rel.get_or_insert(value);
        } else if name.eq_ignore_ascii_case(b"href") {
            attributes.href.get_or_insert(value);
        } else if name.eq_ignore_ascii_case(b"type") {
            attributes.kind.get_or_insert(value);
        }
    }
}

/// The `href` of an icon link, if `attributes` describe one that is not SVG.
fn candidate(attributes: &LinkAttributes<'_>) -> Option<String> {
    let rel = attributes.rel?;
    if !rel
        .split(u8::is_ascii_whitespace)
        .any(|token| token.eq_ignore_ascii_case(b"icon"))
    {
        return None;
    }
    if attributes
        .kind
        .is_some_and(|t| t.to_ascii_lowercase().windows(3).any(|w| w == b"svg"))
    {
        return None;
    }
    let href = decode_ampersands(attributes.href?)?;
    let trimmed = href.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() || trimmed.len() > MAX_REFERENCE_LEN {
        return None;
    }
    let path_end = trimmed.find(['?', '#']).unwrap_or(trimmed.len());
    let path = trimmed.get(..path_end).unwrap_or(trimmed);
    if path.to_ascii_lowercase().ends_with(".svg") {
        return None;
    }
    Some(trimmed.to_owned())
}

/// `value` as ASCII text with `&amp;`, `&#38;` and `&#x26;` read as `&`; `None` unless ASCII.
fn decode_ampersands(value: &[u8]) -> Option<String> {
    if value.len() > MAX_REFERENCE_LEN.saturating_mul(2) || !value.is_ascii() {
        return None;
    }
    let text = core::str::from_utf8(value).ok()?;
    Some(
        text.replace("&amp;", "&")
            .replace("&#38;", "&")
            .replace("&#x26;", "&"),
    )
}

#[cfg(test)]
mod tests {
    //! Discovery rules and bounds.

    use super::*;

    #[test]
    fn finds_icon_and_shortcut_icon_in_order() {
        let html = br#"<!doctype html><html><head>
            <meta charset=utf-8>
            <link rel="stylesheet" href="/s.css">
            <LINK REL="Shortcut Icon" HREF="/favicon.ico">
            <link href='/i.png?a=1&amp;b=2' rel=icon type="image/png" sizes="32x32"/>
            <link rel="apple-touch-icon" href="/apple.png">
            <link rel="mask-icon" href="/mask.png">
            </head>"#;
        assert_eq!(icon_hrefs(html), vec!["/favicon.ico", "/i.png?a=1&b=2"]);
    }

    #[test]
    fn skips_svg_comments_and_empty_hrefs() {
        let html = br#"
            <!-- <link rel="icon" href="/commented.png"> -->
            <link rel="icon" type="image/svg+xml" href="/a">
            <link rel="icon" href="/b.SVG?v=3">
            <link rel="icon" href="">
            <link rel="icon">
            <link rel=icon href=/c.png>"#;
        assert_eq!(icon_hrefs(html), vec!["/c.png"]);
        let non_ascii = b"<link rel=icon href=\"/caf\xc3\xa9.png\"><link rel=icon href=/d.png>";
        assert_eq!(icon_hrefs(non_ascii), vec!["/d.png"]);
    }

    #[test]
    fn not_a_link_tag() {
        assert!(icon_hrefs(br"<linkx rel=icon href=/a.png>").is_empty());
        assert!(icon_hrefs(br"<a rel=icon href=/a.png>").is_empty());
        assert_eq!(icon_hrefs(br"<link/rel=icon href=/a.png>"), vec!["/a.png"]);
        assert!(icon_hrefs(b"").is_empty());
        assert!(icon_hrefs(b"<").is_empty());
        assert!(icon_hrefs(b"<link").is_empty());
        assert!(icon_hrefs(b"<link rel=\"icon href=/x>").is_empty());
        assert!(icon_hrefs(b"<!-- unterminated <link rel=icon href=/a>").is_empty());
    }

    #[test]
    fn only_the_first_64_kib_is_scanned() {
        let mut html = vec![b' '; MAX_HTML_SCAN - 10];
        html.extend_from_slice(br"<link rel=icon href=/late.png>");
        assert!(icon_hrefs(&html).is_empty());
        let mut html = vec![b' '; MAX_HTML_SCAN - 40];
        html.extend_from_slice(br"<link rel=icon href=/in.png>");
        assert_eq!(icon_hrefs(&html), vec!["/in.png"]);
    }

    #[test]
    fn tag_and_attribute_bounds_end_the_scan() {
        let long = format!(
            "<link rel=icon data-x=\"{}\" href=/a.png><link rel=icon href=/b.png>",
            "x".repeat(MAX_TAG_LEN)
        );
        assert!(icon_hrefs(long.as_bytes()).is_empty());
        let many = format!(
            "<link {} rel=icon href=/a.png>",
            "a=1 ".repeat(MAX_ATTRIBUTES)
        );
        assert!(icon_hrefs(many.as_bytes()).is_empty());
        let tags = "<link rel=stylesheet href=/s.css>".repeat(MAX_LINK_TAGS);
        let html = format!("{tags}<link rel=icon href=/a.png>");
        assert!(icon_hrefs(html.as_bytes()).is_empty());
        let icons = "<link rel=icon href=/a.png>".repeat(10);
        assert_eq!(icon_hrefs(icons.as_bytes()).len(), MAX_CANDIDATES);
        let href = format!("<link rel=icon href=/{}>", "a".repeat(MAX_REFERENCE_LEN));
        assert!(icon_hrefs(href.as_bytes()).is_empty());
    }

    #[test]
    fn first_attribute_wins() {
        let html = br"<link rel=icon href=/one.png href=/two.png rel=stylesheet>";
        assert_eq!(icon_hrefs(html), vec!["/one.png"]);
    }

    #[test]
    fn hostile_inputs_do_not_panic() {
        let mut inputs: Vec<Vec<u8>> = vec![
            vec![b'<'; 100_000],
            b"<link ".repeat(20_000),
            b"<link rel='".repeat(10_000),
            b"<!--".repeat(30_000),
            vec![0xff; 70_000],
        ];
        inputs.push(b"<link rel=icon href=\"".to_vec());
        for input in inputs {
            let _ = icon_hrefs(&input);
        }
    }
}

//! A bounded, non-validating XML reader into a tree of zeroizing strings, for the `KeePass` XML
//! export.
//!
//! **What it reads.** An optional XML declaration (whose `encoding`, if present, must be
//! UTF-8), comments, processing instructions (skipped), one root element with attributes,
//! child elements, text and CDATA sections. Text and attribute values have the five predefined
//! entities (`&lt;` `&gt;` `&amp;` `&quot;` `&apos;`) and character references (`&#…;`,
//! `&#x…;`) replaced, and line breaks normalised to `\n` (XML 1.0 §2.11); attribute values
//! also have tabs and line breaks turned into spaces (§3.3.3). Names are taken literally:
//! there is no namespace processing.
//!
//! **What it refuses** (threat model A16: "do not expand XML entities"). A document type
//! declaration, whatever it holds, is [`ImportError::Doctype`], so no entity can be defined,
//! and an entity reference other than the five predefined ones is malformed. There is no
//! external resource of any kind, and no I/O.
//!
//! **Bounds.** The input cap is the caller's; elements nest at most [`MAX_DEPTH`] deep, and
//! elements, attributes and text nodes together count against [`MAX_NODES`]. An element has at
//! most [`MAX_XML_ATTRIBUTES`] attributes, so the duplicate check stays linear in the input.
//! The reader is iterative, so a deep document cannot exhaust the stack, and never panics.
//! Every name, value and text is copied once into a zeroizing buffer sized to its raw text
//! (CRYPTO.md §12.2); whitespace-only text beside child elements is dropped when the element
//! closes.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::limits::{MAX_DEPTH, MAX_NODES, MAX_XML_ATTRIBUTES};
use crate::text;

/// An element: its name, attributes and children. `Debug` prints no content.
pub struct Element {
    /// The element's name, as written (prefix included).
    name: Zeroizing<String>,
    /// Attributes, in source order; names are unique.
    attributes: Vec<(Zeroizing<String>, Zeroizing<String>)>,
    /// Child elements and text, in source order.
    children: Vec<Node>,
}

/// A child of an element.
pub enum Node {
    /// A child element.
    Element(Element),
    /// Text or a CDATA section, with references replaced.
    Text(Zeroizing<String>),
}

impl fmt::Debug for Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Element([REDACTED])")
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Node([REDACTED])")
    }
}

impl Element {
    /// The element's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The value of the attribute `name`, if present.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, v)| v.as_str())
    }

    /// The child elements, in order.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|c| match c {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    /// The child elements named `name`, in order.
    pub fn elements_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.elements().filter(move |e| e.name() == name)
    }

    /// The first child element named `name`.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.name() == name)
    }

    /// The element's own text: its text children joined, in a zeroizing buffer allocated at
    /// the final size.
    #[must_use]
    pub fn text(&self) -> Zeroizing<String> {
        let texts = || {
            self.children.iter().filter_map(|c| match c {
                Node::Text(t) => Some(t.as_str()),
                Node::Element(_) => None,
            })
        };
        let len = texts().map(str::len).fold(0usize, usize::saturating_add);
        let mut out = text::with_capacity(len);
        for t in texts() {
            out.push_str(t);
        }
        out
    }
}

/// Parses one XML document and returns its root element.
///
/// # Errors
/// [`ImportError::TooLarge`] over `max_len`, [`ImportError::Encoding`] if it is not UTF-8 or
/// declares another encoding, [`ImportError::Doctype`] for a document type declaration,
/// [`ImportError::Malformed`] on a syntax error, [`ImportError::TooDeep`] and
/// [`ImportError::TooMany`] past the caps.
pub fn parse(input: &[u8], max_len: usize) -> Result<Element, ImportError> {
    let src = text::utf8_input(input, max_len)?;
    let mut parser = Parser {
        src,
        bytes: src.as_bytes(),
        pos: 0,
        nodes: 0,
    };
    parser.declaration()?;
    parser.document()
}

/// The reader's state: the source and a cursor into it.
struct Parser<'a> {
    /// The document, known to be UTF-8.
    src: &'a str,
    /// The same bytes.
    bytes: &'a [u8],
    /// The next byte to read.
    pos: usize,
    /// Elements, attributes and text nodes so far.
    nodes: usize,
}

/// XML whitespace (§2.3 `S`).
const fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Bytes that end a name.
const fn ends_name(b: u8) -> bool {
    is_ws(b)
        || matches!(
            b,
            b'/' | b'>' | b'=' | b'<' | b'"' | b'\'' | b'&' | b'?' | b'!'
        )
}

impl<'a> Parser<'a> {
    /// `true` if the input continues with `prefix`.
    fn at(&self, prefix: &[u8]) -> bool {
        self.bytes
            .get(self.pos..)
            .is_some_and(|rest| rest.starts_with(prefix))
    }

    /// The byte at the cursor.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Skips whitespace.
    fn skip_ws(&mut self) {
        while self.peek().is_some_and(is_ws) {
            self.pos += 1;
        }
    }

    /// Counts one node against [`MAX_NODES`].
    fn count(&mut self) -> Result<(), ImportError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            Err(ImportError::TooMany)
        } else {
            Ok(())
        }
    }

    /// Moves the cursor past the next `terminator`, returning the text before it.
    fn until(&mut self, terminator: &str) -> Result<&'a str, ImportError> {
        let rest = self.src.get(self.pos..).ok_or(ImportError::Malformed)?;
        let end = rest.find(terminator).ok_or(ImportError::Malformed)?;
        let body = rest.get(..end).ok_or(ImportError::Malformed)?;
        self.pos += end + terminator.len();
        Ok(body)
    }

    /// The optional XML declaration at the very start. Its `encoding`, if given, must be
    /// UTF-8 (any case, with or without the hyphen).
    fn declaration(&mut self) -> Result<(), ImportError> {
        if !(self.at(b"<?xml") && self.bytes.get(self.pos + 5).is_some_and(|b| is_ws(*b))) {
            return Ok(());
        }
        self.pos += 5;
        let body = self.until("?>")?;
        if let Some(at) = body.find("encoding") {
            let after = body.get(at + "encoding".len()..).unwrap_or_default();
            let after = after
                .trim_start()
                .strip_prefix('=')
                .ok_or(ImportError::Malformed)?;
            let after = after.trim_start();
            let quote = after.chars().next().ok_or(ImportError::Malformed)?;
            if quote != '"' && quote != '\'' {
                return Err(ImportError::Malformed);
            }
            let value = after.get(1..).unwrap_or_default();
            let end = value.find(quote).ok_or(ImportError::Malformed)?;
            let name = value.get(..end).unwrap_or_default();
            if !(name.eq_ignore_ascii_case("utf-8") || name.eq_ignore_ascii_case("utf8")) {
                return Err(ImportError::Encoding);
            }
        }
        Ok(())
    }

    /// Skips comments, processing instructions and whitespace outside the root element.
    /// Refuses a document type declaration.
    fn misc(&mut self) -> Result<(), ImportError> {
        loop {
            self.skip_ws();
            if self.at(b"<!--") {
                self.pos += 4;
                self.until("-->")?;
            } else if self.at(b"<?") {
                self.pos += 2;
                self.until("?>")?;
            } else if self.at(b"<!DOCTYPE") || self.at(b"<!doctype") {
                return Err(ImportError::Doctype);
            } else {
                return Ok(());
            }
        }
    }

    /// The whole document after the declaration.
    fn document(&mut self) -> Result<Element, ImportError> {
        self.misc()?;
        if self.peek() != Some(b'<') {
            return Err(ImportError::Malformed);
        }
        // Open elements, innermost last.
        let mut stack: Vec<Element> = Vec::new();
        loop {
            if self.at(b"<!--") {
                self.pos += 4;
                self.until("-->")?;
            } else if self.at(b"<![CDATA[") {
                self.pos += 9;
                let raw = self.until("]]>")?;
                let text = normalized(raw, false);
                self.count()?;
                stack
                    .last_mut()
                    .ok_or(ImportError::Malformed)?
                    .children
                    .push(Node::Text(text));
            } else if self.at(b"<!") {
                return Err(if self.at(b"<!DOCTYPE") || self.at(b"<!doctype") {
                    ImportError::Doctype
                } else {
                    ImportError::Malformed
                });
            } else if self.at(b"<?") {
                self.pos += 2;
                self.until("?>")?;
            } else if self.at(b"</") {
                self.pos += 2;
                let name = self.name()?;
                self.skip_ws();
                if self.peek() != Some(b'>') {
                    return Err(ImportError::Malformed);
                }
                self.pos += 1;
                let mut done = stack.pop().ok_or(ImportError::Malformed)?;
                if done.name.as_str() != name {
                    return Err(ImportError::Malformed);
                }
                finish(&mut done);
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(done)),
                    None => return self.end(done),
                }
            } else if self.peek() == Some(b'<') {
                self.pos += 1;
                let (element, empty) = self.start_tag()?;
                if empty {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(Node::Element(element)),
                        None => return self.end(element),
                    }
                } else {
                    if stack.len() >= MAX_DEPTH {
                        return Err(ImportError::TooDeep);
                    }
                    stack.push(element);
                }
            } else if self.pos >= self.bytes.len() {
                return Err(ImportError::Malformed);
            } else {
                let rest = self.src.get(self.pos..).ok_or(ImportError::Malformed)?;
                let end = rest.find('<').unwrap_or(rest.len());
                let raw = rest.get(..end).ok_or(ImportError::Malformed)?;
                self.pos += end;
                let text = decode(raw, false)?;
                self.count()?;
                stack
                    .last_mut()
                    .ok_or(ImportError::Malformed)?
                    .children
                    .push(Node::Text(text));
            }
        }
    }

    /// After the root element: only comments, processing instructions and whitespace.
    fn end(&mut self, root: Element) -> Result<Element, ImportError> {
        self.misc()?;
        if self.pos == self.bytes.len() {
            Ok(root)
        } else {
            Err(ImportError::Malformed)
        }
    }

    /// Reads a name.
    fn name(&mut self) -> Result<&'a str, ImportError> {
        let start = self.pos;
        match self.peek() {
            Some(b) if !ends_name(b) && !b.is_ascii_digit() && b != b'-' && b != b'.' => {}
            _ => return Err(ImportError::Malformed),
        }
        while self.peek().is_some_and(|b| !ends_name(b)) {
            self.pos += 1;
        }
        // The name ends before an ASCII byte or at the end, so on a character boundary.
        self.src.get(start..self.pos).ok_or(ImportError::Malformed)
    }

    /// Reads a start tag after its `<`. Returns the element and whether it was empty (`/>`).
    fn start_tag(&mut self) -> Result<(Element, bool), ImportError> {
        self.count()?;
        let name = text::copy(self.name()?);
        let mut element = Element {
            name,
            attributes: Vec::new(),
            children: Vec::new(),
        };
        loop {
            let before = self.pos;
            self.skip_ws();
            match self.peek() {
                Some(b'>') => {
                    self.pos += 1;
                    return Ok((element, false));
                }
                Some(b'/') => {
                    self.pos += 1;
                    if self.peek() != Some(b'>') {
                        return Err(ImportError::Malformed);
                    }
                    self.pos += 1;
                    return Ok((element, true));
                }
                // An attribute must follow whitespace.
                Some(_) if self.pos > before => {
                    self.count()?;
                    if element.attributes.len() >= MAX_XML_ATTRIBUTES {
                        return Err(ImportError::TooMany);
                    }
                    let (attr, value) = self.attribute()?;
                    if element.attribute(&attr).is_some() {
                        return Err(ImportError::Malformed);
                    }
                    element.attributes.push((attr, value));
                }
                _ => return Err(ImportError::Malformed),
            }
        }
    }

    /// Reads `name = "value"` or `name = 'value'`.
    fn attribute(&mut self) -> Result<(Zeroizing<String>, Zeroizing<String>), ImportError> {
        let name = text::copy(self.name()?);
        self.skip_ws();
        if self.peek() != Some(b'=') {
            return Err(ImportError::Malformed);
        }
        self.pos += 1;
        self.skip_ws();
        let quote = match self.peek() {
            Some(q @ (b'"' | b'\'')) => char::from(q),
            _ => return Err(ImportError::Malformed),
        };
        self.pos += 1;
        let rest = self.src.get(self.pos..).ok_or(ImportError::Malformed)?;
        let end = rest.find(quote).ok_or(ImportError::Malformed)?;
        let raw = rest.get(..end).ok_or(ImportError::Malformed)?;
        if raw.contains('<') {
            return Err(ImportError::Malformed);
        }
        self.pos += end + 1;
        Ok((name, decode(raw, true)?))
    }
}

/// On closing an element that has child elements, drops its whitespace-only text: that is
/// indentation, not content. An element with no child element keeps its text as it is, so a
/// password of spaces survives.
fn finish(element: &mut Element) {
    if element
        .children
        .iter()
        .any(|c| matches!(c, Node::Element(_)))
    {
        element.children.retain(|c| match c {
            Node::Text(t) => !t.bytes().all(is_ws),
            Node::Element(_) => true,
        });
    }
}

/// CDATA content: line breaks normalised, nothing else replaced.
fn normalized(raw: &str, attribute: bool) -> Zeroizing<String> {
    let mut out = text::with_capacity(raw.len());
    push_normalized(&mut out, raw, attribute);
    out
}

/// Appends `raw` with `\r\n` and lone `\r` turned into `\n` (or, in an attribute value, every
/// tab and line break into a space).
fn push_normalized(out: &mut String, raw: &str, attribute: bool) {
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(if attribute { ' ' } else { '\n' });
            }
            '\n' | '\t' if attribute => out.push(' '),
            _ => out.push(c),
        }
    }
}

/// Text or an attribute value: references replaced, line breaks normalised. The result is
/// never longer than `raw`, so the buffer is allocated once.
fn decode(raw: &str, attribute: bool) -> Result<Zeroizing<String>, ImportError> {
    if !attribute && raw.contains("]]>") {
        return Err(ImportError::Malformed);
    }
    let mut out = text::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        push_normalized(&mut out, rest.get(..amp).unwrap_or_default(), attribute);
        let after = rest.get(amp + 1..).unwrap_or_default();
        let semi = after.find(';').ok_or(ImportError::Malformed)?;
        let reference = after.get(..semi).unwrap_or_default();
        out.push(resolve(reference)?);
        rest = after.get(semi + 1..).unwrap_or_default();
    }
    push_normalized(&mut out, rest, attribute);
    Ok(out)
}

/// The character a reference (between `&` and `;`) stands for. Only the five predefined
/// entities and character references exist here; everything else is malformed.
fn resolve(reference: &str) -> Result<char, ImportError> {
    let code = match reference {
        "lt" => return Ok('<'),
        "gt" => return Ok('>'),
        "amp" => return Ok('&'),
        "quot" => return Ok('"'),
        "apos" => return Ok('\''),
        _ => {
            if let Some(hex) = reference.strip_prefix("#x") {
                number(hex, 16)?
            } else if let Some(dec) = reference.strip_prefix('#') {
                number(dec, 10)?
            } else {
                return Err(ImportError::Malformed);
            }
        }
    };
    // XML 1.0 `Char`: no NUL; `char::from_u32` refuses surrogates and values past U+10FFFF.
    if code == 0 {
        return Err(ImportError::Malformed);
    }
    char::from_u32(code).ok_or(ImportError::Malformed)
}

/// A character reference's number, in `radix`, of at most 8 digits.
fn number(digits: &str, radix: u32) -> Result<u32, ImportError> {
    if digits.is_empty() || digits.len() > 8 {
        return Err(ImportError::Malformed);
    }
    let mut value = 0u32;
    for c in digits.chars() {
        let d = c.to_digit(radix).ok_or(ImportError::Malformed)?;
        value = value
            .checked_mul(radix)
            .and_then(|v| v.checked_add(d))
            .ok_or(ImportError::Malformed)?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses with a generous cap.
    fn p(s: &str) -> Result<Element, ImportError> {
        parse(s.as_bytes(), 1 << 20)
    }

    #[test]
    fn tree() {
        let doc = p("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- c -->\n<a x='1' y=\"&lt;2&gt;\">\n  <b>t&amp;u&#65;&#x42;</b>\n  <c/>\n  <b><![CDATA[<raw>&amp;]]></b>\n  <?pi x?>\n  <d> </d>\r\n</a>\n<!-- after -->\n").unwrap();
        assert_eq!(doc.name(), "a");
        assert_eq!(doc.attribute("x"), Some("1"));
        assert_eq!(doc.attribute("y"), Some("<2>"));
        assert_eq!(doc.attribute("z"), None);
        let bs: Vec<_> = doc
            .elements_named("b")
            .map(|b| b.text().to_string())
            .collect();
        assert_eq!(bs, vec!["t&uAB", "<raw>&amp;"]);
        assert!(doc.child("c").is_some());
        assert_eq!(doc.child("d").unwrap().text().as_str(), " ");
        // Indentation between children is dropped.
        assert_eq!(doc.text().as_str(), "");
        assert_eq!(doc.elements().count(), 4);
    }

    #[test]
    fn line_breaks() {
        let doc = p("<a v=\"1\r\n2\t3\">x\r\ny\rz</a>").unwrap();
        assert_eq!(doc.text().as_str(), "x\ny\nz");
        assert_eq!(doc.attribute("v"), Some("1 2 3"));
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "text",
            "<a>",
            "<a></b>",
            "<a></a><b></b>",
            "<a></a>text",
            "<a x=1></a>",
            "<a x='1' x='2'></a>",
            "<a x='<'></a>",
            "<a>&unknown;</a>",
            "<a>&#0;</a>",
            "<a>&#xD800;</a>",
            "<a>&#x110000;</a>",
            "<a>&amp</a>",
            "<a>]]></a>",
            "<1a></1a>",
            "<a x='1'y='2'></a>",
            "<a><!ELEMENT a ANY></a>",
            "<a/ >",
        ] {
            assert_eq!(p(bad).unwrap_err(), ImportError::Malformed, "{bad:?}");
        }
    }

    #[test]
    fn doctype_is_refused() {
        let bomb = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;\">]><a>&lol2;</a>";
        assert_eq!(p(bomb).unwrap_err(), ImportError::Doctype);
        assert_eq!(
            p("<!DOCTYPE a SYSTEM \"file:///etc/passwd\"><a/>").unwrap_err(),
            ImportError::Doctype
        );
    }

    #[test]
    fn encoding() {
        assert_eq!(
            p("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>").unwrap_err(),
            ImportError::Encoding
        );
        assert!(p("<?xml version='1.0' encoding='utf-8' standalone='yes'?><a/>").is_ok());
        assert_eq!(
            parse(b"<a>\xff</a>", 100).unwrap_err(),
            ImportError::Encoding
        );
    }

    #[test]
    fn depth_cap() {
        let ok = format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(p(&ok).is_ok());
        let deep = format!(
            "{}{}",
            "<a>".repeat(MAX_DEPTH + 1),
            "</a>".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(p(&deep).unwrap_err(), ImportError::TooDeep);
    }

    #[test]
    fn attribute_cap() {
        let attrs = |n: usize| {
            let mut out = String::new();
            for i in 0..n {
                out.push_str(" a");
                out.push_str(&i.to_string());
                out.push_str("=\"\"");
            }
            out
        };
        assert!(p(&format!("<a{}/>", attrs(MAX_XML_ATTRIBUTES))).is_ok());
        assert_eq!(
            p(&format!("<a{}/>", attrs(MAX_XML_ATTRIBUTES + 1))).unwrap_err(),
            ImportError::TooMany
        );
    }

    #[test]
    fn debug_is_redacted() {
        let doc = p("<Value>hunter2</Value>").unwrap();
        assert!(!format!("{doc:?}").contains("hunter2"));
    }
}

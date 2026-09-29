//! A bounded CSV reader (RFC 4180, comma-separated), one record at a time, into zeroizing
//! fields. For the generic, Chrome and Firefox CSV importers.
//!
//! **Dialect.** Fields are separated by `,`. Records end at `\r\n`, `\n` or a lone `\r`, or at
//! the end of the input. A field that starts with `"` is quoted: it runs to the next `"` not
//! doubled, may hold separators and line breaks, and `""` inside it is one `"`; after its
//! closing quote comes a separator, a line break or the end, or the input is malformed. A `"`
//! inside an unquoted field is kept as it is (some hand-made CSV files have them).
//!
//! **Bounds** (threat model A16): the input cap is the caller's; a record may have at most
//! [`MAX_CSV_COLUMNS`] fields, and the reader stops with [`ImportError::TooMany`] after
//! [`MAX_ENTRIES`] records plus the header. Each field is copied once into a zeroizing buffer
//! sized to its raw text (CRYPTO.md §12.2). The reader never panics.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::limits::{MAX_CSV_COLUMNS, MAX_ENTRIES};
use crate::text;

/// One record: its fields, in order.
pub type Record = Vec<Zeroizing<String>>;

/// Reads records from a CSV document. `Debug` prints the position only, never the document.
pub struct Reader<'a> {
    /// The document, known to be UTF-8.
    src: &'a str,
    /// The next byte to read.
    pos: usize,
    /// Records returned so far.
    records: usize,
}

impl fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader")
            .field("pos", &self.pos)
            .field("records", &self.records)
            .finish_non_exhaustive()
    }
}

impl<'a> Reader<'a> {
    /// Starts reading `input`: checks `max_len`, drops a byte-order mark, checks UTF-8.
    ///
    /// # Errors
    /// [`ImportError::TooLarge`] or [`ImportError::Encoding`].
    pub fn new(input: &'a [u8], max_len: usize) -> Result<Self, ImportError> {
        Ok(Self {
            src: text::utf8_input(input, max_len)?,
            pos: 0,
            records: 0,
        })
    }

    /// The next record, or `None` at the end of the input. An empty line is a record of one
    /// empty field.
    ///
    /// # Errors
    /// [`ImportError::Malformed`] for a quoted field that is not closed, or followed by
    /// anything but a separator or line break; [`ImportError::TooMany`] past the column or
    /// record caps.
    pub fn next_record(&mut self) -> Result<Option<Record>, ImportError> {
        let bytes = self.src.as_bytes();
        if self.pos >= bytes.len() {
            return Ok(None);
        }
        self.records += 1;
        if self.records > MAX_ENTRIES + 1 {
            return Err(ImportError::TooMany);
        }
        let mut record = Vec::new();
        loop {
            if record.len() >= MAX_CSV_COLUMNS {
                return Err(ImportError::TooMany);
            }
            let field = if bytes.get(self.pos) == Some(&b'"') {
                self.quoted()?
            } else {
                self.unquoted()?
            };
            record.push(field);
            match bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'\r') => {
                    self.pos += 1;
                    if bytes.get(self.pos) == Some(&b'\n') {
                        self.pos += 1;
                    }
                    return Ok(Some(record));
                }
                Some(b'\n') => {
                    self.pos += 1;
                    return Ok(Some(record));
                }
                None => return Ok(Some(record)),
                Some(_) => return Err(ImportError::Malformed),
            }
        }
    }

    /// Reads an unquoted field, up to a separator, a line break or the end.
    fn unquoted(&mut self) -> Result<Zeroizing<String>, ImportError> {
        let bytes = self.src.as_bytes();
        let start = self.pos;
        while !matches!(bytes.get(self.pos), None | Some(b',' | b'\r' | b'\n')) {
            self.pos += 1;
        }
        let field = self
            .src
            .get(start..self.pos)
            .ok_or(ImportError::Malformed)?;
        Ok(text::copy(field))
    }

    /// Reads a quoted field; the cursor is on its opening quote.
    fn quoted(&mut self) -> Result<Zeroizing<String>, ImportError> {
        let bytes = self.src.as_bytes();
        let start = self.pos + 1;
        // First pass: find the closing quote, so the buffer is allocated once.
        let mut end = start;
        loop {
            match bytes.get(end) {
                None => return Err(ImportError::Malformed),
                Some(b'"') if bytes.get(end + 1) == Some(&b'"') => end += 2,
                Some(b'"') => break,
                Some(_) => end += 1,
            }
        }
        let mut out = text::with_capacity(end - start);
        let mut run = start;
        let mut i = start;
        while i < end {
            if bytes.get(i) == Some(&b'"') {
                // A doubled quote: keep the first, skip the second. Both are ASCII, so the
                // runs are on character boundaries.
                out.push_str(self.src.get(run..=i).ok_or(ImportError::Malformed)?);
                i += 2;
                run = i;
            } else {
                i += 1;
            }
        }
        out.push_str(self.src.get(run..end).ok_or(ImportError::Malformed)?);
        self.pos = end + 1;
        Ok(out)
    }
}

/// `true` if every field of the record is empty: a blank line, or a row of separators only.
pub(crate) fn is_blank(record: &[Zeroizing<String>]) -> bool {
    record.iter().all(|f| f.is_empty())
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// All records of `s`.
    fn all(s: &str) -> Result<Vec<Vec<String>>, ImportError> {
        let mut reader = Reader::new(s.as_bytes(), 1 << 20)?;
        let mut out = Vec::new();
        while let Some(record) = reader.next_record()? {
            out.push(record.iter().map(|f| f.to_string()).collect());
        }
        Ok(out)
    }

    #[test]
    fn records() {
        assert_eq!(
            all("a,b,c\r\n1,\"x,y\",\"say \"\"hi\"\"\"\n\"multi\nline\",,\r").unwrap(),
            vec![
                vec!["a", "b", "c"],
                vec!["1", "x,y", "say \"hi\""],
                vec!["multi\nline", "", ""],
            ]
        );
        assert_eq!(all("").unwrap(), Vec::<Vec<String>>::new());
        assert_eq!(all("\n\n").unwrap(), vec![vec![""], vec![""]]);
        assert_eq!(all("a\"b,c").unwrap(), vec![vec!["a\"b", "c"]]);
        assert_eq!(all("\"\"").unwrap(), vec![vec![""]]);
        assert_eq!(all("é,ü").unwrap(), vec![vec!["é", "ü"]]);
    }

    #[test]
    fn rejects() {
        assert_eq!(all("\"abc").unwrap_err(), ImportError::Malformed);
        assert_eq!(all("\"abc\"x").unwrap_err(), ImportError::Malformed);
        assert_eq!(all("\"a\"\"").unwrap_err(), ImportError::Malformed);
        let wide = ",".repeat(MAX_CSV_COLUMNS);
        assert_eq!(all(&wide).unwrap_err(), ImportError::TooMany);
        let fits = ",".repeat(MAX_CSV_COLUMNS - 1);
        assert_eq!(all(&fits).unwrap()[0].len(), MAX_CSV_COLUMNS);
    }

    #[test]
    fn debug_is_redacted() {
        let mut reader = Reader::new(b"name,password\nmail,hunter2\n", 1 << 10).unwrap();
        let _ = reader.next_record().unwrap();
        let shown = format!("{reader:?}");
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("password"));
    }

    #[test]
    fn record_cap() {
        let rows = "a\n".repeat(MAX_ENTRIES + 1);
        assert_eq!(all(&rows).unwrap().len(), MAX_ENTRIES + 1);
        let more = "a\n".repeat(MAX_ENTRIES + 2);
        assert_eq!(all(&more).unwrap_err(), ImportError::TooMany);
    }

    /// Writes a record the way RFC 4180 does: every field quoted, quotes doubled.
    fn write(record: &[String]) -> String {
        record
            .iter()
            .map(|f| format!("\"{}\"", f.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(",")
    }

    proptest! {
        #[test]
        fn round_trip(records in prop::collection::vec(
            prop::collection::vec(".{0,8}", 1..5), 1..5)
        ) {
            let doc = records.iter().map(|r| write(r)).collect::<Vec<_>>().join("\r\n");
            prop_assert_eq!(all(&doc).unwrap(), records);
        }
    }
}

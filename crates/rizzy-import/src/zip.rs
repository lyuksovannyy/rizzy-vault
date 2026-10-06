//! A minimal, bounded zip reader (PKWARE APPNOTE.TXT) that extracts one member by name, for
//! 1PUX's `export.data`.
//!
//! **What it reads.** The end-of-central-directory record (found from the end, its comment
//! length checked), the central directory, and the one member's local header and data. The
//! central directory's sizes and CRC are authoritative (they are also right when the member
//! has a data descriptor). Methods 0 (stored) and 8 (DEFLATE, [`crate::inflate`]).
//!
//! **What it refuses** ([`ImportError::ArchiveUnsupported`]): ZIP64 (sizes, offsets or counts
//! at their 0xFFFF… markers), split archives, encrypted members, other methods. A second
//! member of the same name is [`ImportError::Malformed`]: which one a reader picks differs
//! between readers, which is how a crafted archive shows one tool one content and another tool
//! another.
//!
//! **Bounds** (threat model A16). The archive is capped by the caller; at most
//! [`MAX_ARCHIVE_ENTRIES`] central-directory entries are read; the member's declared size must
//! be at most the caller's cap, and the output buffer is allocated once at that size and never
//! passed ([`crate::inflate::inflate`]). A deflated member's compressed size must be at most
//! what an encoding of its declared size can take (`max_deflated_len`), so decoding work is
//! bounded too. No other member is decompressed. Every read is
//! bounds-checked, and the reader never panics.

use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::inflate::{crc32, inflate};
use crate::limits::MAX_ARCHIVE_ENTRIES;

/// End-of-central-directory signature.
const EOCD_SIG: u32 = 0x0605_4b50;
/// Central-directory file header signature.
const CDFH_SIG: u32 = 0x0201_4b50;
/// Local file header signature.
const LFH_SIG: u32 = 0x0403_4b50;
/// Fixed size of the end-of-central-directory record.
const EOCD_LEN: usize = 22;
/// Fixed size of a central-directory file header.
const CDFH_LEN: usize = 46;
/// Fixed size of a local file header.
const LFH_LEN: usize = 30;

/// Reads a little-endian `u16` at `at`.
fn u16_at(data: &[u8], at: usize) -> Result<u16, ImportError> {
    let bytes = data
        .get(at..at.saturating_add(2))
        .ok_or(ImportError::Malformed)?;
    let bytes = <[u8; 2]>::try_from(bytes).map_err(|_| ImportError::Malformed)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Reads a little-endian `u32` at `at`.
fn u32_at(data: &[u8], at: usize) -> Result<u32, ImportError> {
    let bytes = data
        .get(at..at.saturating_add(4))
        .ok_or(ImportError::Malformed)?;
    let bytes = <[u8; 4]>::try_from(bytes).map_err(|_| ImportError::Malformed)?;
    Ok(u32::from_le_bytes(bytes))
}

/// A `u32` field as a `usize`.
fn size(value: u32) -> Result<usize, ImportError> {
    usize::try_from(value).map_err(|_| ImportError::TooLarge)
}

/// What the central directory says about the member.
struct Member {
    /// Compression method.
    method: u16,
    /// CRC-32 of the uncompressed data.
    crc: u32,
    /// Compressed size.
    compressed: usize,
    /// Uncompressed size.
    uncompressed: usize,
    /// Offset of its local header.
    local_offset: usize,
}

/// Slack allowed above [`max_deflated_len`]'s per-byte bound, for block headers and a
/// dynamic block's code tables.
const DEFLATE_SLACK: usize = 1024;

/// The largest compressed size accepted for a DEFLATE member of `uncompressed` bytes.
///
/// Every byte costs at most 9 bits in a fixed-code block, so an encoder that sends only fixed
/// blocks needs `uncompressed + uncompressed / 8`; stored blocks add 5 bytes per 65,535; the
/// slack covers the remaining headers. A larger member carries bits that produce no output,
/// such as a run of empty blocks, which would cost decoding time without bound (threat model
/// A16), so it is refused as malformed. This is the conservative reading: an encoder that
/// picks the smallest block kind per block (zlib does) stays below `uncompressed` plus the
/// stored-block overhead.
const fn max_deflated_len(uncompressed: usize) -> usize {
    uncompressed
        .saturating_add(uncompressed / 8)
        .saturating_add(5 * (uncompressed / 65_535 + 1))
        .saturating_add(DEFLATE_SLACK)
}

/// Whether the archive's central directory lists a member named exactly `name`, without
/// decompressing it: for format sniffing (`rizzy-client`'s `export::detect`), which must tell
/// a 1PUX archive (`export.data`) from an `AliasVault` `.avux` one (`manifest.json`) before
/// either is decompressed. `false` for a damaged or unsupported archive, exactly as for a
/// missing member.
#[must_use]
pub fn contains(archive: &[u8], name: &str) -> bool {
    find(archive, name.as_bytes()).is_ok()
}

/// Extracts the member `name` of the archive `archive`, whose uncompressed size may be at most
/// `max_len`, into a zeroizing buffer allocated once at that size.
///
/// # Errors
/// [`ImportError::Malformed`] for a damaged archive, a missing or duplicated member, a
/// local header that disagrees with the central directory, or a deflated member larger than
/// any encoding of its declared size needs; [`ImportError::ArchiveUnsupported`]
/// as the module docs say; [`ImportError::TooLarge`] over `max_len`; [`ImportError::Checksum`]
/// if the CRC-32 does not match; [`ImportError::TooMany`] past [`MAX_ARCHIVE_ENTRIES`].
pub fn extract(
    archive: &[u8],
    name: &str,
    max_len: usize,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let member = find(archive, name.as_bytes())?;
    if member.uncompressed > max_len {
        return Err(ImportError::TooLarge);
    }
    // The local header: its own name must match, and its variable fields say where the data
    // starts.
    let lfh = member.local_offset;
    if u32_at(archive, lfh)? != LFH_SIG {
        return Err(ImportError::Malformed);
    }
    let name_len = usize::from(u16_at(archive, lfh + 26)?);
    let extra_len = usize::from(u16_at(archive, lfh + 28)?);
    let name_at = lfh.checked_add(LFH_LEN).ok_or(ImportError::Malformed)?;
    let local_name = archive
        .get(name_at..name_at.saturating_add(name_len))
        .ok_or(ImportError::Malformed)?;
    if local_name != name.as_bytes() {
        return Err(ImportError::Malformed);
    }
    let data_at = name_at
        .checked_add(name_len)
        .and_then(|n| n.checked_add(extra_len))
        .ok_or(ImportError::Malformed)?;
    let data = archive
        .get(data_at..data_at.saturating_add(member.compressed))
        .ok_or(ImportError::Malformed)?;
    if data.len() != member.compressed {
        return Err(ImportError::Malformed);
    }
    let out = match member.method {
        0 => {
            if member.compressed != member.uncompressed {
                return Err(ImportError::Malformed);
            }
            let mut out = Zeroizing::new(Vec::with_capacity(member.uncompressed));
            out.extend_from_slice(data);
            out
        }
        8 => {
            if member.compressed > max_deflated_len(member.uncompressed) {
                return Err(ImportError::Malformed);
            }
            inflate(data, member.uncompressed)?
        }
        _ => return Err(ImportError::ArchiveUnsupported),
    };
    if crc32(&out) != member.crc {
        return Err(ImportError::Checksum);
    }
    Ok(out)
}

/// Finds the member `name` in the central directory.
fn find(archive: &[u8], name: &[u8]) -> Result<Member, ImportError> {
    let eocd = eocd(archive)?;
    let disk = u16_at(archive, eocd + 4)?;
    let cd_disk = u16_at(archive, eocd + 6)?;
    let on_disk = u16_at(archive, eocd + 8)?;
    let total = u16_at(archive, eocd + 10)?;
    let cd_size = u32_at(archive, eocd + 12)?;
    let cd_offset = u32_at(archive, eocd + 16)?;
    if total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
        return Err(ImportError::ArchiveUnsupported);
    }
    if disk != 0 || cd_disk != 0 || on_disk != total {
        return Err(ImportError::ArchiveUnsupported);
    }
    let total = usize::from(total);
    if total > MAX_ARCHIVE_ENTRIES {
        return Err(ImportError::TooMany);
    }
    let cd_start = size(cd_offset)?;
    let cd_end = cd_start
        .checked_add(size(cd_size)?)
        .ok_or(ImportError::Malformed)?;
    if cd_end > eocd {
        return Err(ImportError::Malformed);
    }
    let mut at = cd_start;
    let mut found = None;
    for _ in 0..total {
        if u32_at(archive, at)? != CDFH_SIG {
            return Err(ImportError::Malformed);
        }
        let flags = u16_at(archive, at + 8)?;
        let method = u16_at(archive, at + 10)?;
        let crc = u32_at(archive, at + 16)?;
        let compressed = u32_at(archive, at + 20)?;
        let uncompressed = u32_at(archive, at + 24)?;
        let name_len = usize::from(u16_at(archive, at + 28)?);
        let extra_len = usize::from(u16_at(archive, at + 30)?);
        let comment_len = usize::from(u16_at(archive, at + 32)?);
        let start_disk = u16_at(archive, at + 34)?;
        let local_offset = u32_at(archive, at + 42)?;
        let name_at = at.checked_add(CDFH_LEN).ok_or(ImportError::Malformed)?;
        let entry_name = archive
            .get(name_at..name_at.saturating_add(name_len))
            .ok_or(ImportError::Malformed)?;
        let next = name_at
            .checked_add(name_len)
            .and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comment_len))
            .ok_or(ImportError::Malformed)?;
        if next > cd_end {
            return Err(ImportError::Malformed);
        }
        if entry_name == name {
            if found.is_some() {
                return Err(ImportError::Malformed);
            }
            if flags & 1 != 0 {
                return Err(ImportError::ArchiveUnsupported);
            }
            if compressed == 0xFFFF_FFFF
                || uncompressed == 0xFFFF_FFFF
                || local_offset == 0xFFFF_FFFF
                || start_disk != 0
            {
                return Err(ImportError::ArchiveUnsupported);
            }
            found = Some(Member {
                method,
                crc,
                compressed: size(compressed)?,
                uncompressed: size(uncompressed)?,
                local_offset: size(local_offset)?,
            });
        }
        at = next;
    }
    found.ok_or(ImportError::UnexpectedShape)
}

/// The offset of the end-of-central-directory record: the last signature, within the last
/// 22 + 65,535 bytes, whose comment runs exactly to the end of the archive.
fn eocd(archive: &[u8]) -> Result<usize, ImportError> {
    let last = archive
        .len()
        .checked_sub(EOCD_LEN)
        .ok_or(ImportError::Malformed)?;
    let first = last.saturating_sub(usize::from(u16::MAX));
    for at in (first..=last).rev() {
        if u32_at(archive, at)? == EOCD_SIG {
            let comment_len = usize::from(u16_at(archive, at + 20)?);
            if at + EOCD_LEN + comment_len == archive.len() {
                return Ok(at);
            }
        }
    }
    Err(ImportError::Malformed)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
pub(crate) mod tests {
    use super::*;
    use crate::inflate::tests::deflate;

    /// One member of a test archive: name, method and stored bytes.
    pub(crate) struct TestMember<'a> {
        /// The name.
        pub(crate) name: &'a str,
        /// The uncompressed content.
        pub(crate) data: &'a [u8],
        /// Compress it with DEFLATE (else stored).
        pub(crate) deflate: bool,
    }

    /// Writes a zip archive of `members`, with an optional archive comment.
    pub(crate) fn archive(members: &[TestMember<'_>], comment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for m in members {
            let body = if m.deflate {
                deflate(m.data, true)
            } else {
                m.data.to_vec()
            };
            let method: u16 = if m.deflate { 8 } else { 0 };
            let offset = u32::try_from(out.len()).unwrap();
            let crc = crc32(m.data);
            let csize = u32::try_from(body.len()).unwrap();
            let usize_ = u32::try_from(m.data.len()).unwrap();
            let nlen = u16::try_from(m.name.len()).unwrap();
            out.extend_from_slice(&LFH_SIG.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&csize.to_le_bytes());
            out.extend_from_slice(&usize_.to_le_bytes());
            out.extend_from_slice(&nlen.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(m.name.as_bytes());
            out.extend_from_slice(&body);
            central.extend_from_slice(&CDFH_SIG.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&csize.to_le_bytes());
            central.extend_from_slice(&usize_.to_le_bytes());
            central.extend_from_slice(&nlen.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(m.name.as_bytes());
        }
        let cd_offset = u32::try_from(out.len()).unwrap();
        let cd_size = u32::try_from(central.len()).unwrap();
        let count = u16::try_from(members.len()).unwrap();
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&u16::try_from(comment.len()).unwrap().to_le_bytes());
        out.extend_from_slice(comment);
        out
    }

    /// A two-member archive, the wanted one compressed or stored.
    fn sample(deflated: bool) -> Vec<u8> {
        archive(
            &[
                TestMember {
                    name: "export.attributes",
                    data: b"{}",
                    deflate: false,
                },
                TestMember {
                    name: "export.data",
                    data: b"{\"accounts\": [], \"accounts2\": []}",
                    deflate: deflated,
                },
            ],
            b"a comment",
        )
    }

    #[test]
    fn extracts() {
        for deflated in [false, true] {
            let out = extract(&sample(deflated), "export.data", 1 << 20).unwrap();
            assert_eq!(out.as_slice(), b"{\"accounts\": [], \"accounts2\": []}");
        }
    }

    #[test]
    fn contains_checks_the_central_directory_only() {
        let archive = sample(false);
        assert!(contains(&archive, "export.data"));
        assert!(contains(&archive, "export.attributes"));
        assert!(!contains(&archive, "manifest.json"));
        assert!(!contains(b"not a zip", "export.data"));
        assert!(!contains(b"", "export.data"));
    }

    #[test]
    fn rejects() {
        let zip = sample(true);
        assert_eq!(
            extract(&zip, "missing", 1 << 20).unwrap_err(),
            ImportError::UnexpectedShape
        );
        assert_eq!(
            extract(&zip, "export.data", 4).unwrap_err(),
            ImportError::TooLarge
        );
        assert_eq!(
            extract(&zip[..zip.len() - 1], "export.data", 1 << 20).unwrap_err(),
            ImportError::Malformed
        );
        assert_eq!(
            extract(b"PK", "export.data", 1 << 20).unwrap_err(),
            ImportError::Malformed
        );

        // A flipped content byte fails the CRC (stored, so the stream still parses).
        let mut stored = sample(false);
        let at = stored.windows(5).position(|w| w == b"accou").unwrap();
        let at = stored[at + 1..]
            .windows(5)
            .position(|w| w == b"accou")
            .unwrap()
            + at
            + 1;
        stored[at] ^= 0x20;
        assert_eq!(
            extract(&stored, "export.data", 1 << 20).unwrap_err(),
            ImportError::Checksum
        );

        let dup = archive(
            &[
                TestMember {
                    name: "export.data",
                    data: b"1",
                    deflate: false,
                },
                TestMember {
                    name: "export.data",
                    data: b"2",
                    deflate: false,
                },
            ],
            b"",
        );
        assert_eq!(
            extract(&dup, "export.data", 10).unwrap_err(),
            ImportError::Malformed
        );
    }

    /// A one-member archive whose `export.data` is a DEFLATE stream of `blocks` empty fixed
    /// blocks and a final empty stored block, declared as 0 bytes: a valid stream that decodes
    /// to nothing.
    fn empty_blocks(blocks: usize) -> Vec<u8> {
        // Four empty fixed blocks are 40 bits: BFINAL 0, BTYPE 01, end-of-block 0000000.
        let mut stream = Vec::new();
        for _ in 0..blocks {
            stream.extend_from_slice(&[0x02, 0x08, 0x20, 0x80, 0x00]);
        }
        // BFINAL 1, BTYPE 00, then LEN 0 and NLEN 0xFFFF.
        stream.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
        let mut zip = archive(
            &[TestMember {
                name: "export.data",
                data: &stream,
                deflate: false,
            }],
            b"",
        );
        let cd = zip
            .windows(4)
            .position(|w| w == CDFH_SIG.to_le_bytes())
            .unwrap();
        // Method 8, CRC-32 of nothing (0), uncompressed size 0, in both headers.
        for (method, crc, usize_) in [(8, 14, 22), (cd + 10, cd + 16, cd + 24)] {
            zip[method..method + 2].copy_from_slice(&8u16.to_le_bytes());
            zip[crc..crc + 4].copy_from_slice(&0u32.to_le_bytes());
            zip[usize_..usize_ + 4].copy_from_slice(&0u32.to_le_bytes());
        }
        zip
    }

    #[test]
    fn deflated_size_is_bounded_by_the_declared_size() {
        let out = extract(&empty_blocks(10), "export.data", 1 << 20).unwrap();
        assert!(out.is_empty());
        // More input than any encoding of 0 bytes needs: refused before decoding.
        assert_eq!(
            extract(&empty_blocks(1_000), "export.data", 1 << 20).unwrap_err(),
            ImportError::Malformed
        );
    }

    #[test]
    fn encrypted_member_is_unsupported() {
        let mut zip = sample(false);
        let cd = zip
            .windows(4)
            .position(|w| w == CDFH_SIG.to_le_bytes())
            .unwrap();
        // The second central entry is export.data.
        let cd2 = zip[cd + 4..]
            .windows(4)
            .position(|w| w == CDFH_SIG.to_le_bytes())
            .unwrap()
            + cd
            + 4;
        zip[cd2 + 8] |= 1;
        assert_eq!(
            extract(&zip, "export.data", 1 << 20).unwrap_err(),
            ImportError::ArchiveUnsupported
        );
    }
}

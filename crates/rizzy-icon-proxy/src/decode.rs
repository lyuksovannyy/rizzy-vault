// SPDX-License-Identifier: AGPL-3.0-only

//! Decode and re-encode ([ADR 0052] point 4; INV-76; INV-51 "no SVG").
//!
//! [`reencode`] turns the bytes of a fetched image into the one thing the role serves: a PNG of
//! at most [`ICON_SIZE`]×[`ICON_SIZE`] pixels, RGBA, with no metadata chunk.
//!
//! - **Formats.** The format is read from the content's magic bytes, never from a header or a
//!   file name, and must be one of [`ACCEPTED_FORMATS`]: PNG, JPEG, GIF, BMP, ICO, WebP
//!   (owner answer 4). SVG, and every vector or script-bearing format, is not decodable by the
//!   build at all: the `image` crate is built with those six codecs only.
//! - **Limits before allocation** (INV-76). The input is at most [`MAX_IMAGE_BYTES`] (the
//!   fetch reads no more). The decoder runs with `image`'s own limits: width and height at
//!   most [`MAX_DIMENSION`] and at most [`MAX_DECODE_ALLOC`] bytes allocated. `image`
//!   checks the header's dimensions and the output buffer's size against them before it
//!   allocates that buffer, so a header that claims a huge image (a decompression bomb) is
//!   refused without its pixels ever being inflated.
//! - **Animation.** A GIF or WebP animation decodes to its first frame.
//! - **Resize.** An image larger than [`ICON_SIZE`] on either side is scaled down to fit,
//!   keeping its aspect ratio (a triangle filter); a smaller one is never scaled up.
//! - **Output.** PNG, 8-bit RGBA, at most [`MAX_ICON_PNG_LEN`] bytes (checked).
//!
//! The function is synchronous and CPU-bound; [`crate::favicon`] runs it on Tokio's blocking
//! pool, so a decoder bug that panics there fails one fetch, not the process. The fuzz target
//! `icon_decode` runs it on arbitrary bytes.
//!
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md

use core::fmt;
use std::io::Cursor;

use image::codecs::png::{CompressionType, FilterType as PngFilter, PngEncoder};
use image::imageops::FilterType;
use image::{ExtendedColorType, ImageEncoder as _, ImageFormat, ImageReader, Limits};
use rizzy_proto::icons::PNG_SIGNATURE;
use rizzy_proto::limits::MAX_ICON_PNG_LEN;

/// The largest fetched response decoded, in bytes (INV-76: 2 MiB).
pub const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;

/// The largest width or height decoded, in pixels. Favicons and touch icons are at most a few
/// hundred pixels; 2048 leaves room for the large PNGs some sites link as their icon.
pub const MAX_DIMENSION: u32 = 2048;

/// The most the decoder may allocate at once, in bytes: a 2048×2048 RGBA16 image is 32 MiB.
pub const MAX_DECODE_ALLOC: u64 = 48 * 1024 * 1024;

/// The side of the box an icon is scaled down to fit (ADR 0052 point 4: 128×128).
pub const ICON_SIZE: u32 = 128;

/// The input formats decoded (ADR 0052 point 4, owner answer 4).
pub const ACCEPTED_FORMATS: [ImageFormat; 6] = [
    ImageFormat::Png,
    ImageFormat::Jpeg,
    ImageFormat::Gif,
    ImageFormat::Bmp,
    ImageFormat::Ico,
    ImageFormat::WebP,
];

/// Why bytes could not be re-encoded. Carries none of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Empty, or larger than [`MAX_IMAGE_BYTES`].
    Size,
    /// Not one of [`ACCEPTED_FORMATS`] by its magic bytes.
    Format,
    /// Past [`MAX_DIMENSION`] or [`MAX_DECODE_ALLOC`].
    Limits,
    /// The decoder refused the content.
    Malformed,
    /// The PNG encoder failed, or its output was larger than [`MAX_ICON_PNG_LEN`].
    Encode,
}

impl DecodeError {
    /// A fixed name for the cause, for a log line.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Size => "image_size",
            Self::Format => "image_format",
            Self::Limits => "image_limits",
            Self::Malformed => "image_malformed",
            Self::Encode => "image_encode",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Size => "image empty or too large",
            Self::Format => "image format not accepted",
            Self::Limits => "image past the decoder limits",
            Self::Malformed => "image could not be decoded",
            Self::Encode => "icon could not be encoded",
        })
    }
}

impl std::error::Error for DecodeError {}

/// The decoder limits of the module docs.
fn limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    limits
}

/// Decodes `bytes` and re-encodes them as the served PNG (module docs).
///
/// # Errors
/// [`DecodeError`].
pub fn reencode(bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
        return Err(DecodeError::Size);
    }
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| DecodeError::Format)?;
    match reader.format() {
        Some(format) if ACCEPTED_FORMATS.contains(&format) => {}
        _ => return Err(DecodeError::Format),
    }
    reader.limits(limits());
    let image = reader.decode().map_err(|e| match e {
        image::ImageError::Limits(_) => DecodeError::Limits,
        image::ImageError::Unsupported(_) => DecodeError::Format,
        _ => DecodeError::Malformed,
    })?;
    let image = if image.width() > ICON_SIZE || image.height() > ICON_SIZE {
        image.resize(ICON_SIZE, ICON_SIZE, FilterType::Triangle)
    } else {
        image
    };
    let rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();
    if width == 0 || height == 0 {
        return Err(DecodeError::Malformed);
    }
    let mut out = Vec::new();
    PngEncoder::new_with_quality(&mut out, CompressionType::Best, PngFilter::Adaptive)
        .write_image(rgba.as_raw(), width, height, ExtendedColorType::Rgba8)
        .map_err(|_| DecodeError::Encode)?;
    if out.len() > MAX_ICON_PNG_LEN || !out.starts_with(&PNG_SIGNATURE) {
        return Err(DecodeError::Encode);
    }
    Ok(out)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "the tests cut and walk encoded images by index; a panic there fails the test, which CLAUDE.md allows"
)]
pub(crate) mod tests {
    //! Every accepted format, scaling, and hostile inputs: decompression bombs (PNG, GIF, BMP,
    //! ICO and WebP headers claiming huge sizes), truncated and malformed files, SVG and HTML.

    use image::{DynamicImage, ImageBuffer, Rgba, RgbaImage};

    use super::*;

    /// An image of `width`×`height` with a gradient, encoded as `format`.
    pub(crate) fn encoded(format: ImageFormat, width: u32, height: u32) -> Vec<u8> {
        let image: RgbaImage = ImageBuffer::from_fn(width, height, |x, y| {
            Rgba([
                u8::try_from(x % 256).unwrap(),
                u8::try_from(y % 256).unwrap(),
                128,
                255,
            ])
        });
        let image = DynamicImage::ImageRgba8(image);
        let image = if format == ImageFormat::Jpeg {
            DynamicImage::ImageRgb8(image.to_rgb8())
        } else {
            image
        };
        let mut out = Cursor::new(Vec::new());
        image.write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    /// Decodes a served PNG back, to check it.
    fn dimensions(png: &[u8]) -> (u32, u32) {
        assert!(png.starts_with(&PNG_SIGNATURE));
        let decoded = image::load_from_memory_with_format(png, ImageFormat::Png).unwrap();
        (decoded.width(), decoded.height())
    }

    /// The CRC-32 of PNG chunks (ISO 3309), for hand-made headers.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for b in bytes {
            crc ^= u32::from(*b);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A PNG chunk.
    fn chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(data.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(&kind);
        out.extend_from_slice(data);
        let mut covered = kind.to_vec();
        covered.extend_from_slice(data);
        out.extend_from_slice(&crc32(&covered).to_be_bytes());
        out
    }

    /// A PNG whose header claims `width`×`height` RGBA8 pixels, with a tiny IDAT.
    pub(crate) fn png_claiming(width: u32, height: u32) -> Vec<u8> {
        let mut ihdr = width.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        let mut out = PNG_SIGNATURE.to_vec();
        out.extend(chunk(*b"IHDR", &ihdr));
        // zlib header and an empty final stored block: inflates to nothing.
        out.extend(chunk(
            *b"IDAT",
            &[0x78, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0, 0, 0, 1],
        ));
        out.extend(chunk(*b"IEND", &[]));
        out
    }

    #[test]
    fn every_accepted_format_reencodes_to_png() {
        for format in ACCEPTED_FORMATS {
            let input = encoded(format, 48, 32);
            let png = reencode(&input).unwrap_or_else(|e| panic!("{format:?}: {e}"));
            assert_eq!(dimensions(&png), (48, 32), "{format:?}");
            assert!(png.len() <= MAX_ICON_PNG_LEN);
        }
    }

    #[test]
    fn large_images_scale_down_keeping_the_aspect_ratio_small_ones_never_up() {
        let png = reencode(&encoded(ImageFormat::Png, 512, 256)).unwrap();
        assert_eq!(dimensions(&png), (128, 64));
        let png = reencode(&encoded(ImageFormat::Png, 16, 16)).unwrap();
        assert_eq!(dimensions(&png), (16, 16));
        let png = reencode(&encoded(ImageFormat::Png, 2048, 2048)).unwrap();
        assert_eq!(dimensions(&png), (128, 128));
    }

    #[test]
    fn output_has_no_metadata_chunks() {
        let png = reencode(&encoded(ImageFormat::Png, 20, 20)).unwrap();
        let mut at = 8usize;
        let mut kinds = Vec::new();
        while at + 8 <= png.len() {
            let len = u32::from_be_bytes(png[at..at + 4].try_into().unwrap()) as usize;
            kinds.push(String::from_utf8(png[at + 4..at + 8].to_vec()).unwrap());
            at += 12 + len;
        }
        assert!(
            kinds
                .iter()
                .all(|k| ["IHDR", "IDAT", "IEND"].contains(&k.as_str())),
            "{kinds:?}"
        );
    }

    #[test]
    fn decompression_bomb_headers_are_refused_before_decoding() {
        // Claims 100,000 × 100,000 RGBA (40 GB) with an 11-byte IDAT.
        assert_eq!(
            reencode(&png_claiming(100_000, 100_000)),
            Err(DecodeError::Limits)
        );
        assert_eq!(
            reencode(&png_claiming(MAX_DIMENSION + 1, 1)),
            Err(DecodeError::Limits)
        );
        assert_eq!(
            reencode(&png_claiming(1, MAX_DIMENSION + 1)),
            Err(DecodeError::Limits)
        );
        // A real, highly compressible 4096 × 4096 image: refused by its header.
        let big = encoded(ImageFormat::Png, 4096, 4096);
        assert!(big.len() < MAX_IMAGE_BYTES);
        assert_eq!(reencode(&big), Err(DecodeError::Limits));
        // GIF: logical screen and frame of 65,535 × 65,535.
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00]);
        gif.extend_from_slice(&[0x2c, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x00]);
        gif.extend_from_slice(&[0x02, 0x02, 0x4c, 0x01, 0x00, 0x3b]);
        assert!(matches!(
            reencode(&gif),
            Err(DecodeError::Limits | DecodeError::Malformed)
        ));
        // BMP claiming 60,000 × 60,000 at 32 bits per pixel.
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0x46, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0]);
        bmp.extend_from_slice(&[40, 0, 0, 0]);
        bmp.extend_from_slice(&60_000u32.to_le_bytes());
        bmp.extend_from_slice(&60_000u32.to_le_bytes());
        bmp.extend_from_slice(&[1, 0, 32, 0, 0, 0, 0, 0]);
        bmp.extend_from_slice(&[0; 20]);
        bmp.extend_from_slice(&[0; 16]);
        assert_eq!(reencode(&bmp), Err(DecodeError::Limits));
        // ICO whose one entry is a PNG claiming 100,000 × 100,000.
        let inner = png_claiming(100_000, 100_000);
        let mut ico = vec![0, 0, 1, 0, 1, 0];
        ico.extend_from_slice(&[0, 0, 0, 0, 1, 0, 32, 0]);
        ico.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_le_bytes());
        ico.extend_from_slice(&22u32.to_le_bytes());
        ico.extend_from_slice(&inner);
        assert!(matches!(
            reencode(&ico),
            Err(DecodeError::Limits | DecodeError::Malformed)
        ));
        // WebP (VP8L) claiming 16,384 × 16,384.
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&20u32.to_le_bytes());
        webp.extend_from_slice(b"WEBPVP8L");
        webp.extend_from_slice(&8u32.to_le_bytes());
        let bits: u32 = 0x3fff | (0x3fff << 14);
        webp.push(0x2f);
        webp.extend_from_slice(&bits.to_le_bytes());
        webp.extend_from_slice(&[0, 0, 0]);
        assert!(matches!(
            reencode(&webp),
            Err(DecodeError::Limits | DecodeError::Malformed)
        ));
    }

    #[test]
    fn malformed_and_unaccepted_inputs_are_refused() {
        assert_eq!(reencode(b""), Err(DecodeError::Size));
        assert_eq!(
            reencode(&vec![0u8; MAX_IMAGE_BYTES + 1]),
            Err(DecodeError::Size)
        );
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
        assert_eq!(reencode(svg), Err(DecodeError::Format));
        assert_eq!(
            reencode(b"<!doctype html><html></html>"),
            Err(DecodeError::Format)
        );
        assert_eq!(reencode(&[0x42; 1000]), Err(DecodeError::Format));
        // Formats the build cannot decode, by their magic bytes.
        assert_eq!(reencode(b"II*\0\x08\0\0\0"), Err(DecodeError::Format));
        assert_eq!(
            reencode(b"qoif\0\0\0\x01\0\0\0\x01\x04\0"),
            Err(DecodeError::Format)
        );
        for format in ACCEPTED_FORMATS {
            let full = encoded(format, 40, 40);
            assert!(reencode(&full[..8]).is_err(), "{format:?}");
            for cut in [full.len() / 3, full.len() / 2, full.len() - 1] {
                // A decoder may accept a file cut after its pixel data; either way the result
                // is an error or a valid PNG, never a panic.
                if let Ok(png) = reencode(&full[..cut]) {
                    assert!(png.starts_with(&PNG_SIGNATURE), "{format:?} {cut}");
                }
            }
            let mut flipped = full.clone();
            for b in flipped.iter_mut().skip(16).step_by(7) {
                *b ^= 0x5a;
            }
            // Corrupted content either fails or still yields a valid PNG; it never panics.
            if let Ok(png) = reencode(&flipped) {
                assert!(png.starts_with(&PNG_SIGNATURE));
            }
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only

// A minimal, dependency-free PNG decoder for the clickjacking fuzz harness's pixel oracle
// (`clickjacking-fuzz.spec.ts`). No new npm package is allowed for this task, so this decodes
// exactly the PNGs Playwright's own `page.screenshot()`/`locator.screenshot()` produce: 8-bit
// depth, RGB or RGBA, non-interlaced (verified empirically against this Playwright version; an
// unsupported encoding throws rather than silently misreading pixels). `zlib.inflateSync`
// (Node's own, no dependency) decompresses the concatenated `IDAT` stream; everything else
// (chunk walking, scanline un-filtering) is the PNG spec's own well-known algorithm, implemented
// directly rather than pulled from a library, since the oracle's whole point is to read real
// pixels through a path independent of anything the extension or this repository already ships.
//
// Deliberately NOT a general-purpose PNG decoder: it does not verify chunk CRCs (nothing here
// is untrusted input — these are local screenshots this same process just took), does not
// support palettes, 16-bit depth, interlacing or ancillary chunks beyond `IHDR`/`IDAT`/`IEND`.
import { inflateSync } from "node:zlib";

const PNG_SIGNATURE = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export interface DecodedPng {
  readonly width: number;
  readonly height: number;
  /** Straight (non-premultiplied) RGBA, row-major, 4 bytes per pixel, alpha 255 when the
   * source had no alpha channel. */
  readonly rgba: Uint8Array;
}

function paethPredictor(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) {
    return a;
  }
  if (pb <= pc) {
    return b;
  }
  return c;
}

/** Decodes a PNG buffer (as returned by Playwright's `screenshot()`) into straight RGBA pixels. */
export function decodePng(buf: Buffer): DecodedPng {
  if (buf.length < PNG_SIGNATURE.length || !buf.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
    throw new Error("decodePng: not a PNG (bad signature)");
  }

  let offset = PNG_SIGNATURE.length;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let interlace = 0;
  const idatParts: Buffer[] = [];

  while (offset + 8 <= buf.length) {
    const chunkLen = buf.readUInt32BE(offset);
    const chunkType = buf.toString("ascii", offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + chunkLen;
    if (dataEnd + 4 > buf.length) {
      throw new Error(`decodePng: truncated ${chunkType} chunk`);
    }
    const data = buf.subarray(dataStart, dataEnd);
    if (chunkType === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data.readUInt8(8);
      colorType = data.readUInt8(9);
      interlace = data.readUInt8(12);
    } else if (chunkType === "IDAT") {
      idatParts.push(Buffer.from(data));
    } else if (chunkType === "IEND") {
      break;
    }
    offset = dataEnd + 4; // skip the trailing CRC, not checked (see module doc)
  }

  if (width <= 0 || height <= 0) {
    throw new Error("decodePng: missing or empty IHDR");
  }
  if (bitDepth !== 8) {
    throw new Error(`decodePng: unsupported bit depth ${bitDepth} (need 8)`);
  }
  if (interlace !== 0) {
    throw new Error("decodePng: interlaced PNGs are not supported");
  }
  if (colorType !== 2 && colorType !== 6) {
    throw new Error(`decodePng: unsupported color type ${colorType} (need 2=RGB or 6=RGBA)`);
  }

  const channels = colorType === 6 ? 4 : 3;
  const stride = width * channels;
  const raw = inflateSync(Buffer.concat(idatParts));

  const rgba = new Uint8Array(width * height * 4);
  let prevRow = new Uint8Array(stride);
  let pos = 0;
  for (let y = 0; y < height; y += 1) {
    if (pos >= raw.length) {
      throw new Error("decodePng: truncated scanline data");
    }
    const filterType = raw[pos];
    pos += 1;
    const outRow = new Uint8Array(stride);
    for (let x = 0; x < stride; x += 1) {
      const rawByte = raw[pos + x] ?? 0;
      const a = x >= channels ? (outRow[x - channels] ?? 0) : 0;
      const b = prevRow[x] ?? 0;
      const c = x >= channels ? (prevRow[x - channels] ?? 0) : 0;
      let value: number;
      switch (filterType) {
        case 0:
          value = rawByte;
          break;
        case 1:
          value = rawByte + a;
          break;
        case 2:
          value = rawByte + b;
          break;
        case 3:
          value = rawByte + Math.floor((a + b) / 2);
          break;
        case 4:
          value = rawByte + paethPredictor(a, b, c);
          break;
        default:
          throw new Error(`decodePng: unsupported filter type ${filterType}`);
      }
      outRow[x] = value & 0xff;
    }
    pos += stride;
    for (let x = 0; x < width; x += 1) {
      const si = x * channels;
      const di = (y * width + x) * 4;
      rgba[di] = outRow[si] ?? 0;
      rgba[di + 1] = outRow[si + 1] ?? 0;
      rgba[di + 2] = outRow[si + 2] ?? 0;
      rgba[di + 3] = channels === 4 ? outRow[si + 3] ?? 255 : 255;
    }
    prevRow = outRow;
  }

  return { width, height, rgba };
}

/** Fraction of pixels (0..1) whose R/G/B each differ by at most `channelTolerance` between `a`
 * and `b`. Returns 0 for mismatched dimensions — never throws, so a trick that resizes the
 * capture (e.g. the viewport clamp near a screen edge) is read as "totally different" rather
 * than aborting the case. Alpha is ignored: both images come from opaque page screenshots. */
export function pixelSimilarity(a: DecodedPng, b: DecodedPng, channelTolerance = 32): number {
  if (a.width !== b.width || a.height !== b.height || a.width === 0 || a.height === 0) {
    return 0;
  }
  const n = a.width * a.height;
  let matching = 0;
  for (let i = 0; i < n; i += 1) {
    const o = i * 4;
    const dr = Math.abs((a.rgba[o] ?? 0) - (b.rgba[o] ?? 0));
    const dg = Math.abs((a.rgba[o + 1] ?? 0) - (b.rgba[o + 1] ?? 0));
    const db = Math.abs((a.rgba[o + 2] ?? 0) - (b.rgba[o + 2] ?? 0));
    if (dr <= channelTolerance && dg <= channelTolerance && db <= channelTolerance) {
      matching += 1;
    }
  }
  return matching / n;
}

/** Standard deviation of perceptual luma across the image: near 0 for a flat-colour region
 * (an occluding decoy, a solid background), well above it for real UI (text, borders, icons).
 * Used as a sanity discriminator, not as the bypass/false-refusal oracle itself. */
export function lumaStdDev(img: DecodedPng): number {
  const n = img.width * img.height;
  if (n === 0) {
    return 0;
  }
  const lumas = new Float64Array(n);
  let sum = 0;
  for (let i = 0; i < n; i += 1) {
    const o = i * 4;
    const luma = 0.2126 * (img.rgba[o] ?? 0) + 0.7152 * (img.rgba[o + 1] ?? 0) + 0.0722 * (img.rgba[o + 2] ?? 0);
    lumas[i] = luma;
    sum += luma;
  }
  const mean = sum / n;
  let variance = 0;
  for (let i = 0; i < n; i += 1) {
    const d = (lumas[i] ?? 0) - mean;
    variance += d * d;
  }
  return Math.sqrt(variance / n);
}

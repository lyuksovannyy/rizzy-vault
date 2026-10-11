// SPDX-License-Identifier: AGPL-3.0-only

// A minimal "stored" (uncompressed) zip writer, for the two zip-based import formats (1PUX and
// AliasVault `.avux`). No new package: `rizzy-import::zip::extract`
// (`crates/rizzy-import/src/zip.rs`) validates the central directory's declared CRC-32 against
// the actual bytes for a real import (not only `zip::contains`'s format-detection path, which
// does not check it), so this writer computes a real CRC-32 with the standard public-domain
// table algorithm, not a package. The on-disk layout mirrors
// `crates/rizzy-client/src/export/detect.rs`'s own test helper `zip_with` byte for byte (local
// header, central directory, end-of-central-directory), method 0 (stored) only.

const CRC_TABLE = buildCrcTable();

function buildCrcTable(): Uint32Array {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
}

/** CRC-32 (ISO 3309 / PKZIP) of `data`. */
export function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (const byte of data) {
    c = CRC_TABLE[(c ^ byte) & 0xff]! ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function le16(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
}

function le32(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** One zip member: a name and its (uncompressed) content. */
export interface ZipMember {
  readonly name: string;
  readonly data: Uint8Array;
}

/** Builds a minimal, valid, all-stored zip archive holding `members`, in order. */
export function buildStoredZip(members: readonly ZipMember[]): Uint8Array {
  const fileChunks: Uint8Array[] = [];
  const centralChunks: Uint8Array[] = [];
  let offset = 0;

  for (const member of members) {
    const name = new TextEncoder().encode(member.name);
    const crc = crc32(member.data);
    const localOffset = offset;

    const localHeader = concat([
      le32(0x04034b50),
      new Uint8Array(10), // version needed, flags, method (0 = stored), mod time, mod date
      le32(crc),
      le32(member.data.length),
      le32(member.data.length),
      le16(name.length),
      le16(0),
      name,
    ]);
    fileChunks.push(localHeader, member.data);
    offset += localHeader.length + member.data.length;

    const centralHeader = concat([
      le32(0x02014b50),
      new Uint8Array(12), // version made by, version needed, flags, method, mod time, mod date
      le32(crc),
      le32(member.data.length),
      le32(member.data.length),
      le16(name.length),
      new Uint8Array(12), // extra len, comment len, disk start, internal attrs, external attrs
      le32(localOffset),
      name,
    ]);
    centralChunks.push(centralHeader);
  }

  const central = concat(centralChunks);
  const centralOffset = offset;
  const eocd = concat([
    le32(0x06054b50),
    new Uint8Array(4), // this disk, disk with central directory
    le16(members.length),
    le16(members.length),
    le32(central.length),
    le32(centralOffset),
    le16(0),
  ]);
  return concat([...fileChunks, central, eocd]);
}

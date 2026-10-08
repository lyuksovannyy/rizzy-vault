// The IndexedDB object-store layout, taken unchanged from ADR 0026 §3's SQLite schema ("holds
// the same logical stores, keyed identically, with the same blobs"; ADR 0036 §3). Every name and
// key path here must match the SQL `PRIMARY KEY` of the matching table exactly: that equality
// is what `test/cache-mapping.test.ts` asserts, and it is the one piece of evidence the
// integration step needs to trust this file without re-deriving it from the ADR.
//
// ADR 0026 §3's note "every `u64` is stored as its 8-byte big-endian `BLOB`, so bytewise order
// is numeric order" applies to IndexedDB too: `encodeU64BE`/`decodeU64BE` below are what
// `cache/idb.ts` uses for `account_objects.key` (when it is a `u64`: `bundle_seq`,
// `settings_seq`) and for `ops.device_seq`. Ids (`account_id`, `device_id`, `vault_id`,
// `item_id`, `item_key_id`, `snapshot_id`) are already 16-byte arrays and need no encoding.

/** One IndexedDB object store's name and key path, exactly as ADR 0026 §3 defines the table. */
export interface StoreDef {
  readonly name: string;
  /** IndexedDB key path(s); `undefined` means "no key path, pass the key explicitly to
   * `put`/`get`" (used for the two singleton tables, whose SQL key is a constant `id = 1`). */
  readonly keyPath: readonly string[] | undefined;
}

export const CACHE_META: StoreDef = { name: "cache_meta", keyPath: ["k"] };
export const DEVICE_STATE: StoreDef = { name: "device_state", keyPath: undefined };
export const PENDING_COMMIT: StoreDef = { name: "pending_commit", keyPath: undefined };
export const ACCOUNT_OBJECTS: StoreDef = { name: "account_objects", keyPath: ["kind", "key"] };
export const VAULTS: StoreDef = { name: "vaults", keyPath: ["vault_id"] };
export const WRAPS: StoreDef = { name: "wraps", keyPath: ["vault_id", "item_id", "item_key_id"] };
export const OPS: StoreDef = { name: "ops", keyPath: ["vault_id", "device_id", "device_seq"] };
export const SNAPSHOTS: StoreDef = { name: "snapshots", keyPath: ["vault_id", "snapshot_id"] };

/** Every store, in the order ADR 0026 §3 lists the SQL tables. `idb.ts` opens exactly these. */
export const ALL_STORES: readonly StoreDef[] = [
  CACHE_META,
  DEVICE_STATE,
  PENDING_COMMIT,
  ACCOUNT_OBJECTS,
  VAULTS,
  WRAPS,
  OPS,
  SNAPSHOTS,
];

/** The IndexedDB database name: one per account, like the SQLite file's `<hex(account_id)>`
 * (ADR 0026 §3), so a shared browser profile with no account switch needs no migration here. */
export function databaseName(accountIdHex: string): string {
  return `rizzy-vault.${accountIdHex}`;
}

/** The current cache format, mirrored from ADR 0026 §5's `cache format 1`. Bumping this is a
 * migration, exactly as it is for `rv`'s SQLite file; this module does not implement one yet
 * because no binding produces a cache row to migrate (`core/bindings.ts`). */
export const CACHE_FORMAT_VERSION = 1;

/** Encodes `n` as its 8-byte big-endian form (ADR 0026 §3): bytewise order equals numeric
 * order, so an IndexedDB key range query sorts the same way a `u64` comparison would. Throws on
 * a negative value or one that does not fit in 64 bits, the same refusal a parser gives a
 * malformed record. */
export function encodeU64BE(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffffffffffffffffn) {
    throw new RangeError(`encodeU64BE: ${n} does not fit in an unsigned 64-bit integer`);
  }
  const bytes = new Uint8Array(8);
  let rest = n;
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return bytes;
}

/** The inverse of {@link encodeU64BE}. Throws unless `bytes` is exactly 8 bytes long. */
export function decodeU64BE(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) {
    throw new RangeError(`decodeU64BE: expected 8 bytes, got ${bytes.length}`);
  }
  let out = 0n;
  for (const byte of bytes) {
    out = (out << 8n) | BigInt(byte);
  }
  return out;
}

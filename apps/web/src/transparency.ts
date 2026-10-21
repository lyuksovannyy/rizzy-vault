// SPDX-License-Identifier: AGPL-3.0-only

// The Settings "What the server stores" group (ROADMAP §4.5, transparency page): what a
// rizzy-vault server holds for an account, worded from THREAT_MODEL.md §3.4 (the table that
// names itself the source for this page), with the retention rules of ADR 0012 §5 and §7,
// ADR 0021 §6 and AR-11. Pure: no wasm, no DOM.
//
// Only the rows of §3.4 that this server holds today are listed: shares (M5), aliases and alias
// mail (M6) and the `icons` role are not built, so a row for them would describe data that is
// not there.
//
// No server-reported numbers. No Accepted ADR defines an endpoint, a response type or fields
// for a server-side report (ADR 0028 item 1 lists `GET /api/v1/devices/grants` as the only
// `GET` under `/api/v1/`; item 14's `/api/meta` holds "nothing about any account"), so the
// counts below are the ones this browser already has from the vault it fetched: what the
// server sent, which is what it stores only on an honest server (THREAT_MODEL §4, A2). Byte
// sizes need such an endpoint, or ADR 0048's `bytes_used` (Proposed), first.

/** One kind of data the server holds, and how. */
export interface StoredRow {
  readonly data: string;
  readonly how: string;
}

/** What the server holds for every account (THREAT_MODEL §3.4, Server mode). */
export const STORED: readonly StoredRow[] = [
  { data: "Your login name", how: "In the clear: the server needs it to find your account at login." },
  {
    data: "Your OPAQUE login record",
    how: "Lets the server check your master password and Secret Key without learning either.",
  },
  {
    data: "Your account key, encrypted",
    how: "Under a key derived from your master password and Secret Key, and under your recovery code if you created one.",
  },
  {
    data: "Public keys",
    how: "Your identity and encryption keys and each device's key, signed. Public keys are not secret.",
  },
  {
    data: "Your items, encrypted",
    how: "Encrypted snapshots and an encrypted change log. The server cannot read titles, fields, tags or whether an item is in the Trash.",
  },
  {
    data: "Item key wraps",
    how: "Encrypted, but they reveal your vault's and items' ids.",
  },
  {
    data: "Sync positions per device",
    how: "Reveal how many changes each device made.",
  },
  {
    data: "Metadata it can see",
    how: "Item ids, the number of changes, padded ciphertext sizes and upload times.",
  },
  {
    data: "Your two-factor secret",
    how: "Only while two-factor login is on or being set up, encrypted under a server key kept outside the database.",
  },
  { data: "Session tokens", how: "Hashes only." },
];

/** How long the server keeps what (ADR 0012 §5 and §7, ADR 0021 §6, AR-11). */
export const RETENTION: readonly string[] = [
  "An item in the Trash is deleted for good 30 days after it was trashed, by the first of your devices that is unlocked after that. The server cannot see the Trash, so it never deletes an item itself.",
  "A deleted item leaves a tombstone of a few tens of bytes, kept for the life of the vault, so that an old copy cannot come back.",
  "The signed header of every change, about 225 bytes, is kept for the life of the vault. Older encrypted item versions are dropped once newer snapshots cover them.",
  "The server's own logs never hold IP addresses, login names or request contents. Your server operator's reverse proxy may log IP addresses, and the operator's backups keep deleted data until they expire.",
];

/** The counts this browser computed from the vault it fetched. */
export interface LocalCounts {
  readonly items: number;
  readonly trashed: number;
  readonly devices: number;
}

/** One row of the counts table. */
export interface CountRow {
  readonly label: string;
  readonly value: number;
}

/** The counts table's rows, in display order. */
export function countRows(counts: LocalCounts): CountRow[] {
  return [
    { label: "Items", value: counts.items },
    { label: "Items in the Trash", value: counts.trashed },
    { label: "Enrolled devices", value: counts.devices },
  ];
}

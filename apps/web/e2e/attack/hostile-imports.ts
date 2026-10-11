// SPDX-License-Identifier: AGPL-3.0-only

// Builds a hostile import file for each of `rizzy-import`'s formats (threat model A16),
// combinatorially: one row/item per `(field, payload)` case, so one file exercises many
// payloads in one import. Every item's title records the triple that produced it
// (`ATTACK|<format>|<field>|<payloadId>`), so a failing assertion names the case directly —
// the harness's minimisation, for free (module docs, `payloads.ts`). Firefox CSV has no title
// column at all (its own generator's docs), so `rowKeyOf`/`HostileFile.rowKeys` carry the
// per-case marker in whichever field actually survives for that one format; every other
// format's row key is simply its title.
//
// Each format's shape below is read from its own parser, not guessed: `bitwarden.rs`,
// `onepux.rs`, `keepass.rs`, `csv_import.rs`, `aliasvault.rs` and `rizzy_json.rs` module docs
// under `crates/rizzy-import/src`, and `crates/rizzy-core/src/item/schema.rs` for the ADR 0018
// §7 field-key grammar `rizzy-json` carries verbatim. A file that does not match its format's
// real grammar would test the generator, not the app.
import type { FieldTarget, Payload } from "./payloads.ts";
import { buildStoredZip } from "./zip.ts";

/** The import formats the web vault's "Export and import" pane offers, `rizzy-json` (our own
 * plaintext export, read back) included — every one named in `FORMAT_LABELS`
 * (`apps/web/src/export-flow.ts`) except `rizzy-encrypted` (not hostile input: it is opened
 * with a password, never auto-parsed) and `rizzy-csv` (refused before any reader runs it). */
export const ALL_FORMATS = [
  "bitwarden-json",
  "1pux",
  "keepass-xml",
  "chrome-csv",
  "firefox-csv",
  "csv",
  "aliasvault-csv",
  "aliasvault-avux",
  "rizzy-json",
] as const;

export type ImportFormatId = (typeof ALL_FORMATS)[number];

/** One combinatorial case: a field and the payload placed into it. */
export interface AttackCase {
  readonly field: FieldTarget;
  readonly payload: Payload;
}

/** A generated hostile file and the cases it carries, in the same order as the items/rows it
 * produces (so the Nth item/row is `cases[N]`, and `rowKeys[N]` is the substring that finds
 * it, in whichever rendered field actually carries it for that format — see `rowKeys` docs). */
export interface HostileFile {
  readonly format: ImportFormatId;
  readonly filename: string;
  readonly mimeType: string;
  readonly bytes: Uint8Array;
  readonly cases: readonly AttackCase[];
  readonly rowKeys: readonly string[];
}

/** The trace title every generated item/row carries (module docs): `ATTACK|format|field|id`.
 * For `field === "title"` the payload is appended after it, so the title field itself still
 * carries the payload under test. Most formats put this in `item.name`, which both the list
 * row and the detail heading render verbatim, so it is also that case's row key. */
export function traceTitle(format: ImportFormatId, field: FieldTarget, payloadId: string): string {
  return `ATTACK|${format}|${field}|${payloadId}`;
}

function titleOf(format: ImportFormatId, c: AttackCase): string {
  const trace = traceTitle(format, c.field, c.payload.id);
  return c.field === "title" ? `${trace} ${c.payload.value}` : trace;
}

function val(c: AttackCase, field: FieldTarget, fallback: string): string {
  return c.field === field ? c.payload.value : fallback;
}

/** Firefox CSV's per-case row key (module docs at its generator): a short, unique marker that
 * lands in `username`, since nothing Firefox CSV writes lands in `item.name`. */
function firefoxRowKey(index: number): string {
  return `fxrow${index}`;
}

/** The substring that finds case `cases[index]`'s row/heading/detail text, for whichever field
 * actually carries it in `format`. Every format but Firefox CSV puts the full trace in the
 * title (`titleOf`), which both the list row and the detail heading render verbatim. Firefox
 * CSV has no title column at all (`firefoxCsv`'s own docs), so its row key rides in `username`
 * instead: the payload itself when `username` is the field under test, `firefoxRowKey` (also
 * written to the file) otherwise. */
function rowKeyOf(format: ImportFormatId, cases: readonly AttackCase[], index: number): string {
  const c = cases[index];
  if (c === undefined) {
    throw new Error(`rowKeyOf: index ${index} out of range for ${cases.length} cases`);
  }
  if (format === "firefox-csv") {
    return c.field === "username" ? c.payload.value : firefoxRowKey(index);
  }
  return titleOf(format, c);
}

/** A benign fallback a case does not target, so every item exercises exactly one field at a
 * time (combinatorial breadth without every item being unreadable noise). */
const BENIGN = {
  username: "bob",
  password: "correct-horse-battery",
  notes: "a benign note",
  uri: "https://example.com/",
  totp: "JBSWY3DPEHPK3PXP",
  customName: "Custom",
  customValue: "a benign value",
  tag: "benign-tag",
} as const;

function hex(n: number, bytes: number): string {
  return n.toString(16).padStart(bytes * 2, "0");
}

function csvCell(text: string): string {
  if (/[",\r\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function csvRow(cells: readonly string[]): string {
  return `${cells.map(csvCell).join(",")}\r\n`;
}

function xmlText(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

// --- Bitwarden JSON (`bitwarden.rs`) --------------------------------------------------------

function bitwardenJson(format: ImportFormatId, cases: readonly AttackCase[]): string {
  const folders: { id: string; name: string }[] = [];
  const items = cases.map((c, i) => {
    const id = `11111111-1111-1111-1111-${hex(i, 6)}`;
    let folderId: string | null = null;
    if (c.field === "tag") {
      folderId = `22222222-2222-2222-2222-${hex(i, 6)}`;
      folders.push({ id: folderId, name: c.payload.value });
    }
    return {
      id,
      folderId,
      organizationId: null,
      type: 1,
      name: titleOf(format, c),
      notes: val(c, "notes", BENIGN.notes),
      favorite: false,
      login: {
        username: val(c, "username", BENIGN.username),
        password: BENIGN.password,
        totp: c.field === "totp" ? c.payload.value : null,
        uris: [{ match: null, uri: val(c, "uri", BENIGN.uri) }],
      },
      fields: [
        {
          name: val(c, "customName", BENIGN.customName),
          value: val(c, "customValue", BENIGN.customValue),
          type: 0,
        },
      ],
    };
  });
  return JSON.stringify({ encrypted: false, folders, collections: [], items });
}

// --- 1Password 1PUX (`onepux.rs`), a zip archive with `export.data` -----------------------

function onePuxData(format: ImportFormatId, cases: readonly AttackCase[]): string {
  const items = cases.map((c, i) => ({
    categoryUuid: "001",
    favIndex: 0,
    createdAt: 1_700_000_000,
    overview: {
      title: titleOf(format, c),
      url: val(c, "uri", BENIGN.uri),
      urls: [],
      tags: c.field === "tag" ? [c.payload.value] : [],
    },
    details: {
      notesPlain: val(c, "notes", BENIGN.notes),
      loginFields: [
        { designation: "username", value: val(c, "username", BENIGN.username), name: "username" },
        { designation: "password", value: BENIGN.password, name: "password" },
      ],
      password: "",
      sections: [
        {
          fields: [
            c.field === "totp"
              ? { id: "totp", title: "one-time password", value: { totp: c.payload.value } }
              : { id: "totp", title: "one-time password", value: { totp: BENIGN.totp } },
            {
              id: `custom-${i}`,
              title: val(c, "customName", BENIGN.customName),
              value: { string: val(c, "customValue", BENIGN.customValue) },
            },
          ],
        },
      ],
      passwordHistory: [],
    },
  }));
  return JSON.stringify({ accounts: [{ vaults: [{ items }] }] });
}

function onePux(format: ImportFormatId, cases: readonly AttackCase[]): Uint8Array {
  return buildStoredZip([{ name: "export.data", data: bytes(onePuxData(format, cases)) }]);
}

// --- KeePass XML (`keepass.rs`) -------------------------------------------------------------

function keepassXml(format: ImportFormatId, cases: readonly AttackCase[]): string {
  const entries = cases
    .map((c) => {
      const tagsEl = c.field === "tag" ? `<Tags>${xmlText(c.payload.value)}</Tags>` : "";
      const str = (key: string, value: string) =>
        `<String><Key>${xmlText(key)}</Key><Value>${xmlText(value)}</Value></String>`;
      return (
        `<Entry>` +
        str("Title", titleOf(format, c)) +
        str("UserName", val(c, "username", BENIGN.username)) +
        str("Password", BENIGN.password) +
        str("Notes", val(c, "notes", BENIGN.notes)) +
        str("URL", val(c, "uri", BENIGN.uri)) +
        str(val(c, "customName", BENIGN.customName), val(c, "customValue", BENIGN.customValue)) +
        (c.field === "totp" ? str("otp", c.payload.value) : "") +
        tagsEl +
        `</Entry>`
      );
    })
    .join("");
  return `<?xml version="1.0" encoding="UTF-8"?><KeePassFile><Root><Group><Name>Root</Name>${entries}</Group></Root></KeePassFile>`;
}

// --- Chrome CSV (`csv_import.rs`): name,url,username,password,note ------------------------

function chromeCsv(format: ImportFormatId, cases: readonly AttackCase[]): string {
  let out = csvRow(["name", "url", "username", "password", "note"]);
  for (const c of cases) {
    out += csvRow([
      titleOf(format, c),
      val(c, "uri", BENIGN.uri),
      val(c, "username", BENIGN.username),
      BENIGN.password,
      val(c, "notes", BENIGN.notes),
    ]);
  }
  return out;
}

// --- Firefox CSV: url,username,password,httpRealm,formActionOrigin,guid,... ---------------

function firefoxCsv(format: ImportFormatId, cases: readonly AttackCase[]): string {
  let out = csvRow([
    "url",
    "username",
    "password",
    "httpRealm",
    "formActionOrigin",
    "guid",
    "timeCreated",
    "timeLastUsed",
    "timePasswordChanged",
  ]);
  cases.forEach((c, i) => {
    // Firefox rows have no title/name column at all: the importer names the item after the
    // URL's host (`csv_import.rs` module docs), so no column this generator controls lands in
    // the list row's title. `username`, however, *is* shown in the row (`ItemsPane.tsx`'s
    // `row-sub`) and in the detail view as plain text, so it carries this case's row key
    // (`firefoxRowKey`) instead — the payload itself when `username` is the field under test
    // (still distinctive), a short per-case marker otherwise.
    out += csvRow([
      val(c, "uri", BENIGN.uri),
      c.field === "username" ? c.payload.value : firefoxRowKey(i),
      BENIGN.password,
      "",
      "",
      "",
      "1700000000000",
      "1700000000000",
      "1700000000000",
    ]);
  });
  return out;
}

// --- Generic CSV: name,username,password,url,totp,notes,folder,tags,<custom header> -------

function genericCsv(format: ImportFormatId, cases: readonly AttackCase[]): string {
  let out = csvRow(["name", "username", "password", "url", "totp", "notes", "folder", "tags", "custom"]);
  for (const c of cases) {
    out += csvRow([
      titleOf(format, c),
      val(c, "username", BENIGN.username),
      BENIGN.password,
      val(c, "uri", BENIGN.uri),
      c.field === "totp" ? c.payload.value : BENIGN.totp,
      val(c, "notes", BENIGN.notes),
      c.field === "tag" ? c.payload.value : "",
      "",
      val(c, "customValue", BENIGN.customValue),
    ]);
  }
  return out;
}

// --- AliasVault CSV: ServiceName,FolderPath,ServiceUrl,Username,CurrentPassword,AliasEmail -

function aliasVaultCsv(format: ImportFormatId, cases: readonly AttackCase[]): string {
  let out = csvRow([
    "ServiceName",
    "FolderPath",
    "ServiceUrl",
    "Username",
    "CurrentPassword",
    "AliasEmail",
    "TwoFactorSecret",
    "Notes",
    "CreatedAt",
    "UpdatedAt",
  ]);
  for (const c of cases) {
    out += csvRow([
      titleOf(format, c),
      c.field === "tag" ? c.payload.value : "",
      val(c, "uri", BENIGN.uri),
      val(c, "username", BENIGN.username),
      BENIGN.password,
      "alias@example.com",
      c.field === "totp" ? c.payload.value : "",
      val(c, "notes", BENIGN.notes),
      "01/01/2026 00:00:00",
      "01/01/2026 00:00:00",
    ]);
  }
  return out;
}

// --- AliasVault .avux (`aliasvault.rs`), a zip archive with manifest.json ----------------

function aliasVaultManifest(format: ImportFormatId, cases: readonly AttackCase[]): string {
  const tags: { id: string; name: string }[] = [];
  const itemTags: { itemId: string; tagId: string }[] = [];
  const items = cases.map((c, i) => {
    const id = `item-${hex(i, 4)}`;
    const fieldValues: { fieldKey: string; value: string }[] = [
      { fieldKey: "login.username", value: val(c, "username", BENIGN.username) },
      { fieldKey: "login.password", value: BENIGN.password },
      { fieldKey: "login.url", value: val(c, "uri", BENIGN.uri) },
      { fieldKey: "notes.content", value: val(c, "notes", BENIGN.notes) },
      {
        fieldKey: c.field === "customName" ? c.payload.value : "custom.field",
        value: val(c, "customValue", BENIGN.customValue),
      },
    ];
    if (c.field === "tag") {
      const tagId = `tag-${hex(i, 4)}`;
      tags.push({ id: tagId, name: c.payload.value });
      itemTags.push({ itemId: id, tagId });
    }
    return {
      id,
      itemType: "Login",
      name: titleOf(format, c),
      createdAt: "2026-01-01T00:00:00Z",
      fieldValues,
      totpCodes:
        c.field === "totp"
          ? [{ secretKey: c.payload.value, algorithm: "SHA1", digits: 6, period: 30, name: "TOTP" }]
          : [],
      tags: [],
    };
  });
  return JSON.stringify({ version: "1.0", folders: [], tags, itemTags, fieldDefinitions: [], items });
}

function aliasVaultAvux(format: ImportFormatId, cases: readonly AttackCase[]): Uint8Array {
  return buildStoredZip([{ name: "manifest.json", data: bytes(aliasVaultManifest(format, cases)) }]);
}

// --- rizzy-vault's own plaintext JSON export, read back (`rizzy_json.rs`) ----------------

/** One `{"key":…, "value":…}` field entry. */
function field(key: string, text: string): { key: string; value: { text: string } } {
  return { key, value: { text } };
}

function tagKey(name: string): string {
  return `tag/${Buffer.from(name, "utf8").toString("hex")}`;
}

function rizzyJson(format: ImportFormatId, cases: readonly AttackCase[]): string {
  const items = cases.map((c, i) => {
    const fields: unknown[] = [
      field("item.name", titleOf(format, c)),
      field("item.notes", val(c, "notes", BENIGN.notes)),
      field("login.username", val(c, "username", BENIGN.username)),
      field("login.password", BENIGN.password),
      field(`uri/${hex(i, 16)}/value`, val(c, "uri", BENIGN.uri)),
      field(
        `field/${hex(i, 16)}/label`,
        val(c, "customName", BENIGN.customName),
      ),
      { key: `field/${hex(i, 16)}/kind`, value: { enum: 1 } },
      field(`field/${hex(i, 16)}/value`, val(c, "customValue", BENIGN.customValue)),
    ];
    if (c.field === "totp") {
      fields.push(field("login.totp", c.payload.value));
    }
    if (c.field === "tag") {
      fields.push({ key: tagKey(c.payload.value), value: { bool: true } });
    }
    if (c.field === "passkeyRpId") {
      fields.push(field(`passkey/${hex(i, 16)}/rp_id`, c.payload.value));
    }
    return { id: hex(i, 16), type: 1, trashed: false, fields };
  });
  return JSON.stringify({ format: "rizzy-vault-plaintext-export", version: 1, items });
}

// --- Dispatch --------------------------------------------------------------------------

const MIME: Record<ImportFormatId, string> = {
  "bitwarden-json": "application/json",
  "1pux": "application/zip",
  "keepass-xml": "application/xml",
  "chrome-csv": "text/csv",
  "firefox-csv": "text/csv",
  csv: "text/csv",
  "aliasvault-csv": "text/csv",
  "aliasvault-avux": "application/zip",
  "rizzy-json": "application/json",
};

const EXT: Record<ImportFormatId, string> = {
  "bitwarden-json": "json",
  "1pux": "1pux",
  "keepass-xml": "xml",
  "chrome-csv": "csv",
  "firefox-csv": "csv",
  csv: "csv",
  "aliasvault-csv": "csv",
  "aliasvault-avux": "avux",
  "rizzy-json": "json",
};

/** Builds a hostile file for `format` covering `cases`, one item/row per case, in order. */
export function buildHostileFile(format: ImportFormatId, cases: readonly AttackCase[]): HostileFile {
  let bytesOut: Uint8Array;
  switch (format) {
    case "bitwarden-json":
      bytesOut = bytes(bitwardenJson(format, cases));
      break;
    case "1pux":
      bytesOut = onePux(format, cases);
      break;
    case "keepass-xml":
      bytesOut = bytes(keepassXml(format, cases));
      break;
    case "chrome-csv":
      bytesOut = bytes(chromeCsv(format, cases));
      break;
    case "firefox-csv":
      bytesOut = bytes(firefoxCsv(format, cases));
      break;
    case "csv":
      bytesOut = bytes(genericCsv(format, cases));
      break;
    case "aliasvault-csv":
      bytesOut = bytes(aliasVaultCsv(format, cases));
      break;
    case "aliasvault-avux":
      bytesOut = aliasVaultAvux(format, cases);
      break;
    case "rizzy-json":
      bytesOut = bytes(rizzyJson(format, cases));
      break;
  }
  return {
    format,
    filename: `attack-${format}-${cases.length}.${EXT[format]}`,
    mimeType: MIME[format],
    bytes: bytesOut,
    cases,
    rowKeys: cases.map((_, i) => rowKeyOf(format, cases, i)),
  };
}

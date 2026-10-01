// Export and import (ROADMAP §4.2; CRYPTO.md §11.14; ADR 0027).
//
// - Encrypted export: under an export password the user types twice; the file is ciphertext.
// - Plaintext export (JSON or CSV): only after the frozen warning, a re-authentication with the
//   Secret Key and master password (valid five minutes, spent by one export), and the typed
//   phrase (ADR 0027 §5). The core enforces all three; this view only collects them.
// - Import: another product's file or our own export, read in the browser and handed to the
//   core as bytes; nothing is uploaded but the resulting encrypted items.
import type { ImportFormat, ImportReport } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { type FormEvent, useEffect, useRef, useState } from "react";

import { secretBytes } from "../core-client.ts";
import { dateStamp, saveFile } from "../download.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, takeSecret, useAction } from "./common.tsx";

/**
 * The largest file read for an import: the core's own cap (`MAX_IMPORT_FILE_LEN` of
 * rizzy-wasm, 512 MiB), checked before the file is read into memory.
 */
export const MAX_IMPORT_BYTES = 512 * 1024 * 1024;

/** The import formats, as the core names them. */
const FORMATS: readonly { readonly id: ImportFormat | "rizzy-encrypted"; readonly label: string }[] = [
  { id: "rizzy-encrypted", label: "rizzy-vault encrypted export (.json)" },
  { id: "rizzy-json", label: "rizzy-vault plaintext JSON export" },
  { id: "bitwarden-json", label: "Bitwarden JSON (unencrypted)" },
  { id: "1pux", label: "1Password (.1pux)" },
  { id: "keepass-xml", label: "KeePass XML" },
  { id: "chrome-csv", label: "Chrome CSV" },
  { id: "firefox-csv", label: "Firefox CSV" },
  { id: "csv", label: "Generic CSV" },
];

/** The encrypted export form. */
function EncryptedExport(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const password = useRef<HTMLInputElement>(null);
  const repeat = useRef<HTMLInputElement>(null);
  const [result, setResult] = useState<string | undefined>();
  const { busy, error, setError, run } = useAction();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const pw = takeSecret(password.current);
    if (pw !== takeSecret(repeat.current)) {
      setError("passwords_differ");
      return;
    }
    void run(async () => {
      const blockers = await ctx.client.call("exportBlockers");
      const out = await ctx.client.call("exportEncrypted", secretBytes(pw));
      saveFile(`rizzy-vault-export-${dateStamp()}.json`, out.file, "application/json");
      setResult(
        `Exported ${out.items} item(s).` +
          (out.unresolved > 0 ? ` ${out.unresolved} had unresolved conflicts, exported as shown.` : "") +
          (blockers.length > 0 ? ` ${blockers.length} item(s) were too large to export.` : ""),
      );
    });
  };

  return (
    <form onSubmit={submit} aria-labelledby="export-enc-title">
      <h3 id="export-enc-title">Encrypted export</h3>
      <p className="muted">
        A file only rizzy-vault can read, with a password of its own. Keep the password: without
        it the file cannot be opened.
      </p>
      <SecretField label="Export password" name="export-password" inputRef={password} required />
      <SecretField label="Repeat the export password" name="export-password-repeat" inputRef={repeat} required />
      {error === "passwords_differ" ? (
        <p className="error" role="alert">The two passwords differ.</p>
      ) : (
        <ErrorText code={error} />
      )}
      {result !== undefined && <p className="notice">{result}</p>}
      <div className="actions">
        <button type="submit" disabled={busy}>
          {busy ? "Exporting…" : "Export"}
        </button>
      </div>
    </form>
  );
}

/** The plaintext export, behind the warning, a re-authentication and the typed phrase. */
function PlaintextExport(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [warning, setWarning] = useState("");
  const [phrase, setPhrase] = useState("");
  const [csvWarning, setCsvWarning] = useState("");
  const [format, setFormat] = useState<"json" | "csv">("json");
  const [typed, setTyped] = useState("");
  const [authed, setAuthed] = useState(false);
  const secretKey = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const { busy, error, run } = useAction();

  useEffect(() => {
    void Promise.all([
      ctx.client.call("plaintextExportWarning"),
      ctx.client.call("plaintextExportPhrase"),
      ctx.client.call("csvExportWarning"),
    ]).then(([w, p, c]) => {
      setWarning(w);
      setPhrase(p);
      setCsvWarning(c);
    });
  }, [ctx.client]);

  const reauth = (e: FormEvent) => {
    e.preventDefault();
    const sk = secretBytes(takeSecret(secretKey.current));
    const pw = secretBytes(takeSecret(password.current));
    void run(async () => {
      await ctx.client.call("reauthenticate", sk, pw);
      setAuthed(true);
    });
  };

  const exportNow = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const bytes = await ctx.client.call("exportPlaintext", format, typed);
      saveFile(
        `rizzy-vault-plaintext-${dateStamp()}.${format}`,
        bytes,
        format === "json" ? "application/json" : "text/csv",
      );
      bytes.fill(0);
      setAuthed(false);
      setTyped("");
    });
  };

  return (
    <div aria-labelledby="export-plain-title">
      <h3 id="export-plain-title">Plaintext export</h3>
      <p className="warning" data-testid="plaintext-warning">{warning}</p>
      {!authed ? (
        <form onSubmit={reauth}>
          <p>Confirm it is you. The confirmation is valid for one export within five minutes.</p>
          <SecretField label="Secret Key" name="reauth-secret-key" inputRef={secretKey} required />
          <SecretField label="Master password" name="reauth-master-password" inputRef={password} required />
          <ErrorText code={error} />
          <div className="actions">
            <button type="submit" disabled={busy}>
              Confirm
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={exportNow}>
          <fieldset>
            <legend>Format</legend>
            <label className="check">
              <input type="radio" name="plain-format" checked={format === "json"} onChange={() => setFormat("json")} />
              JSON (complete)
            </label>
            <label className="check">
              <input type="radio" name="plain-format" checked={format === "csv"} onChange={() => setFormat("csv")} />
              CSV
            </label>
          </fieldset>
          {format === "csv" && <p className="warning">{csvWarning}</p>}
          <label htmlFor="plain-phrase">
            Type <strong>{phrase}</strong> to continue
          </label>
          <input
            id="plain-phrase"
            autoComplete="off"
            spellCheck={false}
            value={typed}
            onChange={(e) => setTyped(e.currentTarget.value)}
          />
          <ErrorText code={error} />
          <div className="actions">
            <button type="submit" className="danger" disabled={busy}>
              Export in plaintext
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

/** The import form. */
function Import(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [format, setFormat] = useState<ImportFormat | "rizzy-encrypted">("rizzy-encrypted");
  const [file, setFile] = useState<File | undefined>();
  const [report, setReport] = useState<ImportReport | undefined>();
  const password = useRef<HTMLInputElement>(null);
  const { busy, error, setError, run } = useAction();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (file === undefined) {
      return;
    }
    if (file.size > MAX_IMPORT_BYTES) {
      setError("server_payload_too_large");
      return;
    }
    const pw = format === "rizzy-encrypted" ? secretBytes(takeSecret(password.current)) : undefined;
    void run(async () => {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const r =
        pw !== undefined
          ? await ctx.client.call("importEncrypted", bytes, pw)
          : await ctx.client.call("importFile", format as ImportFormat, bytes);
      setReport(r);
      await ctx.afterWrite();
    });
  };

  return (
    <form onSubmit={submit} aria-labelledby="import-title">
      <h3 id="import-title">Import</h3>
      <label htmlFor="import-format">Format</label>
      <select
        id="import-format"
        value={format}
        onChange={(e) => setFormat(e.currentTarget.value as ImportFormat | "rizzy-encrypted")}
      >
        {FORMATS.map((f) => (
          <option key={f.id} value={f.id}>
            {f.label}
          </option>
        ))}
      </select>
      <label htmlFor="import-file">File</label>
      <input id="import-file" type="file" onChange={(e) => setFile(e.currentTarget.files?.[0])} required />
      {format === "rizzy-encrypted" && (
        <SecretField label="Export password" name="import-password" inputRef={password} required />
      )}
      <p className="muted">
        Imported entries become new items. Delete the source file afterwards if it is not
        encrypted.
      </p>
      <ErrorText code={error} />
      {report !== undefined && (
        <p className="notice" data-testid="import-report">
          Imported {report.imported}, skipped {report.skipped}, warnings {report.warnings}
          {report.fieldsNotCarried > 0 ? `, fields not carried ${report.fieldsNotCarried}` : ""}
          {report.historyNotCarried > 0 ? `, history entries not carried ${report.historyNotCarried}` : ""}
          {report.collapsedConflicts > 0 ? `, conflicts collapsed ${report.collapsedConflicts}` : ""}.
        </p>
      )}
      <div className="actions">
        <button type="submit" disabled={busy || ctx.session.readOnly}>
          {busy ? "Importing…" : "Import"}
        </button>
      </div>
    </form>
  );
}

/** Export and import (module docs). */
export function TransferPane(props: { readonly ctx: VaultContext }) {
  return (
    <div className="panel narrow">
      <h2>Export and import</h2>
      <EncryptedExport ctx={props.ctx} />
      <hr />
      <PlaintextExport ctx={props.ctx} />
      <hr />
      <Import ctx={props.ctx} />
    </div>
  );
}

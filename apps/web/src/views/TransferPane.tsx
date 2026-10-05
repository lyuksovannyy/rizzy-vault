// Export and import (ROADMAP §4.2; CRYPTO.md §11.14; ADR 0027; owner decision 2026-10-05).
//
// - Every export, encrypted or plaintext, first needs the Secret Key and master password typed
//   again: an OPAQUE re-authentication the core accepts for one export within five minutes.
// - Encrypted export: under a new password for that file, typed twice, which is needed to
//   import the file; the file is ciphertext.
// - Plaintext export (JSON or CSV): in a dialog that shows ADR 0027 §5's warning (with the CSV
//   addition), counts down 10 seconds with the confirm button disabled (the count starts over
//   when the dialog is opened again), and needs the typed phrase. The core enforces all of it;
//   this view collects and shows it.
// - Import: the file's format is recognised from its bytes; our encrypted export then asks for
//   the file's password. A format can still be chosen by hand. The file is read in the browser
//   and handed to the core as bytes; nothing is uploaded but the resulting encrypted items.
import type { DetectedImportFormat, ImportReport } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { type FormEvent, useEffect, useRef, useState } from "react";

import { codeOf, secretBytes } from "../core-client.ts";
import { dateStamp, saveFile } from "../download.ts";
import { FORMAT_LABELS, confirmIdentity, encryptedExport, importPlan } from "../export-flow.ts";
import { confirmEnabled, startCountdown } from "../hold.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, takeSecret, useAction } from "./common.tsx";

/**
 * The largest file read for an import: the core's own cap (`MAX_IMPORT_FILE_LEN` of
 * rizzy-wasm, 512 MiB), checked before the file is read into memory.
 */
export const MAX_IMPORT_BYTES = 512 * 1024 * 1024;

/** The formats the import form offers by hand. */
const FORMATS = Object.entries(FORMAT_LABELS).filter(([id]) => id !== "rizzy-csv") as [
  Exclude<DetectedImportFormat, "unknown" | "rizzy-csv">,
  string,
][];

/** The re-authentication in front of every export. */
function Reauthenticate(props: { readonly ctx: VaultContext; readonly onDone: () => void }) {
  const secretKey = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const { busy, error, run } = useAction();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const sk = takeSecret(secretKey.current);
    const pw = takeSecret(password.current);
    void run(async () => {
      await confirmIdentity(props.ctx.client, sk, pw);
      props.onDone();
    });
  };

  return (
    <form onSubmit={submit} aria-labelledby="export-reauth-title">
      <h3 id="export-reauth-title">Confirm it is you</h3>
      <p>
        Every export, encrypted or not, needs your Secret Key and master password again. The
        confirmation allows one export within five minutes.
      </p>
      <SecretField label="Secret Key" name="reauth-secret-key" inputRef={secretKey} required />
      <SecretField label="Master password" name="reauth-master-password" inputRef={password} required />
      <ErrorText code={error} />
      <div className="actions">
        <button type="submit" disabled={busy}>
          {busy ? "Checking…" : "Confirm"}
        </button>
      </div>
    </form>
  );
}

/** The encrypted export form, after the re-authentication. */
function EncryptedExport(props: {
  readonly ctx: VaultContext;
  readonly onDone: (message: string | undefined, code: string | undefined) => void;
}) {
  const { ctx } = props;
  const password = useRef<HTMLInputElement>(null);
  const repeat = useRef<HTMLInputElement>(null);
  const { busy, error, run } = useAction();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const pw = takeSecret(password.current);
    const again = takeSecret(repeat.current);
    void run(async () => {
      try {
        const blockers = await ctx.client.call("exportBlockers");
        const out = await encryptedExport(ctx.client, pw, again);
        saveFile(`rizzy-vault-export-${dateStamp()}.json`, out.file, "application/json");
        props.onDone(
          `Exported ${out.items} item(s). Keep the file's password: it is needed to import the file.` +
            (out.unresolved > 0 ? ` ${out.unresolved} had unresolved conflicts, exported as shown.` : "") +
            (blockers.length > 0 ? ` ${blockers.length} item(s) were too large to export.` : ""),
          undefined,
        );
      } catch (err) {
        if (codeOf(err) === "reauth_required") {
          props.onDone(undefined, "reauth_required");
          return;
        }
        throw err;
      }
    });
  };

  return (
    <form onSubmit={submit} aria-labelledby="export-enc-title">
      <h3 id="export-enc-title">Encrypted export</h3>
      <p className="muted">
        Choose a password for this export file. It is needed to import the file. It is not your
        master password, and nobody can recover it if it is lost.
      </p>
      <SecretField label="Password for this export file" name="export-password" inputRef={password} required />
      <SecretField
        label="Repeat the password for this export file"
        name="export-password-repeat"
        inputRef={repeat}
        required
      />
      <ErrorText code={error} />
      <div className="actions">
        <button type="submit" disabled={busy}>
          {busy ? "Exporting…" : "Export encrypted"}
        </button>
      </div>
    </form>
  );
}

/**
 * The plaintext export dialog: the warning, the 10-second countdown with the confirm button
 * disabled, and the typed phrase. Mounting it starts the hold (in the core and here);
 * closing and opening it again starts it over.
 */
function PlaintextDialog(props: {
  readonly ctx: VaultContext;
  readonly format: "json" | "csv";
  readonly onClose: (message: string | undefined, code: string | undefined) => void;
}) {
  const { ctx, format } = props;
  const [warning, setWarning] = useState("");
  const [csvWarning, setCsvWarning] = useState("");
  const [phrase, setPhrase] = useState("");
  const [typed, setTyped] = useState("");
  const [left, setLeft] = useState<number | undefined>(undefined);
  const { busy, error, run } = useAction();

  useEffect(() => {
    let stop = () => {};
    let live = true;
    void Promise.all([
      ctx.client.call("plaintextExportWarning"),
      ctx.client.call("plaintextExportPhrase"),
      format === "csv" ? ctx.client.call("csvExportWarning") : Promise.resolve(""),
    ]).then(async ([w, p, c]) => {
      if (!live) {
        return;
      }
      setWarning(w);
      setPhrase(p);
      setCsvWarning(c);
      // The warning is on screen: the hold starts now, in the core and in the countdown.
      const holdMs = await ctx.client.call("plaintextWarningShown");
      if (live) {
        stop = startCountdown(holdMs, setLeft);
      }
    });
    return () => {
      live = false;
      stop();
    };
  }, [ctx.client, format]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      try {
        const bytes = await ctx.client.call("exportPlaintext", format, typed);
        saveFile(
          `rizzy-vault-plaintext-${dateStamp()}.${format}`,
          bytes,
          format === "json" ? "application/json" : "text/csv",
        );
        bytes.fill(0);
        props.onClose("Written, unencrypted. Delete the file as soon as you have used it.", undefined);
      } catch (err) {
        if (codeOf(err) === "reauth_required") {
          props.onClose(undefined, "reauth_required");
          return;
        }
        throw err;
      }
    });
  };

  const ready = left !== undefined && confirmEnabled(left, busy);
  return (
    <div className="overlay">
      <form
        className="panel dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="export-plain-title"
        onSubmit={submit}
      >
        <h2 id="export-plain-title">Plaintext export ({format.toUpperCase()})</h2>
        <p className="warning" data-testid="plaintext-warning">
          {warning}
        </p>
        {format === "csv" && (
          <p className="warning" data-testid="plaintext-csv-warning">
            {csvWarning}
          </p>
        )}
        <p data-testid="plaintext-countdown" aria-live="polite">
          {left === undefined || left > 0
            ? `Read the warning. You can continue in ${left ?? 10} s.`
            : "You can continue now."}
        </p>
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
          <button type="submit" className="danger" disabled={!ready}>
            Export in plaintext
          </button>
          <button type="button" className="secondary" onClick={() => props.onClose(undefined, undefined)}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

/** The plaintext export: the format, and the button that opens the dialog. */
function PlaintextExport(props: {
  readonly ctx: VaultContext;
  readonly onDone: (message: string | undefined, code: string | undefined) => void;
}) {
  const [format, setFormat] = useState<"json" | "csv">("json");
  const [open, setOpen] = useState(false);
  return (
    <div aria-labelledby="export-plain-choice-title">
      <h3 id="export-plain-choice-title">Plaintext export</h3>
      <p className="muted">
        A file anyone can read. Use it only to move to another product; the encrypted export is
        the safe copy.
      </p>
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
      <div className="actions">
        <button type="button" className="danger" onClick={() => setOpen(true)}>
          Export in plaintext…
        </button>
      </div>
      {open && (
        <PlaintextDialog
          ctx={props.ctx}
          format={format}
          onClose={(message, code) => {
            setOpen(false);
            if (message !== undefined || code !== undefined) {
              props.onDone(message, code);
            }
          }}
        />
      )}
    </div>
  );
}

/** Export: the re-authentication, then the encrypted and plaintext exports. */
function Export(props: { readonly ctx: VaultContext }) {
  const [authed, setAuthed] = useState(false);
  const [result, setResult] = useState<string | undefined>();
  const [code, setCode] = useState<string | undefined>();
  // One export per re-authentication: whatever an export did, the next one asks again.
  const done = (message: string | undefined, failure: string | undefined) => {
    setAuthed(false);
    setResult(message);
    setCode(failure);
  };
  return (
    <section aria-label="Export">
      {result !== undefined && <p className="notice">{result}</p>}
      <ErrorText code={code} />
      {!authed ? (
        <Reauthenticate
          ctx={props.ctx}
          onDone={() => {
            setResult(undefined);
            setCode(undefined);
            setAuthed(true);
          }}
        />
      ) : (
        <>
          <EncryptedExport ctx={props.ctx} onDone={done} />
          <hr />
          <PlaintextExport ctx={props.ctx} onDone={done} />
        </>
      )}
    </section>
  );
}

/** The import form. */
function Import(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [file, setFile] = useState<File | undefined>();
  const [detected, setDetected] = useState<DetectedImportFormat | undefined>();
  const [chosen, setChosen] = useState<DetectedImportFormat | "auto">("auto");
  const [report, setReport] = useState<ImportReport | undefined>();
  const password = useRef<HTMLInputElement>(null);
  const { busy, error, setError, run } = useAction();

  const pick = (next: File | undefined) => {
    setFile(next);
    setDetected(undefined);
    setReport(undefined);
    setError(undefined);
    if (next === undefined) {
      return;
    }
    if (next.size > MAX_IMPORT_BYTES) {
      setError("server_payload_too_large");
      return;
    }
    void run(async () => {
      // The bytes go to the core (and are wiped there); the import reads the file again.
      const bytes = new Uint8Array(await next.arrayBuffer());
      setDetected(await ctx.client.call("detectImportFormat", bytes));
    });
  };

  const format = chosen === "auto" ? detected : chosen;
  const plan = format === undefined ? undefined : importPlan(format);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (file === undefined || plan === undefined) {
      return;
    }
    if (plan.kind === "refused") {
      setError(plan.code);
      return;
    }
    const pw = plan.kind === "encrypted" ? takeSecret(password.current) : undefined;
    void run(async () => {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const r =
        plan.kind === "encrypted"
          ? await ctx.client.call("importEncrypted", bytes, secretBytes(pw ?? ""))
          : await ctx.client.call("importFile", plan.format, bytes);
      setReport(r);
      await ctx.afterWrite();
    });
  };

  return (
    <form onSubmit={submit} aria-labelledby="import-title">
      <h3 id="import-title">Import</h3>
      <label htmlFor="import-file">File</label>
      <input id="import-file" type="file" onChange={(e) => pick(e.currentTarget.files?.[0])} required />
      {detected !== undefined && (
        <p className="muted" data-testid="import-detected">
          {detected === "unknown"
            ? "The format was not recognised. Choose it below."
            : `Recognised: ${FORMAT_LABELS[detected]}.`}
        </p>
      )}
      <label htmlFor="import-format">Format</label>
      <select
        id="import-format"
        value={chosen}
        onChange={(e) => setChosen(e.currentTarget.value as DetectedImportFormat | "auto")}
      >
        <option value="auto">Recognise automatically</option>
        {FORMATS.map(([id, label]) => (
          <option key={id} value={id}>
            {label}
          </option>
        ))}
      </select>
      {plan?.kind === "encrypted" && (
        <SecretField
          label="Password of this export file"
          name="import-password"
          inputRef={password}
          hint="The password chosen when the file was exported, not your master password."
          required
        />
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
        <button type="submit" disabled={busy || ctx.session.readOnly || plan === undefined}>
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
      <Export ctx={props.ctx} />
      <hr />
      <Import ctx={props.ctx} />
    </div>
  );
}

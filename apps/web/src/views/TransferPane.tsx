// SPDX-License-Identifier: AGPL-3.0-only

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
// - Passkey export (CXF, ADR 0074 §2): every passkey as a FIDO Credential Exchange Format
//   document sealed under a new password for that file, typed twice in a dialog that is gated
//   like the plaintext one: its own warning, the 10-second countdown, the typed phrase. There
//   is no unencrypted CXF export (ADR 0074 owner answer 4).
// - Import: the file's format is recognised from its bytes; our encrypted export and our CXF
//   export then ask for the file's password; a bare CXF file of another product needs nothing
//   more (ADR 0074 §3). A format can still be chosen by hand. The file is read in the browser
//   and handed to the core as bytes; nothing is uploaded but the resulting encrypted items.
import type { DetectedImportFormat, ImportReport } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";
import { SecretField, setModalOpen, trapTab } from "@rizzy-vault/ui";
import { type FormEvent, useEffect, useId, useRef, useState } from "react";

import { codeOf, secretBytes } from "../core-client.ts";
import { dateStamp, saveFile } from "../download.ts";
import { FORMAT_LABELS, confirmIdentity, cxfExport, encryptedExport, importPlan } from "../export-flow.ts";
import { confirmEnabled, startCountdown } from "../hold.ts";
import { defaultVault, vaultLabel, writableVaults } from "../vaults.ts";
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
      <h2 id="export-reauth-title">Confirm it is you</h2>
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
  /** The vault exported (ADR 0081 §A8: one export is one vault). */
  readonly vaultId: string;
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
        const blockers = await ctx.client.call("exportBlockers", props.vaultId);
        const out = await encryptedExport(ctx.client, props.vaultId, pw, again);
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
      <h2 id="export-enc-title">Encrypted export</h2>
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
 *
 * A modal dialog like `ConfirmDialog`: the focus moves to the phrase field when it opens and
 * back to what opened it when it closes, Tab stays inside it (`trapTab`), Escape cancels, and
 * it registers in the modal registry so the vault's global shortcuts stay silent behind it.
 */
function PlaintextDialog(props: {
  readonly ctx: VaultContext;
  readonly vaultId: string;
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
  const dialogRef = useRef<HTMLDivElement>(null);
  const phraseRef = useRef<HTMLInputElement>(null);
  const { onClose } = props;

  useEffect(() => {
    const previouslyFocused = document.activeElement;
    phraseRef.current?.focus();
    setModalOpen(true);
    return () => {
      setModalOpen(false);
      if (previouslyFocused instanceof HTMLElement) {
        previouslyFocused.focus();
      }
    };
  }, []);

  useEffect(() => {
    let stop = () => {};
    let live = true;
    void Promise.all([
      ctx.client.call("plaintextExportWarning"),
      ctx.client.call("plaintextExportPhrase"),
      format === "csv" ? ctx.client.call("csvExportWarning", props.vaultId) : Promise.resolve(""),
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
  }, [ctx.client, format, props.vaultId]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      try {
        const bytes = await ctx.client.call("exportPlaintext", props.vaultId, format, typed);
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
      {/* The dialog is a `div` around the form: ARIA in HTML does not allow `role="dialog"` on
          a `<form>`. */}
      <div
        ref={dialogRef}
        className="panel dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="export-plain-title"
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose(undefined, undefined);
            return;
          }
          trapTab(e, dialogRef.current);
        }}
      >
        <form onSubmit={submit}>
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
            ref={phraseRef}
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
    </div>
  );
}

/** The plaintext export: the format, and the button that opens the dialog. */
function PlaintextExport(props: {
  readonly ctx: VaultContext;
  readonly vaultId: string;
  readonly onDone: (message: string | undefined, code: string | undefined) => void;
}) {
  const [format, setFormat] = useState<"json" | "csv">("json");
  const [open, setOpen] = useState(false);
  return (
    <div aria-labelledby="export-plain-choice-title">
      <h2 id="export-plain-choice-title">Plaintext export</h2>
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
          vaultId={props.vaultId}
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

/**
 * The CXF passkey export dialog (ADR 0074 §2): its own warning, the 10-second countdown with
 * the confirm button disabled, the new password for the file typed twice, and the typed
 * phrase. Mounting it starts the hold; a modal dialog like {@link PlaintextDialog} (focus in on
 * open and back on close, Tab trapped, Escape cancels, global shortcuts silent behind it).
 */
function CxfDialog(props: {
  readonly ctx: VaultContext;
  readonly vaultId: string;
  readonly onClose: (message: string | undefined, code: string | undefined) => void;
}) {
  const { ctx, onClose } = props;
  const [warning, setWarning] = useState("");
  const [phrase, setPhrase] = useState("");
  const [typed, setTyped] = useState("");
  const [left, setLeft] = useState<number | undefined>(undefined);
  const { busy, error, run } = useAction();
  const dialogRef = useRef<HTMLDivElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const repeat = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement;
    password.current?.focus();
    setModalOpen(true);
    return () => {
      setModalOpen(false);
      if (previouslyFocused instanceof HTMLElement) {
        previouslyFocused.focus();
      }
    };
  }, []);

  useEffect(() => {
    let stop = () => {};
    let live = true;
    void Promise.all([ctx.client.call("cxfExportWarning"), ctx.client.call("plaintextExportPhrase")]).then(
      async ([w, p]) => {
        if (!live) {
          return;
        }
        setWarning(w);
        setPhrase(p);
        // The warning is on screen: the hold starts now, in the core and in the countdown.
        const holdMs = await ctx.client.call("plaintextWarningShown");
        if (live) {
          stop = startCountdown(holdMs, setLeft);
        }
      },
    );
    return () => {
      live = false;
      stop();
    };
  }, [ctx.client]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const pw = takeSecret(password.current);
    const again = takeSecret(repeat.current);
    void run(async () => {
      try {
        const exported = await cxfExport(ctx.client, props.vaultId, pw, again, typed);
        saveFile(`rizzy-vault-passkeys-${dateStamp()}.json`, exported.file, "application/json");
        onClose(t("transfer.cxfWritten", { count: String(exported.passkeys) }), undefined);
      } catch (err) {
        if (codeOf(err) === "reauth_required") {
          onClose(undefined, "reauth_required");
          return;
        }
        throw err;
      }
    });
  };

  const ready = left !== undefined && confirmEnabled(left, busy);
  return (
    <div className="overlay">
      <div
        ref={dialogRef}
        className="panel dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="export-cxf-title"
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose(undefined, undefined);
            return;
          }
          trapTab(e, dialogRef.current);
        }}
      >
        <form onSubmit={submit}>
          <h2 id="export-cxf-title">{t("transfer.cxfDialogTitle")}</h2>
          <p className="warning" data-testid="cxf-warning">
            {warning}
          </p>
          <p data-testid="cxf-countdown" aria-live="polite">
            {left === undefined || left > 0
              ? t("transfer.countdown", { seconds: String(left ?? 10) })
              : t("transfer.countdownDone")}
          </p>
          <SecretField
            label={t("transfer.cxfPassword")}
            name="cxf-password"
            inputRef={password}
            hint={t("transfer.cxfPasswordHint")}
            required
          />
          <SecretField label={t("transfer.cxfPasswordRepeat")} name="cxf-password-repeat" inputRef={repeat} required />
          <label htmlFor="cxf-phrase">{t("transfer.typePhrase", { phrase })}</label>
          <input
            id="cxf-phrase"
            autoComplete="off"
            spellCheck={false}
            value={typed}
            onChange={(e) => setTyped(e.currentTarget.value)}
          />
          <ErrorText code={error} />
          <div className="actions">
            <button type="submit" className="danger" disabled={!ready}>
              {t("transfer.cxfConfirm")}
            </button>
            <button type="button" className="secondary" onClick={() => onClose(undefined, undefined)}>
              {t("action.cancel")}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/** The CXF passkey export: how many passkeys it would hold, and the button that opens the
 * dialog. */
function CxfExport(props: {
  readonly ctx: VaultContext;
  readonly vaultId: string;
  readonly onDone: (message: string | undefined, code: string | undefined) => void;
}) {
  const { ctx } = props;
  const [open, setOpen] = useState(false);
  const [count, setCount] = useState<number | undefined>();
  useEffect(() => {
    let live = true;
    ctx.client.call("cxfExportPasskeys", props.vaultId).then(
      (n) => {
        if (live) {
          setCount(n);
        }
      },
      () => {},
    );
    return () => {
      live = false;
    };
  }, [ctx.client, props.vaultId]);
  return (
    <div aria-labelledby="export-cxf-choice-title">
      <h2 id="export-cxf-choice-title">{t("transfer.cxfTitle")}</h2>
      <p className="muted">{t("transfer.cxfIntro")}</p>
      {count !== undefined && <p data-testid="cxf-count">{t("transfer.cxfCount", { count: String(count) })}</p>}
      <div className="actions">
        <button type="button" className="danger" onClick={() => setOpen(true)}>
          {t("transfer.cxfOpen")}
        </button>
      </div>
      {open && (
        <CxfDialog
          ctx={ctx}
          vaultId={props.vaultId}
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

/** Export: the re-authentication, then the encrypted, plaintext and passkey exports. */
function Export(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [authed, setAuthed] = useState(false);
  /** The vault exported (ADR 0081 §A8: one export is one vault), Personal preselected. */
  const [vaultId, setVaultId] = useState<string | undefined>(() =>
    ctx.vaults.find((v) => v.id === ctx.personalVaultId && v.status === "open")?.id ??
    ctx.vaults.find((v) => v.status === "open")?.id,
  );
  const exportVaultSelect = useId();
  const exportable = ctx.vaults.filter((v) => v.status === "open");
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
        vaultId !== undefined && (
          <>
            <label htmlFor={exportVaultSelect}>{t("vaults.picker")}</label>
            <select
              id={exportVaultSelect}
              name="export-vault"
              value={vaultId}
              onChange={(e) => setVaultId(e.currentTarget.value)}
            >
              {exportable.map((v) => (
                <option key={v.id} value={v.id}>
                  {vaultLabel(v)}
                </option>
              ))}
            </select>
            <EncryptedExport ctx={props.ctx} vaultId={vaultId} onDone={done} />
            <hr />
            <PlaintextExport ctx={props.ctx} vaultId={vaultId} onDone={done} />
            <hr />
            <CxfExport ctx={props.ctx} vaultId={vaultId} onDone={done} />
          </>
        )
      )}
    </section>
  );
}

/** The import form. The getting-started guide (`OnboardingView.tsx`) shows it as its import
 * step; the two are never on screen together, so its element ids stay unique. */
export function ImportForm(props: {
  readonly ctx: VaultContext;
  /** The level of the form's "Import" heading: 2 under this pane's h1 (the default), 3 inside
   * the getting-started guide's step, whose own title is an h2. */
  readonly headingLevel?: 2 | 3;
}) {
  const { ctx } = props;
  const [file, setFile] = useState<File | undefined>();
  const [detected, setDetected] = useState<DetectedImportFormat | undefined>();
  const [chosen, setChosen] = useState<DetectedImportFormat | "auto">("auto");
  const [report, setReport] = useState<ImportReport | undefined>();
  /** The import's target vault (ADR 0081 §A8): the Personal vault, preselected every time. */
  const [vaultId, setVaultId] = useState<string | undefined>(() => defaultVault(ctx.vaults, ctx.personalVaultId));
  const importVaultSelect = useId();
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
    const sealed = plan.kind === "encrypted" || plan.kind === "cxf-encrypted";
    const pw = sealed ? takeSecret(password.current) : undefined;
    const target = vaultId ?? defaultVault(ctx.vaults, ctx.personalVaultId);
    if (target === undefined) {
      setError("vault_set_mismatch");
      return;
    }
    void run(async () => {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const r =
        plan.kind === "encrypted"
          ? await ctx.client.call("importEncrypted", target, bytes, secretBytes(pw ?? ""))
          : plan.kind === "cxf-encrypted"
            ? await ctx.client.call("importCxfEncrypted", target, bytes, secretBytes(pw ?? ""))
            : await ctx.client.call("importFile", target, plan.format, bytes);
      setReport(r);
      await ctx.afterWrite();
    });
  };

  return (
    <form onSubmit={submit} aria-labelledby="import-title">
      {props.headingLevel === 3 ? <h3 id="import-title">Import</h3> : <h2 id="import-title">Import</h2>}
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
      {writableVaults(ctx.vaults).length > 0 && (
        <>
          <label htmlFor={importVaultSelect}>{t("vaults.picker")}</label>
          <select
            id={importVaultSelect}
            name="import-vault"
            value={vaultId ?? ""}
            onChange={(e) => setVaultId(e.currentTarget.value)}
          >
            {writableVaults(ctx.vaults).map((v) => (
              <option key={v.id} value={v.id}>
                {vaultLabel(v)}
              </option>
            ))}
          </select>
        </>
      )}
      {(plan?.kind === "encrypted" || plan?.kind === "cxf-encrypted") && (
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
          {report.credentialsSkipped > 0
            ? ` ${t("transfer.credentialsSkipped", { count: String(report.credentialsSkipped) })}`
            : ""}
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
      <h1>Export and import</h1>
      <Export ctx={props.ctx} />
      <hr />
      <ImportForm ctx={props.ctx} />
    </div>
  );
}

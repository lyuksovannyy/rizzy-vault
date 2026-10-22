// SPDX-License-Identifier: AGPL-3.0-only

// An item's encrypted attachments (ADR 0054): the list (name, size, media type), "Attach a file",
// and per file "Download" and "Delete". Everything cryptographic happens in the core Worker: the
// file's bytes are transferred there (no copy stays on this thread) and come back only when the
// user asks for a download, after every chunk verified (INV-79); the bytes are zeroed once the
// browser has its own copy for the save dialog.
//
// The 25 MiB cap (ADR 0054 §2) is checked here first, so an oversized file is refused before it
// is read; the core checks it again. Words come from `@rizzy-vault/i18n` (`attachments.*`,
// `errors.*`).
import type { AttachmentInfo } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";
import { ConfirmDialog, useToast } from "@rizzy-vault/ui";
import { type ChangeEvent, useEffect, useId, useRef, useState } from "react";

import { declaredMime, formatSize, precheck } from "../attachments.ts";
import { codeOf } from "../core-client.ts";
import { saveFile } from "../download.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The attachments section of an item view (module docs). */
export function AttachmentsSection(props: {
  readonly ctx: VaultContext;
  readonly id: string;
  /** Whether attachments may be added or deleted (a writable vault, an item not in the trash). */
  readonly writable: boolean;
}) {
  const { ctx, id, writable } = props;
  const [listed, setListed] = useState<readonly AttachmentInfo[] | undefined>();
  const [status, setStatus] = useState<string | undefined>();
  const [deleting, setDeleting] = useState<AttachmentInfo | undefined>();
  const [refresh, setRefresh] = useState(0);
  const { busy, error, setError, run } = useAction();
  const { notify } = useToast();
  const headingId = useId();
  const inputId = useId();
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let live = true;
    ctx.client.call("attachments", id).then(
      (a) => live && setListed(a),
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, id, ctx.revision, refresh, setError]);

  const choose = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file === undefined) {
      return;
    }
    const refused = precheck(file.size);
    if (refused !== undefined) {
      setError(refused);
      return;
    }
    void run(async () => {
      setStatus(t("attachments.adding", { name: file.name }));
      try {
        const data = new Uint8Array(await file.arrayBuffer());
        await ctx.client.call("addAttachment", id, file.name, declaredMime(file.type), data);
        notify("success", t("attachments.added", { name: file.name }));
      } finally {
        setStatus(undefined);
        setRefresh((n) => n + 1);
      }
    });
  };

  const download = (a: AttachmentInfo) =>
    void run(async () => {
      const bytes = await ctx.client.call("downloadAttachment", id, a.id);
      try {
        saveFile(a.name, bytes, a.mime);
      } finally {
        bytes.fill(0);
      }
      notify("success", t("attachments.downloaded", { name: a.name }));
    });

  const remove = (a: AttachmentInfo) =>
    void run(async () => {
      try {
        await ctx.client.call("deleteAttachment", id, a.id);
        notify("success", t("attachments.deleted", { name: a.name }));
      } finally {
        setRefresh((n) => n + 1);
      }
    });

  if (listed === undefined) {
    return <ErrorText code={error} />;
  }
  if (listed.length === 0 && !writable) {
    return null;
  }
  return (
    <section className="attachments" aria-labelledby={headingId} data-testid="attachments">
      <h3 id={headingId}>{t("attachments.heading")}</h3>
      {listed.length === 0 ? (
        <p className="muted small">{t("attachments.empty")}</p>
      ) : (
        <ul className="attachment-list">
          {listed.map((a) => (
            <li key={a.id} className="attachment" data-attachment={a.id}>
              <span className="attachment-name">{a.name}</span>{" "}
              <span className="muted small">
                {formatSize(a.size)} · {a.mime}
              </span>
              <span className="field-actions">
                <button type="button" disabled={busy} aria-label={t("attachments.download", { name: a.name })} onClick={() => download(a)}>
                  Download
                </button>
                {writable && (
                  <button
                    type="button"
                    className="danger"
                    disabled={busy}
                    aria-label={t("attachments.delete", { name: a.name })}
                    onClick={() => setDeleting(a)}
                  >
                    Delete
                  </button>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
      {writable && (
        <div className="attachment-add">
          <label htmlFor={inputId}>{t("attachments.add")}</label>
          <input id={inputId} ref={input} type="file" disabled={busy} onChange={choose} aria-describedby={`${inputId}-hint`} />
          <p id={`${inputId}-hint`} className="muted small">
            {t("attachments.limit")}
          </p>
        </div>
      )}
      {status !== undefined && (
        <p className="muted small" role="status">
          {status}
        </p>
      )}
      <ErrorText code={error} />
      <ConfirmDialog
        open={deleting !== undefined}
        titleId={`${headingId}-delete-title`}
        title={t("attachments.deleteTitle")}
        description={t("attachments.deleteDescription", { name: deleting?.name ?? "" })}
        confirmLabel={t("attachments.deleteConfirm")}
        danger
        onConfirm={() => {
          const target = deleting;
          setDeleting(undefined);
          if (target !== undefined) {
            remove(target);
          }
        }}
        onCancel={() => setDeleting(undefined)}
      />
    </section>
  );
}

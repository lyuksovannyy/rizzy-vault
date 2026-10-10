// SPDX-License-Identifier: AGPL-3.0-only

// The late-edit and trash notices the last syncs handed over (gap 02; `notices.ts`): each with
// a Dismiss button, and for an edit that arrived for an item deleted permanently, a type picker
// and "Restore as new item" (ADR 0018 §3 "Surfacing": the user picks the type, it is never
// inferred). The notices live in the vault view's state only (`notices.ts` module docs).
import type { DeviceView, ItemType, Notice } from "@rizzy-vault/core";
import { useToast } from "@rizzy-vault/ui";
import { useEffect, useState } from "react";

import { CREATABLE_TYPES } from "../fields.ts";
import { deviceLabel, noticeKey, noticeText } from "../notices.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** One notice (module docs). */
function NoticeLine(props: {
  readonly ctx: VaultContext;
  readonly notice: Notice;
  readonly devices: readonly DeviceView[];
  readonly onDismiss: () => void;
}) {
  const { ctx, notice } = props;
  const [title, setTitle] = useState("");
  const [itemType, setItemType] = useState<ItemType>("login");
  const { busy, error, run } = useAction();
  const { notify } = useToast();

  // A concurrent trash names the item, which is still in the list; a late edit's item is
  // deleted, so it has no summary to name it by.
  useEffect(() => {
    if (notice.kind !== "concurrent-trash") {
      return;
    }
    let live = true;
    ctx.client.call("item", notice.item).then(
      (s) => live && setTitle(s.title),
      () => undefined, // Unnamed then: the notice still reads.
    );
    return () => {
      live = false;
    };
  }, [ctx.client, notice]);

  const label = (id: string) => deviceLabel(id, props.devices, ctx.session.deviceId);

  const restore = () =>
    void run(async () => {
      await ctx.client.call("restoreLateAsNew", notice.item, itemType);
      await ctx.afterWrite();
      props.onDismiss();
      notify("success", "Restored as a new item.");
    });

  return (
    <div className="notice" role="status" data-notice={notice.kind} data-item={notice.item}>
      <p>{noticeText(notice, label, title)}</p>
      <div className="actions">
        {notice.kind === "late-edit" && !ctx.session.readOnly && (
          <>
            <label>
              <span className="sr-only">Type of the new item</span>
              <select
                value={itemType}
                disabled={busy}
                onChange={(e) => setItemType(e.target.value as ItemType)}
              >
                {CREATABLE_TYPES.map((t) => (
                  <option key={t.type} value={t.type}>
                    {t.label}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" disabled={busy} onClick={restore}>
              Restore as new item
            </button>
          </>
        )}
        <button type="button" className="secondary" disabled={busy} onClick={props.onDismiss}>
          Dismiss
        </button>
      </div>
      <ErrorText code={error} />
    </div>
  );
}

/** The notices (module docs); nothing when there are none. */
export function NoticesPanel(props: {
  readonly ctx: VaultContext;
  readonly notices: readonly Notice[];
  readonly devices: readonly DeviceView[];
  readonly onDismiss: (notice: Notice) => void;
}) {
  if (props.notices.length === 0) {
    return null;
  }
  return (
    <section className="notices" aria-label="Notices">
      {props.notices.map((n) => (
        <NoticeLine
          key={noticeKey(n)}
          ctx={props.ctx}
          notice={n}
          devices={props.devices}
          onDismiss={() => props.onDismiss(n)}
        />
      ))}
    </section>
  );
}

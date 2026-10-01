// The item list with search, and the selected item's view or editor. In the trash, the list
// shows trashed items, and the view offers restore and purge instead of edit.
import type { ItemSummary, ItemType } from "@rizzy-vault/core";
import { useEffect, useState } from "react";

import { codeOf } from "../core-client.ts";
import { CREATABLE_TYPES, matches } from "../fields.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText } from "./common.tsx";
import { ItemEditor } from "./ItemEditor.tsx";
import { ItemView } from "./ItemView.tsx";

/** What the right-hand side shows. */
type Detail =
  | { readonly kind: "none" }
  | { readonly kind: "view"; readonly id: string }
  | { readonly kind: "edit"; readonly id: string }
  | { readonly kind: "new"; readonly itemType: ItemType };

/** The list and the detail (module docs). */
export function ItemsPane(props: { readonly ctx: VaultContext; readonly trash: boolean }) {
  const { ctx, trash } = props;
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [query, setQuery] = useState("");
  const [detail, setDetail] = useState<Detail>({ kind: "none" });
  const [error, setError] = useState<string | undefined>();
  const [localRevision, setLocalRevision] = useState(0);

  useEffect(() => {
    let live = true;
    ctx.client.call("items", trash).then(
      (list) => {
        if (live) {
          setItems(list);
          setError(undefined);
        }
      },
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.revision, trash, localRevision]);

  useEffect(() => setDetail({ kind: "none" }), [trash]);

  const shown = items
    .filter((i) => matches(i, query))
    .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title));

  /** After a write: refresh the list now, and sync. */
  const written = async (next: Detail) => {
    setDetail(next);
    setLocalRevision((r) => r + 1);
    await ctx.afterWrite();
  };

  return (
    <div className="items">
      <div className="item-list">
        <input
          type="search"
          aria-label="Search items"
          placeholder="Search"
          spellCheck={false}
          autoComplete="off"
          value={query}
          onChange={(e) => setQuery(e.currentTarget.value)}
        />
        {!trash && !ctx.session.readOnly && (
          <div className="new-item">
            {CREATABLE_TYPES.map((t) => (
              <button
                key={t.type}
                type="button"
                className="secondary small"
                onClick={() => setDetail({ kind: "new", itemType: t.type })}
              >
                New {t.label.toLowerCase()}
              </button>
            ))}
          </div>
        )}
        <ErrorText code={error} />
        {shown.length === 0 ? (
          <p className="muted">{trash ? "The trash is empty." : items.length === 0 ? "No items yet." : "Nothing matches."}</p>
        ) : (
          <ul aria-label={trash ? "Trashed items" : "Items"}>
            {shown.map((i) => (
              <li key={i.id}>
                <button
                  type="button"
                  className={detail.kind !== "none" && detail.kind !== "new" && detail.id === i.id ? "row selected" : "row"}
                  onClick={() => setDetail({ kind: "view", id: i.id })}
                >
                  <span className="row-title">
                    {i.favorite && <span aria-label="favorite">★ </span>}
                    {i.title === "" ? "(untitled)" : i.title}
                  </span>
                  <span className="row-sub">{i.username ?? i.itemType}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="item-detail">
        {detail.kind === "view" && (
          <ItemView
            key={`${detail.id}-${ctx.revision}-${localRevision}`}
            ctx={ctx}
            id={detail.id}
            onEdit={() => setDetail({ kind: "edit", id: detail.id })}
            onWritten={(gone) => written(gone ? { kind: "none" } : detail)}
          />
        )}
        {detail.kind === "edit" && (
          <ItemEditor
            key={`edit-${detail.id}`}
            ctx={ctx}
            id={detail.id}
            onCancel={() => setDetail({ kind: "view", id: detail.id })}
            onSaved={(id) => written({ kind: "view", id })}
          />
        )}
        {detail.kind === "new" && (
          <ItemEditor
            key={`new-${detail.itemType}`}
            ctx={ctx}
            newType={detail.itemType}
            onCancel={() => setDetail({ kind: "none" })}
            onSaved={(id) => written({ kind: "view", id })}
          />
        )}
      </div>
    </div>
  );
}

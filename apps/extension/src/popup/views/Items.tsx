// The item list, search and detail view (ROADMAP §4.4 "item list and detail with copy").
// Fetches the list once on mount; detail fields are fetched lazily per item (ADR 0013 §3 rule
// 3: list views never carry more than title/username, so the detail call is what reveals a
// concealed field on the user's own request).
import { useEffect, useMemo, useState } from "react";

import type { ExtensionClient } from "../../core/client.ts";
import { copyWithClearing } from "../clipboard.ts";

export interface ItemsViewProps {
  readonly client: ExtensionClient;
  /** Bumped by `App.tsx` after every sync that completes. Only read as a `useEffect`
   * dependency below, to force a refetch — this view has no other use for the number itself. */
  readonly revision: number;
}

interface ItemRow {
  readonly itemId: string;
  readonly title: string;
  readonly username: string;
}

interface FieldRow {
  readonly key: string;
  readonly kind: string;
  readonly concealed: boolean;
  readonly value: string | undefined;
}

export function ItemsView({ client, revision }: ItemsViewProps) {
  const [items, setItems] = useState<readonly ItemRow[] | undefined>(undefined);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | undefined>(undefined);

  useEffect(() => {
    void client
      .listItems()
      .then(setItems)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "list_items_failed"));
  }, [client, revision]);

  const filtered = useMemo(() => {
    if (items === undefined) {
      return undefined;
    }
    const q = query.trim().toLowerCase();
    if (q === "") {
      return items;
    }
    return items.filter((i) => i.title.toLowerCase().includes(q) || i.username.toLowerCase().includes(q));
  }, [items, query]);

  if (error !== undefined) {
    return <p role="alert">{error}</p>;
  }
  if (items === undefined) {
    return <p>Loading items…</p>;
  }
  if (selected !== undefined) {
    return <ItemDetail client={client} itemId={selected} onBack={() => setSelected(undefined)} />;
  }

  return (
    <div>
      <label>
        Search
        <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Title or username" />
      </label>
      {filtered?.length === 0 ? (
        <p>No items.</p>
      ) : (
        <ul>
          {filtered?.map((item) => (
            <li key={item.itemId}>
              <button type="button" onClick={() => setSelected(item.itemId)}>
                {item.title} {item.username !== "" ? `(${item.username})` : undefined}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ItemDetail({ client, itemId, onBack }: { client: ExtensionClient; itemId: string; onBack: () => void }) {
  const [fields, setFields] = useState<readonly FieldRow[] | undefined>(undefined);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [copied, setCopied] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | undefined>(undefined);

  useEffect(() => {
    void client
      .itemFields(itemId)
      .then(setFields)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "item_fields_failed"));
  }, [client, itemId]);

  const copy = (value: string, label: string) => {
    void copyWithClearing(value).then(() => {
      setCopied(label);
      setTimeout(() => setCopied(undefined), 2000);
    });
  };

  const reveal = (key: string) => {
    void client
      .revealField(itemId, key)
      .then((value) => {
        setRevealed((prev) => ({ ...prev, [key]: value }));
        copy(value, key);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "reveal_failed"));
  };

  return (
    <div>
      <button type="button" onClick={onBack}>
        ← Back
      </button>
      {error !== undefined ? <p role="alert">{error}</p> : undefined}
      {fields === undefined ? (
        <p>Loading…</p>
      ) : (
        <ul>
          {fields.map((field) => (
            <li key={field.key}>
              <span>{field.key}: </span>
              {field.concealed ? (
                revealed[field.key] !== undefined ? (
                  <span>{revealed[field.key]}</span>
                ) : (
                  <button type="button" onClick={() => reveal(field.key)}>
                    Reveal &amp; copy
                  </button>
                )
              ) : (
                <>
                  <span>{field.value}</span>
                  {field.value !== undefined && field.value !== "" ? (
                    <button type="button" onClick={() => copy(field.value!, field.key)}>
                      Copy
                    </button>
                  ) : undefined}
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {copied !== undefined ? <p role="status">Copied {copied} (clears from the clipboard shortly).</p> : undefined}
    </div>
  );
}

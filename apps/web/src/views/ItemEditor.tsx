// Creating and editing an item. An edit writes only the keys the user changed, as one op
// (ADR 0018 §11; `fixedChanges`). Concealed values are never fetched to prefill the form: a
// concealed field's input starts empty, an empty input keeps the value, and "Clear" removes it.
// Secret values are typed in the secret-field component (INV-68) and read from the element
// on save, not kept in React state.
import type { ItemChange, ItemSummary, ItemType } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { type FormEvent, useEffect, useRef, useState } from "react";

import { codeOf } from "../core-client.ts";
import { type FixedField, type Grouped, FIXED_FIELDS, fixedChanges, group } from "../fields.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, takeSecret, useAction } from "./common.tsx";

/** The fields of a type this editor shows; unknown types get the title and notes only. */
function fieldsOf(type: ItemType | "unknown"): readonly FixedField[] {
  return (
    (type === "unknown" ? undefined : FIXED_FIELDS[type]) ?? [
      { key: "item.name", label: "Title" },
      { key: "item.notes", label: "Notes", multiline: true },
    ]
  );
}

/** The editor (module docs): `id` to edit an item, `newType` to create one. */
export function ItemEditor(props: {
  readonly ctx: VaultContext;
  readonly id?: string;
  readonly newType?: ItemType;
  readonly onCancel: () => void;
  readonly onSaved: (id: string) => Promise<void>;
}) {
  const { ctx } = props;
  const [summary, setSummary] = useState<ItemSummary | undefined>();
  const [current, setCurrent] = useState<Grouped | undefined>();
  const [texts, setTexts] = useState<Record<string, string>>({});
  const [clearSecret, setClearSecret] = useState<Record<string, boolean>>({});
  const [favorite, setFavorite] = useState(false);
  const [removed, setRemoved] = useState<Record<string, boolean>>({});
  const [newUri, setNewUri] = useState("");
  const [newTags, setNewTags] = useState("");
  const [custom, setCustom] = useState({ label: "", kind: "text" as "text" | "hidden" | "boolean", value: "" });
  const secrets = useRef(new Map<string, HTMLInputElement | null>());
  const customSecret = useRef<HTMLInputElement>(null);
  const { busy, error, setError, run } = useAction();

  const type: ItemType | "unknown" = props.newType ?? summary?.itemType ?? "unknown";

  useEffect(() => {
    if (props.id === undefined) {
      setCurrent(group([]));
      return;
    }
    let live = true;
    const id = props.id;
    Promise.all([ctx.client.call("item", id), ctx.client.call("fields", id)]).then(
      ([s, f]) => {
        if (!live) {
          return;
        }
        const g = group(f);
        setSummary(s);
        setCurrent(g);
        setFavorite(g.favorite);
        const initial: Record<string, string> = {};
        for (const field of g.fixed) {
          if (!field.concealed && field.value !== undefined) {
            initial[field.key] = field.value;
          }
        }
        setTexts(initial);
      },
      (e: unknown) => live && setError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, props.id, setError]);

  if (current === undefined) {
    return <ErrorText code={error} />;
  }

  const held = new Map(current.fixed.map((f) => [f.key, f]));

  const generate = (key: string) =>
    void run(async () => {
      const g = await ctx.client.call("generatePassword", 20, true, false);
      const input = secrets.current.get(key);
      if (input != null) {
        input.value = g.value;
      }
    });

  const save = (e: FormEvent) => {
    e.preventDefault();
    const fields = fieldsOf(type);
    const changes: ItemChange[] = fixedChanges(
      fields.map((f) => {
        const before = held.get(f.key);
        const concealed = before?.concealed ?? f.secret === true;
        const text = concealed ? takeSecret(secrets.current.get(f.key) ?? null) : (texts[f.key] ?? "");
        return {
          key: f.key,
          text,
          before: before?.value,
          present: before !== undefined,
          concealed,
        };
      }),
    );
    for (const f of fields) {
      if (clearSecret[f.key] === true && held.has(f.key)) {
        changes.push({ op: "clear", key: f.key });
      }
    }
    if (favorite !== current.favorite) {
      changes.push(favorite ? { op: "set", key: "item.favorite", value: "true" } : { op: "clear", key: "item.favorite" });
    }
    for (const el of [...current.uris, ...current.custom]) {
      if (removed[`${el.list}/${el.element}`] === true) {
        changes.push({ op: "removeElement", list: el.list, element: el.element });
      }
    }
    for (const t of current.tags) {
      if (removed[`tag:${t}`] === true) {
        changes.push({ op: "untag", name: t });
      }
    }
    if (newUri.trim() !== "") {
      changes.push({ op: "addUri", uri: newUri.trim() });
    }
    for (const t of newTags.split(",").map((s) => s.trim())) {
      if (t !== "" && !current.tags.includes(t)) {
        changes.push({ op: "tag", name: t });
      }
    }
    const customValue = custom.kind === "hidden" ? takeSecret(customSecret.current) : custom.value;
    if (custom.label.trim() !== "") {
      changes.push({
        op: "addCustomField",
        label: custom.label.trim(),
        kind: custom.kind,
        value: custom.kind === "boolean" ? (custom.value === "true" ? "true" : "false") : customValue,
      });
    }
    void run(async () => {
      let id = props.id;
      if (id === undefined) {
        if (props.newType === undefined) {
          return;
        }
        id = await ctx.client.call("createItem", props.newType, changes);
      } else if (changes.length > 0) {
        await ctx.client.call("editItem", id, changes);
      }
      await props.onSaved(id);
    });
  };

  return (
    <form className="panel item-editor" onSubmit={save} aria-labelledby="editor-title">
      <h2 id="editor-title">{props.id === undefined ? `New ${type}` : "Edit item"}</h2>
      {fieldsOf(type).map((f) => {
        const before = held.get(f.key);
        const concealed = before?.concealed ?? f.secret === true;
        if (concealed) {
          return (
            <div key={f.key} className="secret-edit">
              <SecretField
                label={f.label}
                name={f.key}
                inputRef={(el) => {
                  secrets.current.set(f.key, el);
                }}
                {...(before !== undefined ? { hint: "Leave empty to keep the current value." } : {})}
              />
              <div className="actions">
                {f.key === "login.password" && (
                  <button type="button" className="secondary small" onClick={() => generate(f.key)}>
                    Generate
                  </button>
                )}
                {before !== undefined && (
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={clearSecret[f.key] === true}
                      onChange={(e) => setClearSecret({ ...clearSecret, [f.key]: e.currentTarget.checked })}
                    />
                    Clear
                  </label>
                )}
              </div>
            </div>
          );
        }
        const id = `edit-${f.key}`;
        const common = {
          id,
          name: f.key,
          autoComplete: "off",
          value: texts[f.key] ?? "",
          onChange: (e: { currentTarget: { value: string } }) =>
            setTexts({ ...texts, [f.key]: e.currentTarget.value }),
        };
        return (
          <div key={f.key} className="field-edit">
            <label htmlFor={id}>{f.label}</label>
            {f.multiline === true ? <textarea rows={4} {...common} /> : <input {...common} />}
          </div>
        );
      })}
      <label className="check">
        <input type="checkbox" checked={favorite} onChange={(e) => setFavorite(e.currentTarget.checked)} />
        Favorite
      </label>

      {type === "login" && (
        <fieldset>
          <legend>Websites</legend>
          {current.uris.map((u) => {
            const k = `${u.list}/${u.element}`;
            return (
              <label key={k} className="check">
                <input
                  type="checkbox"
                  checked={removed[k] === true}
                  onChange={(e) => setRemoved({ ...removed, [k]: e.currentTarget.checked })}
                />
                Remove {u.attributes.get("value")?.value ?? ""}
              </label>
            );
          })}
          <label htmlFor="new-uri">Add a website</label>
          <input
            id="new-uri"
            name="new-uri"
            type="url"
            autoComplete="off"
            placeholder="https://"
            value={newUri}
            onChange={(e) => setNewUri(e.currentTarget.value)}
          />
        </fieldset>
      )}

      <fieldset>
        <legend>Custom fields</legend>
        {current.custom.map((c) => {
          const k = `${c.list}/${c.element}`;
          return (
            <label key={k} className="check">
              <input
                type="checkbox"
                checked={removed[k] === true}
                onChange={(e) => setRemoved({ ...removed, [k]: e.currentTarget.checked })}
              />
              Remove “{c.attributes.get("label")?.value ?? "field"}”
            </label>
          );
        })}
        <label htmlFor="custom-label">New field label</label>
        <input
          id="custom-label"
          autoComplete="off"
          value={custom.label}
          onChange={(e) => setCustom({ ...custom, label: e.currentTarget.value })}
        />
        <label htmlFor="custom-kind">Kind</label>
        <select
          id="custom-kind"
          value={custom.kind}
          onChange={(e) => setCustom({ ...custom, kind: e.currentTarget.value as "text" | "hidden" | "boolean", value: "" })}
        >
          <option value="text">Text</option>
          <option value="hidden">Hidden</option>
          <option value="boolean">Yes / no</option>
        </select>
        {custom.kind === "hidden" ? (
          <SecretField label="Value" name="custom-value" inputRef={customSecret} />
        ) : custom.kind === "boolean" ? (
          <label className="check">
            <input
              type="checkbox"
              checked={custom.value === "true"}
              onChange={(e) => setCustom({ ...custom, value: e.currentTarget.checked ? "true" : "false" })}
            />
            Yes
          </label>
        ) : (
          <>
            <label htmlFor="custom-value">Value</label>
            <input
              id="custom-value"
              autoComplete="off"
              value={custom.value}
              onChange={(e) => setCustom({ ...custom, value: e.currentTarget.value })}
            />
          </>
        )}
      </fieldset>

      <fieldset>
        <legend>Tags</legend>
        {current.tags.map((t) => (
          <label key={t} className="check">
            <input
              type="checkbox"
              checked={removed[`tag:${t}`] === true}
              onChange={(e) => setRemoved({ ...removed, [`tag:${t}`]: e.currentTarget.checked })}
            />
            Remove “{t}”
          </label>
        ))}
        <label htmlFor="new-tags">Add tags (comma-separated)</label>
        <input id="new-tags" autoComplete="off" value={newTags} onChange={(e) => setNewTags(e.currentTarget.value)} />
      </fieldset>

      <ErrorText code={error} />
      <div className="actions">
        <button type="submit" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </button>
        <button type="button" className="secondary" onClick={props.onCancel} disabled={busy}>
          Cancel
        </button>
      </div>
    </form>
  );
}

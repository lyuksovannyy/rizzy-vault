// SPDX-License-Identifier: AGPL-3.0-only

// Creating and editing an item. An edit writes only the keys the user changed, as one op
// (ADR 0018 §11; `fixedChanges`). Concealed values are never fetched to prefill the form: a
// concealed field's input starts empty, an empty input keeps the value, and "Clear" removes it.
// Secret values are typed in the secret-field component (INV-68) and read from the element
// on save, not kept in React state.
//
// Retrying a save must be idempotent, for secrets as much as for list elements (see below):
// `save()`'s synchronous part only *peeks* at a secret input's value (`peekSecret`), it never
// clears it. The DOM element is cleared (`takeSecret`/`input.value = ""`) only once the async
// `createItem`/`editItem` call has resolved successfully. So if that call fails or times out,
// every secret input still holds what the user typed, and clicking Save again resends the same
// changeset instead of silently sending an empty/omitted secret.
//
// Websites and custom fields (ADR 0018 §6–§7 "list elements"): a row the user is about to add
// gets its element id minted once, with `newElementId`, the moment it is added to the form —
// not when Save is pressed. The id travels with the row in React state and is sent again on
// every attempt to save it, so retrying a failed save (the same pending rows, submitted again)
// writes the same elements rather than creating duplicates: the write is keyed by that id, and
// writing the same key to the same value a second time changes nothing (`fields.ts`,
// `@rizzy-vault/core`'s `ItemChange`). Reordering an *already saved* row calls `editItem` with
// a `move` change right away, one small op at a time, so the list the user sees always matches
// what the move was computed against; reordering a still-pending row is a plain array swap,
// resolved only when the whole draft is first saved.
import type { CustomFieldAutofill, ItemChange, ItemSummary, ItemType } from "@rizzy-vault/core";
import { PasswordGenerateSlot, SecretField } from "@rizzy-vault/ui";
import { t } from "@rizzy-vault/i18n";
import { type FormEvent, useEffect, useId, useRef, useState } from "react";

import {
  type AutocompleteRow,
  type RowProblems,
  autocompleteProblems,
  idProblemText,
  lowercaseAscii,
  shadowedText,
} from "../autocomplete.ts";
import { CallError, codeOf } from "../core-client.ts";
import {
  type Element,
  type FixedField,
  type Grouped,
  CREATABLE_TYPES,
  FIXED_FIELDS,
  SEX_OPTIONS,
  controlOf,
  fixedChanges,
  group,
  MATCH_MODE_OPTIONS,
  MATCH_MODE_REGEX,
} from "../fields.ts";
import { GENERATOR_LIMITS } from "../generator-constants.ts";
import { fillGenerated, generateValue } from "../generator-flow.ts";
import { messageFor } from "../messages.ts";
import { useIdentityGenerator } from "./IdentityGenerator.tsx";
import { defaultVault, vaultLabel, writableVaults } from "../vaults.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, peekSecret, useAction } from "./common.tsx";

/** The element as an input, or `null` for a textarea or none: the generator fills inputs only. */
function inputOf(el: HTMLInputElement | HTMLTextAreaElement | null | undefined): HTMLInputElement | null {
  return el instanceof HTMLInputElement ? el : null;
}

/** The fields of a type this editor shows; unknown types get the title and notes only. */
function fieldsOf(type: ItemType | "unknown"): readonly FixedField[] {
  return (
    (type === "unknown" ? undefined : FIXED_FIELDS[type]) ?? [
      { key: "item.name", label: "Title" },
      { key: "item.notes", label: "Notes", multiline: true },
    ]
  );
}

/** A website or custom field the user is adding, not yet saved. Its id is minted up front
 * (module docs) so a retried save cannot create it twice. */
interface PendingUri {
  readonly id: string;
  uri: string;
  /** `uri/<id>/match`'s wire value, as a decimal string; `"0"` (account default) is never
   * written (module docs; `fields.ts` `MATCH_MODE_OPTIONS`). */
  match: string;
}

/** A custom field the user is adding, not yet saved. */
interface PendingCustom {
  readonly id: string;
  label: string;
  kind: "text" | "hidden" | "boolean";
  value: string;
  /** The autocomplete id (ADR 0076 §2), lowercased as typed; empty for none. */
  autocomplete: string;
}

/** The key of a custom field's autocomplete id. */
function autocompleteKey(element: string): string {
  return `field/${element}/autocomplete`;
}

/** Moves `index` one step `dir` (-1 up, +1 down) in `list`; a no-op at either end. */
export function moved<T>(list: readonly T[], index: number, dir: -1 | 1): T[] {
  const to = index + dir;
  if (to < 0 || to >= list.length) {
    return [...list];
  }
  const out = [...list];
  const [item] = out.splice(index, 1);
  if (item !== undefined) {
    out.splice(to, 0, item);
  }
  return out;
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
  /** The new item's vault (ADR 0081 §A8): the Personal vault, preselected every time. */
  const vaultSelectId = useId();
  const [targetVault, setTargetVault] = useState<string | undefined>(() =>
    defaultVault(ctx.vaults, ctx.personalVaultId),
  );
  const [summary, setSummary] = useState<ItemSummary | undefined>();
  const [current, setCurrent] = useState<Grouped | undefined>();
  const [texts, setTexts] = useState<Record<string, string>>({});
  // `uri/<id>/match`'s selected decimal value, keyed by the URI's element id — a separate map
  // from `texts` because an existing URI may hold no `match` register at all (ADR 0018 §7:
  // absent means the account default, `"0"`), unlike `value`/`order` which every saved URI has.
  const [matchModes, setMatchModes] = useState<Record<string, string>>({});
  const [clearSecret, setClearSecret] = useState<Record<string, boolean>>({});
  const [favorite, setFavorite] = useState(false);
  const [removed, setRemoved] = useState<Record<string, boolean>>({});
  const [reorderError, setReorderError] = useState<string | undefined>();
  const [pendingUris, setPendingUris] = useState<PendingUri[]>([]);
  const [pendingCustom, setPendingCustom] = useState<PendingCustom[]>([]);
  const [newTags, setNewTags] = useState("");
  // What each saved custom field's autocomplete id does (ADR 0076 §2.5): the "also used by"
  // warning of a merge-made duplicate. Empty for a new item.
  const [autofill, setAutofill] = useState<readonly CustomFieldAutofill[]>([]);
  // Set by the first Save press: from then on a missing Display Name is shown as an error.
  const [submitted, setSubmitted] = useState(false);
  // Autocomplete ids the user typed into saved custom fields, by `field/<element>`.
  const [autocompletes, setAutocompletes] = useState<Record<string, string>>({});
  // A fixed field's secret element: an input, or the textarea of a multi-line secret (an SSH
  // private key, ADR 0055; `SecretField`'s `multiline`).
  const secrets = useRef(new Map<string, HTMLInputElement | HTMLTextAreaElement | null>());
  const pendingCustomSecrets = useRef(new Map<string, HTMLInputElement | null>());
  const { busy, error, setError, run } = useAction();
  // Which generate slot (by field key) is mid-call, and the core's message for one whose
  // current options it refused. Keyed by field so two slots on the same form (the password and
  // a hidden custom field) do not share a spinner or an error.
  const [generating, setGenerating] = useState<Record<string, boolean>>({});
  const [generateErrors, setGenerateErrors] = useState<Record<string, string>>({});

  const type: ItemType | "unknown" = props.newType ?? summary?.itemType ?? "unknown";
  // A new identity opens pre-filled, with the generator bar (ADR 0079 §10); never on edit.
  const identityGen = useIdentityGenerator(ctx, props.id === undefined && props.newType === "identity");
  /** A shown field's text: the generator's while it holds the key, else the form's. */
  const textOf = (key: string): string => (identityGen.owns(key) ? identityGen.value(key) : (texts[key] ?? ""));

  /** Reloads the item's current fields (after an initial mount, or after an immediate reorder). */
  const reload = useRef<() => Promise<void>>(async () => undefined);
  reload.current = async () => {
    if (props.id === undefined) {
      setCurrent(group([]));
      return;
    }
    const id = props.id;
    try {
      const [s, f, a] = await Promise.all([
        ctx.client.call("item", id),
        ctx.client.call("fields", id),
        ctx.client.call("customFieldAutofill", id),
      ]);
      const g = group(f);
      setAutofill(a);
      setSummary(s);
      setCurrent(g);
      setFavorite(g.favorite);
      const initial: Record<string, string> = {};
      for (const field of g.fixed) {
        if (!field.concealed && field.value !== undefined) {
          initial[field.key] = field.value;
        }
      }
      for (const el of [...g.uris, ...g.custom]) {
        for (const attr of el.attributes.values()) {
          if (!attr.concealed && attr.value !== undefined) {
            initial[attr.key] = attr.value;
          }
        }
      }
      setTexts(initial);
      const initialMatch: Record<string, string> = {};
      for (const u of g.uris) {
        initialMatch[u.element] = u.attributes.get("match")?.value ?? "0";
      }
      setMatchModes(initialMatch);
    } catch (e: unknown) {
      setError(codeOf(e));
    }
  };

  useEffect(() => {
    void reload.current();
  }, [ctx.client, props.id]);

  if (current === undefined) {
    return <ErrorText code={error} />;
  }

  const held = new Map(current.fixed.map((f) => [f.key, f]));

  // Custom fields and their autocomplete ids (ADR 0076 §2.3–§2.5): the form's rows as the W1–W5
  // checks see them, and their problems, shown inline and checked again on Save.
  const kindOfElement = (c: Element): "text" | "hidden" | "boolean" => {
    const v = c.attributes.get("value");
    return v?.kind === "bool" ? "boolean" : v?.concealed === true ? "hidden" : "text";
  };
  const savedIdOf = (c: Element): string => c.attributes.get("autocomplete")?.value ?? "";
  const idOf = (c: Element): string => autocompletes[`${c.list}/${c.element}`] ?? savedIdOf(c);
  const labelKeyOf = (c: Element): string => `field/${c.element}/label`;
  const labelOfElement = (c: Element): string => texts[labelKeyOf(c)] ?? c.attributes.get("label")?.value ?? "";
  const editedElement = (c: Element): boolean => {
    const savedLabel = c.attributes.get("label")?.value ?? "";
    const v = c.attributes.get("value");
    return (
      labelOfElement(c) !== savedLabel ||
      idOf(c) !== savedIdOf(c) ||
      (v !== undefined && !v.concealed && (texts[v.key] ?? v.value ?? "") !== (v.value ?? "")) ||
      (v !== undefined && clearSecret[v.key] === true)
    );
  };
  const pendingTouched = (row: PendingCustom): boolean =>
    row.label.trim() !== "" || row.value !== "" || row.autocomplete !== "";
  const acRows: AutocompleteRow[] = [
    ...current.custom
      .filter((c) => removed[`${c.list}/${c.element}`] !== true)
      .map((c) => ({
        key: c.element,
        label: labelOfElement(c),
        kind: kindOfElement(c),
        id: idOf(c),
        savedId: savedIdOf(c),
        edited: editedElement(c),
      })),
    ...pendingCustom.map((row) => ({
      key: row.id,
      label: row.label,
      kind: row.kind,
      id: row.autocomplete,
      savedId: "",
      edited: pendingTouched(row),
    })),
  ];
  const acProblems = autocompleteProblems(acRows);
  /** The problems of one row, and the inline messages they render. */
  const fieldMessages = (key: string, id: string, shadowedBy: string | undefined, labelId: string) => {
    const problems: RowProblems = acProblems.get(key) ?? {};
    return (
      <>
        {problems.id !== undefined && (
          <p className="error small" id={`${labelId}-ac`}>
            {idProblemText(problems.id)}
          </p>
        )}
        {problems.id === undefined && shadowedBy !== undefined && (
          <p className="warning small" id={`${labelId}-ac`}>
            {shadowedText(id, shadowedBy)}
          </p>
        )}
        {submitted && problems.label !== undefined && (
          <p className="error small" id={`${labelId}-name`}>
            A display name is required.
          </p>
        )}
      </>
    );
  };
  const shadowedByOf = (c: Element): string | undefined => {
    const state = autofill.find((a) => a.element === c.element);
    if (state?.state !== "shadowed" || idOf(c) !== savedIdOf(c)) {
      return undefined;
    }
    return state.winnerLabel ?? "another field";
  };

  // Fills `key`'s secret input with a fresh value, using the session's shared generator
  // options (`ctx.generator`, generator-memory.ts: the same options the generator page and
  // every other generate slot in this editor last used). `getInput` is resolved at call time,
  // not captured, since the secret input it names may not exist yet when the slot is rendered
  // (e.g. a pending row added after the editor first mounted).
  //
  // Resolves `true` on a successful fill, `false` on a refusal (already recorded in
  // `generateErrors` for `key`) — never rejects. The popover's own "Generate" awaits this to
  // decide whether to close: a refusal must leave the popover open, with the offending option
  // still in view, rather than close before the user can see or fix it.
  const generate = (key: string, getInput: () => HTMLInputElement | null): Promise<boolean> => {
    setGenerating((g) => ({ ...g, [key]: true }));
    setGenerateErrors((g) =>
      Object.fromEntries(Object.entries(g).filter(([k]) => k !== key)),
    );
    return (async () => {
      try {
        const { mode, passwordOptions, passphraseOptions } = ctx.generator;
        const value = await generateValue(ctx.client, mode, passwordOptions, passphraseOptions);
        fillGenerated(getInput(), value);
        return true;
      } catch (e) {
        setGenerateErrors((g) => ({ ...g, [key]: messageFor(codeOf(e)) }));
        return false;
      } finally {
        setGenerating((g) => ({ ...g, [key]: false }));
      }
    })();
  };

  /** The props every {@link PasswordGenerateSlot} in this editor shares (module docs). */
  const generatorSlotProps = (key: string, getInput: () => HTMLInputElement | null) => ({
    fieldName: key,
    mode: ctx.generator.mode,
    onModeChange: ctx.generator.setMode,
    passwordOptions: ctx.generator.passwordOptions,
    onPasswordOptionsChange: ctx.generator.setPasswordOptions,
    passphraseOptions: ctx.generator.passphraseOptions,
    onPassphraseOptionsChange: ctx.generator.setPassphraseOptions,
    limits: GENERATOR_LIMITS,
    onGenerate: () => generate(key, getInput),
    busy: generating[key] === true,
    ...(generateErrors[key] !== undefined ? { errorMessage: generateErrors[key] } : {}),
  });

  /** Moves an already-saved element one step, right away, and reloads. */
  const moveExisting = (list: string, element: string, dir: -1 | 1, neighbours: readonly Element[]) => {
    const index = neighbours.findIndex((e) => e.element === element);
    if (index < 0) {
      return;
    }
    const to = index + dir;
    if (to < 0 || to >= neighbours.length) {
      return;
    }
    const id = props.id;
    if (id === undefined) {
      return;
    }
    void run(async () => {
      setReorderError(undefined);
      try {
        // `to` is the slot `element` should land in, still occupied (by the element it is
        // hopping over) at this point. Moving up (`dir === -1`) places it just before that
        // occupant, or first when `to` is the top; moving down places it just after.
        const place =
          dir === -1
            ? to === 0
              ? { at: "first" as const }
              : { at: "before" as const, element: neighbours[to]?.element ?? "" }
            : { at: "after" as const, element: neighbours[to]?.element ?? "" };
        await ctx.client.call("editItem", id, [{ op: "move", list, element, place }]);
        await reload.current();
      } catch (e) {
        setReorderError(codeOf(e));
      }
    });
  };

  const addPendingUri = () =>
    void run(async () => {
      const id = await ctx.client.call("newElementId");
      setPendingUris((rows) => [...rows, { id, uri: "", match: "0" }]);
    });

  const addPendingCustom = () =>
    void run(async () => {
      const id = await ctx.client.call("newElementId");
      setPendingCustom((rows) => [...rows, { id, label: "", kind: "text", value: "", autocomplete: "" }]);
    });

  const save = (e: FormEvent) => {
    e.preventDefault();
    // Secret inputs are only *peeked* here, in the synchronous part of save: the DOM element
    // must still hold its value if the async save below fails, so a retry resends the same
    // secret instead of silently dropping it (module docs; mirrors the id-based idempotency
    // for list elements). Every peeked input is collected and cleared only once the save has
    // resolved successfully, inside `run`.
    const toClear: (HTMLInputElement | HTMLTextAreaElement)[] = [];
    const peek = (input: HTMLInputElement | HTMLTextAreaElement | null | undefined): string => {
      if (input == null) {
        return "";
      }
      toClear.push(input);
      return peekSecret(input);
    };
    const fields = fieldsOf(type);
    const changes: ItemChange[] = fixedChanges(
      fields.map((f) => {
        const before = held.get(f.key);
        const concealed = before?.concealed ?? f.secret === true;
        const text = concealed ? peek(secrets.current.get(f.key)) : textOf(f.key);
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
    // Existing elements: edits (by their attribute's own key, same rule as a fixed field) and
    // removals.
    for (const el of [...current.uris, ...current.custom]) {
      const k = `${el.list}/${el.element}`;
      if (removed[k] === true) {
        changes.push({ op: "removeElement", list: el.list, element: el.element });
        continue;
      }
      for (const attr of el.attributes.values()) {
        // `order` and `kind` are layout attributes written elsewhere (reordering, the custom
        // field's own kind control); `match` is handled below, where the "absent" case (no
        // register at all) can be represented, which this generic loop cannot (module docs).
        // `autocomplete` is written by its own pass below: clearing it is a "clear", never an
        // empty set (ADR 0076 §2.1).
        if (
          attr.attribute === "order" ||
          attr.attribute === "kind" ||
          attr.attribute === "match" ||
          attr.attribute === "autocomplete"
        ) {
          continue;
        }
        if (attr.concealed) {
          const text = peek(secrets.current.get(attr.key));
          if (text !== "") {
            changes.push({ op: "set", key: attr.key, value: text });
          } else if (clearSecret[attr.key] === true) {
            changes.push({ op: "clear", key: attr.key });
          }
        } else {
          const text = texts[attr.key] ?? attr.value ?? "";
          if (text !== (attr.value ?? "")) {
            changes.push({ op: "set", key: attr.key, value: text });
          }
        }
      }
    }
    // `uri/<id>/match` of existing websites (module docs: a separate pass, since a URI may
    // hold no `match` register at all). A removed row is already covered by `removeElement`
    // above, which clears every register of the element (ADR 0018 §6), `match` included.
    for (const u of current.uris) {
      if (removed[`${u.list}/${u.element}`] === true) {
        continue;
      }
      const matchKey = `uri/${u.element}/match`;
      const held = u.attributes.get("match")?.value ?? "0";
      const selected = matchModes[u.element] ?? held;
      if (selected === held) {
        continue;
      }
      if (selected === "0") {
        changes.push({ op: "clear", key: matchKey });
      } else {
        changes.push({ op: "set", key: matchKey, value: selected });
      }
    }
    for (const t of current.tags) {
      if (removed[`tag:${t}`] === true) {
        changes.push({ op: "untag", name: t });
      }
    }
    for (const row of pendingUris) {
      if (row.uri.trim() !== "") {
        changes.push({ op: "addUri", element: row.id, uri: row.uri.trim() });
        if (row.match !== "0") {
          changes.push({ op: "set", key: `uri/${row.id}/match`, value: row.match });
        }
      }
    }
    // Saved custom fields: a Display Name typed into an unnamed one (it has no `label` register
    // for the loop above to compare against), and autocomplete ids, set or cleared.
    for (const c of current.custom) {
      if (removed[`${c.list}/${c.element}`] === true) {
        continue;
      }
      const typedLabel = texts[labelKeyOf(c)];
      if (!c.attributes.has("label") && typedLabel !== undefined && typedLabel.trim() !== "") {
        changes.push({ op: "set", key: labelKeyOf(c), value: typedLabel });
      }
      const id = idOf(c);
      if (id !== savedIdOf(c)) {
        changes.push(id === "" ? { op: "clear", key: autocompleteKey(c.element) } : { op: "set", key: autocompleteKey(c.element), value: id });
      }
    }
    // ADR 0076 §2.3: W1–W5 are checked here first, so the errors show next to their fields;
    // `rizzy-client` checks them again on write.
    if (acProblems.size > 0) {
      setSubmitted(true);
      const all = [...acProblems.values()];
      const firstId = all.find((p) => p.id !== undefined)?.id;
      setError(
        all.some((p) => p.label !== undefined)
          ? "label_required"
          : firstId === "duplicate"
            ? "autocomplete_duplicate"
            : firstId === "kind"
              ? "autocomplete_kind"
              : firstId === "reserved"
                ? "autocomplete_reserved"
                : "autocomplete_invalid",
      );
      return;
    }
    for (const row of pendingCustom) {
      if (!pendingTouched(row)) {
        continue;
      }
      const value =
        row.kind === "hidden"
          ? peek(pendingCustomSecrets.current.get(row.id))
          : row.kind === "boolean"
            ? row.value === "true"
              ? "true"
              : "false"
            : row.value;
      changes.push({
        op: "addCustomField",
        element: row.id,
        label: row.label.trim(),
        kind: row.kind,
        value,
        ...(row.autocomplete !== "" ? { autocomplete: row.autocomplete } : {}),
      });
    }
    for (const t of newTags.split(",").map((s) => s.trim())) {
      if (t !== "" && !current.tags.includes(t)) {
        changes.push({ op: "tag", name: t });
      }
    }
    void run(async () => {
      let id = props.id;
      if (id === undefined) {
        if (props.newType === undefined) {
          return;
        }
        const vault = targetVault ?? defaultVault(ctx.vaults, ctx.personalVaultId) ?? ctx.personalVaultId;
        if (vault === undefined) {
          throw new CallError("vault_set_mismatch");
        }
        id = await ctx.client.call("createItem", vault, props.newType, changes);
        identityGen.saved();
      } else if (changes.length > 0) {
        await ctx.client.call("editItem", id, changes);
      }
      // Only now that the save has resolved successfully: clear the secret inputs so a typed
      // value doesn't linger in the DOM. A failed call above throws before this line, leaving
      // every input untouched for a retry to resend.
      for (const input of toClear) {
        input.value = "";
      }
      await props.onSaved(id);
    });
  };

  return (
    <form className="panel item-editor" onSubmit={save} aria-labelledby="editor-title">
      <h2 id="editor-title">
        {props.id === undefined ? `New ${CREATABLE_TYPES.find((t) => t.type === type)?.noun ?? type}` : "Edit item"}
      </h2>
      {props.id === undefined && writableVaults(ctx.vaults).length > 0 && (
        <div className="field-edit">
          <label htmlFor={vaultSelectId}>{t("vaults.picker")}</label>
          <select
            id={vaultSelectId}
            name="item-vault"
            value={targetVault ?? ""}
            onChange={(e) => setTargetVault(e.currentTarget.value)}
          >
            {writableVaults(ctx.vaults).map((v) => (
              <option key={v.id} value={v.id}>
                {vaultLabel(v)}
              </option>
            ))}
          </select>
        </div>
      )}
      {identityGen.bar}
      {fieldsOf(type).map((f) => {
        const before = held.get(f.key);
        const concealed = before?.concealed ?? f.secret === true;
        if (concealed) {
          return (
            <div key={f.key} className="secret-edit">
              <SecretField
                label={f.label}
                name={f.key}
                {...(f.multiline === true
                  ? {
                      multiline: true,
                      textareaRef: (el: HTMLTextAreaElement | null) => {
                        secrets.current.set(f.key, el);
                      },
                    }
                  : {
                      inputRef: (el: HTMLInputElement | null) => {
                        secrets.current.set(f.key, el);
                      },
                    })}
                {...(before !== undefined ? { hint: "Leave empty to keep the current value." } : {})}
              />
              <div className="actions">
                {f.key === "login.password" && (
                  <PasswordGenerateSlot {...generatorSlotProps(f.key, () => inputOf(secrets.current.get(f.key)))} />
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
        const extras = identityGen.extras(f.key, id);
        const common = {
          id,
          name: f.key,
          autoComplete: "off",
          value: textOf(f.key),
          onChange: (e: { currentTarget: { value: string } }) => {
            const value = e.currentTarget.value;
            if (identityGen.owns(f.key)) {
              identityGen.type(f.key, value);
            } else {
              setTexts((t) => ({ ...t, [f.key]: value }));
            }
          },
          // What an empty field means (`ssh.port`: 22, never stored; ADR 0055 §1).
          ...(f.placeholder !== undefined ? { placeholder: f.placeholder } : {}),
          ...(extras.describedBy !== undefined ? { "aria-describedby": extras.describedBy } : {}),
        };
        // Sex and Birthday (ADR 0079 §1): a select or a date input only for a value they show
        // unchanged, decided from the stored value (or, on create, the form's), else as entered.
        const control = controlOf(f, before !== undefined ? (before.value ?? "") : textOf(f.key));
        const input =
          f.multiline === true ? (
            <textarea rows={4} {...common} />
          ) : control === "sex" ? (
            <select {...common}>
              <option value="">Not set</option>
              {SEX_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          ) : control === "date" ? (
            <input type="date" {...common} />
          ) : (
            <input {...common} />
          );
        return (
          <div key={f.key} className="field-edit">
            <label htmlFor={id}>{f.label}</label>
            {extras.after === null ? (
              input
            ) : extras.describedBy !== undefined ? (
              <>
                {input}
                {extras.after}
              </>
            ) : (
              <div className="field-edit-row">
                {input}
                {extras.after}
              </div>
            )}
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
          <ErrorText code={reorderError} />
          {current.uris.map((u, index) => {
            const k = `${u.list}/${u.element}`;
            const valueKey = u.attributes.get("value")?.key ?? "";
            const matchValue = matchModes[u.element] ?? u.attributes.get("match")?.value ?? "0";
            return (
              <div key={k} className="list-row">
                <input
                  type="url"
                  autoComplete="off"
                  aria-label={`Website ${index + 1}`}
                  value={texts[valueKey] ?? u.attributes.get("value")?.value ?? ""}
                  disabled={removed[k] === true}
                  onChange={(e) => setTexts({ ...texts, [valueKey]: e.currentTarget.value })}
                />
                <select
                  aria-label={`Website ${index + 1} match mode`}
                  value={matchValue}
                  disabled={removed[k] === true}
                  onChange={(e) =>
                    setMatchModes({ ...matchModes, [u.element]: e.currentTarget.value })
                  }
                >
                  {MATCH_MODE_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
                {Number.parseInt(matchValue, 10) === MATCH_MODE_REGEX && (
                  <p className="muted small">
                    Regex matching is not evaluated by this build yet: this website will never
                    be offered for autofill until that lands.
                  </p>
                )}
                <div className="row-actions">
                  <button
                    type="button"
                    className="secondary small"
                    aria-label={`Move website ${index + 1} up`}
                    disabled={index === 0}
                    onClick={() => moveExisting(u.list, u.element, -1, current.uris)}
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    className="secondary small"
                    aria-label={`Move website ${index + 1} down`}
                    disabled={index === current.uris.length - 1}
                    onClick={() => moveExisting(u.list, u.element, 1, current.uris)}
                  >
                    ↓
                  </button>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={removed[k] === true}
                      onChange={(e) => setRemoved({ ...removed, [k]: e.currentTarget.checked })}
                    />
                    Remove
                  </label>
                </div>
              </div>
            );
          })}
          {pendingUris.map((row, index) => (
            <div key={row.id} className="list-row">
              <input
                type="url"
                autoComplete="off"
                placeholder="https://"
                aria-label={`New website ${index + 1}`}
                value={row.uri}
                onChange={(e) => {
                  const uri = e.currentTarget.value;
                  setPendingUris((rows) => rows.map((r) => (r.id === row.id ? { ...r, uri } : r)));
                }}
              />
              <select
                aria-label={`New website ${index + 1} match mode`}
                value={row.match}
                onChange={(e) => {
                  const match = e.currentTarget.value;
                  setPendingUris((rows) => rows.map((r) => (r.id === row.id ? { ...r, match } : r)));
                }}
              >
                {MATCH_MODE_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
              {Number.parseInt(row.match, 10) === MATCH_MODE_REGEX && (
                <p className="muted small">
                  Regex matching is not evaluated by this build yet: this website will never be
                  offered for autofill until that lands.
                </p>
              )}
              <div className="row-actions">
                <button
                  type="button"
                  className="secondary small"
                  aria-label={`Move new website ${index + 1} up`}
                  disabled={index === 0}
                  onClick={() => setPendingUris((rows) => moved(rows, index, -1))}
                >
                  ↑
                </button>
                <button
                  type="button"
                  className="secondary small"
                  aria-label={`Move new website ${index + 1} down`}
                  disabled={index === pendingUris.length - 1}
                  onClick={() => setPendingUris((rows) => moved(rows, index, 1))}
                >
                  ↓
                </button>
                <button
                  type="button"
                  className="secondary small"
                  onClick={() => setPendingUris((rows) => rows.filter((r) => r.id !== row.id))}
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
          <button type="button" className="secondary" onClick={addPendingUri} disabled={busy}>
            Add a website
          </button>
        </fieldset>
      )}

      <fieldset>
        <legend>Custom fields</legend>
        {current.custom.map((c, index) => {
          const k = `${c.list}/${c.element}`;
          const labelKey = labelKeyOf(c);
          const valueField = c.attributes.get("value");
          const kind = kindOfElement(c);
          const problems = acProblems.get(c.element) ?? {};
          const msgId = `cf-${c.element}`;
          const id = idOf(c);
          const shadowedBy = shadowedByOf(c);
          return (
            <div key={k} className="list-row custom-field-row">
              <input
                type="text"
                autoComplete="off"
                aria-label={`Custom field ${index + 1} label`}
                placeholder={c.attributes.has("label") ? "Display name" : "Unnamed field"}
                aria-required="true"
                aria-invalid={submitted && problems.label !== undefined}
                aria-describedby={submitted && problems.label !== undefined ? `${msgId}-name` : undefined}
                value={labelOfElement(c)}
                disabled={removed[k] === true}
                onChange={(e) => setTexts({ ...texts, [labelKey]: e.currentTarget.value })}
              />
              {kind === "hidden" ? (
                <div className="secret-edit">
                  <SecretField
                    label="Value"
                    name={`${k}-value`}
                    inputRef={(el) => {
                      secrets.current.set(valueField?.key ?? k, el);
                    }}
                    hint="Leave empty to keep the current value."
                  />
                  <PasswordGenerateSlot
                    {...generatorSlotProps(valueField?.key ?? k, () => inputOf(secrets.current.get(valueField?.key ?? k)))}
                  />
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={clearSecret[valueField?.key ?? k] === true}
                      onChange={(e) =>
                        setClearSecret({ ...clearSecret, [valueField?.key ?? k]: e.currentTarget.checked })
                      }
                    />
                    Clear
                  </label>
                </div>
              ) : kind === "boolean" ? (
                <label className="check">
                  <input
                    type="checkbox"
                    checked={(texts[valueField?.key ?? ""] ?? valueField?.value) === "true"}
                    onChange={(e) =>
                      setTexts({
                        ...texts,
                        [valueField?.key ?? ""]: e.currentTarget.checked ? "true" : "false",
                      })
                    }
                  />
                  Yes
                </label>
              ) : (
                <input
                  type="text"
                  autoComplete="off"
                  aria-label={`Custom field ${index + 1} value`}
                  value={texts[valueField?.key ?? ""] ?? valueField?.value ?? ""}
                  disabled={removed[k] === true}
                  onChange={(e) => setTexts({ ...texts, [valueField?.key ?? ""]: e.currentTarget.value })}
                />
              )}
              {(kind !== "boolean" || id !== "") && (
                <input
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  aria-label={`Custom field ${index + 1} autocomplete id`}
                  placeholder="Autocomplete id (optional)"
                  aria-invalid={problems.id !== undefined}
                  aria-describedby={problems.id !== undefined || shadowedBy !== undefined ? `${msgId}-ac` : undefined}
                  value={id}
                  disabled={removed[k] === true}
                  onChange={(e) => setAutocompletes({ ...autocompletes, [k]: lowercaseAscii(e.currentTarget.value) })}
                />
              )}
              {removed[k] !== true && fieldMessages(c.element, id, shadowedBy, msgId)}
              <div className="row-actions">
                <button
                  type="button"
                  className="secondary small"
                  aria-label={`Move custom field ${index + 1} up`}
                  disabled={index === 0}
                  onClick={() => moveExisting(c.list, c.element, -1, current.custom)}
                >
                  ↑
                </button>
                <button
                  type="button"
                  className="secondary small"
                  aria-label={`Move custom field ${index + 1} down`}
                  disabled={index === current.custom.length - 1}
                  onClick={() => moveExisting(c.list, c.element, 1, current.custom)}
                >
                  ↓
                </button>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={removed[k] === true}
                    onChange={(e) => setRemoved({ ...removed, [k]: e.currentTarget.checked })}
                  />
                  Remove
                </label>
              </div>
            </div>
          );
        })}
        {pendingCustom.map((row, index) => (
          <div key={row.id} className="list-row custom-field-row">
            <input
              type="text"
              autoComplete="off"
              placeholder="Display name (required)"
              aria-label={`New custom field ${index + 1} label`}
              aria-required="true"
              aria-invalid={submitted && acProblems.get(row.id)?.label !== undefined}
              aria-describedby={submitted && acProblems.get(row.id)?.label !== undefined ? `cf-${row.id}-name` : undefined}
              value={row.label}
              onChange={(e) => {
                const label = e.currentTarget.value;
                setPendingCustom((rows) => rows.map((r) => (r.id === row.id ? { ...r, label } : r)));
              }}
            />
            <select
              aria-label={`New custom field ${index + 1} kind`}
              value={row.kind}
              onChange={(e) => {
                const kind = e.currentTarget.value as PendingCustom["kind"];
                setPendingCustom((rows) =>
                  rows.map((r) => (r.id === row.id ? { ...r, kind, value: "" } : r)),
                );
              }}
            >
              <option value="text">Text</option>
              <option value="hidden">Hidden</option>
              <option value="boolean">Yes / no</option>
            </select>
            {row.kind === "hidden" ? (
              <>
                <SecretField
                  label="Value"
                  name={`${row.id}-value`}
                  inputRef={(el) => {
                    pendingCustomSecrets.current.set(row.id, el);
                  }}
                />
                <PasswordGenerateSlot
                  {...generatorSlotProps(`${row.id}-value`, () => pendingCustomSecrets.current.get(row.id) ?? null)}
                />
              </>
            ) : row.kind === "boolean" ? (
              <label className="check">
                <input
                  type="checkbox"
                  checked={row.value === "true"}
                  onChange={(e) => {
                    const value = e.currentTarget.checked ? "true" : "false";
                    setPendingCustom((rows) => rows.map((r) => (r.id === row.id ? { ...r, value } : r)));
                  }}
                />
                Yes
              </label>
            ) : (
              <input
                type="text"
                autoComplete="off"
                aria-label={`New custom field ${index + 1} value`}
                value={row.value}
                onChange={(e) => {
                  const value = e.currentTarget.value;
                  setPendingCustom((rows) => rows.map((r) => (r.id === row.id ? { ...r, value } : r)));
                }}
              />
            )}
            {row.kind !== "boolean" || row.autocomplete !== "" ? (
              <input
                type="text"
                autoComplete="off"
                spellCheck={false}
                aria-label={`New custom field ${index + 1} autocomplete id`}
                placeholder="Autocomplete id (optional)"
                aria-invalid={acProblems.get(row.id)?.id !== undefined}
                aria-describedby={acProblems.get(row.id)?.id !== undefined ? `cf-${row.id}-ac` : undefined}
                value={row.autocomplete}
                onChange={(e) => {
                  const autocomplete = lowercaseAscii(e.currentTarget.value);
                  setPendingCustom((rows) => rows.map((r) => (r.id === row.id ? { ...r, autocomplete } : r)));
                }}
              />
            ) : null}
            {fieldMessages(row.id, row.autocomplete, undefined, `cf-${row.id}`)}
            <div className="row-actions">
              <button
                type="button"
                className="secondary small"
                aria-label={`Move new custom field ${index + 1} up`}
                disabled={index === 0}
                onClick={() => setPendingCustom((rows) => moved(rows, index, -1))}
              >
                ↑
              </button>
              <button
                type="button"
                className="secondary small"
                aria-label={`Move new custom field ${index + 1} down`}
                disabled={index === pendingCustom.length - 1}
                onClick={() => setPendingCustom((rows) => moved(rows, index, 1))}
              >
                ↓
              </button>
              <button
                type="button"
                className="secondary small"
                onClick={() => setPendingCustom((rows) => rows.filter((r) => r.id !== row.id))}
              >
                Remove
              </button>
            </div>
          </div>
        ))}
        <button type="button" className="secondary" onClick={addPendingCustom} disabled={busy}>
          Add a custom field
        </button>
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
        <input
          id="new-tags"
          autoComplete="off"
          list="tag-suggestions"
          value={newTags}
          onChange={(e) => setNewTags(e.currentTarget.value)}
        />
        <datalist id="tag-suggestions">
          {current.tags.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
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

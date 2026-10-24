// SPDX-License-Identifier: AGPL-3.0-only

// The extension-origin save dialog's own script (ADR 0076 §5.2–§5.3). Framework-free, like the
// inline menu. It asks the long-lived context for the pending prompt's rows by the save-prompt
// token (never trusting the page for them), lets the user tick rows and edit a new field's
// Display Name (an empty one cannot be saved: W5), and answers on a trusted click only.
import "@rizzy-vault/ui/tokens.css";
import "../surface.css";

import { SAVE_DIALOG_DONE, dialogTitle, isSaveDialogShowMessage, rowText } from "./protocol.ts";
import type {
  SaveDialogChoicesMessage,
  SaveDialogRequestMessage,
  SaveDialogResolveMessage,
} from "../messaging/contract.ts";

/** One element of `index.html`, of the expected kind. */
function byId<T extends HTMLElement>(id: string, kind: { new (): T; prototype: T }): T {
  const el = document.getElementById(id);
  if (!(el instanceof kind)) {
    throw new Error(`save-dialog: #${id} is missing from index.html`);
  }
  return el;
}

const title = byId("dialog-title", HTMLElement);
const host = byId("dialog-host", HTMLElement);
const rowsBox = byId("rows", HTMLFieldSetElement);
const saveButton = byId("save", HTMLButtonElement);
const dismissButton = byId("dismiss", HTMLButtonElement);
const errorLine = byId("dialog-error", HTMLElement);

let replyOrigin: string | undefined;
let instanceToken: string | undefined;
let promptToken: string | undefined;
let suggestion: "save" | "update" = "save";
/** Each rendered row: its index, checkbox and (for "add") Display Name input. */
let rendered: { readonly index: number; readonly box: HTMLInputElement; readonly name: HTMLInputElement | undefined }[] = [];

function runtime(): typeof chrome | undefined {
  return typeof chrome !== "undefined" ? chrome : browser;
}

function isChoices(value: unknown): value is SaveDialogChoicesMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    v["type"] === "save_dialog_choices" &&
    (v["suggestion"] === "save" || v["suggestion"] === "update") &&
    typeof v["pageHost"] === "string" &&
    Array.isArray(v["rows"]) &&
    (v["rows"] as unknown[]).length <= 8 &&
    (v["rows"] as unknown[]).every((r) => {
      if (typeof r !== "object" || r === null) {
        return false;
      }
      const row = r as Record<string, unknown>;
      return (
        typeof row["index"] === "number" &&
        (row["kind"] === "add" || row["kind"] === "update") &&
        typeof row["label"] === "string" &&
        row["label"].length <= 256 &&
        typeof row["concealed"] === "boolean" &&
        typeof row["checked"] === "boolean"
      );
    })
  );
}

function render(choices: SaveDialogChoicesMessage): void {
  suggestion = choices.suggestion;
  title.textContent = dialogTitle(choices.suggestion, choices.itemTitle);
  host.textContent = choices.pageHost;
  saveButton.textContent = choices.suggestion === "save" ? "Save" : "Update";
  rendered = [];
  for (const old of Array.from(rowsBox.querySelectorAll("div"))) {
    old.remove();
  }
  for (const row of choices.rows) {
    const line = document.createElement("div");
    const id = "row-" + String(row.index);
    const box = document.createElement("input");
    box.type = "checkbox";
    box.id = id;
    box.checked = row.checked;
    const label = document.createElement("label");
    label.htmlFor = id;
    label.textContent = rowText(row.kind, row.label, row.concealed);
    line.append(box, label);
    let name: HTMLInputElement | undefined;
    if (row.kind === "add") {
      name = document.createElement("input");
      name.type = "text";
      name.value = row.label;
      name.maxLength = 256;
      name.setAttribute("aria-label", "Display name for " + row.label);
      name.autocomplete = "off";
      line.append(" ", name);
    }
    rowsBox.appendChild(line);
    rendered.push({ index: row.index, box, name });
  }
  rowsBox.hidden = choices.rows.length === 0;
  updateSave();
}

/** W5: a ticked new field needs a non-blank Display Name; Save waits for one. */
function updateSave(): void {
  saveButton.disabled = rendered.some((r) => r.box.checked && r.name !== undefined && r.name.value.trim() === "");
}

rowsBox.addEventListener("input", updateSave);
rowsBox.addEventListener("change", updateSave);

window.addEventListener("message", (event) => {
  if (event.source !== window.parent || !isSaveDialogShowMessage(event.data)) {
    return;
  }
  // The page can post a show message too (the forgeable direction, `protocol.ts`). A show
  // message is adopted only once the long-lived context answers it with real choices, which a
  // forged instance token or prompt token never gets: a forgery cannot replace the dialog's
  // state, only fail.
  const shown = event.data;
  const ext = runtime();
  if (ext === undefined) {
    return;
  }
  void ext.runtime
    .sendMessage({ type: "save_dialog_request", instanceToken: shown.instanceToken, token: shown.token } satisfies SaveDialogRequestMessage)
    .then((answer: unknown) => {
      if (isChoices(answer)) {
        replyOrigin = shown.pageOrigin;
        instanceToken = shown.instanceToken;
        promptToken = shown.token;
        render(answer);
      }
    })
    .catch(() => undefined);
});

function finish(action: "save" | "update" | "dismiss", event: MouseEvent): void {
  // INV-36: only a real click in this extension-origin document answers the prompt.
  if (!event.isTrusted) {
    return;
  }
  const ext = runtime();
  const token = instanceToken;
  const prompt = promptToken;
  const origin = replyOrigin;
  if (ext === undefined || token === undefined || prompt === undefined || origin === undefined) {
    return;
  }
  const rows = action === "dismiss" ? [] : rendered.filter((r) => r.box.checked).map((r) => ({ index: r.index, label: r.name?.value ?? "" }));
  saveButton.disabled = true;
  dismissButton.disabled = true;
  void ext.runtime
    .sendMessage({ type: "save_dialog_resolve", instanceToken: token, token: prompt, action, rows } satisfies SaveDialogResolveMessage)
    .catch(() => undefined)
    .then((answer: unknown) => {
      const done = typeof answer === "object" && answer !== null && (answer as Record<string, unknown>)["type"] === "save_prompt_done";
      if (done || action === "dismiss") {
        window.parent.postMessage({ type: SAVE_DIALOG_DONE }, origin);
        return;
      }
      // The prompt is gone either way (it is answered once); say so instead of vanishing.
      errorLine.textContent = "Could not save this login. Open rizzy-vault to add it by hand.";
      const code = typeof answer === "object" && answer !== null ? (answer as Record<string, unknown>)["code"] : undefined;
      errorLine.dataset["code"] = typeof code === "string" ? code.slice(0, 200) : "no_answer";
      dismissButton.disabled = false;
    });
}

saveButton.addEventListener("click", (event) => finish(suggestion, event));
dismissButton.addEventListener("click", (event) => finish("dismiss", event));

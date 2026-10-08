// Runtime validation of every message the background receives from a content script
// (ADR 0036 §4, INV-40: "the background treats every content-script message as untrusted").
// `parseFromContentScript` is the one entry point the service worker calls; it never trusts the
// caller's type annotation, because a compromised or outdated content script is exactly the
// threat this file defends against (THREAT_MODEL A7).
//
// Checks run in this fixed order, each cheap and total before the next, so a hostile payload
// cannot reach an expensive or unsafe path: (1) overall byte budget, (2) is it a plain object,
// (3) does `type` name a known message, (4) does every field of that variant have the right
// type and fit its own length budget. A message that fails any check is refused whole: this
// module never repairs or truncates a bad message.
import {
  type CredentialsSubmittedMessage,
  type FieldDescriptor,
  type FieldsDetectedMessage,
  type FillChosenMessage,
  type FromContentScript,
  MAX_FIELDS_PER_REPORT,
  MAX_FIELD_VALUE_LEN,
  MAX_MESSAGE_BYTES,
  MAX_URL_LEN,
} from "./contract.ts";

export class MessageRejected extends Error {
  constructor(reason: string) {
    super(`message rejected: ${reason}`);
    this.name = "MessageRejected";
  }
}

/** A rough but cheap byte-size estimate: exact enough to reject pathological input without the
 * cost of a full UTF-8 byte count on every message. */
function approximateByteSize(message: unknown): number {
  try {
    return JSON.stringify(message).length;
  } catch {
    // Not structured-clone/JSON-safe (a function, a cyclic object, a class instance): reject.
    return Number.POSITIVE_INFINITY;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, maxLen: number): value is string {
  return typeof value === "string" && value.length <= maxLen;
}

function isBoundedUrl(value: unknown): value is string {
  return isBoundedString(value, MAX_URL_LEN);
}

function isFieldDescriptor(value: unknown): value is FieldDescriptor {
  if (!isPlainObject(value)) {
    return false;
  }
  if (!isBoundedString(value["fieldId"], 256)) {
    return false;
  }
  if (value["kind"] !== "username" && value["kind"] !== "password" && value["kind"] !== "other") {
    return false;
  }
  if (typeof value["visible"] !== "boolean") {
    return false;
  }
  if (value["currentValue"] !== undefined && !isBoundedString(value["currentValue"], MAX_FIELD_VALUE_LEN)) {
    return false;
  }
  // A password's current value is never reported (ADR 0036 §4): enforced here, not left to the
  // content script's own good behaviour.
  if (value["kind"] === "password" && value["currentValue"] !== undefined) {
    return false;
  }
  return true;
}

function parseFieldsDetected(body: Record<string, unknown>): FieldsDetectedMessage {
  if (!isBoundedUrl(body["pageUrl"])) {
    throw new MessageRejected("fields_detected: pageUrl");
  }
  if (typeof body["isTopFrame"] !== "boolean") {
    throw new MessageRejected("fields_detected: isTopFrame");
  }
  if (!Array.isArray(body["fields"]) || body["fields"].length > MAX_FIELDS_PER_REPORT) {
    throw new MessageRejected("fields_detected: fields");
  }
  const fields = body["fields"] as unknown[];
  if (!fields.every(isFieldDescriptor)) {
    throw new MessageRejected("fields_detected: fields[]");
  }
  return {
    type: "fields_detected",
    pageUrl: body["pageUrl"],
    isTopFrame: body["isTopFrame"],
    fields: fields as FieldDescriptor[],
  };
}

function parseFillChosen(body: Record<string, unknown>): FillChosenMessage {
  if (!isBoundedUrl(body["pageUrl"])) {
    throw new MessageRejected("fill_chosen: pageUrl");
  }
  if (typeof body["isTopFrame"] !== "boolean") {
    throw new MessageRejected("fill_chosen: isTopFrame");
  }
  if (!isBoundedString(body["itemId"], 256)) {
    throw new MessageRejected("fill_chosen: itemId");
  }
  if (
    !Array.isArray(body["fieldIds"]) ||
    body["fieldIds"].length === 0 ||
    body["fieldIds"].length > MAX_FIELDS_PER_REPORT ||
    !body["fieldIds"].every((v) => isBoundedString(v, 256))
  ) {
    throw new MessageRejected("fill_chosen: fieldIds");
  }
  return {
    type: "fill_chosen",
    pageUrl: body["pageUrl"],
    isTopFrame: body["isTopFrame"],
    itemId: body["itemId"],
    fieldIds: body["fieldIds"] as string[],
  };
}

function parseCredentialsSubmitted(body: Record<string, unknown>): CredentialsSubmittedMessage {
  if (!isBoundedUrl(body["pageUrl"])) {
    throw new MessageRejected("credentials_submitted: pageUrl");
  }
  if (body["usernameValue"] !== undefined && !isBoundedString(body["usernameValue"], MAX_FIELD_VALUE_LEN)) {
    throw new MessageRejected("credentials_submitted: usernameValue");
  }
  if (body["passwordValue"] !== undefined && !isBoundedString(body["passwordValue"], MAX_FIELD_VALUE_LEN)) {
    throw new MessageRejected("credentials_submitted: passwordValue");
  }
  const out: CredentialsSubmittedMessage = { type: "credentials_submitted", pageUrl: body["pageUrl"] };
  return {
    ...out,
    ...(body["usernameValue"] !== undefined ? { usernameValue: body["usernameValue"] as string } : {}),
    ...(body["passwordValue"] !== undefined ? { passwordValue: body["passwordValue"] as string } : {}),
  };
}

/**
 * Validates and narrows a raw message claimed to come from a content script. Throws
 * {@link MessageRejected} for anything that does not exactly match one known shape within its
 * size budget. The caller (the service worker) still must not trust `pageUrl` for the sender's
 * actual origin — that comes only from `sender.origin`/`sender.tab.url` (`sender.ts`).
 */
export function parseFromContentScript(raw: unknown): FromContentScript {
  if (approximateByteSize(raw) > MAX_MESSAGE_BYTES) {
    throw new MessageRejected("over MAX_MESSAGE_BYTES");
  }
  if (!isPlainObject(raw)) {
    throw new MessageRejected("not a plain object");
  }
  switch (raw["type"]) {
    case "fields_detected":
      return parseFieldsDetected(raw);
    case "fill_chosen":
      return parseFillChosen(raw);
    case "credentials_submitted":
      return parseCredentialsSubmitted(raw);
    default:
      throw new MessageRejected(`unknown type: ${String(raw["type"])}`);
  }
}

// SPDX-License-Identifier: AGPL-3.0-only

// A device removal under way on another device (ADR 0091 §2, `src/revocation.ts`): the banner
// says the core's sentence word for word, the refused write has its own error text, and the
// Devices pane's state puts a verified revocation before the server's unsigned "suspended".
import { revocationPendingNotice } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";
import { beforeAll, describe, expect, it } from "vitest";

import { messageFor } from "../src/messages.ts";
import { REVOCATION_PENDING, deviceStateText } from "../src/revocation.ts";
import { loadCore } from "./load-core.ts";

beforeAll(() => {
  loadCore();
});

describe("the revocation_pending banner and error", () => {
  it("says ADR 0091 §2's sentence, the core's own (rizzy-client REVOCATION_PENDING_MESSAGE)", () => {
    const sentence = "Another of your devices is removing a device. Changes are paused for up to 10 minutes.";
    expect(t("revocation.pending")).toBe(sentence);
    expect(revocationPendingNotice()).toBe(sentence);
  });

  it("words the refused write once the retries are over", () => {
    expect(REVOCATION_PENDING).toBe("server_revocation_pending");
    const text = messageFor(REVOCATION_PENDING);
    expect(text).toBe(t("errors.server_revocation_pending"));
    expect(text).toContain("removing a device");
    expect(text).not.toContain("server_revocation_pending");
  });
});

describe("the Devices pane's state", () => {
  it("is Revoked, Suspended or Active, a verified revocation first", () => {
    expect(deviceStateText({ revoked: false, suspended: false })).toBe("Active");
    expect(deviceStateText({ revoked: false, suspended: true })).toBe("Suspended");
    expect(deviceStateText({ revoked: true, suspended: false })).toBe("Revoked");
    expect(deviceStateText({ revoked: true, suspended: true })).toBe("Revoked");
  });
});

// SPDX-License-Identifier: AGPL-3.0-only

// The Sessions section's words (ADR 0075 §9) and the session-ended signal of the Worker (§6).
import type { SessionRowView } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { CoreClient, type WorkerPort } from "../src/core-client.ts";
import { messageFor } from "../src/messages.ts";
import { type FromWorker, METHODS, SESSION_ENDED, type ToWorker } from "../src/protocol.ts";
import { sessionHint, sessionLabel } from "../src/views/SessionsSection.tsx";

/** A row of `kind`. */
function row(kind: string, extra: Partial<SessionRowView> = {}): SessionRowView {
  return {
    id: "ab".repeat(16),
    kind,
    deviceId: kind === "device" || kind === "password-recheck" ? "cd".repeat(16) : undefined,
    createdAtMs: 1,
    expiresAtMs: 2,
    current: false,
    endable: kind === "password-login" || kind === "password-recheck" || kind === "recovery",
    ...extra,
  };
}

describe("session rows", () => {
  it("are named as ADR 0075 §9 names them", () => {
    expect(sessionLabel(row("password-login"))).toBe("Web or password login");
    expect(sessionLabel(row("password-recheck"))).toMatch(/^Password re-check on device cdcdcdcd/);
    expect(sessionLabel(row("device"))).toMatch(/^Device cdcdcdcd/);
    expect(sessionLabel(row("recovery"))).toBe("Account recovery in progress");
    expect(sessionLabel(row("passkey"))).toBe("Session of an unknown kind");
  });

  it("send a device to suspension and a recovery to its cancellation, never to End", () => {
    expect(sessionHint(row("device"))).toBe("Use another of your devices to suspend or revoke it.");
    expect(sessionHint(row("recovery"))).toMatch(/cancel it from one of your enrolled devices/);
    expect(sessionHint(row("password-login"))).toBeUndefined();
    expect(sessionHint(row("password-login", { current: true, endable: false }))).toMatch(
      /This browser/,
    );
  });
});

describe("an ended session", () => {
  it("is a call the Worker serves and a code with its own words", () => {
    for (const m of ["sessions", "endSession", "endOtherSessions", "refreshSession"]) {
      expect(METHODS).toContain(m);
    }
    expect(messageFor(SESSION_ENDED)).toBe("This session has ended. Log in again.");
  });

  it("tells the handler once the Worker answers session_ended", async () => {
    let listener: ((event: MessageEvent<unknown>) => void) | undefined;
    const sent: ToWorker[] = [];
    const port: WorkerPort = {
      postMessage: (message) => sent.push(message),
      addEventListener: (_type, l) => {
        listener = l;
      },
    };
    const client = new CoreClient(port);
    let ended = 0;
    client.setSessionEndedHandler(() => {
      ended += 1;
    });
    const reply = (data: FromWorker) => listener?.({ data } as MessageEvent<unknown>);

    const sync = client.call("sync");
    reply({ kind: "result", id: 1, ok: false, code: "server_unauthorized" });
    await expect(sync).rejects.toMatchObject({ code: "server_unauthorized" });
    expect(ended).toBe(0);

    const again = client.call("sync");
    reply({ kind: "result", id: 2, ok: false, code: SESSION_ENDED });
    await expect(again).rejects.toMatchObject({ code: SESSION_ENDED });
    expect(ended).toBe(1);

    client.setSessionEndedHandler(undefined);
    const third = client.call("sync");
    reply({ kind: "result", id: 3, ok: false, code: SESSION_ENDED });
    await expect(third).rejects.toMatchObject({ code: SESSION_ENDED });
    expect(ended).toBe(1);
    expect(sent).toHaveLength(3);
  });
});

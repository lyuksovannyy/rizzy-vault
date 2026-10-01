// Every code gets a message, and no message echoes input (INV-48).
import { describe, expect, it } from "vitest";

import { messageFor } from "../src/messages.ts";
import { KIT_LOSS_WARNING, KIT_TAKEOVER_WARNING, kitHtml } from "../src/kit.ts";

describe("messages", () => {
  it("words known codes and names unknown ones", () => {
    expect(messageFor("wrong_password_or_secret_key")).toContain("Secret Key");
    expect(messageFor("core_crashed")).toContain("Reload");
    expect(messageFor("something_new")).toBe("Something went wrong (something_new).");
  });
});

describe("the Emergency Kit file", () => {
  const kit = {
    serverOrigin: "https://vault.example",
    loginName: "alice",
    secretKey: "RV1-AAAA",
    recoveryCode: "RVR1-BBBB",
  };

  it("holds the server, login name, Secret Key and recovery code, never the password", () => {
    const html = kitHtml(kit);
    expect(html).toContain("<code>https://vault.example</code>");
    expect(html).toContain("<code>RV1-AAAA</code>");
    expect(html).toContain("<dt>Recovery code</dt>");
    expect(html).toContain("<code>RVR1-BBBB</code>");
    expect(html).toContain("<dt>Master password</dt>\n<dd>____");
    expect(kitHtml({ ...kit, recoveryCode: undefined })).not.toContain("Recovery code");
  });

  it("says the CRYPTO.md §7 warnings in plain words, with or without a recovery code", () => {
    expect(KIT_TAKEOVER_WARNING).toBe(
      "Anyone with this sheet and access to your server can take over your account.",
    );
    expect(KIT_LOSS_WARNING).toContain("your data is gone");
    for (const k of [kit, { ...kit, recoveryCode: undefined }]) {
      const html = kitHtml(k);
      expect(html).toContain(KIT_TAKEOVER_WARNING);
      expect(html).toContain(KIT_LOSS_WARNING);
    }
  });

  it("loads nothing, runs nothing, and escapes every value", () => {
    const html = kitHtml({ ...kit, loginName: `<script>alert("x")</script>&'` });
    expect(html).toContain(`content="default-src 'none'"`);
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#39;");
  });
});

// The generator view (ADR 0036 §4 "generator in field"; ROADMAP §4.4). Needs no device state,
// so it is real today, unlike the item list/detail views it sits next to in the popup.
import { useState } from "react";

import type { ExtensionClient } from "../../core/client.ts";

export interface GeneratorViewProps {
  readonly client: ExtensionClient;
}

export function GeneratorView({ client }: GeneratorViewProps) {
  const [kind, setKind] = useState<"password" | "passphrase">("password");
  const [length, setLength] = useState(20);
  const [value, setValue] = useState<string | undefined>(undefined);
  const [copied, setCopied] = useState(false);

  return (
    <section>
      <h2>Generator</h2>
      <label>
        <input type="radio" checked={kind === "password"} onChange={() => setKind("password")} /> Password
      </label>
      <label>
        <input type="radio" checked={kind === "passphrase"} onChange={() => setKind("passphrase")} /> Passphrase
      </label>
      <label>
        {kind === "password" ? "Length" : "Words"}
        <input
          type="number"
          value={length}
          onChange={(e) => setLength(Number(e.target.value))}
          min={kind === "password" ? 8 : 3}
          max={kind === "password" ? 128 : 20}
        />
      </label>
      <button
        type="button"
        onClick={() => {
          setCopied(false);
          void client.generatePassword(kind, length).then(setValue);
        }}
      >
        Generate
      </button>
      {value !== undefined ? (
        <p>
          <output>{value}</output>
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard.writeText(value).then(() => {
                setCopied(true);
                // Clears the clipboard after a short hold so a generated-but-unused value does
                // not sit there indefinitely (the same clearing behaviour the popup's item-copy
                // action needs, ADR 0036 §4 "copy (clipboard clearing)"; that action itself is
                // `not_done` since it needs an unlocked item).
                setTimeout(() => {
                  void navigator.clipboard.writeText("").catch(() => undefined);
                }, 30_000);
              });
            }}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </p>
      ) : undefined}
    </section>
  );
}

// The password and passphrase generator (ROADMAP §4.2). The core generates (rizzy-core
// `generator`, OS randomness in the Worker); this view only shows the value, in the
// secret-field component, with its entropy and a copy button.
import type { Generated } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { useState } from "react";

import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The generator (module docs). */
export function GeneratorPane(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [length, setLength] = useState(20);
  const [symbols, setSymbols] = useState(true);
  const [ambiguous, setAmbiguous] = useState(false);
  const [words, setWords] = useState(5);
  const [result, setResult] = useState<Generated | undefined>();
  const [copied, setCopied] = useState(false);
  const { busy, error, run } = useAction();

  const generate = () =>
    void run(async () => {
      setCopied(false);
      setResult(
        mode === "password"
          ? await ctx.client.call("generatePassword", length, symbols, ambiguous)
          : await ctx.client.call("generatePassphrase", words),
      );
    });

  return (
    <div className="panel narrow">
      <h2>Generator</h2>
      <fieldset>
        <legend>Kind</legend>
        <label className="check">
          <input type="radio" name="gen-mode" checked={mode === "password"} onChange={() => setMode("password")} />
          Password
        </label>
        <label className="check">
          <input type="radio" name="gen-mode" checked={mode === "passphrase"} onChange={() => setMode("passphrase")} />
          Passphrase
        </label>
      </fieldset>
      {mode === "password" ? (
        <>
          <label htmlFor="gen-length">Length: {length}</label>
          <input
            id="gen-length"
            type="range"
            min={8}
            max={128}
            value={length}
            onChange={(e) => setLength(Number(e.currentTarget.value))}
          />
          <label className="check">
            <input type="checkbox" checked={symbols} onChange={(e) => setSymbols(e.currentTarget.checked)} />
            Symbols
          </label>
          <label className="check">
            <input type="checkbox" checked={ambiguous} onChange={(e) => setAmbiguous(e.currentTarget.checked)} />
            Avoid look-alike characters
          </label>
        </>
      ) : (
        <>
          <label htmlFor="gen-words">Words: {words}</label>
          <input
            id="gen-words"
            type="range"
            min={3}
            max={12}
            value={words}
            onChange={(e) => setWords(Number(e.currentTarget.value))}
          />
        </>
      )}
      <div className="actions">
        <button type="button" onClick={generate} disabled={busy}>
          Generate
        </button>
      </div>
      <ErrorText code={error} />
      {result !== undefined && (
        <div className="generated">
          <SecretField label="Generated" name="generated" value={result.value} initiallyRevealed />
          <p className="muted">About {Math.floor(result.entropyBits)} bits of entropy.</p>
          <button
            type="button"
            className="secondary"
            onClick={() =>
              void run(async () => {
                await ctx.clipboard.copy(result.value);
                setCopied(true);
              })
            }
          >
            {copied ? "Copied (cleared in 30 s)" : "Copy"}
          </button>
        </div>
      )}
    </div>
  );
}

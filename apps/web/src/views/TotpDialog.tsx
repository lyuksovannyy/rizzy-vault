// The second-factor prompt: the Worker asks for it mid-login, when the server wants a code
// (`ask-totp` in `protocol.ts`). The code is single-use, so it is a plain numeric input.
import { type FormEvent, useState } from "react";

/** Asks for the authenticator code; answers `null` on cancel. */
export function TotpDialog(props: { readonly onAnswer: (code: string | null) => void }) {
  const [code, setCode] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    props.onAnswer(code.trim());
  };
  return (
    <div className="overlay">
      <form className="panel dialog" role="dialog" aria-modal="true" aria-labelledby="totp-title" onSubmit={submit}>
        <h2 id="totp-title">Two-factor code</h2>
        <p>Enter the current code from your authenticator app.</p>
        <label htmlFor="totp-code">Code</label>
        <input
          id="totp-code"
          name="totp"
          inputMode="numeric"
          autoComplete="one-time-code"
          spellCheck={false}
          autoFocus
          required
          value={code}
          onChange={(e) => setCode(e.currentTarget.value)}
        />
        <div className="actions">
          <button type="submit">Continue</button>
          <button type="button" className="secondary" onClick={() => props.onAnswer(null)}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

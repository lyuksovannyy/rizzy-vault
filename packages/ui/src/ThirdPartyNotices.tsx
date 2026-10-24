// SPDX-License-Identifier: AGPL-3.0-only

// The third-party notices every client shows (THIRD_PARTY_NOTICES.md, "Attribution text" of each
// section): EFF's Long Wordlist, compiled into `rizzy-core` for the passphrase generator, and
// the default site groups (ADR 0080, owner answer 5), derived from the Bitwarden server's
// equivalent-domains list via Vaultwarden, and the identity generator's data (ADR 0079 §5) from
// faker-js and Unicode CLDR. One source for the web vault's Settings and the
// extension's options page, so the two never drift. The texts are copied from
// THIRD_PARTY_NOTICES.md; a change there is a change here.
//
// The URLs are plain text, not links: this panel is read, not navigated, and adds no stop to the
// keyboard walk.

/** The attribution lines, in THIRD_PARTY_NOTICES.md order. */
export const THIRD_PARTY_ATTRIBUTIONS: readonly string[] = [
  "EFF's Long Wordlist by the Electronic Frontier Foundation, https://www.eff.org/dice, licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). Used unmodified.",
  "Default site groups derived from the Bitwarden server's equivalent-domains list via Vaultwarden, AGPL-3.0.",
  "Identity generator names and address patterns derived from faker-js (https://github.com/faker-js/faker), Copyright (c) 2022-2025 Faker, MIT License.",
  "Identity generator country and subdivision names derived from Unicode CLDR (https://github.com/unicode-org/cldr), Copyright © 2001–2026 Unicode, Inc., Unicode License v3.",
];

/** The notices as a titled section. `className` lets each app place it in its own layout. */
export function ThirdPartyNotices(props: { readonly className?: string; readonly headingLevel?: 2 | 3 }) {
  const Heading = props.headingLevel === 3 ? "h3" : "h2";
  return (
    <section className={props.className} aria-labelledby="third-party-notices-title">
      <Heading id="third-party-notices-title">Third-party notices</Heading>
      <ul>
        {THIRD_PARTY_ATTRIBUTIONS.map((text) => (
          <li key={text}>{text}</li>
        ))}
      </ul>
    </section>
  );
}

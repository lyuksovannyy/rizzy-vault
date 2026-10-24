// SPDX-License-Identifier: AGPL-3.0-only

// The vault name limit the clients accept (ADR 0081 §A4, §D): 64 Unicode scalar values, as
// `rizzy_client::vaults::MAX_VAULT_NAME_CHARS`. The core checks it again (and trims); this copy
// only sets the input's `maxLength`, which counts UTF-16 code units, so it can only be stricter
// for names with characters outside the BMP — the core's answer is the one that counts.

/** The longest vault name, in characters. */
export const MAX_VAULT_NAME_CHARS = 64;

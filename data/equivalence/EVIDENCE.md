# Evidence for the global equivalence list

This file records, for every member of every group in [`groups.txt`](groups.txt), the evidence
[ADR 0038](../../docs/adr/0038-equivalent-domain-list.md) §4 requires before a group is signed
into a shipped list. [ADR 0080](../../docs/adr/0080-default-site-groups-vaultwarden-seed.md) §3
puts it here, in the repository, so a later second maintainer can audit the seed batch without
depending on a forge.

## Status

**The owner's review is outstanding for every group.** Every "Ownership evidence" cell is
`TODO (owner)`. Nothing in this file is proof yet, and no list may be signed from
`groups.txt` until every member that stays in it has evidence here. A member that finds no
evidence is **dropped** from `groups.txt`, not waived (ADR 0080 §3, no waiver).

## What each row records (ADR 0080 §3)

1. **Provenance**: the upstream `type` and name, and that bitwarden/server kept the group in its
   2026-09 keep/cut review (PR #8404). This is context, **not** proof.
2. **Ownership evidence (rules 1 and 4)**, of a kind ADR 0038 §4 point 1 accepts: a support or
   legal page on the main domain naming the other domain; the brand's own country-site directory
   linking each ccTLD (one page can cover many variants, provided every variant is linked from
   it and serves the same sign-in); for gTLDs, an RDAP registrar and creation date consistent
   with the brand's own corporate registrar. Registrant names are mostly redacted, so RDAP alone
   is supporting evidence, not proof. Cite the URL and the date it was read.
3. **The rule-3 and rule-5 screens**: whether a third party can host content on the domain, and
   the DNS and RDAP observation with its date.
4. **The next re-check**: the next release cycle (ADR 0038, owner answer; §4 point 5).

## About the "Screen" column

The "Screen (agent-collected, unverified)" column was filled in by an AI coding agent on
2026-10-24, from one network vantage point, with `dig +short NS <domain>` (first two answers,
sorted) and `curl -L --max-time 15` against `https://<domain>/` (the HTTP status and the URL
after redirects). It is **not** ownership evidence and was **not** verified by a human. A
`403`, a `000` (no complete answer) or a missing NS answer from that vantage point is a prompt
to look, not a finding. The owner re-runs or replaces each observation during review, with its
own date. RDAP was not collected here.

## Removed before import (ADR 0080 §2)

| Member | Upstream group | Why |
|---|---|---|
| `amazon.com.be` | Amazon (18) | ADR 0044: not its own registrable domain. The PSL lists `be` but not `com.be`. |
| `net.cn` | Alibaba (41) | ADR 0044: a bare public suffix. Anyone can register `<x>.net.cn`. |
| `atlassian.net` | Atlassian (89) | ADR 0038 §4 point 3: serves customer tenant sites, not split by the PSL. |
| `statuspage.io` | Atlassian (89) | ADR 0038 §4 point 3: serves customer status pages, not split by the PSL. |
| `jira.com` | Atlassian (89) | ADR 0038 §4 point 3: a legacy tenant host, not split by the PSL. |
| `yandex.ua` | Yandex (83) | Not delegated, and no ownership evidence is available. |

The starter YouTube group (id `8ce962df…`) is merged into Google and its id is retired.

## Google (type 0)

- **Group id:** `ad39c37cee45d28736adc53bcafa8db2`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Google = 0`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Merge:** upstream `youtube.com`, `google.com`, `gmail.com` plus the starter groups' `youtu.be`, `youtube-nocookie.com`, `google.co.uk` and `google.de` (ADR 0080 §2). The ccTLDs need per-variant proof (rule 4).
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `google.com` | TODO (owner) | NS `ns1.google.com`, `ns2.google.com`; HTTPS 200, final URL `https://www.google.com/` | next release cycle |
| `gmail.com` | TODO (owner) | NS `ns1.google.com`, `ns2.google.com`; HTTPS 200, final URL `https://accounts.google.com/v3/signin/identifier?continue=https://mail.google.com/mail/u/0/&emr=1&followup=https://mail.google.com/mail/u/0/&osid=1&passive=1209600&service=mail&flowName=WebLiteSignIn&flowEntry=ServiceLogin&dsh=S1275543681:1792800368898153` | next release cycle |
| `youtube.com` | TODO (owner) | NS `ns1.google.com`, `ns2.google.com`; HTTPS 200, final URL `https://www.youtube.com/` | next release cycle |
| `youtu.be` | TODO (owner) | NS `ns1.google.com`, `ns2.google.com`; HTTPS 200, final URL `https://www.youtube.com/?feature=youtu.be` | next release cycle |
| `youtube-nocookie.com` | TODO (owner) | NS `ns1.google.com`, `ns2.google.com`; HTTPS: no complete answer within 15 s (last URL `https://youtube-nocookie.com/`) | next release cycle |
| `google.co.uk` | TODO (owner) | NS `ns1.google.com`, `ns2.google.com`; HTTPS 200, final URL `https://www.google.com/` | next release cycle |
| `google.de` | TODO (owner) | NS `ns1.google.com`, `ns2.google.com`; HTTPS 200, final URL `https://www.google.com/` | next release cycle |

## Apple (type 1)

- **Group id:** `1e683ea6d91b48d95a602cf7e6b71747`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Apple = 1`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Merge:** equal to the starter Apple group, which keeps its id (ADR 0080 §2).
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `apple.com` | TODO (owner) | NS `a.ns.apple.com`, `b.ns.apple.com`; HTTPS 200, final URL `https://www.apple.com/` | next release cycle |
| `icloud.com` | TODO (owner) | NS `a.ns.apple.com`, `b.ns.apple.com`; HTTPS 200, final URL `https://www.icloud.com/` | next release cycle |

## Merrill (type 6)

- **Group id:** `f8163dba26dad5bd2f92eb9f2c09b2e6`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Merrill = 6`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `mymerrill.com` | TODO (owner) | NS `a.ns-bac.com`, `b.ns-bac.org`; HTTPS 200, final URL `https://olui2.fs.ml.com/login/signin.aspx` | next release cycle |
| `ml.com` | TODO (owner) | NS `a.ns-bac.com`, `b.ns-bac.org`; HTTPS 200, final URL `https://www.ml.com/` | next release cycle |
| `merrilledge.com` | TODO (owner) | NS `a.ns-bac.com`, `b.ns-bac.org`; HTTPS 200, final URL `https://www.merrilledge.com/` | next release cycle |

## Microsoft (type 10)

- **Group id:** `adcb58afc60e3e9e86e3ff4556329040`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Microsoft = 10`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `bing.com` | TODO (owner) | NS `dns1.p09.nsone.net`, `dns2.p09.nsone.net`; HTTPS 200, final URL `https://www.bing.com:443/?toWww=1&redig=F7454C991C3B4644BB8192A5CB16D357` | next release cycle |
| `hotmail.com` | TODO (owner) | NS `ns1-205.azure-dns.com`, `ns2-205.azure-dns.net`; HTTPS 417, final URL `https://outlook.live.com/mail/` | next release cycle |
| `live.com` | TODO (owner) | NS `ns1-37.azure-dns.com`, `ns2-37.azure-dns.net`; HTTPS 417, final URL `https://outlook.live.com/mail/` | next release cycle |
| `microsoft.com` | TODO (owner) | NS `ns1-39.azure-dns.com`, `ns2-39.azure-dns.net`; HTTPS 403, final URL `https://www.microsoft.com/` | next release cycle |
| `msn.com` | TODO (owner) | NS `dns1.p08.nsone.net`, `dns2.p08.nsone.net`; HTTPS 200, final URL `https://www.msn.com/nl-nl` | next release cycle |
| `passport.net` | TODO (owner) | NS `a1-115.akam.net`, `a28-64.akam.net`; HTTPS: no complete answer within 15 s (last URL `https://passport.net/`) | next release cycle |
| `windows.com` | TODO (owner) | NS `ns1-205.azure-dns.com`, `ns2-205.azure-dns.net`; HTTPS 403, final URL `https://www.microsoft.com/windows` | next release cycle |
| `microsoftonline.com` | TODO (owner) | NS `ns1-38.azure-dns.com`, `ns2-38.azure-dns.net`; HTTPS: no complete answer within 15 s (last URL `https://microsoftonline.com/`) | next release cycle |
| `office.com` | TODO (owner) | NS `ns1-05.azure-dns.com`, `ns2-05.azure-dns.net`; HTTPS 200, final URL `https://m365.cloud.microsoft/` | next release cycle |
| `office365.com` | TODO (owner) | NS `ns1-07.azure-dns.com`, `ns2-07.azure-dns.net`; HTTPS 403, final URL `https://office365.com/` | next release cycle |
| `microsoftstore.com` | TODO (owner) | NS `ns1-08.azure-dns.com`, `ns2-08.azure-dns.net`; HTTPS 403, final URL `https://www.microsoft.com/store/b/home` | next release cycle |
| `xbox.com` | TODO (owner) | NS `ns1-205.azure-dns.com`, `ns2-205.azure-dns.net`; HTTPS 200, final URL `https://www.xbox.com/nl-NL/` | next release cycle |
| `azure.com` | TODO (owner) | NS `ns1-39.azure-dns.com`, `ns2-39.azure-dns.net`; HTTPS 200, final URL `https://azure.microsoft.com/en-us` | next release cycle |
| `windowsazure.com` | TODO (owner) | NS `ns1-205.azure-dns.com`, `ns2-205.azure-dns.net`; HTTPS 200, final URL `https://azure.microsoft.com/en-us` | next release cycle |
| `cloud.microsoft` | TODO (owner) | NS `ns1-33.azure-dns.com`, `ns2-33.azure-dns.net`; HTTPS 200, final URL `https://m365.cloud.microsoft/` | next release cycle |

## PayPal (type 14)

- **Group id:** `014f2b81d24e470658e2c9035a0244fd`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.PayPal = 14`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `paypal.com` | TODO (owner) | NS `ns1-pchnet.paypal.com`, `ns2-pchnet.paypal.com`; HTTPS 200, final URL `https://www.paypal.com/nl/home` | next release cycle |
| `paypal-search.com` | TODO (owner) | NS `ns1.markmonitor.com`, `ns2.markmonitor.com`; HTTPS: no complete answer within 15 s (last URL `https://paypal-search.com/`) | next release cycle |

## Amazon (type 18)

- **Group id:** `d1ba74c84d4a2b50f728bc56b20a9829`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Amazon = 18`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Removed before import:** `amazon.com.be` (see above).
- **Note:** Every ccTLD variant needs its own proof (rule 4; ADR 0080 §2).
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `amazon.com` | TODO (owner) | NS `ns-1447.awsdns-52.org`, `ns-1707.awsdns-21.co.uk`; HTTPS 202, final URL `https://www.amazon.com/` | next release cycle |
| `amazon.ae` | TODO (owner) | NS `ns-1411.awsdns-48.org`, `ns-1806.awsdns-33.co.uk`; HTTPS 202, final URL `https://www.amazon.ae/` | next release cycle |
| `amazon.ca` | TODO (owner) | NS `ns-1036.awsdns-01.org`, `ns-1561.awsdns-03.co.uk`; HTTPS 202, final URL `https://www.amazon.ca/` | next release cycle |
| `amazon.co.uk` | TODO (owner) | NS `ns-1256.awsdns-29.org`, `ns-1689.awsdns-19.co.uk`; HTTPS 202, final URL `https://www.amazon.co.uk/` | next release cycle |
| `amazon.com.au` | TODO (owner) | NS `ns1.amzndns.co.uk`, `ns1.amzndns.com`; HTTPS 202, final URL `https://www.amazon.com.au/` | next release cycle |
| `amazon.com.br` | TODO (owner) | NS `ns-104.awsdns-13.com`, `ns-1384.awsdns-45.org`; HTTPS 202, final URL `https://www.amazon.com.br/` | next release cycle |
| `amazon.com.mx` | TODO (owner) | NS `ns1.amzndns.co.uk`, `ns1.amzndns.com`; HTTPS 202, final URL `https://www.amazon.com.mx/` | next release cycle |
| `amazon.com.tr` | TODO (owner) | NS `ns-104.awsdns-13.com`, `ns-1258.awsdns-29.org`; HTTPS 202, final URL `https://www.amazon.com.tr/` | next release cycle |
| `amazon.de` | TODO (owner) | NS `ns-1343.awsdns-39.org`, `ns-2037.awsdns-62.co.uk`; HTTPS 202, final URL `https://www.amazon.de/` | next release cycle |
| `amazon.es` | TODO (owner) | NS `ns1.amzndns.co.uk`, `ns1.amzndns.com`; HTTPS 202, final URL `https://www.amazon.es/` | next release cycle |
| `amazon.fr` | TODO (owner) | NS `ns1.amzndns.co.uk`, `ns1.amzndns.com`; HTTPS 200, final URL `https://www.amazon.fr/` | next release cycle |
| `amazon.in` | TODO (owner) | NS `ns1.amzndns.co.uk`, `ns1.amzndns.com`; HTTPS 202, final URL `https://www.amazon.in/` | next release cycle |
| `amazon.it` | TODO (owner) | NS `ns2.amzndns.co.uk`, `ns2.amzndns.com`; HTTPS 202, final URL `https://www.amazon.it/` | next release cycle |
| `amazon.nl` | TODO (owner) | NS `ns-1258.awsdns-29.org`, `ns-1871.awsdns-41.co.uk`; HTTPS 202, final URL `https://www.amazon.nl/` | next release cycle |
| `amazon.pl` | TODO (owner) | NS `ns-1131.awsdns-13.org`, `ns-1595.awsdns-07.co.uk`; HTTPS 202, final URL `https://www.amazon.pl/` | next release cycle |
| `amazon.sa` | TODO (owner) | NS `ns-1074.awsdns-06.org`, `ns-1718.awsdns-22.co.uk`; HTTPS 200, final URL `https://www.amazon.sa/` | next release cycle |
| `amazon.se` | TODO (owner) | NS `ns-1465.awsdns-55.org`, `ns-1620.awsdns-10.co.uk`; HTTPS 200, final URL `https://www.amazon.se/` | next release cycle |
| `amazon.sg` | TODO (owner) | NS `ns-1318.awsdns-36.org`, `ns-1754.awsdns-27.co.uk`; HTTPS 202, final URL `https://www.amazon.sg:443/` | next release cycle |

## Comcast (type 36)

- **Group id:** `ebfc3dce9b5af467ffacb7bbf89e8c2c`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Comcast = 36`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `comcast.com` | TODO (owner) | NS `dns101.comcast.net`, `dns102.comcast.net`; HTTPS: no complete answer within 15 s (last URL `https://comcast.com/`) | next release cycle |
| `comcast.net` | TODO (owner) | NS `dns101.comcast.net`, `dns102.comcast.net`; HTTPS 403, final URL `https://www.xfinity.com/` | next release cycle |
| `xfinity.com` | TODO (owner) | NS `dns101.comcast.net`, `dns102.comcast.net`; HTTPS 403, final URL `https://www.xfinity.com/` | next release cycle |

## Alibaba (type 41)

- **Group id:** `6bc8f6284fdf69705322ea67f921bc57`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Alibaba = 41`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Removed before import:** `net.cn` (see above).
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `alibaba.com` | TODO (owner) | NS `ns1.alibabadns.com`, `ns2.alibabadns.com`; HTTPS 200, final URL `https://www.alibaba.com/` | next release cycle |
| `aliexpress.com` | TODO (owner) | NS `ns1.alibabadns.com`, `ns2.alibabadns.com`; HTTPS 200, final URL `https://aliexpress.com/` | next release cycle |
| `aliyun.com` | TODO (owner) | NS `ns3.aliyun.com`, `ns4.aliyun.com`; HTTPS 200, final URL `https://www.alibabacloud.com/en?_p_lc=1&f-8DC992C756BA=` | next release cycle |

## Autodesk (type 45)

- **Group id:** `1bc2b3512ae358f9bcb26b7df9f0dd06`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Autodesk = 45`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `autodesk.com` | TODO (owner) | NS `ns-1192.awsdns-21.org`, `ns-1869.awsdns-41.co.uk`; HTTPS 403, final URL `https://www.autodesk.com/` | next release cycle |
| `tinkercad.com` | TODO (owner) | NS `ns-1463.awsdns-54.org`, `ns-1626.awsdns-11.co.uk`; HTTPS 200, final URL `https://www.tinkercad.com:443/` | next release cycle |

## Facebook (type 51)

- **Group id:** `9f1ab17bf502904784ae3263d612e8f0`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Facebook = 51`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `facebook.com` | TODO (owner) | NS `a.ns.facebook.com`, `b.ns.facebook.com`; HTTPS 200, final URL `https://www.facebook.com/` | next release cycle |
| `messenger.com` | TODO (owner) | NS `a.ns.facebook.com`, `b.ns.facebook.com`; HTTPS 200, final URL `https://www.messenger.com/` | next release cycle |

## Disney (type 54)

- **Group id:** `5b9b1db9a822709f67db336adbb0e667`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Disney = 54`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Note:** `disneymoviesanywhere.com` redirects to `moviesanywhere.com`, a multi-studio service (ADR 0080 Context). It must find its evidence or be dropped (ADR 0080 §2).
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `disneymoviesanywhere.com` | TODO (owner) | NS `ns-1152.awsdns-16.org`, `ns-1698.awsdns-20.co.uk`; HTTPS 200, final URL `https://moviesanywhere.com/home` | next release cycle |
| `go.com` | TODO (owner) | NS `ns1.twdcns.com`, `ns2.twdcns.com`; HTTPS 200, final URL `https://www.go.com/` | next release cycle |
| `disney.com` | TODO (owner) | NS `ns1.twdcns.com`, `ns2.twdcns.com`; HTTPS 200, final URL `https://www.disney.com/` | next release cycle |
| `dadt.com` | TODO (owner) | NS `ns-1313.awsdns-36.org`, `ns-1539.awsdns-00.co.uk`; HTTPS 200, final URL `https://press.disneyplus.com/` | next release cycle |
| `disneyplus.com` | TODO (owner) | NS `dns1.p09.nsone.net`, `dns2.p09.nsone.net`; HTTPS 200, final URL `https://www.disneyplus.com/` | next release cycle |

## Turbotax (type 62)

- **Group id:** `8a7a0b4c1a723be04d3166b115132b69`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Turbotax = 62`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `turbotax.com` | TODO (owner) | NS `a1-182.akam.net`, `a11-64.akam.net`; HTTPS 200, final URL `https://turbotax.intuit.com/` | next release cycle |
| `intuit.com` | TODO (owner) | NS `a1-182.akam.net`, `a11-64.akam.net`; HTTPS 429, final URL `https://www.intuit.com/` | next release cycle |

## Ebay (type 64)

- **Group id:** `e984482b3e754289c4a60dad0acd01d8`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Ebay = 64`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Note:** Every ccTLD variant needs its own proof (rule 4; ADR 0080 §2).
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `ebay.com` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.com/` | next release cycle |
| `ebay.at` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.at/` | next release cycle |
| `ebay.be` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.be/` | next release cycle |
| `ebay.ca` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.ca/` | next release cycle |
| `ebay.ch` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.ch/` | next release cycle |
| `ebay.cn` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 200, final URL `https://www.ebay.cn/` | next release cycle |
| `ebay.co.jp` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 200, final URL `https://ebay.co.jp/` | next release cycle |
| `ebay.co.th` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.com/` | next release cycle |
| `ebay.co.uk` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.co.uk/` | next release cycle |
| `ebay.com.au` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.com.au/` | next release cycle |
| `ebay.com.hk` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.com.hk/` | next release cycle |
| `ebay.com.my` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.com.my/` | next release cycle |
| `ebay.com.sg` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.com.sg/` | next release cycle |
| `ebay.com.tw` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS: no complete answer within 15 s (last URL `https://ebay.com.tw/`) | next release cycle |
| `ebay.de` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.de/` | next release cycle |
| `ebay.es` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.es/` | next release cycle |
| `ebay.fr` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.fr/` | next release cycle |
| `ebay.ie` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.ie/` | next release cycle |
| `ebay.in` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 200, final URL `https://export.ebay.com/in/` | next release cycle |
| `ebay.it` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.it/` | next release cycle |
| `ebay.nl` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.nl/` | next release cycle |
| `ebay.ph` | TODO (owner) | NS `dns1.p06.nsone.net`, `ns01.ebaydns.com`; HTTPS 403, final URL `https://www.ebay.ph/` | next release cycle |
| `ebay.pl` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 403, final URL `https://www.ebay.pl/` | next release cycle |

## MorganStanley (type 69)

- **Group id:** `7d535ea3307bba120e627555c82681fe`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.MorganStanley = 69`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `morganstanley.com` | TODO (owner) | NS `ext-ns1.morganstanley.net`, `ext-ns10.morganstanley.net`; HTTPS 200, final URL `https://www.morganstanley.com/` | next release cycle |
| `morganstanleyclientserv.com` | TODO (owner) | NS `ext-ns1.morganstanley.net`, `ext-ns2.morganstanley.net`; HTTPS 301, final URL `https://www.morganstanleyclientserv.com/` | next release cycle |
| `stockplanconnect.com` | TODO (owner) | NS `ext-ns1.morganstanley.net`, `ext-ns2.morganstanley.net`; HTTPS: no complete answer within 15 s (last URL `https://stockplanconnect.com/`) | next release cycle |
| `ms.com` | TODO (owner) | NS `ext-ns1.morganstanley.net`, `ext-ns10.morganstanley.net`; HTTPS 200, final URL `https://www.morganstanley.com/` | next release cycle |

## Airbnb (type 72)

- **Group id:** `80fe4e616a573676a346482b3427fde4`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Airbnb = 72`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Note:** Every ccTLD variant needs its own proof (rule 4; ADR 0080 §2). The largest group: 53 members.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `airbnb.at` | TODO (owner) | NS `dns1.p05.nsone.net`, `dns2.p05.nsone.net`; HTTPS 200, final URL `https://www.airbnb.at/` | next release cycle |
| `airbnb.be` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.be/` | next release cycle |
| `airbnb.ca` | TODO (owner) | NS `dns1.p02.nsone.net`, `dns2.p02.nsone.net`; HTTPS 200, final URL `https://www.airbnb.ca/` | next release cycle |
| `airbnb.ch` | TODO (owner) | NS `dns1.p02.nsone.net`, `dns2.p02.nsone.net`; HTTPS 200, final URL `https://www.airbnb.ch/` | next release cycle |
| `airbnb.cl` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.cl/` | next release cycle |
| `airbnb.co.cr` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.co.cr/` | next release cycle |
| `airbnb.co.id` | TODO (owner) | NS `ns-1148.awsdns-15.org`, `ns-1927.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.co.id/` | next release cycle |
| `airbnb.co.in` | TODO (owner) | NS `ns-1148.awsdns-15.org`, `ns-1927.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.co.in/` | next release cycle |
| `airbnb.co.kr` | TODO (owner) | NS `ns-1148.awsdns-15.org`, `ns-1927.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.co.kr/` | next release cycle |
| `airbnb.co.nz` | TODO (owner) | NS `ns-1046.awsdns-02.org`, `ns-1538.awsdns-00.co.uk`; HTTPS 200, final URL `https://www.airbnb.co.nz/` | next release cycle |
| `airbnb.co.uk` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 200, final URL `https://www.airbnb.co.uk/` | next release cycle |
| `airbnb.co.ve` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.co.ve/` | next release cycle |
| `airbnb.com` | TODO (owner) | NS `dns1.p08.nsone.net`, `dns2.p08.nsone.net`; HTTPS 200, final URL `https://www.airbnb.com/` | next release cycle |
| `airbnb.com.ar` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 200, final URL `https://www.airbnb.com.ar/` | next release cycle |
| `airbnb.com.au` | TODO (owner) | NS `dns1.p06.nsone.net`, `dns2.p06.nsone.net`; HTTPS 200, final URL `https://www.airbnb.com.au/` | next release cycle |
| `airbnb.com.bo` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.bo/` | next release cycle |
| `airbnb.com.br` | TODO (owner) | NS `dns1.p01.nsone.net`, `dns2.p01.nsone.net`; HTTPS 200, final URL `https://www.airbnb.com.br/` | next release cycle |
| `airbnb.com.bz` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.bz/` | next release cycle |
| `airbnb.com.co` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.co/` | next release cycle |
| `airbnb.com.ec` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.ec/` | next release cycle |
| `airbnb.com.gt` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.gt/` | next release cycle |
| `airbnb.com.hk` | TODO (owner) | NS `ns-1148.awsdns-15.org`, `ns-1927.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.hk/` | next release cycle |
| `airbnb.com.hn` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.hn/` | next release cycle |
| `airbnb.com.mt` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.mt/` | next release cycle |
| `airbnb.com.my` | TODO (owner) | NS `ns-1148.awsdns-15.org`, `ns-1927.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.my/` | next release cycle |
| `airbnb.com.ni` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.ni/` | next release cycle |
| `airbnb.com.pa` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.pa/` | next release cycle |
| `airbnb.com.pe` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.pe/` | next release cycle |
| `airbnb.com.py` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.py/` | next release cycle |
| `airbnb.com.sg` | TODO (owner) | NS `ns-1148.awsdns-15.org`, `ns-1927.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.sg/` | next release cycle |
| `airbnb.com.sv` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.sv/` | next release cycle |
| `airbnb.com.tr` | TODO (owner) | NS `ns-1148.awsdns-15.org`, `ns-1927.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.tr/` | next release cycle |
| `airbnb.com.tw` | TODO (owner) | NS `ns-1148.awsdns-15.org`, `ns-1927.awsdns-48.co.uk`; HTTPS 200, final URL `https://www.airbnb.com.tw/` | next release cycle |
| `airbnb.cz` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.cz/` | next release cycle |
| `airbnb.de` | TODO (owner) | NS `dns1.p01.nsone.net`, `dns2.p01.nsone.net`; HTTPS 200, final URL `https://www.airbnb.de/` | next release cycle |
| `airbnb.dk` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.dk/` | next release cycle |
| `airbnb.es` | TODO (owner) | NS `dns1.p04.nsone.net`, `dns2.p04.nsone.net`; HTTPS 200, final URL `https://www.airbnb.es/` | next release cycle |
| `airbnb.fi` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.fi/` | next release cycle |
| `airbnb.fr` | TODO (owner) | NS `dns1.p07.nsone.net`, `dns2.p07.nsone.net`; HTTPS 200, final URL `https://www.airbnb.fr/` | next release cycle |
| `airbnb.gr` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.gr/` | next release cycle |
| `airbnb.gy` | TODO (owner) | NS `ns-1095.awsdns-08.org`, `ns-1926.awsdns-48.co.uk`; HTTPS 429, final URL `https://www.airbnb.gy/` | next release cycle |
| `airbnb.hu` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 403, final URL `https://www.airbnb.hu/` | next release cycle |
| `airbnb.ie` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.ie/` | next release cycle |
| `airbnb.is` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.is/` | next release cycle |
| `airbnb.it` | TODO (owner) | NS `dns1.p03.nsone.net`, `dns2.p03.nsone.net`; HTTPS 200, final URL `https://www.airbnb.it/` | next release cycle |
| `airbnb.jp` | TODO (owner) | NS `dns1.p05.nsone.net`, `dns2.p05.nsone.net`; HTTPS 200, final URL `https://www.airbnb.jp/` | next release cycle |
| `airbnb.mx` | TODO (owner) | NS `dns1.p01.nsone.net`, `ns-1095.awsdns-08.org`; HTTPS 403, final URL `https://www.airbnb.mx/` | next release cycle |
| `airbnb.nl` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 200, final URL `https://www.airbnb.nl/` | next release cycle |
| `airbnb.no` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 403, final URL `https://www.airbnb.no/` | next release cycle |
| `airbnb.pl` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 403, final URL `https://www.airbnb.pl/` | next release cycle |
| `airbnb.pt` | TODO (owner) | NS `dns1.p02.nsone.net`, `dns2.p02.nsone.net`; HTTPS 200, final URL `https://www.airbnb.pt/` | next release cycle |
| `airbnb.ru` | TODO (owner) | NS `dns1.p02.nsone.net`, `dns2.p02.nsone.net`; HTTPS 404, final URL `https://airbnb.ru/` | next release cycle |
| `airbnb.se` | TODO (owner) | NS `ns-1087.awsdns-07.org`, `ns-1877.awsdns-42.co.uk`; HTTPS 403, final URL `https://www.airbnb.se/` | next release cycle |

## StackExchange (type 74)

- **Group id:** `c04a4ddfdd7745333a57c05c29d1bd71`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.StackExchange = 74`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `stackexchange.com` | TODO (owner) | NS `damian.ns.cloudflare.com`, `sureena.ns.cloudflare.com`; HTTPS 200, final URL `https://stackexchange.com/` | next release cycle |
| `superuser.com` | TODO (owner) | NS `damian.ns.cloudflare.com`, `sureena.ns.cloudflare.com`; HTTPS 200, final URL `https://superuser.com/` | next release cycle |
| `stackoverflow.com` | TODO (owner) | NS `damian.ns.cloudflare.com`, `sureena.ns.cloudflare.com`; HTTPS 403, final URL `https://stackoverflow.com/questions` | next release cycle |
| `serverfault.com` | TODO (owner) | NS `damian.ns.cloudflare.com`, `sureena.ns.cloudflare.com`; HTTPS 200, final URL `https://serverfault.com/` | next release cycle |
| `mathoverflow.net` | TODO (owner) | NS `damian.ns.cloudflare.com`, `sureena.ns.cloudflare.com`; HTTPS 200, final URL `https://mathoverflow.net/` | next release cycle |
| `askubuntu.com` | TODO (owner) | NS `damian.ns.cloudflare.com`, `sureena.ns.cloudflare.com`; HTTPS 200, final URL `https://askubuntu.com/` | next release cycle |
| `stackapps.com` | TODO (owner) | NS `damian.ns.cloudflare.com`, `sureena.ns.cloudflare.com`; HTTPS 200, final URL `https://stackapps.com/` | next release cycle |

## Docusign (type 75)

- **Group id:** `df92fb07c5935f2c563916a35dfd56d6`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Docusign = 75`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `docusign.com` | TODO (owner) | NS `a1-246.akam.net`, `a10-65.akam.net`; HTTPS 200, final URL `https://www.docusign.com/` | next release cycle |
| `docusign.net` | TODO (owner) | NS `a10-65.akam.net`, `a11-66.akam.net`; HTTPS: no complete answer within 15 s (last URL `https://docusign.net/`) | next release cycle |

## Ubiquiti (type 80)

- **Group id:** `b4ca2866e0a5a09d38da09277b211664`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Ubiquiti = 80`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `ubnt.com` | TODO (owner) | NS `ns-1213.awsdns-23.org`, `ns-159.awsdns-19.com`; HTTPS 200, final URL `https://www.ui.com/` | next release cycle |
| `ui.com` | TODO (owner) | NS `ns-1469.awsdns-55.org`, `ns-1849.awsdns-39.co.uk`; HTTPS 200, final URL `https://ui.com/` | next release cycle |

## Yandex (type 83)

- **Group id:** `f530841b54dfd626a7fc90bcc95d889b`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Yandex = 83`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Removed before import:** `yandex.ua` (see above).
- **Note:** Every ccTLD variant needs its own proof (rule 4; ADR 0080 §2).
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `yandex.com` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.com/` | next release cycle |
| `ya.ru` | TODO (owner) | NS `ns1.yandex.ru`, `ns2.yandex.ru`; HTTPS 200, final URL `https://ya.ru/showcaptcha?cc=1&form-fb-hint=2.47&mt=E1D99ECCCA6D1C25A9E701D15E720BC409CD6C3D58FAE9FDD2FC7745374908C6E955EB0EC6D90695280C6C84F0C799E11FDB40E176FB34CF3A623B9B43CBE77B69ECD328F640661CAC6428DD69748A437F59282ACB0D6D4F1A347F4FA5E8D70E040643C17289285974A4ADDD328AE0D2C3446A93E82997C9CDB5FCA5B12DE8A8D8BB73CADB0BC5D0&retpath=aHR0cHM6Ly95YS5ydS8%2C_cb157a0e0c610bc325b91bc8908ec750&t=2%252F1792800380%252Fce46ea91bf10a309b8afa6a74f9412a2&u=9632332438517323093&s=49fe6e418ada44ee44c85dcc373edd96` | next release cycle |
| `yandex.az` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.az/` | next release cycle |
| `yandex.by` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.by/` | next release cycle |
| `yandex.co.il` | TODO (owner) | NS `ns1.yandex.ru`, `ns2.yandex.ru`; HTTPS 200, final URL `https://yandex.co.il/` | next release cycle |
| `yandex.com.am` | TODO (owner) | NS `ns3.yandex.ru`, `ns4.yandex.ru`; HTTPS 200, final URL `https://yandex.com.am/` | next release cycle |
| `yandex.com.ge` | TODO (owner) | NS `ns3.yandex.ru`, `ns4.yandex.ru`; HTTPS 200, final URL `https://yandex.com.ge/` | next release cycle |
| `yandex.com.tr` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.com.tr/` | next release cycle |
| `yandex.ee` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.com/` | next release cycle |
| `yandex.fi` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.com/` | next release cycle |
| `yandex.fr` | TODO (owner) | NS `ns1.yandex.ru`, `ns2.yandex.ru`; HTTPS 200, final URL `https://ya.ru/showcaptcha?cc=1&form-fb-hint=2.47&mt=E77D456299D0AA84665D1B32FFE8A536BE96A32F011E88C53DE3198F1EFF29DC1689314A1BEF04E20E691FAFC80511F20FA3F16E5908FE747E39B913A9E7AEDB752CA9DB0CC7A009468218107586D2AB486640B21464D3B63E668849705D5E53738ECBD2C57F8A6913DC6950205EA0B734EF56DE1A6A3F8053026569C7B175ABBDA495E282781622&retpath=aHR0cHM6Ly95YS5ydS8%2C_cb157a0e0c610bc325b91bc8908ec750&t=2%252F1792800380%252F314bf0fd756664297526709504dee4f2&u=9632332464891106632&s=4db134a137ece79008a24bb5f988547e` | next release cycle |
| `yandex.kg` | TODO (owner) | NS `ns3.yandex.ru`, `ns4.yandex.ru`; HTTPS: no complete answer within 15 s (last URL `https://yandex.kg/`) | next release cycle |
| `yandex.kz` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.kz/` | next release cycle |
| `yandex.lt` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.com/` | next release cycle |
| `yandex.lv` | TODO (owner) | NS `ns1.yandex.ru`, `ns2.yandex.ru`; HTTPS 200, final URL `https://yandex.com/` | next release cycle |
| `yandex.md` | TODO (owner) | NS `ns1.yandex.md`, `ns2.yandex.md`; HTTPS 200, final URL `https://yandex.md/` | next release cycle |
| `yandex.pl` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.com/` | next release cycle |
| `yandex.ru` | TODO (owner) | NS `ns1.yandex.ru`, `ns2.yandex.ru`; HTTPS 200, final URL `https://sso.passport.yandex.ru/push?uuid=c5e9a708-4f5e-4de8-9c93-f69ce6636360&retpath=https%3A%2F%2Fdzen.ru%2F%3Fyredirect%3Dtrue%26is_autologin_ya%3Dtrue` | next release cycle |
| `yandex.tj` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.tj/` | next release cycle |
| `yandex.tm` | TODO (owner) | NS `ns1.yandex.net`, `ns2.yandex.net`; HTTPS 200, final URL `https://yandex.tm/` | next release cycle |
| `yandex.uz` | TODO (owner) | NS `ns1.yandex.ru`, `ns2.yandex.ru`; HTTPS 200, final URL `https://yandex.uz/` | next release cycle |

## Proton (type 85)

- **Group id:** `ec26724894c5367e7c4ef8841603b448`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Proton = 85`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `proton.me` | TODO (owner) | NS `ns1.proton.me`, `ns2.proton.me`; HTTPS 200, final URL `https://proton.me/` | next release cycle |
| `protonmail.com` | TODO (owner) | NS `ns1.protonmail.com`, `ns2.protonmail.com`; HTTPS 200, final URL `https://proton.me/mail` | next release cycle |
| `protonvpn.com` | TODO (owner) | NS `mitch.ns.cloudflare.com`, `nora.ns.cloudflare.com`; HTTPS 200, final URL `https://protonvpn.com/` | next release cycle |

## Atlassian (type 89)

- **Group id:** `addad629d1f976de3286a858cbab9ce2`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Atlassian = 89`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Removed before import:** `statuspage.io`, `atlassian.net`, `jira.com` (see above).
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `atlassian.com` | TODO (owner) | NS `ns-112.awsdns-14.com`, `ns-1388.awsdns-45.org`; HTTPS 200, final URL `https://www.atlassian.com/` | next release cycle |
| `bitbucket.org` | TODO (owner) | NS `ns-1305.awsdns-35.org`, `ns-1746.awsdns-26.co.uk`; HTTPS 200, final URL `https://bitbucket.org/` | next release cycle |
| `trello.com` | TODO (owner) | NS `ns-1442.awsdns-52.org`, `ns-2013.awsdns-59.co.uk`; HTTPS 200, final URL `https://trello.com/` | next release cycle |

## Twitter (type 91)

- **Group id:** `4aa14f4e767d633f60a88f4d96c08c09`
- **Provenance:** Bitwarden `GlobalEquivalentDomainsType.Twitter = 91`, kept by bitwarden/server PR #8404 (`e1f32b96…`); identical in Vaultwarden `b71cb7a8…` `global_domains.json`. Context, not proof.
- **Owner review:** TODO (owner): reviewer, date, decision.

| Member | Ownership evidence (rules 1, 4) | Screen (agent-collected, unverified, 2026-10-24) | Next re-check |
|---|---|---|---|
| `twitter.com` | TODO (owner) | NS `a.r06.twtrdns.net`, `a.u06.twtrdns.net`; HTTPS 200, final URL `https://x.com/` | next release cycle |
| `x.com` | TODO (owner) | NS `a.r10.twtrdns.net`, `a.u10.twtrdns.net`; HTTPS 200, final URL `https://x.com/` | next release cycle |

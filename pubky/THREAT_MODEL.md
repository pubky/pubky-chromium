# Threat model

Status: initial version, October 2026. This document grows with the project:
each feature adds or updates its section before it ships enabled by default.
It covers what the browser does today and the planned PKResolve resolution
described in [TLS_TRUST_MODEL.md](TLS_TRUST_MODEL.md).

## What we protect

- **Connection integrity for public-key sites.** A page at `https://<key>/`
  comes from the holder of that key, or from a server the key holder
  delegated to.
- **Ordinary browsing.** DNS, HTTPS and certificate checks for ordinary
  domains behave as in upstream Chromium.
- **Browsing privacy.** Which sites a user visits, including the lookups the
  browser makes to reach them.
- **Update integrity.** Only builds signed with the pinned owner key install
  through the in-app updater.

## Who we defend against

- **Network attacker**: controls the user's Wi-Fi, ISP or any path to a
  server.
- **Resolver operator**: the DNS-over-HTTPS server today
  (`pkdns.pubky.org`), the PKResolve service later. Honest but curious, or
  compromised.
- **Hostile publisher**: anyone can publish a signed packet for their own key,
  with malformed, oversized, looping or misleading records.
- **Delegated provider**: a server a key holder delegated TLS to, which may
  later misbehave.
- **Hostile website**: page scripts on any origin.
- **Release channel attacker**: someone who gains access to the GitHub
  repository, release assets or update feeds.

Out of scope: malware on the user's machine, a compromised operating system,
and attackers with physical access, as in upstream Chromium.

## Threats

| # | Threat | Today | With PKResolve | Status |
|---|---|---|---|---|
| T1 | Impersonate a public-key site | Raw-key TLS: the server must present the exact key in the URL. Certificate exceptions cannot bypass it. | The server must present the key that verified delegation names. | Mitigated |
| T2 | Resolver returns a wrong address or port | Leads to a failed TLS handshake (denial of service), not impersonation. | Records are checked against the key's signature, so a lying service can only withhold answers. | Open: the client does not yet verify signatures; needs the PKARR fix |
| T3 | Resolver hides records or claims a name does not exist | The site does not load. | A service error never proves non-existence and never allows weaker authentication. | Accepted: availability depends on the resolver |
| T4 | Resolver learns what users browse | In the default secure DNS mode, `pkdns.pubky.org` sees every hostname the browser resolves, key or not, and the user's IP. | The PKResolve service sees the full service name, port and protocols. | Open: logging and retention policy undecided; disclose in release notes |
| T5 | Replay of an old signed packet (rollback to old routes or old delegation) | Not checked. | The spec requires rejecting versions older than ones already accepted. | Open: not implemented in PKResolve yet |
| T6 | Stale records accepted for too long | DoH TTLs apply. | Reuse is capped by record TTL and packet age. | Open: no cap on signed-packet age yet; clock-skew bound undecided |
| T7 | Malformed or oversized packets crash or stall the browser | Handled by Chromium's DNS parser. | The bundle is size-limited before parsing; Rust parsing runs in the network stack. | Open: PKARR 8.1 can panic on short input (fixed upstream, unreleased); no parsing work limit yet |
| T8 | Records become browser configuration | Only addresses, ports and protocols from HTTPS records are used. | Same: records select endpoints and the TLS key, nothing else. | Mitigated by design |
| T9 | Delegation chain loops or grows without bound | No delegation. | Chains have hop, query and time limits, plus cycle checks. | Open: limit values undecided |
| T10 | Downgrade: fall back to ordinary DNS, CA TLS or plain HTTP | Key hosts use secure DNS only, with no system resolver fallback. | An authentication failure never enables CA fallback. | Open: plain `http://<key>` still loads without key authentication when there is no HTTPS record; decided fix is HTTPS-only key hosts |
| T11 | A connection authenticated for one key is reused for another site | HTTP/2 pooling across names, TLS resumption and HTTP/3 are off for key hosts. | Origins stay isolated even when they share a delegated provider key. | Mitigated; must hold when delegation lands |
| T12 | User is tricked by a lookalike key | Keys are 52 random characters that people cannot compare by eye. The key stays visible and copyable. | Same. | Accepted for now; identity cards (later stage) address it |
| T13 | Page scripts learn the browser supports Pubky | `navigator.pubky` exposes two capability flags. | Same. | Accepted: a small fingerprinting signal, can be turned off |
| T14 | Forged or malicious update | Ed25519-signed update records checked against the pinned owner key, then package size and SHA-256. | Unchanged. | Mitigated; the owner key is a single point of failure |
| T15 | Users trained to bypass OS warnings | macOS builds are ad-hoc signed, so users must allow them in Settings. | Unchanged. | Open: Developer ID and notarization (#35) |
| T16 | Known Chromium vulnerabilities stay unpatched | The fork is pinned to Chromium 156.0.8073.0, a `main` snapshot that receives no security fixes. | Unchanged. | Open: sync policy in [PROJECT.md](PROJECT.md#upstream-chromium-updates); mitigated once the first synced release ships |
| T17 | Idle requests to Google reveal browser use | Search suggestions, AI Mode and prewarming are off by default. | Unchanged. | Partly mitigated; full Google-service inventory pending |
| T18 | Lookalike labels before the key, such as `paypal.com.<key>` | Labels are shown as typed; nothing emphasizes the key. | Same. | Open: emphasize the key and keep labels in ASCII ([IDENTIFIERS.md](IDENTIFIERS.md)) |

## Before PKResolve ships enabled by default

T2, T5, T6, T7 and T9 must be mitigated, and T4 needs a stated policy. Until
then PKResolve stays behind a flag, with DNS-over-HTTPS as the default and the
kill switch.

## Adding to this document

When a feature changes what the browser fetches, stores, trusts or shows,
add its threats to the table, with today's state and what closes each open
item. Keep entries short and link the issue or pull request that changes the
status.

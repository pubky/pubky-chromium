# Session layer

Status: October 2026. Decided in
[#62](https://github.com/pubky/pubky-chromium/issues/62). This document defines
how the browser signs in with a Pubky identity and how sites use that identity.
It builds on Pubky v0.10 grant authentication (`pubky-core`
`docs/v0.10-migration/grant-auth.md`, `docs/grant-session-lifecycle.md`,
`docs/scoped-encryption-keys.md`). Threats are tracked in
[THREAT_MODEL.md](THREAT_MODEL.md#session-layer).

## Model

- **One browser grant per identity.** The user approves the browser once. The
  browser holds one grant with client ID `pubky-browser`, keeps its
  proof-of-possession key and current bearer in browser-owned storage, and
  refreshes the bearer itself. Neither ever reaches a renderer.
- **The browser enforces each site's scope.** Sites never call the homeserver
  with a credential of their own. The browser makes the call for them and
  rejects any path outside the scopes that site was allowed.
- **The homeserver sees one client.** Per-site access is recorded and revoked
  in the browser. Per-site grants minted by the homeserver (grant delegation)
  can replace this later; the site API stays the same.

## Sign-in

- **Signers.** Pubky Ring by QR code through the relay, or Passport. A local
  Ring handoff without QR and relay comes later.
- **Scope.** The sign-in approval covers `/pub/:rw`. Nothing in `/priv/` and no
  encryption keys.
- **Entry points.** The identity button, or any site calling the API while the
  browser is signed out, which opens the same sign-in panel.

## Site access

- **API.** `navigator.pubky.requestSession(scopes)` takes capability strings in
  the existing `<path>:<r|rw>` form. It resolves to a session handle with the
  identity's public key and fetch-like methods (`get`, `put`, `delete`, `list`)
  that the browser executes with the bearer. The bearer and the grant key never
  reach the page. The JS SDK's browser transport wraps the handle, so SDK apps
  need no changes.
- **First use.** The first request from a site shows one prompt, anchored to
  the address bar, naming the site, the identity and the scopes. Allow is
  remembered for that site until revoked.
- **Escalation.** A request for scopes beyond those already allowed prompts
  again for the difference.
- **Private storage.** A request for `/priv/` paths, or any scope outside the
  browser's approval, needs a new Ring approval for that scope only. The
  prompt shows that approval's QR code instead of Allow: approving in Ring is
  the answer, and Cancel withdraws it. The browser holds the result as a
  separate grant next to the sign-in grant and uses whichever grant covers a
  path.
- **Encryption keys.** Deferred. A request with the `e` action fails with
  `NotSupportedError` until the key API is decided, because keys must not
  reach the page and pubky-core leaves the content encryption format to each
  app. When it comes, the prompt warns that keys are permanent: revoking does
  not take them back, and a key for a directory covers everything below it.
  Decided in #71.
- **Revocation.** Page info and settings list each site's access and remove it
  at once. A removed site's next call fails.
- **Scripts on an approved site.** Any script on an allowed origin can use that
  origin's access. The limits are the allowed scopes, the escalation prompt and
  instant revocation; there is no per-request confirmation.
- **Eligible origins.** Secure contexts only: HTTPS sites, key hosts and
  `http://localhost`. Workers and opaque origins get no access.
- **Frames.** The top-level document and same-origin iframes: the document's
  origin must match every ancestor's. A cross-origin embed, or a frame below
  one, gets `NotAllowedError`. Decided in #71.

## Identities

- **One identity per browser profile.** The toolbar's profile button becomes
  the identity button and switches identities. Adding an identity creates a
  browser profile, so cookies, history and storage stay separate per identity.
- **Identity button states.** Signed out (Sign in), waiting for Ring, signed in
  (avatar and name), approval expired, Incognito.

## Implementation

Decided with the owner in October 2026 while starting
[#68](https://github.com/pubky/pubky-chromium/issues/68)–[#73](https://github.com/pubky/pubky-chromium/issues/73):

- **Protocol in C++ on BoringSSL.** Ed25519, HPKE (X25519-HKDF-SHA256 with
  ChaCha20-Poly1305) and randomness come from BoringSSL. BLAKE3 (relay channel
  IDs) and XSalsa20-Poly1305 (bare grant approvals) come from small vendored C
  libraries, `//third_party/blake3` and `//third_party/tweetnacl`.
- **Checked against the SDK.** `//components/pubky_session/core` tests run
  against fixtures generated from the Pubky Rust SDK at a pinned revision by
  `//pubky/tools/session_vectors`.
- **Storage.** The client key, grant and bearer live in a per-profile file
  encrypted with Chromium's OS-backed encryption, as cookies and passwords are.
- **Finding the homeserver.** After approval the browser fetches the user's
  signed PKARR packet from the pkarr relays (`pkarr.pubky.app`, then
  `pkarr.pubky.org`), verifies its Ed25519 signature itself and reads the
  `_pubky` record's target, as the SDK does. Relays can withhold the record
  but cannot forge it. Decided in #69.
- **Sign-in format.** Sign-in asks for a bare grant, which every Ring release
  with grants supports; signed approvals (HPKE) are used only when a site asks
  for encryption keys.
- **Site API surface.** `requestSession(scopes)` resolves to a `PubkySession`
  with `publicKey`, `get(path)` (a `Response`), `put(path, bytes,
  contentType)`, `delete(path)` and `list(dir, {limit, cursor, shallow,
  reverse})` (`pubky://` URLs). Paths are canonical storage paths; anything
  else is a `TypeError`. Refusals are `NotAllowedError`, a signed-out or
  expired browser is `InvalidStateError`. Calls use path addressing,
  `/storage/<user>/<path>`, on the user's homeserver. Public reads work
  without a bearer, so they continue while the approval is expired.
- **Site UI.** The prompt anchors to the address bar like a permission
  prompt, asks only for scopes the site lacks, and closes, as a refusal, when
  the user leaves the page or switches tabs. A connected site shows a chip
  with the identity in the address bar; it opens page info, whose "Pubky
  identity" section lists the access and disconnects the site.
  `chrome://settings/pubky`, also reached from the identity panel's "Manage
  sites", shows the identity, its approval and homeserver, every site with
  its access and first-grant date and a Remove button, and sign-out.
- **Site records.** Each site's scopes live in the `PUBKY_SITE_ACCESS` website
  setting with the identity's key and the date of the first grant. A record
  for another key does not count, so a different identity starts over.
  Clearing site settings removes them.

## Lifetime

- The browser grant survives restarts until it expires or the user signs out.
- When it expires, sites keep their permissions but writes fail until the user
  approves again; the identity button asks for attention.
- Sign-out revokes the grant on the homeserver and removes the local record.
- Incognito windows start signed out. A sign-in there lasts until the window
  closes, when its grant is revoked.

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
- **Private storage and keys.** A request for `/priv/` paths or the `e` action
  needs a new Ring approval for that scope only, added to the browser's
  approval. The prompt warns that encryption keys are permanent: revoking does
  not take them back, and a key for a directory covers everything below it.
- **Revocation.** Page info and settings list each site's access and remove it
  at once. A removed site's next call fails.
- **Scripts on an approved site.** Any script on an allowed origin can use that
  origin's access. The limits are the allowed scopes, the escalation prompt and
  instant revocation; there is no per-request confirmation.
- **Eligible origins.** Secure contexts only: HTTPS sites, key hosts and
  `http://localhost`. Workers and opaque origins get no access.

## Identities

- **One identity per browser profile.** The toolbar's profile button becomes
  the identity button and switches identities. Adding an identity creates a
  browser profile, so cookies, history and storage stay separate per identity.
- **Identity button states.** Signed out (Sign in), waiting for Ring, signed in
  (avatar and name), approval expired, Incognito.

## Lifetime

- The browser grant survives restarts until it expires or the user signs out.
- When it expires, sites keep their permissions but writes fail until the user
  approves again; the identity button asks for attention.
- Sign-out revokes the grant on the homeserver and removes the local record.
- Incognito windows start signed out. A sign-in there lasts until the window
  closes, when its grant is revoked.

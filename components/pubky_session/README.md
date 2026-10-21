# Pubky sessions

The browser's Pubky session layer, designed in
[`pubky/SESSIONS.md`](../../pubky/SESSIONS.md).

`core/` holds the grant protocol with no network or UI: the
`pubkyauth://signin_grant` link, relay channel IDs, opening and checking
approvals, proof of possession and the homeserver's session response.
`crypto`, `capabilities` and `signin_link` use only the standard library,
BoringSSL, BLAKE3 and TweetNaCl. The rest uses `//base`.

Tests run against `core/test_data/sdk_vectors.json`, generated from the Pubky
Rust SDK by `//pubky/tools/session_vectors` at a pinned pubky-core revision.
Regenerate it after a protocol change:

```sh
cd pubky/tools/session_vectors
cargo run --release > ../../../components/pubky_session/core/test_data/sdk_vectors.json
```

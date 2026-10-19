# The familiar browser. A new kind of web address.

**Pubky Chromium brings public-key websites into your browser.** Paste a public
key into the address bar, and the browser finds the server and verifies that it
holds the matching private key. Browse ordinary websites alongside it, using
the familiar Chromium interface.

[Get started](../README.md#fresh-checkout-and-build) ·
[Try the demos](#try-the-public-key-web) ·
[Build for it](#for-developers-build-websites-around-keys)

## Why browse with Pubky Chromium?

### Open public-key links directly

A public key can be a website's address. Pubky Chromium understands these
addresses out of the box, including bare keys pasted into the address bar.
It opens them over HTTPS, with no extension or local proxy to install.

You can follow a public-key link from a message, bookmark it, or share it with
someone else using a compatible browser.

### Let the browser verify the site's identity

For a public-key website, the address tells the browser which key to expect.
During the encrypted connection, the server must prove possession of the matching
private key. A different key is rejected.

This authentication is built into the browser's TLS stack. The site-info panel
identifies public-key TLS connections, and a certificate exception cannot bypass
a mismatching key. No certificate authority is needed to authenticate these
public-key connections.

### Keep using the ordinary web

Pubky Chromium is a Chromium fork with public-key browsing added to it. Ordinary
HTTPS websites continue to use standard certificate verification. Public-key
sites use the new authentication path. Both open in the same browser.

## What changes compared with standard Chromium?

| | Standard Chromium | Pubky Chromium |
|---|---|---|
| DNS-over-HTTPS | Configurable | PKDNS configured in strict mode by default |
| Public-key name resolution | Requires a suitable resolver to be configured | Ready to use through PKDNS |
| Bare public key in the address bar | Often treated as a search | Opens the public-key HTTPS address |
| Raw-public-key HTTPS | Not supported natively | TLS 1.3 with RFC 7250 and Ed25519 URL-key verification |
| Connection identity | X.509 certificate information | Public-key authentication shown for public-key sites |
| JavaScript support detection | No Pubky capability API | Native `navigator.pubky` object |
| Ordinary HTTPS websites | Standard certificate verification | Standard certificate verification |

## Try the public-key web

Once you have Pubky Chromium running, paste this key into the address bar:

```text
8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty
```

The [homeserver demo](https://8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty/)
displays **“Pubky Homeserver.”** The address stays on the public key. In our
verified browser test, its DNS records selected port 6287 and the connection
authenticated that key directly, without switching to an ICANN hostname.

For a more visual example, open the
[public-key website demo](https://4msqbgpkfcdgnzrrsyp5hgno8rfa4sx15c79ughsq95ikycunowy/).
It demonstrates serving a page over HTTP and public-key HTTPS. The browser's
connection information verifies authentication; the page's own HTTPS indicator
only describes its URL.

[Read the verification results](../VERIFICATION.md) for the connection evidence
and tests covering wrong-key rejection, DNS behavior, and browser integration.

## For developers: build websites around keys

Give a site a key-based identity that can stay the same when its hosting changes.
Publish updated endpoint records to point that identity at a new server, and
serve TLS with the same key. You can use this addressing model without registering
a conventional domain for the site itself.

The browser still renders ordinary HTML, CSS, and JavaScript. To host a
public-key site:

1. **Publish its endpoint records with [PKARR](https://github.com/pubky/pkarr).**
   Advertise the address and, where needed, an HTTPS ServiceMode record with
   target `.` and the service port.
2. **Serve raw-public-key TLS with the matching key.**
   [Pubky TLS Proxy](https://github.com/pubky/pubky-tls-proxy) can terminate that
   connection and forward requests to your existing web server.
3. **Share `https://<public-key>/` links.**
   Pubky Chromium keeps the public-key hostname as the URL and web origin.

### Offer public-key links to compatible browsers

Detect native support from an HTTP or HTTPS page:

```js
const publicKey =
  '8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty';

const supportsPubky =
  navigator.pubky?.supportsPkdns === true &&
  navigator.pubky?.supportsRawPublicKeyTls === true;

if (supportsPubky) {
  const link = document.createElement('a');
  link.href = `https://${publicKey}/`;
  link.textContent = 'Open the public-key website';
  document.body.append(link);
}
```

These read-only properties report built-in support. They stay true while offline
or with secure DNS disabled; they do not report server availability or how the
current page was authenticated. Ordinary browsers fall through the check without
requiring user-agent detection.

[Explore the JavaScript API](../README.md#javascript-capability-detection).

## How a key becomes a connection

**PKDNS finds the endpoint. The key in the URL authenticates the server.**

[PKARR](https://github.com/pubky/pkarr) publishes signed DNS records associated
with public keys. [PKDNS](https://github.com/pubky/pkdns) makes those records
available through DNS. This browser uses `https://pkdns.pubky.org/dns-query` as
its default encrypted resolver, then verifies the destination's key during TLS.

Public-key lookups fail if secure DNS cannot resolve them, rather than falling
back to the system resolver. The browser uses PKDNS for discovery; it does not
run a DHT client or retrieve PKARR packets directly from a relay.

## Get started

Available today: a tested **macOS Apple Silicon development build**.
Start with the [checkout and build guide](../README.md#fresh-checkout-and-build),
then [launch the browser](../README.md#launch) and try a public-key address.
The launcher uses a separate browser profile. Keep the full build output
directory together, since this component build uses libraries alongside the app.

The current public-key transport uses TCP TLS. The
[technical overview](../README.md#features) documents the implementation's scope,
including HTTP/3 and key-delegation limitations.

Want to help more people use it? Test your sites, improve packaging, or contribute
platform support. Open a [pull request](https://github.com/pubky/pubky-chromium/pulls)
with your changes, or include a reproducible test case when proposing a fix.

**[Build Pubky Chromium and try your first public-key website →](../README.md#fresh-checkout-and-build)**

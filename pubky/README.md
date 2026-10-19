# Pubky Chromium

Native macOS ARM64 Chromium integration for PKDNS and RFC 7250 raw-public-key
TLS. The initial Chromium 156.0.8073.0 build passed 148 automated tests and both
live public-key website checks. See [VERIFICATION.md](VERIFICATION.md).

## Features

- Strict DoH at `https://pkdns.pubky.org/dns-query`, enabled by default.
- Bare canonical z-base-32 Ed25519 keys in the omnibox select HTTPS.
- Public-key lookups use secure DNS only, without system-resolver fallback,
  hosts-file overrides, or DNS search suffixes. System DNS can bootstrap the
  ordinary hostname of the DoH endpoint itself.
- Public-key TLS requires TLS 1.3, RFC 7250, and the Ed25519 key encoded in the
  URL. Certificate exceptions cannot bypass a mismatching key. Ordinary HTTPS
  retains Chromium's X.509 verification.
- Same-name HTTPS ServiceMode records can select a different destination port,
  subject to Chromium's restricted-port checks.
- Raw-key authentication metadata survives network IPC and HTTP cache storage
  and is displayed in the browser's security state and site-info panel.
- No PKARR relay is used by the browser; DoH discovers the endpoint and the URL
  key authenticates the server.
- Native JavaScript capability detection through `navigator.pubky`.

The initial implementation uses TCP TLS. It disables TLS resumption/0-RTT,
HTTP/3, cross-origin HTTP/2 coalescing, and X.509-dependent NTLM/Negotiate channel
binding for public-key connections. Cross-name/key delegation is not implemented.

## JavaScript capability detection

```js
const supportsPubky =
  navigator.pubky?.supportsPkdns === true &&
  navigator.pubky?.supportsRawPublicKeyTls === true;

if (supportsPubky) {
  link.href = `https://${publicKey}/`;
}
```

`navigator.pubky` is a native, read-only `PubkyCapabilities` object. Repeated
access on the same Navigator returns the same object. Its two read-only boolean
properties report **built-in support**:

| Property | Meaning |
|---|---|
| `supportsPkdns` | Public-key hostname resolution through PKDNS is implemented. |
| `supportsRawPublicKeyTls` | RFC 7250 TLS with Ed25519 URL-key verification is implemented. |

The API is exposed to page scripts on both HTTP and HTTPS origins, including
ordinary domains and public-key domains. It is not exposed in workers. It
requires no permissions, performs no network requests, and stays true while
offline or when a user disables secure DNS. It does not report current DNS
configuration, server reachability, or the authentication used for the current
page. Read-only WebIDL getters are feature detection, not an attestation against
scripts that deliberately replace JavaScript properties.

Ordinary browsers do not provide this API. The Blink runtime feature
`PubkyCapabilities` is enabled by default in this fork; launching with
`--disable-blink-features=PubkyCapabilities` removes both `navigator.pubky` and the
`PubkyCapabilities` interface. This flag controls API exposure, not DNS/TLS support.

Configure `out/Pubky` and run the HTTP, HTTPS, worker, and feature-disabled
web-platform tests with:

```sh
bash pubky/scripts/test_capabilities.sh
```

## Repository and branches

- Primary repository (`origin`): https://github.com/SeverinAlexB/pubky-chromium
- Custom/default branch: `pubky`
- Chromium remote (`upstream`): https://chromium.googlesource.com/chromium/src.git
- Initial upstream base: [upstream-revision.txt](upstream-revision.txt)
- Build-tools pin: [depot-tools-revision.txt](depot-tools-revision.txt)
- BoringSSL is pinned through Chromium's `DEPS`; the initial revision is
  `5fbad2285b096858fc9afa3e4c949fde39452070` and already implements RFC 7250.

All Pubky source modifications are committed directly in Chromium's tree. No
separate patch application is needed after cloning this fork.

## Fresh checkout and build

Requires an Apple Silicon Mac, Xcode and its Metal toolchain, and substantial
free APFS storage. The initial build used Xcode 27.0 and 48 GiB RAM.

From a directory where you want to create the checkout:

```sh
mkdir pubky-checkout
git clone --depth=1 --single-branch --branch pubky \
  https://github.com/SeverinAlexB/pubky-chromium.git pubky-checkout/src
git -C pubky-checkout/src remote add upstream \
  https://chromium.googlesource.com/chromium/src.git
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git \
  pubky-checkout/depot_tools
git -C pubky-checkout/depot_tools checkout \
  "$(< pubky-checkout/src/pubky/depot-tools-revision.txt)"
export PATH="$PWD/pubky-checkout/depot_tools:$PATH"
"$PWD/pubky-checkout/depot_tools/ensure_bootstrap"
cp pubky-checkout/src/pubky/gclient.py pubky-checkout/.gclient
bash pubky-checkout/src/pubky/scripts/sync.sh
xcodebuild -downloadComponent MetalToolchain
bash pubky-checkout/src/pubky/scripts/build.sh
```

The `.gclient` solution is deliberately unmanaged: `sync.sh` updates dependencies
from the checked-out `DEPS` without switching away from the Pubky branch.
`BUILD_JOBS` (default 4) and `SYNC_JOBS` (default 8) control parallelism. Blink's
binding generators use `blink_bindings_single_process = true` to avoid each
concurrent generator spawning a separate CPU-sized Python worker pool. Set
`DEPOT_TOOLS_DIR` if depot_tools is elsewhere; otherwise adjacent checkout
locations and the existing `PATH` are supported.

Build configuration: [args.gn](args.gn). The build script runs the focused
network and browser-response/omnibox tests before compiling the application.
Keep the whole `out/Pubky` directory together: this development component build
uses libraries adjacent to `Chromium.app`.

## Launch

From the Chromium Git root (`src`):

```sh
bash pubky/scripts/run.sh https://8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty/
```

Expected body: **Pubky Homeserver**. The tested endpoint was
`34.65.156.171:6287`, discovered through the HTTPS record. The TLS peer key
matched the public-key URL, and no ICANN homeserver identity was used.

The launcher uses a separate profile under `pubky/profiles/default`. It supplies
no DNS, TLS-verification, or proxy overrides. The other live fixture is:

```text
https://4msqbgpkfcdgnzrrsyp5hgno8rfa4sx15c79ughsq95ikycunowy/
```

## Installing the Linux package

Releases ship a `.deb` for Ubuntu 24.04. Check the download against the
release's `SHA256SUMS.txt`, then install it from a terminal:

```sh
sudo apt install ./pubky-chromium_<version>_amd64.deb
```

Opening the file in Ubuntu's App Center instead shows "Unknown publisher" and
"Potentially unsafe". App Center shows that for every `.deb` opened from a file;
it is not a signature failure, and a signed APT repository would not change it.
The terminal install shows no such warning. Later versions arrive through the
in-app updater (Settings > About), which verifies the owner's signature before
installing.

## Independent diagnostics

With Python 3 and OpenSSL supporting `-enable_server_rpk`:

```sh
python3 pubky/scripts/probe_endpoint.py --port 443
python3 pubky/scripts/summarize_netlog.py /path/to/closed-browser-netlog.json
```

The probe resolves through PKDNS and verifies raw-key TLS, HTTP 200, and wrong-key
rejection. Omit `--port` to derive the port from a usable ServiceMode HTTPS
record. Its locally constructed TLSA value pins the URL key; it is not a DNSSEC
record obtained from a resolver. No redirects are followed.

The NetLog checker verifies strict PKDNS configuration, main-frame public-key
URLs, secure DNS lookups, matching raw peer keys, and the expected test ports.
NetLog `SSL_CONNECT` completion events expose `peer_authentication` and
`verified_raw_public_key`.

Standalone decoder test:

```sh
clang++ -std=c++20 -Wall -Wextra -Werror -I . \
  pubky/tests/public_key_test.cc -o /tmp/pubky_public_key_test
/tmp/pubky_public_key_test
```

## Merging Chromium updates

[PROJECT.md](PROJECT.md#upstream-chromium-updates) says which Chromium releases
the fork follows and how often. On a branch off `pubky`, with a clean working
tree, merge the release tag:

```sh
git fetch --no-tags upstream refs/tags/<version>:refs/tags/<version>
git merge <version>
bash pubky/scripts/sync.sh
bash pubky/scripts/build.sh
```

Then open a pull request against `pubky`. A shallow clone works as long as it
contains the current base commit from `upstream-revision.txt`; the fetch then
downloads only the upstream commits after it. Resolve source conflicts and
rerun both live raw-key acceptance tests after each Chromium update. The
`upstream` remote retains Google's original repository; GitHub also records
this repository as a fork of `chromium/chromium`.

# Chromium-owned PKResolve requests: prototype

This prototype uses the PKResolve CXX bridge pinned as a Git submodule at
`third_party/pkarr` to derive Pubky service endpoints. It does not change
browser navigation, the default DoH resolver, or destination TLS. The C++
implementation is isolated in explicit test-only targets.

Pinned `pubky/pkarr` revision:
`1203024b3a0da7716b4a2ab3768375ce0bc1fb64`.

Initialize only this dependency after checking out the branch:

```sh
git submodule update --init -- third_party/pkarr
```

The submodule uses `https://github.com/pubky/pkarr.git`. Its Git link pins
the tested revision; no separate local repository is required. Do not use
`--remote` when reproducing the prototype. The initialization command does not
run `gclient sync` or initialize Chromium's other submodules.

## Flow and ownership

`Resolver::Resolve()` accepts a service hostname, original URL port, supported
HTTP protocols, and a callback:

```text
Rust prepare()
  -> cached result or error: deliver immediately
  -> fetch needed: retain the opaque preparation
       Chromium SimpleURLLoader POSTs the Rust JSON request
       Rust accept_bundle() validates and derives endpoints
       deliver endpoints, expected raw key, and absolute reuse deadline
```

Pass a profile-isolated `SharedURLLoaderFactory`. The default bundle endpoint
is `https://pkarr.dev/v1/resolve`. An optional constructor argument selects
another HTTPS endpoint. Each uncached lookup sends the requested service name,
original URL port, and supported protocols to that service.

Illustrative browser-side use, on one sequence:

```cpp
auto resolver = std::make_unique<pubky::prototype::Resolver>(
    profile_factory);
resolver->Resolve(
    service_hostname, 443,
    {pkresolve::HttpProtocol::Http2, pkresolve::HttpProtocol::Http11},
    base::BindOnce([](pubky::prototype::ResolveResult result) {
      if (result.net_error != net::OK || !result.response ||
          result.response->status.code != pkresolve::StatusCode::Ok) {
        return;  // Report transport or protocol failure to your caller.
      }
      // Select from result.response->resolution.candidates.
      // Preserve result.expires_at and the original HTTP authority.
      // Verify resolution.public_key during destination raw-key TLS.
      // It is the final routing owner's key after HTTPS alias delegation.
    }));
// Retain resolver until completion; Cancel() suppresses callback delivery.
```

Callbacks can run inline for cache hits and input errors. The callback may
destroy the resolver. Each instance permits one active lookup; another lookup
fails without disturbing the first. Cancellation or destruction drops the
Chromium loader and retained preparation, with no Rust cancellation operation.

The experimental transport omits credentials, rejects redirects, disables HTTP
caching, uses a 10-second timeout, and caps the response at 1 MiB. These bounds
are prototype choices, not settled protocol policy. A successful HTTP exchange
can still return a Rust protocol error; check both result layers.

## Check the real bridge without building Chromium

Prerequisites: Rust, a C++17 compiler, cached Cargo dependencies, and the CXX
generator matching the bridge's pinned version. If needed, install it to a
chosen temporary tool directory:

```sh
cargo install cxxbridge-cmd --version 1.0.194 --locked \
  --root /tmp/pubky-prototype-tools
python3 pubky/resolve_prototype/check_bridge.py \
  --cxxbridge /tmp/pubky-prototype-tools/bin/cxxbridge
```

The script defaults to offline Cargo operations. Add `--allow-downloads` only
when dependency downloads are authorized. It builds in a temporary copy and
leaves the submodule unchanged. It finds the dependency relative to this
repository, independently of the current working directory.
The prototype's `bridge.Cargo.lock` pins the standalone Cargo dependency graph;
the script copies it into the temporary bridge workspace before building.
Upstream does not track a lockfile for that separate workspace.

The standalone test uses a freshly signed fixture from the real library. It
checks endpoint derivation, cache reuse, retained freshness, invalid input,
and cache preservation after malformed JSON. It performs no network request
and does not prove signature validation or destination TLS.

## Build and test the Chromium wrapper

The GN targets are explicit and have no dependency from normal browser targets.
The C++ resolver target is test-only. The source is pinned at
`//third_party/pkarr`. Adding the source submodule does not provide the
library's generated Rust dependency targets.

Check the configuration prerequisites in your build environment:

```sh
python3 pubky/resolve_prototype/check_chromium_environment.py
```

This checks the pinned toolchains, initial source dependencies, and generated
Rust targets. It does not start a build or guarantee that the full dependency
closure is present. A custom system compiler installation does not provide
Chromium's source submodules or generated gclient arguments.

The prototype uses `//third_party/pkarr/bindings/chromium:bridge` directly.
The upstream GN file builds PKARR with only `signed_packet` enabled,
PKResolve with `service-client` and `service-protocol`, and the CXX bridge.
The fixture depends directly on the upstream `:pkarr` target. Restricted
external dependencies grant visibility to that target through gnrt settings.
The C++ caller and fixtures are test-only; no shipping browser target uses them.

Chromium's Cargo manifest lists their external Rust dependencies directly so
gnrt can vendor them and generate GN targets. The prototype links PKARR and
PKResolve from the submodule.

The Rust `ServiceClient` calls synchronous `derive_resolution()` for both
cache lookup and bundle acceptance. The CXX API is synchronous, while
Chromium owns asynchronous HTTP. The integration requires no async executor.

The submodule includes the PKARR and PKResolve licenses and builds without
local source patches.

To vendor dependencies and generate their GN targets, use a nightly Rust
sysroot for gnrt's `cargo -Zbindeps` support. Replace `<nightly-sysroot>` with
the toolchain root containing `bin/cargo` and `bin/rustc`:

```sh
python3 pubky/resolve_prototype/prepare_rust_dependencies.py \
  --rust-sysroot <nightly-sysroot>
```

The runner puts the selected Rust binaries first on PATH, preserves other tools,
and uses a temporary tool output directory. Inspect the metadata and generated
GN files before claiming the Rust dependency preparation is complete.

Use the Chromium source dependencies and tool versions pinned by the checkout.
DEPS pins GN revision `56c22442ee369ddc6f44c2ff5e0664d47a3c6b0e`; use the
binary at `buildtools/linux64/gn`. Download the pinned compiler packages with:

```sh
python3 tools/clang/scripts/update.py
python3 tools/rust/update_rust.py
```

To prepare GN, Python, test data, and generated arguments for this prototype:

```sh
python3 pubky/resolve_prototype/prepare_build_inputs.py --plan
python3 pubky/resolve_prototype/prepare_build_inputs.py
python3 pubky/resolve_prototype/check_chromium_environment.py
```

The setup requires Linux x86_64, Python with tarfile's data filter, Bash, curl,
Git, and sha256sum. Even `--plan` downloads the pinned depot_tools source to a
temporary directory so its official evaluator can read DEPS.

The setup uses depot_tools' digest-verified CIPD bootstrap to install the GN,
mold linker, host Python, TypeScript compiler, and variations test-data packages
pinned in DEPS, plus the Go toolchain pinned in Dawn's DEPS for Tint generation.
It installs clang-format, the Linux Node runtime, Node packages, and test fonts
from DEPS-pinned GCS objects after checking their sizes and SHA-256 digests.
It runs the DEPS hooks for LASTCHANGE and the GPU, Skia, and Dawn revision files
against the local checkouts.
Git submodule initialization does not supply these packages. The setup derives
each listed argument from DEPS defaults and Linux x64 built-ins, including
conditions and `Str()` values. It refuses to replace an existing differing or
symlinked arguments file.
This prepares the prototype's Linux configuration, not a complete gclient state.
No full sync, dependency pin change, or Chromium build occurs.

With an existing shared Chromium output folder, inspect the plan first:

```sh
autoninja -n -C <output> pubky/resolve_prototype:resolver_unittests \
  pkresolve_chromium_unittests
autoninja -C <output> -j16 pubky/resolve_prototype:resolver_unittests \
  pkresolve_chromium_unittests
<output>/resolver_unittests
<output>/pkresolve_chromium_unittests
```

Follow PROJECT.md's lock, resource limits, and incremental build gates.

For the prepared Guix build directory, run the C++ and Rust tests with:

```sh
env -u LD_LIBRARY_PATH out/PkresolvePrototype/resolver_unittests
env -u LD_LIBRARY_PATH out/PkresolvePrototype/pkresolve_chromium_unittests
```

Unsetting `LD_LIBRARY_PATH` avoids mixing the host loader with Guix libraries.

The upstream `pkresolve_chromium_unittests` target checks bridge conversion,
alias routing and delegated keys, packet age, cache reuse, and malformed
bundle rejection in Rust.

The C++ test target uses an entry point based on Chromium's `NetTestSuite` and
initializes Mojo once per test process before creating message pipes.

The wrapper tests cover request policy, invalid inputs and bundles, HTTP
failures, oversized responses, timeouts, cancellation, destruction, and a second
lookup while busy. They also verify rejection of a tampered signature without
cache insertion, a successful signed-bundle response,
endpoint/key/protocol results, preserved packet freshness, cache reuse without
another request, cache expiration and refetch, and resolver destruction inside
both network and inline cache callbacks.

The test-only `signed_bundle_fixture.rs` helper signs packets at runtime using
PKARR and public deterministic test keys. Each response includes the required
resolution summary, while the client derives its result from the packets.
Responses pass through Chromium's `TestURLLoaderFactory` and the real Rust
bundle decoder. The expiration test
waits three seconds in real time because Chromium's mock clock does not advance
Rust's cache clock. The 18 `ResolverTest` cases use an in-process URL loader
factory. An HTTPS AliasMode test checks that network and cached results
preserve the original service and return the delegate's TLS key.

The three `ResolverHttpsTest` cases use Chromium's embedded HTTPS server
and a real network context and certificate verifier. They check successful
bundle transport and cache reuse, rejection of a mismatched server certificate,
and rejection of redirects. The server's test CA is scoped to the test process;
no certificate-error bypass is enabled. They exercise HTTPS to the bundle
service, not raw-key TLS to the resolved destination.

TLS handshake errors logged by the certificate-mismatch case are expected.
To run only the HTTPS suite, use an environment that permits loopback sockets:

```sh
env -u LD_LIBRARY_PATH out/PkresolvePrototype/resolver_unittests \
  --single-process-tests --gtest_filter=ResolverHttpsTest.*
```

## Resolve a live domain through pkarr.dev

The live test uses Chromium HTTP and the Rust bundle client. It requires
outbound HTTPS and DNS. It is disabled in ordinary test runs because live
records and service availability can change. Run it explicitly:

```sh
env -u LD_LIBRARY_PATH out/PkresolvePrototype/resolver_unittests \
  --single-process-tests --gtest_also_run_disabled_tests \
  --gtest_filter=ResolverHttpsTest.DISABLED_ResolvesDomainThroughPkarrDev \
  --pubky-service=_pubky.w7dxfm5euq4z1o38ksiqd8oih4fybzw48by47kbnkze1xo6939wo
```

Replace the `--pubky-service` value with the canonical service hostname to
resolve. The test prints the derived endpoint addresses and ports. It performs
resolution only; it does not connect to the destination application.

## Verification

The pinned revision builds incrementally with `-j16`. All 21 deterministic
Chromium tests and all three upstream Rust bridge tests pass. The tampered-signature test checks the
HTTP-to-CXX rejection path and verifies that a subsequent lookup fetches again.
The standalone smoke test and opt-in live test have not been run for this pin.

## Remaining integration work

The library verifies packet signatures before deriving routes or caching.
Observation time (`last_seen`) remains unsigned, so signature verification
does not authenticate freshness. Cache capacity and packet-version handling
remain library work.

Before browser use, approve the isolation and service policies, integrate
host resolution and endpoint metadata, and validate raw-key TLS and ordinary
HTTPS regressions. The bridge returns the final routing owner's TLS key after
HTTPS AliasMode delegation; browser code must enforce that key while preserving
the original service as SNI and HTTP authority.

Browser navigation, destination TLS enforcement, and performance improvements
remain outside this prototype.

# TLS trust model

Status: October 2026. This document defines who may authenticate a website
whose host is a public key, and what the browser does when that fails. It
assumes the browser adopts PKResolve for resolution
([`pubky/pkresolve`](https://github.com/pubky/pkresolve), spec at
`docs/SPEC.md`, revision `e88b7072`), which follows the routing and TLS
delegation proposal in `pubky/pkdns` (`research/delegation` branch,
`research-delegation/05-routing-and-tls-delegation.md`, revision
`03d711d2`). Addresses and names follow [IDENTIFIERS.md](IDENTIFIERS.md);
open risks are tracked in [THREAT_MODEL.md](THREAT_MODEL.md).

## Principles

1. **A key, not a certificate authority, authenticates a key host.** For
   `https://<key-host>/`, the server must prove possession of an Ed25519
   key that the URL key authorized: the URL key itself, or a key it
   delegated to.
2. **Routing and authentication are separate.** Routing records decide where
   to connect. Only TLS delegation records decide who may answer. A routing
   record, address hint or resolver answer never grants TLS authority.
3. **Signed records only.** Every record used for routing or delegation comes
   from a packet signed by the key that owns the name, and the browser
   verifies that signature itself.
4. **No fallback.** An authentication or resolution failure never falls back
   to CA-verified TLS, plain HTTP or ordinary DNS, and the user cannot click
   through it.
5. **Ordinary sites are unchanged.** Hosts that are not key hosts keep
   Chromium's DNS, X.509 and certificate-error behaviour.

## Today: direct key with DNS-over-HTTPS

Implemented in the current fork.

- **Resolution.** Key hosts resolve only through secure DNS, by default
  `https://pkdns.pubky.org/dns-query`. There is no system resolver, hosts
  file or search-suffix fallback, and resolution fails closed without DoH
  (`HostResolverManagerTest.PubkyFailsClosedWithoutDoh`). The browser queries
  A, AAAA and HTTPS records. An HTTPS ServiceMode record may select another
  port, subject to Chromium's restricted-port list. A/AAAA records at the URL
  port are still used when no HTTPS record matches.
- **DoH settings.** The PKDNS server is only a default. If the user or a
  policy picks another DoH provider, key-host lookups go there. If secure DNS
  is turned off, key hosts fail to resolve. In the default secure mode every
  hostname, not only key hosts, is resolved through PKDNS.
- **Trust in the resolver.** The browser does not verify PKARR signatures on
  DoH answers. The DoH server is trusted for routing only: a wrong answer
  causes a failed handshake, not impersonation.
- **Handshake.** TLS 1.3 only, RFC 7250 raw public keys only, Ed25519 only.
  The peer's key must equal the key in the URL host's last label; otherwise
  the connection fails with `ERR_SSL_PROTOCOL_ERROR`. Certificate exceptions
  and `--ignore-certificate-errors` cannot bypass it.
- **SNI.** The full URL host (`<key>` or `app.<key>`).
- **Disabled for key hosts.** Early data (0-RTT), renegotiation, TLS session
  resumption, HTTP/2 connection pooling across names, QUIC and HTTP/3,
  Alt-Svc, and NTLM/Negotiate authentication. Certificate-only checks
  (certificate verifier, Certificate Transparency, OCSP, key pins) do not
  apply.
- **Not special-cased.** Encrypted Client Hello is attempted when the HTTPS
  record carries a config; if the server rejects it, the connection fails.
  X.509 client certificates still work.
- **Display.** A verified raw key counts as a valid certificate for the
  security state. Page info shows "Public-key TLS connection is secure"
  (English only).
- **Delegation.** Not supported: a site can only be served by the holder of
  its own key. Delegation needs verified packets, so this path never gains
  it ([#60](https://github.com/pubky/pubky-chromium/issues/60)).

## With PKResolve

Decided. PKResolve replaces DoH routing for key hosts outright; see
[Rollout](#rollout).

### Inputs

- **Service name**: the URL host, lowercased, without the trailing dot.
  `<key>`, `app.<key>` and `_pubky.<key>` are distinct services owned by
  `<key>`.
- **URL port**: the port in the URL (443 by default). It stays in the HTTP
  `Host` header even when routing selects another connection port.

### Routing: where to connect

- Routing comes from HTTPS ServiceMode records in the owner's signed packet,
  at `<service>` for port 443 and at `_<port>._https.<service>` otherwise.
- Each compatible ServiceMode record gives one candidate: addresses, a
  connection port and protocols (`h2`, `http/1.1`).
- A ServiceMode target is `.` or another key name. With `.` the addresses
  come from the owner's own packet. With a key name they come from that
  key's verified packet, while the connection port and protocols still come
  from this record; the target's HTTPS records are not followed.
- A ServiceMode record is required. A/AAAA records alone do not route a key
  host. This is stricter than today's DoH path.
- `HTTPS 0 .` means the owner declared the service unavailable; the browser
  shows an error.
- Deferred: HTTPS AliasMode to other names, ServiceMode targets that are
  ordinary domains, routing CNAMEs, ECH and HTTP/3.

### TLS authority: who may answer

The authority is found separately for each connection port, at
`_<port>._tcp.<service>`:

- **No TLS CNAME** there, proven by a verified packet: the URL key is the
  authority. This is the direct case and matches today's behaviour.
- **A TLS CNAME to another key name**: follow it to the target, keeping the
  port and transport labels, and repeat. The authority is the key of the
  namespace where the chain ends. Chains are bounded by hop, query and time
  limits and reject cycles.
- **A TLS CNAME to an ordinary domain** (CA delegation): deferred. The
  connection fails.
- **Missing or unverifiable evidence** never proves that a chain ended. The
  connection fails.

### Example: a site served by the user's homeserver

Decided in [#60](https://github.com/pubky/pubky-chromium/issues/60), following the pkdns delegation proposal with a ServiceMode
target in place of its AliasMode example:

```dns
; Signed by the user
<user-key>.                  IN HTTPS 1 <homeserver-key>. port=8443
_8443._tcp.<user-key>.       IN CNAME _8443._tcp.<homeserver-key>.
blog.<user-key>.             IN HTTPS 1 <homeserver-key>. port=8443
_8443._tcp.blog.<user-key>.  IN CNAME _8443._tcp.<homeserver-key>.
; Signed by the homeserver
<homeserver-key>.            IN HTTPS 1 . port=8443
<homeserver-key>.            IN A 203.0.113.10
```

- The browser connects to the homeserver's address on the port in the user's
  record and expects the homeserver's key, because the homeserver publishes
  no TLS CNAME of its own.
- SNI and the `Host` header stay `<user-key>` or `blog.<user-key>`, which is
  how the homeserver selects the site ([pubky/pubky-homeserver#711](https://github.com/pubky/pubky-homeserver/issues/711)).
- Every service delegates on its own: the records for `<user-key>` do not
  cover `blog.<user-key>`.
- The TLS CNAME name carries the connection port. A homeserver that changes
  its address needs no user update; one that changes its TLS port needs every
  user to republish both records.

### Handshake

- **Expected key**: the authority key for the selected connection port. The
  peer's raw key must equal it exactly.
- **SNI**: the original URL host, unaffected by routing or delegation.
- **HTTP authority**: the original host and URL port.
- Unchanged from today: TLS 1.3, raw public keys, Ed25519, no early data, no
  resumption, no bypass. X.509 client certificates keep upstream behaviour.
- Encrypted Client Hello is not used for key hosts until it is specified.
- The handshake proves identity. A verified resolution alone does not.

### Verification by the browser

PKResolve's Rust client runs these checks inside the browser, whatever the
PKResolve service returns:

1. Bound the response size and parsing work, verify every packet signature,
   and reject conflicting versions in one response.
2. Enforce freshness and reject packet versions older than ones already
   accepted.
3. Follow routing and TLS chains from the original request, enforcing name
   scope, record rules, cycle checks and lookup limits.
4. Resolve TLS authority separately for each connection port. Routing grants
   no TLS authority.
5. Derive every compatible candidate. A missing packet fails the lookup; the
   order of the response grants no priority.

The PKResolve service is trusted for availability only. It can delay or
withhold answers, but it cannot change where the browser connects or which
key it accepts.

### Reuse and isolation

- A resolution can be reused until its earliest dependency expires: record
  TTLs, packet age limits and local cache limits, measured on a monotonic
  clock.
- Connections are keyed by origin and expected key. Two origins delegated to
  the same provider key never share a connection.
- Resolution caches are per browser profile, and separate for Incognito.
- When a newer packet changes routing or authority, existing connections and
  cached results for the affected names are dropped.

### Failures

| Failure | Result |
|---|---|
| PKResolve service unreachable or times out | Error page. No fallback to DoH within the same navigation. |
| Signature, packet or record invalid | Error page. |
| Records expired | Fetch again; error page if that fails. |
| Response older than packets already accepted | Rejected; the newer cached packets stay. |
| No compatible ServiceMode record | Error page. No bare-address fallback. |
| Delegation chain too long, looping or unprovable | Error page. |
| Peer key does not match the expected key | `ERR_SSL_PROTOCOL_ERROR`. No bypass. |

### Display

- The security state is secure only after a successful raw-key handshake.
- Page info names the authenticating key. When the site is delegated it
  shows both: served by the provider key on behalf of the URL key.
- Delegated sites get no other marker in the address bar or security chip.

### Plain HTTP, secure contexts and mixed content

- Key hosts are HTTPS-only. `http://<key-host>` is upgraded before any
  request, with no fallback ([IDENTIFIERS.md](IDENTIFIERS.md)).
- Key-host pages loaded over HTTPS are secure contexts, and Chromium's
  mixed-content rules apply to them as to any HTTPS page.

## Rollout

Decided in [#60](https://github.com/pubky/pubky-chromium/issues/60).

- PKResolve replaces DoH for key hosts outright as soon as the integration
  passes the release checks in [PROJECT.md](PROJECT.md). There is no flag, and
  no DoH fallback or kill switch for key hosts.
- The gaps under [Not yet implemented in PKResolve](#not-yet-implemented-in-pkresolve)
  ship as open threats in [THREAT_MODEL.md](THREAT_MODEL.md) until fixed.
  Until packet signatures are verified, the PKResolve service is trusted for
  routing and delegation.
- Delegation works only through PKResolve. The DoH path keeps direct keys
  only until PKResolve replaces it.
- Ordinary hostnames then use Chromium's default secure DNS mode: the system
  resolver, upgraded to its DNS-over-HTTPS service when it offers one. The
  `pkdns.pubky.org` default is removed.

## Not yet implemented in PKResolve

As of `e88b7072`, the PKResolve code implements less than this model:

- Packet signatures are not verified, because PKARR 8.1 does not check them
  when parsing stored packets. A PKARR release with the fix is needed.
- TLS CNAMEs are ignored; only the direct case works. The Chromium interface
  returns one key per resolution and needs one per connection port.
- ServiceMode targets that are other key names are not followed.
- Version rollback is not checked, and there is no cap on signed-packet age.
- Response size and parsing work are not bounded in Rust.
- The service has no HTTP server yet.

## Open decisions

Owned by the PKResolve specification; this document adopts whatever it
settles:

- Delegation limits: hops, queries and time.
- Freshness: maximum packet age and allowed clock skew.
- Which PKResolve service the browser uses, and its logging and retention
  policy.

Owned by this project:

- Key hosts behind an HTTP proxy: the proxy resolves the name, so neither
  DoH routing nor PKResolve applies. TLS still checks the key end to end.
  Behaviour is untested.

## Deferred

Pubky-signed certificates, CA delegation and CA endpoint declarations,
HTTPS aliases, alternate targets, routing CNAMEs combined with TLS
delegation, ECH, HTTP/3 and session resumption for key hosts.

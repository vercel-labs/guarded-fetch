# guarded-fetch

Drop-in `fetch` on the server for URLs you don't trust!

Server Side Request Forgery is when user modified urls let an attacker point your server at
`http://169.254.169.254` and read your cloud credentials (Common cases are urls like webhooks,
log drains, connector
callbacks, etc.). `guardedFetch` is a
drop-in replacement that blocks that whole class of attack (SSRF), plus DNS
rebinding, redirect tricks, header smuggling, and unbounded responses.

Built on [undici](https://github.com/nodejs/undici). Two runtime
dependencies (`undici`, `ipaddr.js`). Node ≥ 20.19.

## Getting started

```bash
npm install guarded-fetch
```

```ts
import {
  guardedFetch,
  guardedFetchJson,
  GuardedFetchError,
} from 'guarded-fetch';

// Just like fetch — returns a standard Response:
const response = await guardedFetch('https://example.com/api/data');
const data = await response.json();

// Or fetch + parse JSON with a size limit in one call:
const config = await guardedFetchJson<{ issuer: string }>(
  'https://example.com/.well-known/openid-configuration',
);
```

When a request is blocked or fails, a `GuardedFetchError` is thrown with a
stable `code` you can branch on:

```ts
try {
  await guardedFetch(userSuppliedUrl, { method: 'POST', body: payload });
} catch (err) {
  if (err instanceof GuardedFetchError && err.code === 'hostname_unsafe') {
    // The URL resolved to a private/internal address — likely an SSRF probe.
  }
  throw err;
}
```

## What's on by default

`guarded-fetch` has a high security bar by default. `guardedFetch(url)` call with no additional options prevents:

| Protection              | Default behavior                                                                                                                                                                 |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Protocol allowlist      | Only `http:` and `https:` URLs are accepted.                                                                                                                                     |
| SSRF DNS check          | The hostname is DNS-resolved before connecting; private, loopback, link-local, CGNAT, and cloud-metadata addresses are rejected. `localhost` and `*.local` are rejected by name. |
| Connect-time IP pinning | The resolved IP is re-validated _inside_ the socket connect, so a DNS server can't swap in a private IP between the check and the connection (DNS rebinding).                    |
| Header sanitization     | `Host`, `Cookie`, `X-Forwarded-*`, cloud-metadata headers, and other dangerous headers are silently stripped from your request.                                                  |
| Safe redirects          | Redirects are followed manually (max 5 hops) and every hop re-runs all of the checks above.                                                                                      |
| Credential stripping    | `Authorization` and `Cookie` are dropped when a redirect crosses origins, so tokens never leak to a different host.                                                              |
| Timeout attacks         | The whole request chain (including redirects) is capped at 10 seconds.                                                                                                           |

Two things that always need configuration:

- **Response size limits** apply only to `guardedFetchJson` / `guardedFetchText`
  (10 MB default). Bare `guardedFetch` returns the `Response` unread, so if you
  call `response.json()` yourself there's no size cap — prefer the wrappers
  for untrusted endpoints.
- **A host allowlist** — any publicly-resolving host is allowed unless you
  pass `allowedHosts`. Entries are explicit matches only; use a leading `*.`
  wildcard to allow one subdomain level (`*.example.com`), or `**.` for any
  subdomain depth (`**.example.com`).

## Recipes

### User-configured webhook / log drain

Strict timeout, opaque errors, capped redirects — for URLs where the
attacker can both choose the destination and read your error messages:

```ts
import { guardedFetch, isGuardedFetchError } from 'guarded-fetch';

try {
  await guardedFetch(webhook.url, {
    method: 'POST',
    headers: webhook.headers, // sanitized automatically
    body: JSON.stringify(event),
    timeoutMs: 4_000,
    maxRedirects: 3,
    opaqueErrors: true,
  });
} catch (err) {
  if (isGuardedFetchError(err)) {
    // err.code is intact for internal logging;
    // err.message is safe to show the user.
    logger.info({ code: err.code, hostname: err.hostname }, 'delivery failed');
  }
  throw err;
}
```

### Locked-down fetch to a known vendor

```ts
const data = await guardedFetchJson(vendorUrl, {
  httpsOnly: true,
  allowedHosts: ['api.vendor.com'],
  maxResponseBytes: 1 * 1024 * 1024,
  throwOnHttpError: true,
});
```

### Size-bounded reads on an existing Response

```ts
import { guardedFetch, readBodyAsJson } from 'guarded-fetch';

const response = await guardedFetch(url);
const data = await readBodyAsJson(response, {
  maxResponseBytes: 512 * 1024,
});
```

## Options reference

All options are optional, and standard `RequestInit` fields (`method`,
`headers`, `body`, ...) pass through as usual — except `redirect` and
`signal`, which are managed internally. `maxResponseBytes` and
`throwOnHttpError` exist only on the `guardedFetchJson` / `guardedFetchText`
wrappers.

| Option                         | Type                 | Default                | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------ | -------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `timeoutMs`                    | `number`             | `10_000`               | Deadline in ms for the entire chain: connection, redirects, and (in the JSON/text wrappers) the body read.                                                                                                                                                                                                                                                                                                                                                 |
| `followRedirects`              | `boolean`            | `true`                 | Follow redirects, re-validating every hop. When `false`, the 3xx response is returned as-is.                                                                                                                                                                                                                                                                                                                                                               |
| `maxRedirects`                 | `number`             | `5`                    | Redirect hop cap. Exceeding it throws `too_many_redirects`.                                                                                                                                                                                                                                                                                                                                                                                                |
| `httpsOnly`                    | `boolean`            | `false`                | Restrict to `https:` URLs (`http:` and `https:` are otherwise both allowed).                                                                                                                                                                                                                                                                                                                                                                               |
| `allowedHosts`                 | `string[]`           | _(none)_               | Hostname allowlist — explicit exact match only (`api.example.com` matches only `api.example.com`). Leading wildcards: `*.example.com` allows one subdomain level (`api.example.com`); `**.example.com` allows any depth (`a.b.example.com` too). Neither matches the base domain itself. Not public-suffix-aware — scope wildcards to domains you own (`**.com` would allow every `.com` host). Omit to allow any public host. **Empty array = deny all.** |
| `skipSsrfCheckForAllowedHosts` | `boolean`            | `false`                | Skip the DNS/SSRF check for hosts that matched `allowedHosts`. Only safe for hosts you fully control.                                                                                                                                                                                                                                                                                                                                                      |
| `sanitizeHeaders`              | `boolean`            | `true`                 | Strip [dangerous request headers](#headers-that-are-stripped) before sending. Set `false` to send headers verbatim (dangerous with user input).                                                                                                                                                                                                                                                                                                            |
| `allowedCookie`                | `string`             | _(none)_               | Explicitly send a `Cookie` header (which sanitization otherwise strips). Dropped on cross-origin redirects, like `Authorization`.                                                                                                                                                                                                                                                                                                                          |
| `opaqueErrors`                 | `boolean`            | `false`                | Replace every error message with one generic string so failures are indistinguishable to attackers. Error `code` is preserved.                                                                                                                                                                                                                                                                                                                             |
| `onUrlBlocked`                 | `function`           | _(none)_               | Per-call block-event handler; overrides the module-level `setUrlBlockedHandler` for this call.                                                                                                                                                                                                                                                                                                                                                             |
| `signal`                       | `AbortSignal`        | _(none)_               | External abort signal, combined with the internal timeout.                                                                                                                                                                                                                                                                                                                                                                                                 |
| `fetch`                        | `fetch` impl         | `undici.fetch`         | Injectable fetch for tests. Must be undici-compatible.                                                                                                                                                                                                                                                                                                                                                                                                     |
| `dispatcher`                   | `Dispatcher \| null` | shared safe dispatcher | undici dispatcher for the request. `null` disables connect-time IP pinning — dangerous; only for when a trusted proxy already controls the connection target.                                                                                                                                                                                                                                                                                              |
| `maxResponseBytes`             | `number`             | `10 * 1024 * 1024`     | _(wrappers only)_ Max body size; exceeding it throws `response_too_large`.                                                                                                                                                                                                                                                                                                                                                                                 |
| `throwOnHttpError`             | `boolean`            | `false`                | _(wrappers only)_ Throw on non-2xx responses instead of returning the body.                                                                                                                                                                                                                                                                                                                                                                                |

Always on, not configurable:

- **Credential stripping on cross-origin redirects** — `Authorization` and
  `Cookie` never follow a redirect to a different origin.
- **RFC 7231 redirect normalization** — 301/302/303 responses convert the
  method to `GET` and drop the body (307/308 preserve both).

## What's prevented

Every outbound attempt — the original URL and every redirect hop — is
protected against:

| Attack                                                                                      | How it's stopped                                                            |
| ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| SSRF to private / loopback / link-local IPs, incl. AWS/GCP metadata (`169.254.169.254`)     | Hostname is DNS-resolved and every record classified before connecting.     |
| SSRF via non-HTTP schemes (`file:`, `ftp:`, `gopher:`, ...)                                 | Protocol allowlist: `http:`/`https:` only.                                  |
| DNS rebinding (TTL=0 flip between check and connect)                                        | IP re-validated inside the socket connect via a pinned undici lookup.       |
| Multi-record DNS races (one public + one private record)                                    | Rejected if _any_ resolved A/AAAA record is unsafe.                         |
| Private IPv4 hidden in IPv6 literals (`::ffff:`, 6to4 `2002::/16`, NAT64 `64:ff9b::/96`)    | Embedded IPv4 is decoded and classified with the same rules as native IPv4. |
| NAT64 translation to private IPv4 via the local-use prefix (`64:ff9b:1::/48`)               | Whole range rejected — it addresses a local translator, never a real host.  |
| Redirect to an internal host after an initial safe response                                 | Manual redirect following; every hop re-runs all checks.                    |
| Infinite / abusive redirect chains                                                          | Hop cap (`maxRedirects`, default 5).                                        |
| Cloud-credential theft via metadata headers (`Metadata-Flavor`, `X-aws-ec2-metadata-token`) | Header stripped.                                                            |
| Origin-IP spoofing (`X-Forwarded-*`, `Forwarded`, `Via`, `X-Real-IP`)                       | Header stripped.                                                            |
| Virtual-host routing to internal backends via a supplied `Host` header                      | Header stripped.                                                            |
| Session leakage via `Cookie` to a user-controlled destination                               | Header stripped (opt back in with `allowedCookie`).                         |
| Auth-token leak on cross-origin redirect                                                    | `Authorization` and `Cookie` dropped when the redirect changes origin.      |
| Memory exhaustion from huge responses; slow-loris bodies                                    | `maxResponseBytes` + whole-chain `timeoutMs` (use the JSON/text wrappers).  |
| Internal-network mapping via distinguishable error messages                                 | `opaqueErrors: true` normalizes every failure message.                      |

### Blocked network destinations

Requests are refused when the hostname resolves to (or literally is) any of:

- Loopback (`127.0.0.0/8`, `::1`) and unspecified (`0.0.0.0`, `::`)
- Private ranges (`10/8`, `172.16/12`, `192.168/16`, IPv6 ULA `fc00::/7`)
- Link-local — where cloud metadata lives (`169.254.0.0/16`, `fe80::/10`)
- CGNAT (`100.64.0.0/10`) — note this covers Tailscale-style addresses
- IPv6 forms that embed any of the above (IPv4-mapped, 6to4, NAT64
  `64:ff9b::/96`), plus the NAT64 local-use prefix `64:ff9b:1::/48` in full
- `localhost`, `*.localhost`, and `*.local` — blocked by name, regardless
  of what DNS says

### Headers that are stripped

`BLOCKED_REQUEST_HEADERS` is exported if you need the canonical list. It
covers:

- **Hop-by-hop / transport**: `Connection`, `Keep-Alive`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`
- **Host routing**: `Host`
- **Proxy / origin spoofing**: `Forwarded`, `Proxy-Authorization`, `Via`,
  `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`
- **Cloud metadata**: `Metadata`, `Metadata-Flavor`,
  `X-Aws-Ec2-Metadata-Token`, `X-Metadata-Token`
- **Session**: `Cookie` (see `allowedCookie`), `Set-Cookie`

### DNS rebinding protection

`guardedFetch` defends against DNS rebinding with a **two-layer** approach:

1. **Preflight**: `assertUrlIsSafeToFetch` DNS-resolves the hostname and
   rejects if any A/AAAA record is private/loopback/link-local.
2. **Connect-time pin**: the default undici dispatcher installs a custom
   `connect.lookup` (`createGuardedLookup`) that re-validates the IP **inside
   the same resolution call the socket connects with**. A separate
   check-then-fetch sequence leaves a window where an attacker's DNS server
   returns a public IP for the check and `169.254.169.254` for the
   connection; this closes it.

Layer 2 is on by default via the shared dispatcher; injected `fetch`
implementations must be undici-compatible for it to stay active. Pass
`dispatcher: null` to opt out (dangerous — only behind a trusted proxy that
controls the connection target).

### Using `createGuardedLookup` on its own

A `dns.lookup` function only runs when the host actually needs resolving.
Node's socket APIs skip DNS entirely for IP literals, so **no `lookup`
implementation is called for `net.connect({ host: '127.0.0.1' })`** — this one
included. On its own, `createGuardedLookup` is a DNS-rebinding guard, not a
complete SSRF guard.

`guardedFetch` is unaffected: it runs `assertUrlIsSafeToFetch` first, which
rejects unsafe IP literals before any socket work. `getSharedGuardedDispatcher`
and `createGuardedDispatcher` are also complete on their own — they pair the
lookup with a pre-connect IP-literal check.

If you are wiring sockets by hand, validate the target first:

```ts
import net from 'node:net';
import { assertUrlIsSafeToFetch, createGuardedLookup } from 'guarded-fetch';

await assertUrlIsSafeToFetch(target); // rejects IP literals and unsafe DNS
net.connect({ host, port, lookup: createGuardedLookup() });
```

## API surface

| Export                                       | Purpose                                                                                                                  |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `guardedFetch(url, opts?)`                   | SSRF-safe `fetch` — returns a `Response`.                                                                                |
| `guardedFetchJson<T>(url, opts?)`            | Fetch + bounded JSON parse.                                                                                              |
| `guardedFetchText(url, opts?)`               | Fetch + bounded UTF-8 read.                                                                                              |
| `assertUrlIsSafeToFetch(url, opts?)`         | Pre-flight validator — no HTTP request, but does resolve DNS.                                                            |
| `sanitizeRequestHeaders(headers)`            | Strip SSRF/proxy/cookie headers → `Headers`.                                                                             |
| `readBodyAsJson(res, opts?)`                 | Size-bounded JSON reader for an existing `Response`.                                                                     |
| `readBodyAsText(res, opts?)`                 | Size-bounded text reader for an existing `Response`.                                                                     |
| `GuardedFetchError`, `GuardedFetchErrorCode` | Structured error type for every failure mode.                                                                            |
| `isGuardedFetchError(v)`                     | Type guard resilient to duplicate module copies.                                                                         |
| `isPermanentGuardedFetchError(v)`            | True when the failure cannot succeed on retry.                                                                           |
| `BLOCKED_REQUEST_HEADERS`                    | The canonical header blocklist.                                                                                          |
| `createGuardedLookup(opts?)`                 | `dns.lookup`-compatible function that validates and pins resolved IPs inline. Rebinding guard only — see the note below. |
| `isSafeIpAddress(ip)`                        | Returns `true` for public IPv4/IPv6 addresses.                                                                           |
| `getSharedGuardedDispatcher()`               | Lazy process-wide undici `Agent` used by default. Connection-pooled.                                                     |
| `createGuardedDispatcher(opts?)`             | Fresh undici `Agent` with IP pinning. Caller must `.close()`.                                                            |
| `setUrlBlockedHandler(handler)`              | Register a process-wide block-event handler.                                                                             |
| `URL_BLOCKED_LOG_MESSAGE`                    | Suggested constant log message for block events.                                                                         |

## Error codes

Every failure throws `GuardedFetchError` with a stable string `code`
(`err.code`, also available as the `GuardedFetchErrorCode` enum):

| Code                      | Meaning                                                                             | Permanent? |
| ------------------------- | ----------------------------------------------------------------------------------- | ---------- |
| `invalid_url`             | URL string failed to parse.                                                         | Yes        |
| `protocol_not_allowed`    | Scheme outside the allowlist (`http:`/`https:`, or `https:` only with `httpsOnly`). | Yes        |
| `host_not_allowed`        | Host not in `allowedHosts`.                                                         | Yes        |
| `hostname_unsafe`         | Resolved to a private/loopback/link-local address — or DNS failed (fail-closed).    | Usually    |
| `timeout`                 | Exceeded `timeoutMs`, or the external `signal` aborted.                             | No         |
| `too_many_redirects`      | Redirect chain exceeded `maxRedirects`.                                             | No         |
| `redirect_invalid`        | Redirect `Location` missing or malformed.                                           | No         |
| `redirect_to_unsafe_host` | A redirect target failed the SSRF/protocol/host checks.                             | No         |
| `response_too_large`      | Body exceeded `maxResponseBytes`.                                                   | No         |
| `network_error`           | DNS / connection / TLS / parse failure, or non-2xx with `throwOnHttpError`.         | No         |

Use `isPermanentGuardedFetchError(err)` rather than hardcoding the
retryability column.

## Observability

Blocked URLs dispatch a `{ reason, domain, subReason? }` event to an
optional handler — nothing is collected until you register one, and handler
errors never reach your request path:

```ts
import { setUrlBlockedHandler, URL_BLOCKED_LOG_MESSAGE } from 'guarded-fetch';

// Once at startup — works with any logger or metrics stack:
setUrlBlockedHandler(({ reason, domain, subReason }) => {
  logger.info({ reason, domain, subReason }, URL_BLOCKED_LOG_MESSAGE);
});
```

For per-request context, pass `onUrlBlocked` on the individual call — but
connect-time (DNS-rebinding) blocks only reach the module-level handler, so
register both for full coverage.

## FAQ

### Why use this instead of plain `fetch` + an IP check?

A hand-rolled "resolve the hostname, check the IP, then fetch" sequence has
a race condition (DNS rebinding) and misses a long tail of bypasses:
redirects to internal hosts, IPv6 literals that embed private IPv4
addresses, multi-record DNS responses where only one record is private, and
header smuggling. See
[DNS rebinding protection](#dns-rebinding-protection) for how the race is
closed.

### Why is `localhost` blocked? I need it for local development.

Blocking loopback is the point — in production, `http://127.0.0.1:8080`
from user input is an attack. For dev and tests, inject a fetch
implementation instead of weakening the production configuration:

```ts
await guardedFetch(url, { fetch: mockFetch }); // tests
```

### Why did my request go through but the destination returned 401/404?

Header sanitization is silent: blocked headers (see
[the full list](#headers-that-are-stripped)) are dropped, not rejected, so
a destination that relied on one fails on its side. For cookies there's a
narrow opt-in: `allowedCookie`.

### Why does `allowedHosts: []` block everything?

An empty array means "allow these zero hosts" — deny-all — not "no
allowlist configured". If you build the list dynamically, guard against it
ending up empty; to disable allowlisting, omit the option entirely.

### The URL is valid, the host is public — why `hostname_unsafe`?

DNS is fail-closed: resolver errors and empty results block, and one
private A/AAAA record rejects the whole host, even alongside public ones
(split-horizon DNS). Use `isPermanentGuardedFetchError(err)` to decide
whether to retry.

### Can I validate a URL without making a request?

Yes — use `assertUrlIsSafeToFetch` at write time, e.g. when a user saves a
webhook URL:

```ts
import { assertUrlIsSafeToFetch } from 'guarded-fetch';

await assertUrlIsSafeToFetch(body.webhookUrl, { httpsOnly: true });
// Throws GuardedFetchError if unsafe; safe to store otherwise.
```

Note the DNS answer can change between write time and request time — the
request-time checks still run on every fetch.

### What about error messages leaking information to attackers?

If the URL supplier can read your error messages (e.g. a webhook delivery
log), distinguishable failures let them map your internal network.
`opaqueErrors: true` collapses every failure into one generic message while
preserving `err.code` for your internal logs.

### What are the limitations?

- **Injected `fetch` implementations must be undici-compatible**, or
  connect-time IP pinning silently doesn't apply to them.
- **`node:http`-level `localAddress`/`family` hints** set outside this
  package can reintroduce private-network reachability. Don't combine them
  with user-controlled URLs.
- **DNS is fail-closed** — resolver errors block as `hostname_unsafe`
  rather than surfacing a retryable network error.
- **One unsafe DNS record blocks the whole host**, even alongside public
  records (split-horizon DNS, stray internal records).
- **CGNAT and `*.local` are always unsafe**, which can reject legitimate
  Tailscale-style or mDNS endpoints.
- **Header stripping is silent** — see
  [the FAQ entry](#why-did-my-request-go-through-but-the-destination-returned-401404).
- **Credential stripping on cross-origin redirects is not configurable** —
  auth-preserving redirect patterns (e.g. an API 302 to a presigned URL
  that also expects the auth header) will lose the header.
- **`allowedHosts: []` denies every host** — see
  [the FAQ entry](#why-does-allowedhosts--block-everything).
- **Redirect chains through link shorteners** can exceed the default 5-hop
  cap; raise `maxRedirects` if you expect them.

## License

Apache-2.0

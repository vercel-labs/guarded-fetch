# safe-fetch

<!-- TODO: final npm package name TBD — update the title, install command, and import paths before publishing. -->

Drop-in `fetch` for URLs you don't trust.

If your server makes HTTP requests to URLs that users configure — webhooks,
log drains, OIDC discovery, JWKS endpoints, image registries, connector
callbacks — a plain `fetch(userUrl)` lets an attacker point your server at
`http://169.254.169.254` and read your cloud credentials. `safeFetch` is a
drop-in replacement that blocks that whole class of attack (SSRF), plus DNS
rebinding, redirect tricks, header smuggling, and unbounded responses.

Built on [undici](https://github.com/nodejs/undici). Two runtime
dependencies (`undici`, `ipaddr.js`). Node ≥ 20.19.

## Getting started

```bash
npm install safe-fetch
```

```ts
import { safeFetch, safeFetchJson, SafeFetchError } from 'safe-fetch';

// Just like fetch — returns a standard Response:
const response = await safeFetch('https://example.com/api/data');
const data = await response.json();

// Or fetch + parse JSON with a size limit in one call:
const config = await safeFetchJson<{ issuer: string }>(
  'https://example.com/.well-known/openid-configuration',
);
```

When a request is blocked or fails, a `SafeFetchError` is thrown with a
stable `code` you can branch on:

```ts
try {
  await safeFetch(userSuppliedUrl, { method: 'POST', body: payload });
} catch (err) {
  if (err instanceof SafeFetchError && err.code === 'hostname_unsafe') {
    // The URL resolved to a private/internal address — likely an SSRF probe.
  }
  throw err;
}
```

## What's on by default

A bare `safeFetch(url)` call, with no options, already does all of this:

| Protection | Default behavior |
| --- | --- |
| Protocol allowlist | Only `http:` and `https:` URLs are accepted. |
| SSRF DNS check | The hostname is DNS-resolved before connecting; private, loopback, link-local, CGNAT, and cloud-metadata addresses are rejected. `localhost` and `*.local` are rejected by name. |
| Connect-time IP pinning | The resolved IP is re-validated *inside* the socket connect, so a DNS server can't swap in a private IP between the check and the connection (DNS rebinding). |
| Header sanitization | `Host`, `Cookie`, `X-Forwarded-*`, cloud-metadata headers, and other dangerous headers are silently stripped from your request. |
| Safe redirects | Redirects are followed manually (max 5 hops) and every hop re-runs all of the checks above. |
| Credential stripping | `Authorization` and `Cookie` are dropped when a redirect crosses origins, so tokens never leak to a different host. |
| Timeout | The whole request chain (including redirects) is capped at 10 seconds. |

Two things are **not** on by default:

- **Response size limits** apply only to `safeFetchJson` / `safeFetchText`
  (10 MB default). Bare `safeFetch` returns the `Response` unread, so if you
  call `response.json()` yourself there's no size cap — prefer the wrappers
  for untrusted endpoints.
- **A host allowlist** — any publicly-resolving host is allowed unless you
  pass `allowedHosts`.

## FAQ

### Why use this instead of plain `fetch` + an IP check?

Because a naive "resolve the hostname, check the IP, then fetch" sequence
has a race condition: an attacker-controlled DNS server can return a public
IP for your check, then `169.254.169.254` for the actual connection (DNS
rebinding). `safeFetch` closes that window by validating the IP inside the
same DNS resolution the socket connects with — see
[DNS rebinding protection](#dns-rebinding-protection). It also handles the
long tail a hand-rolled check misses: redirects to internal hosts, IPv6
literals that embed private IPv4 addresses (`::ffff:10.0.0.1`, 6to4, NAT64),
multi-record DNS responses where only one record is private, and header
smuggling.

### What if I want to log or count blocked requests?

Register a block-event handler. Nothing is collected until you do, and
handler errors never propagate into your request path:

```ts
import { setUrlBlockedHandler, URL_BLOCKED_LOG_MESSAGE } from 'safe-fetch';

// Once at startup — works with any logger or metrics stack:
setUrlBlockedHandler(({ reason, domain, subReason }) => {
  logger.info({ reason, domain, subReason }, URL_BLOCKED_LOG_MESSAGE);
});
```

For per-request context (webhook ID, tenant ID), pass `onUrlBlocked` on the
individual call instead — it overrides the module handler for that call.
One caveat: blocks that happen at socket-connect time (the DNS-rebinding
layer) only reach the module-level handler, so register both if you want
full coverage.

### Why is `localhost` blocked? I need it for local development.

Blocking loopback is the point — in production, `http://127.0.0.1:8080`
from user input is an attack. For local dev and tests, inject a fetch
implementation or disable IP pinning explicitly rather than weakening the
production configuration:

```ts
await safeFetch(url, { fetch: mockFetch }); // tests
```

### Why did my request go through but the destination returned 401/404?

Header sanitization is silent: blocked headers (see
[the full list](#headers-that-are-stripped)) are dropped, not rejected. If
the destination relied on `Host`, `Cookie`, or `X-Forwarded-For`, it will
fail on its side with nothing pointing back at the stripped header. For
cookies specifically there's a narrow opt-in: `allowedCookie`.

### Why does `allowedHosts: []` block everything?

An empty array means "allow these zero hosts" — deny-all — not "no
allowlist configured". If you build the list dynamically, guard against it
ending up empty; to disable allowlisting, omit the option entirely.

### The URL is valid, the host is public — why `hostname_unsafe`?

DNS is fail-closed. A transient resolver error or an empty DNS result is
indistinguishable from an unsafe host, so it blocks rather than passing.
Also, if *any* A/AAAA record for the host is private — even alongside
public ones (split-horizon DNS) — the whole host is rejected. Retrying is
reasonable for transient cases; use `isPermanentSafeFetchError(err)` to
tell retryable failures from permanent ones.

### Can I validate a URL without making a request?

Yes — use `assertUrlIsSafeToFetch` at write time, e.g. when a user saves a
webhook URL:

```ts
import { assertUrlIsSafeToFetch } from 'safe-fetch';

await assertUrlIsSafeToFetch(body.webhookUrl, { httpsOnly: true });
// Throws SafeFetchError if unsafe; safe to store otherwise.
```

Note the DNS answer can change between write time and request time — the
request-time checks still run on every fetch.

### What about error messages leaking information to attackers?

If your error messages can reach the person who supplied the URL (e.g. a
user-facing webhook delivery log), a probing attacker can use them to map
your internal network — "timed out" vs "refused" vs "resolved to private
address" each leak a bit. Set `opaqueErrors: true` to collapse every
failure into one generic message. The `code` field on the error is
preserved, so your internal logs stay useful.

## Options reference

All options are optional. `safeFetch`, `safeFetchJson`, and `safeFetchText`
accept everything below; the last two rows are wrapper-only. Standard
`RequestInit` fields (`method`, `headers`, `body`, ...) pass through as
usual, except `redirect` and `signal`, which are managed internally
(`signal` is accepted as a safe-fetch option and merged with the internal
timeout).

| Option | Type | Default | What it does |
| --- | --- | --- | --- |
| `timeoutMs` | `number` | `10_000` | Deadline in ms for the entire chain: connection, redirects, and (in the JSON/text wrappers) the body read. |
| `followRedirects` | `boolean` | `true` | Follow redirects, re-validating every hop. When `false`, the 3xx response is returned as-is. |
| `maxRedirects` | `number` | `5` | Redirect hop cap. Exceeding it throws `too_many_redirects`. |
| `httpsOnly` | `boolean` | `false` | Restrict to `https:` URLs (`http:` and `https:` are otherwise both allowed). |
| `allowedHosts` | `string[]` | *(none)* | Hostname allowlist — exact match or subdomain (`api.example.com` matches `example.com`). Omit to allow any public host. **Empty array = deny all.** |
| `skipSsrfCheckForAllowedHosts` | `boolean` | `false` | Skip the DNS/SSRF check for hosts that matched `allowedHosts`. Only safe for hosts you fully control. |
| `sanitizeHeaders` | `boolean` | `true` | Strip [dangerous request headers](#headers-that-are-stripped) before sending. Set `false` to send headers verbatim (dangerous with user input). |
| `allowedCookie` | `string` | *(none)* | Explicitly send a `Cookie` header (which sanitization otherwise strips). Dropped on cross-origin redirects, like `Authorization`. |
| `opaqueErrors` | `boolean` | `false` | Replace every error message with one generic string so failures are indistinguishable to attackers. Error `code` is preserved. |
| `onUrlBlocked` | `function` | *(none)* | Per-call block-event handler; overrides the module-level `setUrlBlockedHandler` for this call. |
| `signal` | `AbortSignal` | *(none)* | External abort signal, combined with the internal timeout. |
| `fetch` | `fetch` impl | `undici.fetch` | Injectable fetch for tests. Must be undici-compatible. |
| `dispatcher` | `Dispatcher \| null` | shared safe dispatcher | undici dispatcher for the request. `null` disables connect-time IP pinning — dangerous; only for when a trusted proxy already controls the connection target. |
| `maxResponseBytes` | `number` | `10 * 1024 * 1024` | *(wrappers only)* Max body size; exceeding it throws `response_too_large`. |
| `throwOnHttpError` | `boolean` | `false` | *(wrappers only)* Throw on non-2xx responses instead of returning the body. |

Always on, not configurable:

- **Credential stripping on cross-origin redirects** — `Authorization` and
  `Cookie` never follow a redirect to a different origin.
- **RFC 7231 redirect normalization** — 301/302/303 responses convert the
  method to `GET` and drop the body (307/308 preserve both).

## What's prevented

Every outbound attempt — the original URL and every redirect hop — is
protected against:

| Attack | How it's stopped |
| --- | --- |
| SSRF to private / loopback / link-local IPs, incl. AWS/GCP metadata (`169.254.169.254`) | Hostname is DNS-resolved and every record classified before connecting. |
| SSRF via non-HTTP schemes (`file:`, `ftp:`, `gopher:`, ...) | Protocol allowlist: `http:`/`https:` only. |
| DNS rebinding (TTL=0 flip between check and connect) | IP re-validated inside the socket connect via a pinned undici lookup. |
| Multi-record DNS races (one public + one private record) | Rejected if *any* resolved A/AAAA record is unsafe. |
| Private IPv4 hidden in IPv6 literals (`::ffff:`, 6to4 `2002::/16`, NAT64 `64:ff9b::/96`) | Embedded IPv4 is decoded and classified with the same rules as native IPv4. |
| Redirect to an internal host after an initial safe response | Manual redirect following; every hop re-runs all checks. |
| Infinite / abusive redirect chains | Hop cap (`maxRedirects`, default 5). |
| Cloud-credential theft via metadata headers (`Metadata-Flavor`, `X-aws-ec2-metadata-token`) | Header stripped. |
| Origin-IP spoofing (`X-Forwarded-*`, `Forwarded`, `Via`, `X-Real-IP`) | Header stripped. |
| Virtual-host routing to internal backends via a supplied `Host` header | Header stripped. |
| Session leakage via `Cookie` to a user-controlled destination | Header stripped (opt back in with `allowedCookie`). |
| Auth-token leak on cross-origin redirect | `Authorization` and `Cookie` dropped when the redirect changes origin. |
| Memory exhaustion from huge responses; slow-loris bodies | `maxResponseBytes` + whole-chain `timeoutMs` (use the JSON/text wrappers). |
| Internal-network mapping via distinguishable error messages | `opaqueErrors: true` normalizes every failure message. |

### Blocked network destinations

Requests are refused when the hostname resolves to (or literally is) any of:

- Loopback (`127.0.0.0/8`, `::1`) and unspecified (`0.0.0.0`, `::`)
- Private ranges (`10/8`, `172.16/12`, `192.168/16`, IPv6 ULA `fc00::/7`)
- Link-local — where cloud metadata lives (`169.254.0.0/16`, `fe80::/10`)
- CGNAT (`100.64.0.0/10`) — note this covers Tailscale-style addresses
- IPv6 forms that embed any of the above (IPv4-mapped, 6to4, NAT64)
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

## DNS rebinding protection

`safeFetch` defends against DNS rebinding with a **two-layer** approach:

1. **Preflight**: `assertUrlIsSafeToFetch` DNS-resolves the hostname and
   rejects if any A/AAAA record is private/loopback/link-local.
2. **Connect-time pin**: the default undici dispatcher installs a custom
   `connect.lookup` (`createSafeLookup`) that re-validates the IP **inside
   the same resolution call the socket connects with**. A separate
   check-then-fetch sequence leaves a window where an attacker's DNS server
   returns a public IP for the check and `169.254.169.254` for the
   connection; this closes it.

Layer 2 is active by default because `safeFetch` uses `undici.fetch` and
passes the shared safe dispatcher on every request. Injected `fetch`
implementations must be undici-compatible for it to stay active. To
explicitly opt out (dangerous; only when a trusted upstream proxy already
guarantees the connection target), pass `dispatcher: null`.

## Recipes

### User-configured webhook / log drain

Strict timeout, opaque errors, capped redirects — for URLs where the
attacker can both choose the destination and read your error messages:

```ts
import { safeFetch, isSafeFetchError } from 'safe-fetch';

try {
  await safeFetch(webhook.url, {
    method: 'POST',
    headers: webhook.headers, // sanitized automatically
    body: JSON.stringify(event),
    timeoutMs: 4_000,
    maxRedirects: 3,
    opaqueErrors: true,
  });
} catch (err) {
  if (isSafeFetchError(err)) {
    // err.code is intact for internal logging;
    // err.message is safe to show the user.
    logger.info({ code: err.code, hostname: err.hostname }, 'delivery failed');
  }
  throw err;
}
```

### Locked-down fetch to a known vendor

```ts
const data = await safeFetchJson(vendorUrl, {
  httpsOnly: true,
  allowedHosts: ['api.vendor.com'],
  maxResponseBytes: 1 * 1024 * 1024,
  throwOnHttpError: true,
});
```

### Size-bounded reads on an existing Response

```ts
import { safeFetch, readBodyAsJson } from 'safe-fetch';

const response = await safeFetch(url);
const data = await readBodyAsJson(response, {
  maxResponseBytes: 512 * 1024,
});
```

## API surface

| Export | Purpose |
| --- | --- |
| `safeFetch(url, opts?)` | SSRF-safe `fetch` — returns a `Response`. |
| `safeFetchJson<T>(url, opts?)` | Fetch + bounded JSON parse. |
| `safeFetchText(url, opts?)` | Fetch + bounded UTF-8 read. |
| `assertUrlIsSafeToFetch(url, opts?)` | Pre-flight validator — no HTTP request, but does resolve DNS. |
| `sanitizeRequestHeaders(headers)` | Strip SSRF/proxy/cookie headers → `Headers`. |
| `sanitizeHeaderRecord(headers)` | Same, but returns a `Record<string, string>`. |
| `readBodyAsJson(res, opts?)` | Size-bounded JSON reader for an existing `Response`. |
| `readBodyAsText(res, opts?)` | Size-bounded text reader for an existing `Response`. |
| `readBodyAsBytes(res, opts?)` | Size-bounded raw-bytes reader for an existing `Response`. |
| `SafeFetchError`, `SafeFetchErrorCode` | Structured error type for every failure mode. |
| `isSafeFetchError(v)` | Type guard resilient to duplicate module copies. |
| `isPermanentSafeFetchError(v)` | True when the failure cannot succeed on retry. |
| `BLOCKED_REQUEST_HEADERS` | The canonical header blocklist. |
| `isHostInAllowlist(hostname, allowlist)` | Shared exact-or-subdomain allowlist matcher. |
| `createSafeLookup(opts?)` | `dns.lookup`-compatible function that validates and pins IPs inline — embed in `https.Agent`, `net.connect`, or an undici Agent. |
| `isSafeIpAddress(ip)` | Returns `true` for public IPv4/IPv6 addresses. |
| `getSharedSafeDispatcher()` | Lazy process-wide undici `Agent` used by default. Connection-pooled. |
| `createSafeDispatcher(opts?)` | Fresh undici `Agent` with IP pinning. Caller must `.close()`. |
| `setUrlBlockedHandler(handler)` | Register a process-wide block-event handler. |
| `URL_BLOCKED_LOG_MESSAGE` | Suggested constant log message for block events. |
| `dangerousNakedFetch` | Re-export of undici's raw `fetch` — **no protections**. Only for URLs that can never be user-controlled; the name is meant to fail code review. |

## Error codes

Every failure throws `SafeFetchError` with a stable string `code`
(`err.code`, also available as the `SafeFetchErrorCode` enum):

| Code | Meaning | Permanent? |
| --- | --- | --- |
| `invalid_url` | URL string failed to parse. | Yes |
| `protocol_not_allowed` | Scheme outside the allowlist (`http:`/`https:`, or `https:` only with `httpsOnly`). | Yes |
| `host_not_allowed` | Host not in `allowedHosts`. | Yes |
| `hostname_unsafe` | Resolved to a private/loopback/link-local address — or DNS failed (fail-closed). | Usually |
| `timeout` | Exceeded `timeoutMs`, or the external `signal` aborted. | No |
| `too_many_redirects` | Redirect chain exceeded `maxRedirects`. | No |
| `redirect_invalid` | Redirect `Location` missing or malformed. | No |
| `redirect_to_unsafe_host` | A redirect target failed the SSRF/protocol/host checks. | No |
| `response_too_large` | Body exceeded `maxResponseBytes`. | No |
| `network_error` | DNS / connection / TLS / parse failure, or non-2xx with `throwOnHttpError`. | No |

Use `isPermanentSafeFetchError(err)` rather than hardcoding the
retryability column.

## Observability

When a URL is rejected for security reasons, the package dispatches a
**block event** — `{ reason, domain, subReason? }` — to an optional handler.
No event is emitted (and nothing is collected) until you register one;
handlers never throw into callers. See
[the FAQ entry](#what-if-i-want-to-log-or-count-blocked-requests) for setup.

Event shapes:

- **Direct block** (preflight or connect-time pinning): one event. `reason`
  is the error code (e.g. `hostname_unsafe`); `domain` is the blocked
  hostname. For `hostname_unsafe`, `subReason` distinguishes the path —
  e.g. `dns_unsafe_address` (preflight) vs `connect_time_ip_rejected`
  (rebinding caught at socket connect).
- **Unsafe redirect**: two events — first the redirect *target's* failure
  with its own reason and the target's domain, then
  `redirect_to_unsafe_host` with the *original* request hostname, so you
  can see which upstream returned the bad `Location`.
- **Redirect abuse**: one event — `too_many_redirects` (original hostname)
  or `redirect_invalid` (hostname of the response with the bad `Location`).

## Limitations and sharp edges

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

MIT

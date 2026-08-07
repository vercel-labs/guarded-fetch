# safe-fetch

<!-- TODO: final npm package name TBD — update the title, install command, and import paths before publishing. -->

SSRF-safe HTTP(S) fetch utilities backed by `undici`.

One isolated, dependency-light implementation for outbound HTTP calls driven
by user-controlled input — webhooks, log drains, OIDC discovery, JWKS,
image-registry manifests, HAR proxies, connector callbacks.

## What it protects against

| Threat                                                                                 | Protection                                                                                                                                                                          |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SSRF to private / loopback / link-local IPs (incl. AWS/GCP metadata `169.254.169.254`) | DNS-resolved hostname preflight on every hop                                                                                                                                        |
| DNS rebinding (TTL=0 flip between preflight and connect)                               | IP is validated **inside** the socket `connect` via an undici `Agent` with a custom `lookup`, closing the TOCTOU window. See [DNS rebinding protection](#dns-rebinding-protection). |
| Multi-record races (one public, one private in the same response)                      | Rejects if **any** A/AAAA record is unsafe (preflight + connect)                                                                                                                    |
| Redirect-to-metadata after initial safe response                                       | Manual redirect following; each hop re-validated                                                                                                                                    |
| SSRF escalation via `Metadata-Flavor`, `X-aws-ec2-metadata-token` headers              | Request header sanitization                                                                                                                                                         |
| Origin-IP spoofing via `X-Forwarded-*`, `Forwarded`, `Via`                             | Request header sanitization                                                                                                                                                         |
| Virtual-host routing via attacker-supplied `Host` header                               | Request header sanitization                                                                                                                                                         |
| Cookie / session leaks to user-controlled destination                                  | Request header sanitization                                                                                                                                                         |
| Auth-token leak on cross-origin redirect                                               | `Authorization` dropped when redirect crosses origin                                                                                                                                |
| Unbounded response → OOM / slow-loris                                                  | `maxResponseBytes` + `timeoutMs` with `AbortController`                                                                                                                             |
| IPv6 literals hiding private IPv4 (`::ffff:`, 6to4 `2002::/16`, NAT64 `64:ff9b::/96`)  | Embedded IPv4 decoded and classified with the same rules as native IPv4                                                                                                             |
| Information leak via distinguishable error messages                                    | `opaqueErrors: true` normalizes every failure mode                                                                                                                                  |

## Protection matrix

What each protection covers, whether it's on by default for a bare
`safeFetch(url)` call, how to control it, and where it can reject or alter a
legitimate request.

| Protection                                                                                                                    | Default                                                                          | Control                                                           | Benign-request risk                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Protocol allowlist (`http:`/`https:` only)                                                                                    | On                                                                               | `httpsOnly: true` restricts to `https:`                           | Near zero — only rejects non-HTTP schemes, which are out of scope by design.                                                                                                                                                                                                                                                                                                              |
| Hostname allowlist                                                                                                            | Off                                                                              | `allowedHosts: [...]`                                             | `allowedHosts: []` means **deny-all**, not "no allowlist" — a dynamically built list that ends up empty silently blocks every request.                                                                                                                                                                                                                                                    |
| Pre-flight SSRF DNS check (private/loopback/link-local/CGNAT/metadata ranges, `localhost`, `*.local`, mapped/6to4/NAT64 IPv6) | On                                                                               | `skipSsrfCheckForAllowedHosts: true` (allowlisted hosts only)     | Highest false-positive surface: a DNS lookup error or empty result is treated as unsafe (not a distinct network error); a domain is blocked if **any** resolved A/AAAA record is private, even alongside public records (split-horizon DNS); CGNAT `100.64.0.0/10` blocks Tailscale-style and some ISP-hosted endpoints; `*.local`/`*.localhost` are blocked by suffix regardless of DNS. |
| Connect-time IP pinning (closes the DNS-rebinding TOCTOU window)                                                              | On                                                                               | `dispatcher: null` disables it; a custom `dispatcher` replaces it | DNS is resolved once at preflight and again at connect; a low-TTL round-robin host can pass one and fail the other, producing intermittent `hostname_unsafe` errors that are hard to reproduce.                                                                                                                                                                                           |
| Request header sanitization (`Host`, `X-Forwarded-*`, `Via`, `X-Real-IP`, `Cookie`, cloud-metadata, hop-by-hop)               | On                                                                               | `sanitizeHeaders: false`; `allowedCookie` for `Cookie` only       | Fails quietly — blocked headers are dropped, not rejected. Breaks virtual-host routing via `Host`, `Cookie`-authenticated receivers, and intentional `X-Forwarded-For` passthrough; the destination then errors with nothing pointing back at the stripped header.                                                                                                                        |
| Manual redirect validation (every hop re-runs the checks above)                                                               | On                                                                               | `followRedirects: false`                                          | Inherits the DNS false positives above per hop. A redirect with a missing/malformed `Location` throws instead of returning the 3xx response.                                                                                                                                                                                                                                              |
| Redirect hop cap                                                                                                              | On, `5`                                                                          | `maxRedirects`                                                    | Long benign chains (link shorteners, tracking redirects) can exceed 5 hops.                                                                                                                                                                                                                                                                                                               |
| Credential stripping on cross-origin redirects (`Authorization`, `Cookie`)                                                    | On, not configurable                                                             | —                                                                 | Breaks auth-preserving cross-domain redirects, e.g. an API 302'ing to a presigned CDN/S3 URL that also expects the auth header, or a same-tenant domain move.                                                                                                                                                                                                                             |
| RFC 7231 method/body normalization (301/302/303 → GET, body dropped)                                                          | On, not configurable                                                             | —                                                                 | Spec-correct, but some servers 302 a POST expecting the client to replay it (legacy-browser behavior); those integrations lose the body.                                                                                                                                                                                                                                                  |
| Whole-chain timeout                                                                                                           | On, `10_000` ms                                                                  | `timeoutMs`                                                       | Slow-to-respond or slow-streaming endpoints hit `timeout`; in `safeFetchJson`/`safeFetchText` the body read shares the same budget as connection + redirects.                                                                                                                                                                                                                             |
| Response-size limit                                                                                                           | Only in `safeFetchJson`/`safeFetchText` (`10 MB`); bare `safeFetch` is unbounded | `maxResponseBytes`                                                | Legitimate payloads over the limit throw `response_too_large`. Conversely, call sites that use `safeFetch(...).then(r => r.json())` directly get no size protection at all.                                                                                                                                                                                                               |
| Opaque error messages                                                                                                         | Off                                                                              | `opaqueErrors: true`                                              | No request breakage, but once enabled every failure collapses to one generic message, making benign failures (typo'd URL, transient DNS blip) hard to distinguish from real blocks.                                                                                                                                                                                                       |
| Block events (`setUrlBlockedHandler` / `onUrlBlocked`)                                                                        | Off (no-op until a handler is registered)                                        | `setUrlBlockedHandler` once, or `onUrlBlocked` per call           | Observe-only; false positives from the DNS/header rows above will inflate blocked-URL counts and can look like an attack.                                                                                                                                                                                                                                                                 |
| `throwOnHttpError`                                                                                                            | Off                                                                              | `throwOnHttpError: true`                                          | None by default; once enabled, expected non-2xx flows need `try`/`catch` instead of a status check.                                                                                                                                                                                                                                                                                       |

## DNS rebinding protection

`safeFetch` defends against DNS rebinding with a **two-layer** approach:

1. **Preflight**: `assertUrlIsSafeToFetch` DNS-resolves the hostname through
   package-local safety checks and rejects if any A/AAAA record is
   private/loopback/link-local.
2. **Connect-time pin**: the default undici `Dispatcher` installs a custom
   `connect.lookup` (`createSafeLookup`) that re-validates the IP
   **inside the same resolution call the socket connects with**. This closes
   the TOCTOU window a separate preflight-then-resolve sequence leaves open
   (attacker DNS server returning a public IP first, then 169.254.169.254 on
   the next query).

Layer 2 is active by default because `safeFetch` uses `undici.fetch` and passes
the shared safe dispatcher on every request. Injected `fetch` implementations
are expected to be undici-compatible.

```ts
import { safeFetch } from 'safe-fetch';

await safeFetch(url);
```

To explicitly opt out of layer 2 (dangerous; only useful when an upstream
HTTP proxy already guarantees the connection target), pass `dispatcher: null`.

## Installation

```bash
npm install safe-fetch
```

## Observability

When a URL is rejected for security reasons, the package dispatches a
**block event** — `{ reason, domain, subReason? }` — to an optional handler
you register. No event is emitted (and nothing is collected) until you
register one; handlers never throw into callers.

- **Direct block** (preflight or connect-time pinning): one event; `reason`
  is the underlying code (e.g. `hostname_unsafe`); `domain` is the blocked
  target hostname. When `reason` is `hostname_unsafe`, `subReason`
  distinguishes the block path (e.g. `dns_unsafe_address` vs
  `connect_time_ip_rejected` for DNS rebinding caught at socket connect).
- **Unsafe redirect**: two events — (1) the redirect target check with the
  underlying `reason` and **target** `domain` (e.g. `hostname_unsafe` /
  `169.254.169.254`), then (2) `redirect_to_unsafe_host` with the **original**
  request hostname (the URL passed to `safeFetch`) so you can see which
  upstream returned a bad `Location`.
- **Redirect abuse**: one event with `too_many_redirects` (original request
  hostname) when the hop limit is exceeded, or `redirect_invalid` (hostname of
  the response that lacked or malformed `Location`) for broken redirect chains.

Register a process-wide handler once at startup with `setUrlBlockedHandler`,
or pass `onUrlBlocked` on a single call when you need extra context. Wire the
handler to whatever logging or metrics stack you use;
`URL_BLOCKED_LOG_MESSAGE` (`'safe-fetch blocked URL'`) is a suggested constant
log message so blocks are easy to search for:

```ts
import {
  setUrlBlockedHandler,
  URL_BLOCKED_LOG_MESSAGE,
  safeFetch,
} from 'safe-fetch';

// Structured logs:
setUrlBlockedHandler(({ reason, domain, subReason }) => {
  logger.info({ reason, domain, subReason }, URL_BLOCKED_LOG_MESSAGE);
});

// Or metrics (any provider — OpenTelemetry, StatsD, Prometheus, ...):
setUrlBlockedHandler(({ reason, domain, subReason }) => {
  urlBlockedCounter.add(1, { reason, domain, sub_reason: subReason });
});

// Per-call override with request context:
await safeFetch(userUrl, {
  onUrlBlocked: ({ reason, domain, subReason }) =>
    logger.info(
      { webhookId, reason, domain, subReason },
      URL_BLOCKED_LOG_MESSAGE,
    ),
});
```

Per-call `onUrlBlocked` overrides the module handler. Connect-time blocks from
the shared dispatcher only see the module handler (not per-call overrides).

## Usage

### Basic fetch

```ts
import { safeFetch } from 'safe-fetch';

const response = await safeFetch('https://example.com/api/data');
const body = await response.json();
```

### JSON with size limit and HTTP-error throwing

```ts
import { safeFetchJson } from 'safe-fetch';

const discovery = await safeFetchJson<{ issuer: string }>(issuerUrl, {
  timeoutMs: 10_000,
  maxResponseBytes: 1 * 1024 * 1024,
  throwOnHttpError: true,
});
```

### User-configured webhook / log drain

Use an opaque error mode and strict host allowlist when the URL comes from
user input and attackers might probe for information leaks.

```ts
import {
  safeFetch,
  SafeFetchError,
  SafeFetchErrorCode,
  URL_BLOCKED_LOG_MESSAGE,
} from 'safe-fetch';

try {
  await safeFetch(userSuppliedUrl, {
    method: 'POST',
    headers: userSuppliedHeaders, // will be sanitized
    body: JSON.stringify(payload),
    timeoutMs: 4_000,
    opaqueErrors: true,
    maxRedirects: 3,
  });
} catch (err) {
  // `err.code` is still populated (for internal logs),
  // but `err.message` is a generic public string.
  if (
    err instanceof SafeFetchError &&
    err.code === SafeFetchErrorCode.HOSTNAME_UNSAFE
  ) {
    logger.info(
      { hostname: err.hostname, reason: err.code },
      URL_BLOCKED_LOG_MESSAGE,
    );
  }
  throw err;
}
```

### Pre-flight validation (no request)

For write-time validation (e.g. `POST /v1/webhooks` storing the URL):

```ts
import { assertUrlIsSafeToFetch } from 'safe-fetch';

await assertUrlIsSafeToFetch(body.webhookUrl, {
  httpsOnly: true,
  allowedHosts: tenant.allowlistedDomains, // optional
});
// throws SafeFetchError on failure; URL is safe to store otherwise.
```

### Injecting `fetch` for tests

```ts
import { safeFetch } from 'safe-fetch';

const response = await safeFetch(url, { fetch: mockFetch });
```

## API surface

| Export                                   | Purpose                                                                                                                          |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `safeFetch(url, opts?)`                  | SSRF-safe `fetch` — returns a `Response`.                                                                                        |
| `safeFetchJson<T>(url, opts?)`           | Fetch + bounded JSON parse.                                                                                                      |
| `safeFetchText(url, opts?)`              | Fetch + bounded UTF-8 read.                                                                                                      |
| `assertUrlIsSafeToFetch(url, opts?)`     | Pre-flight validator (no network).                                                                                               |
| `sanitizeRequestHeaders(headers)`        | Strip SSRF/proxy/cookie headers → `Headers`.                                                                                     |
| `sanitizeHeaderRecord(headers)`          | Same, but returns a `Record<string, string>`.                                                                                    |
| `readBodyAsJson(res, opts?)`             | Size-bounded JSON reader for an existing `Response`.                                                                             |
| `readBodyAsText(res, opts?)`             | Size-bounded text reader for an existing `Response`.                                                                             |
| `readBodyAsBytes(res, opts?)`            | Size-bounded raw-bytes reader for an existing `Response`.                                                                        |
| `SafeFetchError`, `SafeFetchErrorCode`   | Structured error type for every failure mode.                                                                                    |
| `isSafeFetchError(v)`                    | Type guard resilient to duplicate module copies.                                                                                 |
| `isPermanentSafeFetchError(v)`           | True when the failure cannot succeed on retry.                                                                                   |
| `BLOCKED_REQUEST_HEADERS`                | The canonical header blocklist (export for tests/docs).                                                                          |
| `isHostInAllowlist(hostname, allowlist)` | Shared exact-or-subdomain allowlist matcher.                                                                                     |
| `createSafeLookup(opts?)`                | `dns.lookup`-compatible function that validates and pins IPs inline — embed in `https.Agent`, `net.connect`, or an undici Agent. |
| `isSafeIpAddress(ip)`                    | Predicate used by `createSafeLookup`. Returns `true` for public IPv4/IPv6.                                                       |
| `getSharedSafeDispatcher()`              | Lazy process-wide undici `Agent` used by default. Connection-pooled.                                                             |
| `createSafeDispatcher(opts?)`            | Constructs a fresh undici `Agent` with IP pinning. Caller must `.close()`.                                                       |
| `setUrlBlockedHandler(handler)`          | Register a process-wide block-event handler.                                                                                     |
| `URL_BLOCKED_LOG_MESSAGE`                | Suggested constant log message for block events.                                                                                 |
| `dangerousNakedFetch`                    | Re-export of undici's raw `fetch` — no protections. Only for URLs that can never be user-controlled.                             |

## Error codes

Every failure mode throws `SafeFetchError` with a stable string `code`:

- `invalid_url` — URL string failed to parse.
- `protocol_not_allowed` — URL protocol not allowed (`http:`/`https:` by default; `https:` only when `httpsOnly: true`).
- `host_not_allowed` — Host outside `allowedHosts`.
- `hostname_unsafe` — DNS-resolved to private / loopback / link-local.
- `timeout` — Request exceeded `timeoutMs` or external signal aborted.
- `too_many_redirects` — Redirect chain exceeded `maxRedirects`.
- `redirect_invalid` — Redirect `Location` missing or malformed.
- `redirect_to_unsafe_host` — Redirect target failed SSRF/protocol/host check.
- `response_too_large` — Body exceeded `maxResponseBytes`.
- `network_error` — DNS / connection / TLS / parse failure.

## Defaults

| Option             | Default                               |
| ------------------ | ------------------------------------- |
| `timeoutMs`        | `10_000`                              |
| `followRedirects`  | `true`                                |
| `maxRedirects`     | `5`                                   |
| `sanitizeHeaders`  | `true`                                |
| `httpsOnly`        | `false` (allows `http:` and `https:`) |
| `maxResponseBytes` | `10 * 1024 * 1024` (10 MB)            |
| `throwOnHttpError` | `false`                               |
| `opaqueErrors`     | `false`                               |
| `fetch`            | `undici.fetch`                        |

## Limitations

Implementation constraints:

- **Injected fetch implementations must be undici-compatible.** `safeFetch`
  passes an undici `dispatcher` by default so connect-time IP pinning stays
  active. Pass `dispatcher: null` only when a trusted upstream layer already
  guarantees the connection target.
- **`node:http`-level `localAddress` / `family` hints can reintroduce
  private-network reachability** if set outside this package. Don't do that
  for user-controlled URLs.

Known false-positive / benign-breakage modes (see the [protection
matrix](#protection-matrix) for the full per-protection breakdown):

- **DNS is fail-closed.** A transient resolver error or empty result is
  indistinguishable from an actively unsafe hostname and blocks the request
  as `hostname_unsafe` rather than surfacing a retryable network error.
- **Any one unsafe DNS record blocks the whole host**, even when other
  records for the same name are public — this affects domains with
  split-horizon DNS or a stray internal record.
- **CGNAT (`100.64.0.0/10`) and `*.local`/`*.localhost` are always unsafe**,
  which can reject legitimate Tailscale-style or mDNS-addressed endpoints.
- **Local dev/test targets are blocked by design** (`localhost`,
  `127.0.0.1`, Docker-Compose service IPs) — use the injectable `fetch` or
  `dispatcher: null` for local/test environments, not a broadened allowlist.
- **Header stripping is silent.** Callers relying on `Host`, `Cookie`, or
  `X-Forwarded-*` for legitimate routing/auth get a request sent without
  that header and no error — only a downstream 401/404 from the destination.
- **`Authorization`/`Cookie` are always dropped on cross-origin redirects**,
  which breaks auth-preserving redirect patterns (e.g. to a presigned URL
  that also expects the original auth header). Not configurable.
- **`allowedHosts: []` denies every host**, rather than being treated as "no
  allowlist configured" — a common bug when the list is built dynamically.

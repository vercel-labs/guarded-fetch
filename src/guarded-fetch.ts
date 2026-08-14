import { fetch as undiciFetch, Headers, type Dispatcher } from 'undici';

import {
  assertUrlIsSafeToFetch,
  type AssertUrlSafeOptions,
} from './assert-url-safe';
import {
  isGuardedFetchError,
  OPAQUE_ERROR_MESSAGE,
  GuardedFetchError,
  GuardedFetchErrorCode,
} from './errors';
import { getSharedGuardedDispatcher } from './guarded-dispatcher';
import { sanitizeRequestHeaders } from './sanitize-headers';
import { recordUrlBlocked } from './url-blocked';

/**
 * Subset of `RequestInit` fields we accept verbatim. We strip:
 * - `signal` / `redirect` — managed internally (timeout + manual redirect).
 * - `dispatcher` — re-typed on {@link GuardedFetchOptions} to allow `null` as
 *   an explicit opt-out.
 */
type PassthroughRequestInit = Omit<
  RequestInit,
  'signal' | 'redirect' | 'dispatcher'
>;

type FetchBody = NonNullable<RequestInit['body']>;
type FetchImpl = typeof globalThis.fetch;

export interface GuardedFetchOptions
  extends PassthroughRequestInit, AssertUrlSafeOptions {
  /**
   * Timeout in milliseconds for the entire request chain (including redirect
   * hops). When exceeded, the underlying `AbortController` is aborted and a
   * {@link GuardedFetchError} with code `TIMEOUT` is thrown.
   *
   * @default 10_000
   */
  timeoutMs?: number;

  /**
   * Whether to follow HTTP redirects. Every hop is independently validated
   * with the same protocol, allowlist, and SSRF checks as the original URL.
   *
   * @default true
   */
  followRedirects?: boolean;

  /**
   * Maximum number of redirect hops. Has no effect when
   * `followRedirects: false`.
   *
   * @default 5
   */
  maxRedirects?: number;

  /**
   * Strip SSRF/proxy/cookie-bearing headers from `init.headers` before
   * sending. See {@link BLOCKED_REQUEST_HEADERS} for the full list.
   *
   * @default true
   */
  sanitizeHeaders?: boolean;

  /**
   * External abort signal. If it fires, the request is aborted. The internal
   * timeout signal is combined with this one.
   */
  signal?: AbortSignal;

  /**
   * Injectable undici-compatible `fetch` implementation for tests.
   *
   * @default `undici.fetch`
   */
  fetch?: FetchImpl;

  /**
   * undici `Dispatcher` used for the outbound request. Defaults to a
   * process-wide shared dispatcher whose `connect.lookup` validates and
   * **pins** the resolved IP address — this is what closes the DNS
   * rebinding TOCTOU window (see README).
   *
   * - Pass `null` to explicitly disable IP pinning (dangerous; only useful
   *   when the upstream layer already guarantees the connection
   *   target — e.g. a trusted HTTP proxy).
   */
  dispatcher?: Dispatcher | null;

  /**
   * Attaches the provided value as a `Cookie` request header on the initial
   * request. Mirrors the existing `Authorization` semantics: sent on the
   * first hop, stripped on cross-origin redirects, preserved on same-origin
   * redirects.
   *
   * The opt-in is a separate, narrower surface than the generic `headers`
   * input because `Cookie` is in {@link BLOCKED_REQUEST_HEADERS} (default
   * deny) — callers that legitimately need to send a cookie must do so
   * through this option.
   *
   * All other guarded-fetch protections (URL validation, protocol allowlist,
   * IP pinning, response size limit) remain in force.
   */
  allowedCookie?: string;
}

export const DEFAULT_TIMEOUT_MS = 10_000;

const DEFAULT_MAX_REDIRECTS = 5;

/**
 * Performs an SSRF-safe HTTP(S) fetch.
 *
 * Guarantees on every outbound attempt (including redirects):
 *
 * 1. **Protocol allowlisted** — defaults to `http:` and `https:`; set
 *    `httpsOnly: true` to restrict to `https:`.
 * 2. **Host allowlisted** (when `allowedHosts` is provided).
 * 3. **Hostname is public** — DNS-resolved and checked against private,
 *    loopback, and link-local ranges via
 *    package-local hostname safety checks. Covers AWS/GCP metadata endpoints
 *    (`169.254.0.0/16`), container/k8s service CIDRs, and
 *    `.local`/`localhost`.
 * 4. **Request headers sanitized** — proxy-forwarding, hop-by-hop, cookie,
 *    and cloud-metadata headers are stripped unless `sanitizeHeaders: false`.
 * 5. **Redirects validated** — `redirect: 'manual'` is used internally so
 *    every hop runs checks 1-3 again; TOCTOU-style bypass via redirect-to-
 *    metadata is blocked.
 * 6. **Bounded time** — an `AbortController` enforces `timeoutMs` across the
 *    entire chain.
 *
 * On failure, throws {@link GuardedFetchError}. On success, returns the final
 * `Response` — callers are responsible for reading the body. Use
 * {@link guardedFetchJson} / {@link guardedFetchText} when a body-size limit is
 * desired.
 */
export async function guardedFetch(
  rawUrl: string | URL,
  options: GuardedFetchOptions = {},
): Promise<Response> {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    followRedirects = true,
    maxRedirects = DEFAULT_MAX_REDIRECTS,
    sanitizeHeaders = true,
    httpsOnly,
    allowedHosts,
    skipSsrfCheckForAllowedHosts,
    opaqueErrors = false,
    onUrlBlocked,
    signal: externalSignal,
    fetch: fetchImpl = undiciFetch as unknown as FetchImpl,
    dispatcher: providedDispatcher,
    allowedCookie,
    headers,
    body,
    method,
    ...rest
  } = options;

  // IP-pinning dispatcher closes the DNS rebinding window. `null` explicitly
  // opts out.
  const dispatcher =
    providedDispatcher === null
      ? undefined
      : (providedDispatcher ?? getSharedGuardedDispatcher());

  const assertOptions: AssertUrlSafeOptions = {
    httpsOnly,
    allowedHosts,
    skipSsrfCheckForAllowedHosts,
    opaqueErrors,
    onUrlBlocked,
  };

  const { url } = await assertUrlIsSafeToFetch(rawUrl, assertOptions);

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(
      new GuardedFetchError(
        GuardedFetchErrorCode.TIMEOUT,
        opaqueErrors
          ? OPAQUE_ERROR_MESSAGE
          : `Request to "${url.hostname}" timed out after ${timeoutMs}ms.`,
        { hostname: url.hostname, url: url.toString() },
      ),
    );
  }, timeoutMs);

  const onExternalAbort = () => {
    controller.abort(externalSignal?.reason);
  };
  if (externalSignal) {
    if (externalSignal.aborted) {
      onExternalAbort();
    } else {
      externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    }
  }

  const outboundHeaders = sanitizeHeaders
    ? sanitizeRequestHeaders(
        headers as Parameters<typeof sanitizeRequestHeaders>[0],
      )
    : new Headers(
        headers as ConstructorParameters<typeof Headers>[0] | undefined,
      );

  if (allowedCookie !== undefined) {
    outboundHeaders.set('cookie', allowedCookie);
  }

  try {
    return await followChain({
      url,
      method: method ?? 'GET',
      body,
      headers: outboundHeaders,
      init: rest,
      fetchImpl,
      dispatcher,
      signal: controller.signal,
      followRedirects,
      maxRedirects,
      assertOptions,
      opaqueErrors,
    });
  } finally {
    clearTimeout(timer);
    if (externalSignal) {
      externalSignal.removeEventListener('abort', onExternalAbort);
    }
  }
}

async function followChain(params: {
  url: URL;
  method: string;
  body: FetchBody | null | undefined;
  headers: Headers;
  init: Omit<PassthroughRequestInit, 'headers' | 'body' | 'method'>;
  fetchImpl: FetchImpl;
  dispatcher: Dispatcher | undefined;
  signal: AbortSignal;
  followRedirects: boolean;
  maxRedirects: number;
  assertOptions: AssertUrlSafeOptions;
  opaqueErrors: boolean;
}): Promise<Response> {
  let {
    url: currentUrl,
    method: currentMethod,
    body: currentBody,
    headers: currentHeaders,
  } = params;
  const {
    init,
    fetchImpl,
    dispatcher,
    signal,
    followRedirects,
    maxRedirects,
    assertOptions,
    opaqueErrors,
  } = params;

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const response = await executeFetch({
      url: currentUrl,
      method: currentMethod,
      body: currentBody,
      headers: currentHeaders,
      init,
      fetchImpl,
      dispatcher,
      signal,
      opaqueErrors,
    });

    if (!isRedirect(response.status)) {
      return response;
    }

    if (!followRedirects) {
      return response;
    }

    if (hop === maxRedirects) {
      // Drain body to avoid socket leak when not returned to caller.
      await drainBody(response);
      recordUrlBlocked(
        GuardedFetchErrorCode.TOO_MANY_REDIRECTS,
        params.url.hostname.toLowerCase(),
        undefined,
        assertOptions.onUrlBlocked,
      );
      throw new GuardedFetchError(
        GuardedFetchErrorCode.TOO_MANY_REDIRECTS,
        opaqueErrors
          ? OPAQUE_ERROR_MESSAGE
          : `Exceeded ${maxRedirects} redirects starting from "${params.url}".`,
        { url: params.url.toString() },
      );
    }

    const locationHeader = response.headers.get('location');
    if (!locationHeader) {
      await drainBody(response);
      recordUrlBlocked(
        GuardedFetchErrorCode.REDIRECT_INVALID,
        currentUrl.hostname.toLowerCase(),
        undefined,
        assertOptions.onUrlBlocked,
      );
      throw new GuardedFetchError(
        GuardedFetchErrorCode.REDIRECT_INVALID,
        opaqueErrors
          ? OPAQUE_ERROR_MESSAGE
          : `Redirect response from "${currentUrl}" is missing a Location header.`,
        { url: currentUrl.toString(), status: response.status },
      );
    }

    let nextUrl: URL;
    try {
      nextUrl = new URL(locationHeader, currentUrl);
    } catch (cause) {
      await drainBody(response);
      recordUrlBlocked(
        GuardedFetchErrorCode.REDIRECT_INVALID,
        currentUrl.hostname.toLowerCase(),
        undefined,
        assertOptions.onUrlBlocked,
      );
      throw new GuardedFetchError(
        GuardedFetchErrorCode.REDIRECT_INVALID,
        opaqueErrors
          ? OPAQUE_ERROR_MESSAGE
          : `Redirect Location "${locationHeader}" from "${currentUrl}" is not a valid URL.`,
        { url: currentUrl.toString(), status: response.status, cause },
      );
    }

    // Drain the redirect response before issuing the next one.
    await drainBody(response);

    try {
      await assertUrlIsSafeToFetch(nextUrl, assertOptions);
    } catch (error) {
      if (
        error instanceof GuardedFetchError &&
        (error.code === GuardedFetchErrorCode.HOSTNAME_UNSAFE ||
          error.code === GuardedFetchErrorCode.HOST_NOT_ALLOWED ||
          error.code === GuardedFetchErrorCode.PROTOCOL_NOT_ALLOWED ||
          error.code === GuardedFetchErrorCode.INVALID_URL)
      ) {
        recordUrlBlocked(
          GuardedFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
          params.url.hostname.toLowerCase(),
          undefined,
          assertOptions.onUrlBlocked,
        );
        throw new GuardedFetchError(
          GuardedFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
          opaqueErrors
            ? OPAQUE_ERROR_MESSAGE
            : `Redirect to "${nextUrl.toString()}" was rejected: ${error.message}`,
          {
            hostname: nextUrl.hostname,
            url: nextUrl.toString(),
            cause: error,
          },
        );
      }
      throw error;
    }

    // Per RFC 7231 §6.4: 301/302/303 SHOULD change method to GET and drop body;
    // 307/308 MUST preserve method and body.
    const statusChangesMethod =
      response.status === 301 ||
      response.status === 302 ||
      response.status === 303;

    if (statusChangesMethod && currentMethod.toUpperCase() !== 'HEAD') {
      currentMethod = 'GET';
      currentBody = undefined;
      // Drop content-* headers since the body is dropped.
      currentHeaders = dropContentHeaders(currentHeaders);
    }

    // Drop credentials on cross-origin redirects to avoid leaking them to
    // attacker-controlled hosts. Cookie is treated identically to
    // Authorization because the `allowedCookie` option opts in
    // a `Cookie` header that must not follow a redirect off-origin.
    if (nextUrl.origin !== currentUrl.origin) {
      currentHeaders = stripHeader(currentHeaders, 'authorization');
      currentHeaders = stripHeader(currentHeaders, 'cookie');
    }

    currentUrl = nextUrl;
  }

  // Unreachable: loop always returns or throws before exhausting.
  throw new GuardedFetchError(
    GuardedFetchErrorCode.TOO_MANY_REDIRECTS,
    opaqueErrors ? OPAQUE_ERROR_MESSAGE : 'Redirect chain exhausted.',
    { url: params.url.toString() },
  );
}

async function executeFetch(params: {
  url: URL;
  method: string;
  body: FetchBody | null | undefined;
  headers: Headers;
  init: Omit<PassthroughRequestInit, 'headers' | 'body' | 'method'>;
  fetchImpl: FetchImpl;
  dispatcher: Dispatcher | undefined;
  signal: AbortSignal;
  opaqueErrors: boolean;
}): Promise<Response> {
  const {
    url,
    method,
    body,
    headers,
    init,
    fetchImpl,
    dispatcher,
    signal,
    opaqueErrors,
  } = params;

  const fetchInit: RequestInit = {
    ...init,
    method,
    headers: headers as RequestInit['headers'],
    body: body ?? undefined,
    redirect: 'manual',
    signal,
  };
  if (dispatcher) {
    (fetchInit as Record<string, unknown>).dispatcher = dispatcher;
  }

  try {
    return await fetchImpl(url.toString(), fetchInit);
  } catch (error) {
    // AbortError — surface as TIMEOUT if we raised it via our own reason,
    // otherwise as NETWORK_ERROR to preserve caller intent.
    if (signal.aborted && signal.reason instanceof GuardedFetchError) {
      throw signal.reason;
    }

    // The guarded-lookup rejects the connect with a GuardedFetchError. undici
    // typically wraps lookup errors inside a TypeError/fetch error with the
    // original error available via `.cause` (sometimes nested one level
    // deeper). Walk the chain and surface the original if we find one so
    // that callers see `HOSTNAME_UNSAFE` rather than a generic network
    // error when DNS rebinding is blocked at connect time.
    const unwrapped = findGuardedFetchErrorInCause(error);
    if (unwrapped) {
      throw unwrapped;
    }

    if (isAbortError(error)) {
      throw new GuardedFetchError(
        GuardedFetchErrorCode.NETWORK_ERROR,
        opaqueErrors
          ? OPAQUE_ERROR_MESSAGE
          : `Request to "${url.hostname}" was aborted.`,
        { hostname: url.hostname, url: url.toString(), cause: error },
      );
    }
    throw new GuardedFetchError(
      GuardedFetchErrorCode.NETWORK_ERROR,
      opaqueErrors
        ? OPAQUE_ERROR_MESSAGE
        : `Network error connecting to "${url.hostname}": ${errorMessage(error)}`,
      { hostname: url.hostname, url: url.toString(), cause: error },
    );
  }
}

function isRedirect(status: number): boolean {
  return (
    status === 301 ||
    status === 302 ||
    status === 303 ||
    status === 307 ||
    status === 308
  );
}

function isAbortError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === 'AbortError' ||
      (error as { code?: string }).code === 'ABORT_ERR')
  );
}

/**
 * Walks `error.cause` up to 5 levels looking for a {@link GuardedFetchError}.
 * undici tends to wrap socket-connect errors in its own `TypeError: fetch
 * failed`, placing the real error on `.cause`. When our safe lookup blocks
 * a connection due to DNS rebinding, the `GuardedFetchError` we raise there
 * needs to be surfaced to the caller with its original code intact.
 */
function findGuardedFetchErrorInCause(
  error: unknown,
): GuardedFetchError | undefined {
  let current: unknown = error;
  for (let i = 0; i < 5; i += 1) {
    if (isGuardedFetchError(current)) {
      return current as GuardedFetchError;
    }
    if (!(current instanceof Error) || !('cause' in current)) {
      return undefined;
    }
    current = (current as Error).cause;
    if (current === undefined || current === null) {
      return undefined;
    }
  }
  return undefined;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function dropContentHeaders(headers: Headers): Headers {
  const out = new Headers();
  headers.forEach((value, name) => {
    const lower = name.toLowerCase();
    if (
      lower === 'content-length' ||
      lower === 'content-type' ||
      lower === 'content-encoding' ||
      lower === 'content-language' ||
      lower === 'content-location'
    ) {
      return;
    }
    out.append(name, value);
  });
  return out;
}

function stripHeader(headers: Headers, name: string): Headers {
  const lower = name.toLowerCase();
  const out = new Headers();
  headers.forEach((value, key) => {
    if (key.toLowerCase() !== lower) {
      out.append(key, value);
    }
  });
  return out;
}

/**
 * How much of a discarded redirect body is read before the connection is
 * dropped instead. Small bodies are drained so the socket can be reused by
 * the next hop; anything larger is not worth holding a connection for.
 */
const MAX_REDIRECT_DRAIN_BYTES = 64 * 1024;

/**
 * Releases the socket behind a redirect response whose body is never returned
 * to the caller.
 *
 * Reads at most {@link MAX_REDIRECT_DRAIN_BYTES} and cancels beyond that.
 * Buffering the whole body here would be unbounded: redirect bodies are
 * attacker-controlled, `maxResponseBytes` only applies to the readers in
 * `read-body.ts`, and `timeoutMs` caps how long a hop may take but not how
 * much memory it may consume while doing so.
 */
async function drainBody(response: Response): Promise<void> {
  const body = response.body;
  if (!body) {
    return;
  }

  const reader = body.getReader();
  try {
    let drained = 0;
    while (drained <= MAX_REDIRECT_DRAIN_BYTES) {
      const { done, value } = await reader.read();
      if (done) {
        return;
      }
      drained += value?.byteLength ?? 0;
    }
    await reader.cancel();
  } catch {
    // Aborted, errored, or already-consumed stream — nothing left to release.
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Already released by cancel().
    }
  }
}

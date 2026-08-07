/**
 * Error codes for {@link SafeFetchError}.
 *
 * Codes are stable strings so they can be switched on in callers and logged.
 */
export const SafeFetchErrorCode = {
  /** The URL string could not be parsed. */
  INVALID_URL: 'invalid_url',
  /** The URL's protocol is not allowed (`http:`/`https:` by default; `https:` only when `httpsOnly: true`). */
  PROTOCOL_NOT_ALLOWED: 'protocol_not_allowed',
  /** The URL's hostname is not in the caller-provided allowlist. */
  HOST_NOT_ALLOWED: 'host_not_allowed',
  /**
   * The hostname DNS-resolves to a private, loopback, or link-local address
   * (or is `localhost` / `.local`). This is the primary SSRF guard.
   */
  HOSTNAME_UNSAFE: 'hostname_unsafe',
  /** The request was aborted because it exceeded `timeoutMs`. */
  TIMEOUT: 'timeout',
  /** A redirect chain exceeded `maxRedirects`. */
  TOO_MANY_REDIRECTS: 'too_many_redirects',
  /** A redirect `Location` header was missing, invalid, or used a disallowed protocol. */
  REDIRECT_INVALID: 'redirect_invalid',
  /**
   * A redirect `Location` pointed at an unsafe host (private/loopback/link-local,
   * or outside the allowlist). Distinct from `HOSTNAME_UNSAFE` so callers can
   * tell whether the original URL or a redirect was the problem.
   */
  REDIRECT_TO_UNSAFE_HOST: 'redirect_to_unsafe_host',
  /** The response body exceeded `maxResponseBytes`. Only raised by convenience readers. */
  RESPONSE_TOO_LARGE: 'response_too_large',
  /** A network-level failure occurred (DNS, connection, TLS, socket). */
  NETWORK_ERROR: 'network_error',
} as const;

export type SafeFetchErrorCode =
  (typeof SafeFetchErrorCode)[keyof typeof SafeFetchErrorCode];

/**
 * Error thrown by {@link safeFetch} and related helpers.
 *
 * All failure modes — SSRF rejection, timeout, oversized body, redirect abuse —
 * surface as `SafeFetchError` with a stable `code`. Callers should switch on
 * `code` rather than parsing `message`.
 */
export class SafeFetchError extends Error {
  readonly code: SafeFetchErrorCode;
  readonly hostname?: string;
  readonly url?: string;
  readonly status?: number;

  constructor(
    code: SafeFetchErrorCode,
    message: string,
    details: {
      hostname?: string;
      url?: string;
      status?: number;
      cause?: unknown;
    } = {},
  ) {
    super(message, details.cause !== undefined ? { cause: details.cause } : {});
    this.name = 'SafeFetchError';
    this.code = code;
    this.hostname = details.hostname;
    this.url = details.url;
    this.status = details.status;
  }
}

/**
 * Type guard for {@link SafeFetchError}. Resilient to multiple package copies
 * (e.g. in tests that bundle the module twice) because it also accepts any
 * `Error` with `name === 'SafeFetchError'` and a string `code`.
 */
export function isSafeFetchError(value: unknown): value is SafeFetchError {
  if (value instanceof SafeFetchError) {
    return true;
  }
  return (
    value instanceof Error &&
    value.name === 'SafeFetchError' &&
    typeof (value as { code?: unknown }).code === 'string'
  );
}

/**
 * Generic opaque message used when `opaqueErrors: true`. Avoids leaking DNS
 * resolution, port, or redirect details that could be probed via timing or
 * error comparison (e.g. SSRF reconnaissance through error messages that
 * reach an attacker-visible log drain).
 */
export const OPAQUE_ERROR_MESSAGE =
  'The URL could not be fetched: either it is not reachable or the request was rejected by policy.';

/**
 * Failure codes that cannot succeed on retry: the URL itself is unfetchable
 * (SSRF-blocked, malformed, redirect abuse) or the response exceeded a hard
 * limit. Timeouts and network-level failures are excluded — they may succeed
 * on retry.
 */
const PERMANENT_FAILURE_CODES: ReadonlySet<SafeFetchErrorCode> = new Set([
  SafeFetchErrorCode.INVALID_URL,
  SafeFetchErrorCode.PROTOCOL_NOT_ALLOWED,
  SafeFetchErrorCode.HOST_NOT_ALLOWED,
  SafeFetchErrorCode.HOSTNAME_UNSAFE,
  SafeFetchErrorCode.TOO_MANY_REDIRECTS,
  SafeFetchErrorCode.REDIRECT_INVALID,
  SafeFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
  SafeFetchErrorCode.RESPONSE_TOO_LARGE,
]);

/**
 * True when `error` is a {@link SafeFetchError} whose failure is permanent —
 * retrying the same URL cannot succeed. Callers deciding between "retry
 * later" and "record a permanent failure" should treat everything else
 * (timeouts, network errors, non-SafeFetch errors) as potentially transient.
 */
export function isPermanentSafeFetchError(error: unknown): boolean {
  return isSafeFetchError(error) && PERMANENT_FAILURE_CODES.has(error.code);
}

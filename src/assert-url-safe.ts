import {
  OPAQUE_ERROR_MESSAGE,
  SafeFetchError,
  SafeFetchErrorCode,
} from './errors';
import {
  checkHostnameSafetyForServerSideFetch,
  parseHostnameForOutboundLookup,
} from './hostname-safety';
import {
  HostnameUnsafeSubReason,
  recordUrlBlocked,
  resolveBlockedDomain,
  type UrlBlockedHandler,
  type UrlBlockedSubReason,
} from './url-blocked';

/**
 * Options controlling {@link assertUrlIsSafeToFetch}.
 */
export interface AssertUrlSafeOptions {
  /**
   * When `true`, only `https:` URLs are allowed. When `false` (the default),
   * both `http:` and `https:` are allowed.
   *
   * @default false
   */
  httpsOnly?: boolean;

  /**
   * Optional hostname allowlist. If provided, the URL's hostname must either
   * match an entry exactly (case-insensitive) or be a subdomain of one
   * (`*.<entry>`). Passing an empty array treats every host as disallowed.
   *
   * If omitted, any publicly-resolving host passes.
   */
  allowedHosts?: readonly string[];

  /**
   * When a host matches {@link allowedHosts}, skip the DNS/SSRF check. Only
   * safe for hosts under full organizational control (e.g. `*.example.com`
   * when you own `example.com`).
   *
   * @default false
   */
  skipSsrfCheckForAllowedHosts?: boolean;

  /**
   * Return a generic error message for every failure mode to avoid leaking
   * DNS, port, or reachability information to callers who can see error
   * messages (e.g. via a user-facing log drain). The `code` field on the
   * thrown error is preserved for internal logging.
   *
   * @default false
   */
  opaqueErrors?: boolean;

  /**
   * Called when this validation blocks a URL for security reasons. Overrides
   * the module-level handler from {@link setUrlBlockedHandler} for this call
   * only. Use for per-request context (team ID, webhook ID, etc.).
   */
  onUrlBlocked?: UrlBlockedHandler;
}

export interface ValidatedFetchTarget {
  /** The parsed, validated URL. Guaranteed to have an allowed protocol and safe host. */
  url: URL;
  /** Lower-cased hostname extracted from `url`. */
  hostname: string;
}

const HTTP_AND_HTTPS_PROTOCOLS: readonly string[] = ['http:', 'https:'];
const HTTPS_ONLY_PROTOCOLS: readonly string[] = ['https:'];

function getAllowedProtocols(httpsOnly: boolean): readonly string[] {
  return httpsOnly ? HTTPS_ONLY_PROTOCOLS : HTTP_AND_HTTPS_PROTOCOLS;
}

/**
 * Performs all pre-flight checks that {@link safeFetch} runs internally,
 * **without** making an HTTP request. Useful for validating user-configured
 * URLs at write time (webhook endpoints, log drain destinations, OIDC
 * issuers, JWKS URIs, etc.).
 *
 * Throws {@link SafeFetchError} on any failure.
 */
export async function assertUrlIsSafeToFetch(
  rawUrl: string | URL,
  options: AssertUrlSafeOptions = {},
): Promise<ValidatedFetchTarget> {
  const {
    httpsOnly = false,
    allowedHosts,
    skipSsrfCheckForAllowedHosts = false,
    opaqueErrors = false,
    onUrlBlocked,
  } = options;

  const allowedProtocols = getAllowedProtocols(httpsOnly);

  const fail = (
    code: (typeof SafeFetchErrorCode)[keyof typeof SafeFetchErrorCode],
    publicMessage: string,
    details: { hostname?: string; url?: string; cause?: unknown } = {},
    subReason?: UrlBlockedSubReason,
  ): never => {
    recordUrlBlocked(
      code,
      resolveBlockedDomain(details),
      subReason,
      onUrlBlocked,
    );
    throw new SafeFetchError(
      code,
      opaqueErrors ? OPAQUE_ERROR_MESSAGE : publicMessage,
      details,
    );
  };

  let url: URL;
  try {
    url = rawUrl instanceof URL ? rawUrl : new URL(rawUrl);
  } catch (cause) {
    return fail(SafeFetchErrorCode.INVALID_URL, 'The URL is not valid.', {
      url: String(rawUrl),
      cause,
    });
  }

  const normalizedProtocols = allowedProtocols.map((p) => p.toLowerCase());
  if (!normalizedProtocols.includes(url.protocol.toLowerCase())) {
    return fail(
      SafeFetchErrorCode.PROTOCOL_NOT_ALLOWED,
      `Protocol "${url.protocol}" is not allowed. Allowed: ${normalizedProtocols.join(', ')}.`,
      { url: url.toString() },
    );
  }

  const hostname = url.hostname.toLowerCase();

  if (allowedHosts !== undefined) {
    if (!isHostInAllowlist(hostname, allowedHosts)) {
      return fail(
        SafeFetchErrorCode.HOST_NOT_ALLOWED,
        `Host "${hostname}" is not in the allowlist.`,
        { hostname, url: url.toString() },
      );
    }

    if (skipSsrfCheckForAllowedHosts) {
      return { url, hostname };
    }
  }

  const lookupHost = parseHostnameForOutboundLookup(hostname);
  if (!lookupHost) {
    return fail(
      SafeFetchErrorCode.HOSTNAME_UNSAFE,
      `Hostname "${hostname}" is not a valid outbound target.`,
      { hostname, url: url.toString() },
      HostnameUnsafeSubReason.INVALID,
    );
  }

  const safety = await checkHostnameSafetyForServerSideFetch(lookupHost);
  if (!safety.safe) {
    return fail(
      SafeFetchErrorCode.HOSTNAME_UNSAFE,
      `Refusing to connect to "${hostname}": resolves to a private, loopback, or link-local address.`,
      { hostname, url: url.toString() },
      safety.subReason,
    );
  }

  return { url, hostname };
}

/**
 * Returns true if `hostname` equals any entry in `allowedHosts` exactly, or
 * is a subdomain of one. All comparisons are case-insensitive.
 *
 * Examples (with allowlist `['example.com']`):
 * - `example.com`          → true (exact)
 * - `api.example.com`      → true (subdomain)
 * - `notexample.com`       → false (would only match `.example.com` suffix)
 * - `example.com.evil.net` → false (right-anchored match only)
 */
export function isHostInAllowlist(
  hostname: string,
  allowedHosts: readonly string[],
): boolean {
  const host = hostname.toLowerCase();
  for (const entry of allowedHosts) {
    const normalized = entry.toLowerCase();
    if (!normalized) {
      continue;
    }
    if (host === normalized || host.endsWith(`.${normalized}`)) {
      return true;
    }
  }
  return false;
}

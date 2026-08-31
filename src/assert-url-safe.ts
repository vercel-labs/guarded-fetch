import {
  OPAQUE_ERROR_MESSAGE,
  GuardedFetchError,
  GuardedFetchErrorCode,
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
   * Optional hostname allowlist. If provided, the URL's hostname must match
   * an entry exactly (case-insensitive). Two leading-wildcard forms exist:
   * `*.example.com` matches exactly one subdomain level (`api.example.com`
   * but not `a.b.example.com`); `**.example.com` matches any number of
   * subdomain levels (`a.b.example.com` too). Neither wildcard matches the
   * base domain itself — list `example.com` explicitly if you want it.
   * Passing an empty array treats every host as disallowed.
   *
   * Wildcards are not validated against the public-suffix list: `**.com`
   * would allow every `.com` host. Scope wildcard entries to domains you
   * control.
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
 * Performs all pre-flight checks that {@link guardedFetch} runs internally,
 * **without** making an HTTP request. Useful for validating user-configured
 * URLs at write time (webhook endpoints, log drain destinations, OIDC
 * issuers, JWKS URIs, etc.).
 *
 * Throws {@link GuardedFetchError} on any failure.
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
    code: (typeof GuardedFetchErrorCode)[keyof typeof GuardedFetchErrorCode],
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
    throw new GuardedFetchError(
      code,
      opaqueErrors ? OPAQUE_ERROR_MESSAGE : publicMessage,
      details,
    );
  };

  let url: URL;
  try {
    url = rawUrl instanceof URL ? rawUrl : new URL(rawUrl);
  } catch (cause) {
    return fail(GuardedFetchErrorCode.INVALID_URL, 'The URL is not valid.', {
      url: String(rawUrl),
      cause,
    });
  }

  const normalizedProtocols = allowedProtocols.map((p) => p.toLowerCase());
  if (!normalizedProtocols.includes(url.protocol.toLowerCase())) {
    return fail(
      GuardedFetchErrorCode.PROTOCOL_NOT_ALLOWED,
      `Protocol "${url.protocol}" is not allowed. Allowed: ${normalizedProtocols.join(', ')}.`,
      { url: url.toString() },
    );
  }

  const hostname = url.hostname.toLowerCase();

  if (allowedHosts !== undefined) {
    if (!isHostInAllowlist(hostname, allowedHosts)) {
      return fail(
        GuardedFetchErrorCode.HOST_NOT_ALLOWED,
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
      GuardedFetchErrorCode.HOSTNAME_UNSAFE,
      `Hostname "${hostname}" is not a valid outbound target.`,
      { hostname, url: url.toString() },
      HostnameUnsafeSubReason.INVALID,
    );
  }

  const safety = await checkHostnameSafetyForServerSideFetch(lookupHost);
  if (!safety.safe) {
    return fail(
      GuardedFetchErrorCode.HOSTNAME_UNSAFE,
      `Refusing to connect to "${hostname}": resolves to a private, loopback, or link-local address.`,
      { hostname, url: url.toString() },
      safety.subReason,
    );
  }

  return { url, hostname };
}

/**
 * Returns true if `hostname` matches an entry in `allowedHosts`. Entries are
 * explicit matches only (case-insensitive), plus two leading-wildcard forms:
 *
 * - `*.`  — matches exactly one subdomain level below the base domain.
 * - `**.` — matches one or more subdomain levels below the base domain.
 *
 * Neither wildcard matches the base domain itself.
 *
 * Examples (with allowlist `['example.com', '*.example.com', '**.example.com']`):
 * - `example.com`              → true (exact)
 * - `api.example.com`          → true (one wildcard level, also `**.`)
 * - `a.b.example.com`          → true (`**.` only)
 * - `www.example.com.evil.net` → false
 * - `notexample.com`           → false
 *
 * With allowlist `['example.com']` alone, `api.example.com` is rejected.
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
    if (normalized.startsWith('**.')) {
      const base = normalized.slice(3);
      // One or more subdomain levels. Require the matched prefix to be
      // non-empty and to contain no empty label: reject a leading-dot host
      // (`.base`) and any double-dot (`a..base`) by checking the prefix
      // neither starts with nor contains a leading/trailing/double dot.
      if (
        base &&
        host.length > base.length + 1 &&
        host.endsWith(`.${base}`) &&
        !host.slice(0, -base.length - 1).startsWith('.') &&
        !host.slice(0, -base.length - 1).includes('..')
      ) {
        return true;
      }
      continue;
    }
    if (normalized.startsWith('*.')) {
      const base = normalized.slice(2);
      // Exactly one subdomain level: the prefix (host minus `.` + base) must
      // be a single non-empty label — no `.`, and not empty (rejects `.base`).
      if (
        base &&
        host.length > base.length + 1 &&
        host.endsWith(`.${base}`) &&
        !host.slice(0, -base.length - 1).includes('.')
      ) {
        return true;
      }
      continue;
    }
    if (host === normalized) {
      return true;
    }
  }
  return false;
}

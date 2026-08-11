import { GuardedFetchErrorCode } from './errors';

/** Suggested log message for {@link UrlBlockedHandler} implementations. */
export const URL_BLOCKED_LOG_MESSAGE = 'guarded-fetch blocked URL' as const;

/**
 * Sub-reasons for {@link GuardedFetchErrorCode.HOSTNAME_UNSAFE}. Public
 * {@link GuardedFetchError.code} stays `hostname_unsafe`; use `subReason` in
 * block events to distinguish block paths.
 */
export const HostnameUnsafeSubReason = {
  INVALID: 'hostname_invalid',
  LOCALHOST: 'hostname_localhost',
  LOCAL_DOMAIN: 'hostname_local_domain',
  IP_LITERAL_UNSAFE: 'ip_literal_unsafe',
  DNS_UNSAFE_ADDRESS: 'dns_unsafe_address',
  DNS_RESOLUTION_FAILED: 'dns_resolution_failed',
  CONNECT_TIME_IP_REJECTED: 'connect_time_ip_rejected',
} as const;

export type HostnameUnsafeSubReason =
  (typeof HostnameUnsafeSubReason)[keyof typeof HostnameUnsafeSubReason];

/** Block-event `subReason`: public error code or hostname-unsafe detail. */
export type UrlBlockedSubReason =
  | GuardedFetchErrorCode
  | HostnameUnsafeSubReason;

/** GuardedFetch error codes that emit block events (SSRF, allowlist, protocol, redirect abuse). */
export const URL_BLOCKED_REASONS: ReadonlySet<GuardedFetchErrorCode> = new Set([
  GuardedFetchErrorCode.INVALID_URL,
  GuardedFetchErrorCode.PROTOCOL_NOT_ALLOWED,
  GuardedFetchErrorCode.HOST_NOT_ALLOWED,
  GuardedFetchErrorCode.HOSTNAME_UNSAFE,
  GuardedFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
  GuardedFetchErrorCode.TOO_MANY_REDIRECTS,
  GuardedFetchErrorCode.REDIRECT_INVALID,
]);

/** Payload for {@link UrlBlockedHandler} and {@link setUrlBlockedHandler}. */
export type UrlBlockedEvent = {
  reason: GuardedFetchErrorCode;
  domain: string;
  subReason?: UrlBlockedSubReason;
};

/** Optional logging hook for security block events. Must not throw. */
export type UrlBlockedHandler = (event: UrlBlockedEvent) => void;

let globalUrlBlockedHandler: UrlBlockedHandler | undefined;

/**
 * Registers a process-wide handler for security block events. Call once at
 * service/app startup (e.g. next to logger init). Per-call overrides via
 * {@link AssertUrlSafeOptions.onUrlBlocked} take precedence.
 */
export function setUrlBlockedHandler(
  handler: UrlBlockedHandler | undefined,
): void {
  globalUrlBlockedHandler = handler;
}

/**
 * Lower-cased hostname for block events. Falls back to parsing `url`, then
 * `'unknown'` when the input is not a valid URL string.
 */
export function resolveBlockedDomain(details: {
  hostname?: string;
  url?: string;
}): string {
  if (details.hostname) {
    return details.hostname.toLowerCase();
  }
  if (details.url) {
    try {
      return new URL(details.url).hostname.toLowerCase();
    } catch {
      return 'unknown';
    }
  }
  return 'unknown';
}

/**
 * Dispatches a block event with `reason`, `domain`, and optional `subReason`
 * to `onUrlBlocked` when set, otherwise to the module-level handler from
 * {@link setUrlBlockedHandler}. Never throws.
 */
export function recordUrlBlocked(
  reason: GuardedFetchErrorCode,
  domain: string,
  subReason?: UrlBlockedSubReason,
  onUrlBlocked?: UrlBlockedHandler,
): void {
  if (!URL_BLOCKED_REASONS.has(reason)) {
    return;
  }

  const normalizedDomain = domain || 'unknown';

  const handler = onUrlBlocked ?? globalUrlBlockedHandler;
  if (!handler) {
    return;
  }

  try {
    handler({
      reason,
      domain: normalizedDomain,
      ...(subReason !== undefined ? { subReason } : {}),
    });
  } catch {
    // Hooks must not affect fetch behavior.
  }
}

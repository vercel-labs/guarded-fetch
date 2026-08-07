/**
 * Only use `dangerousNakedFetch` if you: (1) are 100% certain it will never
 * be passed a user-modifiable URL, or (2) have a strong blocker from using
 * `safeFetch`, and (3) accept the risks with such usage.
 */
export { fetch as dangerousNakedFetch } from 'undici';
export { BLOCKED_REQUEST_HEADERS } from './blocked-headers';
export {
  isPermanentSafeFetchError,
  isSafeFetchError,
  OPAQUE_ERROR_MESSAGE,
  SafeFetchError,
  SafeFetchErrorCode,
} from './errors';
export {
  assertUrlIsSafeToFetch,
  isHostInAllowlist,
  type AssertUrlSafeOptions,
  type ValidatedFetchTarget,
} from './assert-url-safe';
export {
  sanitizeHeaderRecord,
  sanitizeRequestHeaders,
  type HeadersLike,
} from './sanitize-headers';
export {
  readBodyAsBytes,
  readBodyAsJson,
  readBodyAsText,
  type ReadBodyOptions,
} from './read-body';
export {
  createSafeLookup,
  isSafeIpAddress,
  type SafeLookupOptions,
} from './safe-lookup';
export {
  createSafeDispatcher,
  getSharedSafeDispatcher,
} from './safe-dispatcher';
export { safeFetch, type SafeFetchOptions } from './safe-fetch';
export {
  safeFetchJson,
  safeFetchText,
  type SafeFetchBodyOptions,
} from './safe-fetch-helpers';
export {
  HostnameUnsafeSubReason,
  setUrlBlockedHandler,
  URL_BLOCKED_LOG_MESSAGE,
  type UrlBlockedEvent,
  type UrlBlockedHandler,
  type UrlBlockedSubReason,
} from './url-blocked';

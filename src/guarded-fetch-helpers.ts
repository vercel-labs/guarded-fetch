import {
  OPAQUE_ERROR_MESSAGE,
  GuardedFetchError,
  GuardedFetchErrorCode,
} from './errors';
import {
  DEFAULT_TIMEOUT_MS,
  guardedFetch,
  type GuardedFetchOptions,
} from './guarded-fetch';
import {
  readBodyAsJson,
  readBodyAsText,
  type ReadBodyOptions,
} from './read-body';

export interface GuardedFetchBodyOptions
  extends GuardedFetchOptions, ReadBodyOptions {
  /**
   * If true, non-2xx responses throw a {@link GuardedFetchError} with code
   * `NETWORK_ERROR` and the response's `status` populated. If false (default),
   * the body is returned regardless of status, matching `fetch`'s behavior.
   *
   * @default false
   */
  throwOnHttpError?: boolean;
}

/**
 * Convenience wrapper: performs a safe fetch and parses the body as JSON,
 * enforcing a configurable response-size limit and the same `timeoutMs`
 * budget through body streaming.
 */
export async function guardedFetchJson<T = unknown>(
  url: string | URL,
  options: GuardedFetchBodyOptions = {},
): Promise<T> {
  const { maxResponseBytes, throwOnHttpError, timeoutMs, ...fetchOptions } =
    options;
  const startedAt = Date.now();
  const deadlineAt = startedAt + (timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const response = await guardedFetch(url, { ...fetchOptions, timeoutMs });
  maybeThrowForStatus(response, throwOnHttpError, options.opaqueErrors);
  return readBodyAsJson<T>(response, {
    maxResponseBytes,
    deadlineAt,
    opaqueErrors: options.opaqueErrors,
  });
}

/**
 * Convenience wrapper: performs a safe fetch and returns the body as UTF-8
 * text, enforcing a configurable response-size limit and the same `timeoutMs`
 * budget through body streaming.
 */
export async function guardedFetchText(
  url: string | URL,
  options: GuardedFetchBodyOptions = {},
): Promise<string> {
  const { maxResponseBytes, throwOnHttpError, timeoutMs, ...fetchOptions } =
    options;
  const startedAt = Date.now();
  const deadlineAt = startedAt + (timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const response = await guardedFetch(url, { ...fetchOptions, timeoutMs });
  maybeThrowForStatus(response, throwOnHttpError, options.opaqueErrors);
  return readBodyAsText(response, {
    maxResponseBytes,
    deadlineAt,
    opaqueErrors: options.opaqueErrors,
  });
}

function maybeThrowForStatus(
  response: Response,
  throwOnHttpError: boolean | undefined,
  opaqueErrors: boolean | undefined,
): void {
  if (!throwOnHttpError || response.ok) {
    return;
  }
  throw new GuardedFetchError(
    GuardedFetchErrorCode.NETWORK_ERROR,
    opaqueErrors
      ? OPAQUE_ERROR_MESSAGE
      : `HTTP ${response.status} from "${response.url}".`,
    { url: response.url, status: response.status },
  );
}

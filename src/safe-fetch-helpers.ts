import {
  OPAQUE_ERROR_MESSAGE,
  SafeFetchError,
  SafeFetchErrorCode,
} from './errors';
import {
  readBodyAsJson,
  readBodyAsText,
  type ReadBodyOptions,
} from './read-body';
import { safeFetch, type SafeFetchOptions } from './safe-fetch';

const DEFAULT_TIMEOUT_MS = 10_000;

export interface SafeFetchBodyOptions
  extends SafeFetchOptions, ReadBodyOptions {
  /**
   * If true, non-2xx responses throw a {@link SafeFetchError} with code
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
export async function safeFetchJson<T = unknown>(
  url: string | URL,
  options: SafeFetchBodyOptions = {},
): Promise<T> {
  const { maxResponseBytes, throwOnHttpError, timeoutMs, ...fetchOptions } =
    options;
  const startedAt = Date.now();
  const deadlineAt = startedAt + (timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const response = await safeFetch(url, { ...fetchOptions, timeoutMs });
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
export async function safeFetchText(
  url: string | URL,
  options: SafeFetchBodyOptions = {},
): Promise<string> {
  const { maxResponseBytes, throwOnHttpError, timeoutMs, ...fetchOptions } =
    options;
  const startedAt = Date.now();
  const deadlineAt = startedAt + (timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const response = await safeFetch(url, { ...fetchOptions, timeoutMs });
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
  throw new SafeFetchError(
    SafeFetchErrorCode.NETWORK_ERROR,
    opaqueErrors
      ? OPAQUE_ERROR_MESSAGE
      : `HTTP ${response.status} from "${response.url}".`,
    { url: response.url, status: response.status },
  );
}

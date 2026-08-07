import { Headers } from 'undici';

import { BLOCKED_REQUEST_HEADERS } from './blocked-headers';

/**
 * Supported input shapes, mirroring the DOM `HeadersInit` type but without
 * depending on DOM lib being enabled.
 */
export type HeadersLike =
  | Headers
  | globalThis.Headers
  | Record<string, string | string[] | undefined>
  | readonly (readonly [string, string])[];

/**
 * Returns a new `Headers` instance with {@link BLOCKED_REQUEST_HEADERS}
 * removed. The input is never mutated.
 *
 * Accepts any shape that `new Headers(...)` would accept, plus a plain record
 * whose values may be `undefined` (ignored) or `string[]` (joined per
 * `Headers.append` semantics).
 */
export function sanitizeRequestHeaders(
  input: HeadersLike | undefined,
): Headers {
  const out = new Headers();
  if (!input) {
    return out;
  }

  const append = (name: string, value: string) => {
    if (BLOCKED_REQUEST_HEADERS.has(name.toLowerCase())) {
      return;
    }
    out.append(name, value);
  };

  if (isHeadersObject(input)) {
    input.forEach((value, name) => {
      append(name, value);
    });
    return out;
  }

  if (Array.isArray(input)) {
    for (const entry of input) {
      const [name, value] = entry;
      if (typeof name === 'string' && typeof value === 'string') {
        append(name, value);
      }
    }
    return out;
  }

  for (const [name, value] of Object.entries(
    input as Record<string, string | string[] | undefined>,
  )) {
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const v of value) {
        append(name, v);
      }
    } else {
      append(name, value);
    }
  }

  return out;
}

function isHeadersObject(
  input: HeadersLike,
): input is Headers | globalThis.Headers {
  return (
    !Array.isArray(input) &&
    typeof (input as { forEach?: unknown }).forEach === 'function'
  );
}

/**
 * Returns a new plain object with {@link BLOCKED_REQUEST_HEADERS} removed.
 *
 * Offered for callers that must keep a `Record` shape (e.g. to splat into
 * another HTTP client's `headers` option).
 */
export function sanitizeHeaderRecord(
  headers: Readonly<Record<string, string>>,
): Record<string, string> {
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!BLOCKED_REQUEST_HEADERS.has(key.toLowerCase())) {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

import {
  OPAQUE_ERROR_MESSAGE,
  GuardedFetchError,
  GuardedFetchErrorCode,
} from './errors';

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MB

export interface ReadBodyOptions {
  /**
   * Maximum number of bytes to read from the response body before aborting
   * with {@link GuardedFetchErrorCode.RESPONSE_TOO_LARGE}.
   *
   * @default 10 MB
   */
  maxResponseBytes?: number;

  /**
   * Wall-clock deadline (ms since epoch) for reading the full response body.
   * When exceeded, the stream is cancelled and {@link GuardedFetchErrorCode.TIMEOUT}
   * is thrown. Used by {@link guardedFetchJson} / {@link guardedFetchText} to extend
   * the same `timeoutMs` budget through body streaming.
   */
  deadlineAt?: number;

  /**
   * Return an opaque error for size-limit / decode failures to avoid leaking
   * response-shape information.
   *
   * @default false
   */
  opaqueErrors?: boolean;
}

class BodyReadDeadlineExceeded extends Error {
  constructor() {
    super('Response body read deadline exceeded.');
    this.name = 'BodyReadDeadlineExceeded';
  }
}

function createBodyReadTimeoutError(
  response: Response,
  opaqueErrors: boolean,
): GuardedFetchError {
  return new GuardedFetchError(
    GuardedFetchErrorCode.TIMEOUT,
    opaqueErrors
      ? OPAQUE_ERROR_MESSAGE
      : `Response body read from "${response.url}" timed out.`,
    { url: response.url, status: response.status },
  );
}

async function readChunkWithDeadline(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  deadlineAt: number | undefined,
  response: Response,
  opaqueErrors: boolean,
): Promise<{ done: boolean; value?: Uint8Array }> {
  if (deadlineAt === undefined) {
    return reader.read();
  }

  const remainingMs = deadlineAt - Date.now();
  if (remainingMs <= 0) {
    throw createBodyReadTimeoutError(response, opaqueErrors);
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      reader.read(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new BodyReadDeadlineExceeded()),
          remainingMs,
        );
      }),
    ]);
  } catch (error) {
    if (error instanceof BodyReadDeadlineExceeded) {
      throw createBodyReadTimeoutError(response, opaqueErrors);
    }
    throw error;
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

async function cancelReader(
  reader: ReadableStreamDefaultReader<Uint8Array>,
): Promise<void> {
  try {
    await reader.cancel();
  } catch {
    // ignore
  }
}

function releaseReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    reader.releaseLock();
  } catch {
    // reader may already be closed / cancelled
  }
}

/**
 * Reads a `Response` body as a UTF-8 string, bounded by `maxResponseBytes`.
 *
 * Streaming is used where available so oversized responses are detected
 * early, without buffering the full body. The underlying connection is
 * cancelled as soon as the limit is exceeded.
 */
export async function readBodyAsText(
  response: Response,
  options: ReadBodyOptions = {},
): Promise<string> {
  const {
    maxResponseBytes = DEFAULT_MAX_BYTES,
    deadlineAt,
    opaqueErrors = false,
  } = options;

  const body = response.body;
  if (!body) {
    return '';
  }

  const reader = body.getReader();
  const decoder = new TextDecoder('utf-8');
  const chunks: string[] = [];
  let received = 0;

  try {
    while (true) {
      const { done, value } = await readChunkWithDeadline(
        reader,
        deadlineAt,
        response,
        opaqueErrors,
      );
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      received += value.byteLength;
      if (received > maxResponseBytes) {
        await cancelReader(reader);
        throw new GuardedFetchError(
          GuardedFetchErrorCode.RESPONSE_TOO_LARGE,
          opaqueErrors
            ? OPAQUE_ERROR_MESSAGE
            : `Response body exceeded ${maxResponseBytes} bytes.`,
          { url: response.url, status: response.status },
        );
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
  } catch (error) {
    if (
      error instanceof GuardedFetchError &&
      error.code === GuardedFetchErrorCode.TIMEOUT
    ) {
      await cancelReader(reader);
    }
    throw error;
  } finally {
    releaseReader(reader);
  }

  return chunks.join('');
}

/**
 * Reads a `Response` body as JSON, bounded by `maxResponseBytes`. Throws
 * {@link GuardedFetchError} with code `NETWORK_ERROR` on parse failure.
 */
export async function readBodyAsJson<T = unknown>(
  response: Response,
  options: ReadBodyOptions = {},
): Promise<T> {
  const text = await readBodyAsText(response, options);
  try {
    return JSON.parse(text) as T;
  } catch (cause) {
    throw new GuardedFetchError(
      GuardedFetchErrorCode.NETWORK_ERROR,
      options.opaqueErrors
        ? OPAQUE_ERROR_MESSAGE
        : `Failed to parse JSON response from "${response.url}".`,
      { url: response.url, status: response.status, cause },
    );
  }
}

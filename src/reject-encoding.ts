import { DecoratorHandler, type Dispatcher } from 'undici';

import { GuardedFetchError, GuardedFetchErrorCode } from './errors';

// undici's types do not declare the handler methods on `DecoratorHandler`.
const Base = DecoratorHandler as unknown as new (
  handler: Dispatcher.DispatchHandler,
) => Dispatcher.DispatchHandler;

/**
 * Aborts a response whose `Content-Encoding` lists a blocked coding.
 *
 * This runs before undici's fetch handler sees the headers. undici selects the
 * decoder from the response header, not from `Accept-Encoding`. A hostile
 * server can send an encoding that the client did not request. The abort
 * keeps that data out of the decoder.
 */
class RejectEncodingHandler extends Base {
  readonly #blocked: ReadonlySet<string>;

  constructor(
    handler: Dispatcher.DispatchHandler,
    blocked: ReadonlySet<string>,
  ) {
    super(handler);
    this.#blocked = blocked;
  }

  override onResponseStart(
    controller: Dispatcher.DispatchController,
    statusCode: number,
    headers: Record<string, string | string[] | undefined>,
    statusMessage?: string,
  ): void {
    const found = findBlocked(headers['content-encoding'], this.#blocked);
    if (found !== undefined) {
      controller.abort(
        new GuardedFetchError(
          GuardedFetchErrorCode.RESPONSE_ENCODING_NOT_ALLOWED,
          `Response uses content-encoding "${found}", which is not allowed.`,
        ),
      );
      return;
    }
    super.onResponseStart?.(controller, statusCode, headers, statusMessage);
  }
}

function findBlocked(
  value: string | string[] | undefined,
  blocked: ReadonlySet<string>,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const joined = Array.isArray(value) ? value.join(',') : value;
  return joined
    .toLowerCase()
    .split(',')
    .map((coding) => coding.trim())
    .find((coding) => blocked.has(coding));
}

/** Returns an undici interceptor that rejects responses using any of `encodings`. */
export function rejectEncoding(
  encodings: readonly string[],
): Dispatcher.DispatcherComposeInterceptor {
  const blocked = new Set(encodings.map((e) => e.toLowerCase()));
  return (dispatch) => (opts, handler) =>
    dispatch(opts, new RejectEncodingHandler(handler, blocked));
}

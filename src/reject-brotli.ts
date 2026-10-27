import { DecoratorHandler, type Dispatcher } from 'undici';

import { GuardedFetchError, GuardedFetchErrorCode } from './errors';

// undici's types do not declare the handler methods on `DecoratorHandler`.
const Base = DecoratorHandler as unknown as new (
  handler: Dispatcher.DispatchHandler,
) => Dispatcher.DispatchHandler;

/**
 * Aborts a response that lists `br` in `Content-Encoding`.
 *
 * This runs before undici's fetch handler sees the headers. undici selects the
 * decoder from the response header, not from `Accept-Encoding`. A hostile
 * server can send brotli data that the client did not request. The abort
 * keeps that data out of the Node brotli decoder (CVE-2026-111497).
 */
class RejectBrotliHandler extends Base {
  override onResponseStart(
    controller: Dispatcher.DispatchController,
    statusCode: number,
    headers: Record<string, string | string[] | undefined>,
    statusMessage?: string,
  ): void {
    if (hasBrotli(headers['content-encoding'])) {
      controller.abort(
        new GuardedFetchError(
          GuardedFetchErrorCode.RESPONSE_ENCODING_NOT_ALLOWED,
          'Response uses brotli content-encoding, which is not allowed.',
        ),
      );
      return;
    }
    super.onResponseStart?.(controller, statusCode, headers, statusMessage);
  }
}

function hasBrotli(value: string | string[] | undefined): boolean {
  if (value === undefined) {
    return false;
  }
  const joined = Array.isArray(value) ? value.join(',') : value;
  return joined
    .toLowerCase()
    .split(',')
    .some((coding) => coding.trim() === 'br');
}

export const rejectBrotli: Dispatcher.DispatcherComposeInterceptor =
  (dispatch) => (opts, handler) =>
    dispatch(opts, new RejectBrotliHandler(handler));

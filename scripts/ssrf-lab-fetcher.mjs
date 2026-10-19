import {
  createGuardedDispatcher,
  guardedFetch,
  GuardedFetchError,
  GuardedFetchErrorCode,
} from '../dist/index.mjs';

// Exercise this checkout's build with the default address and redirect policy.
const dispatcher = createGuardedDispatcher();

export const name = 'guarded-fetch checkout';

export function fetchUrl(url, { signal, timeoutMs }) {
  return guardedFetch(url, { signal, timeoutMs, dispatcher });
}

export function classifyRefusal(error) {
  if (
    error instanceof GuardedFetchError &&
    [
      GuardedFetchErrorCode.HOSTNAME_UNSAFE,
      GuardedFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
    ].includes(error.code)
  ) {
    return 'forbidden-address';
  }
}

export async function close() {
  await dispatcher.destroy();
}

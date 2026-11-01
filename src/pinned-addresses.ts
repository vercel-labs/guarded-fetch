import { AsyncLocalStorage } from 'node:async_hooks';
import type { LookupAddress } from 'node:dns';

interface PinnedAnswer {
  hostname: string;
  addresses: readonly LookupAddress[];
}

const pinned = new AsyncLocalStorage<PinnedAnswer>();

/**
 * Runs `fn` with a validated DNS answer for `hostname` in scope, so the
 * connect-time lookup can reuse it instead of resolving the host again.
 */
export function withPinnedAddresses<T>(
  hostname: string,
  addresses: readonly LookupAddress[] | undefined,
  fn: () => T,
): T {
  if (!addresses || addresses.length === 0) {
    return fn();
  }
  return pinned.run({ hostname: hostname.toLowerCase(), addresses }, fn);
}

/**
 * The answer pinned for `hostname` in the current async context, narrowed to
 * `family` (`0` for both). Returns `undefined` when nothing usable is pinned,
 * and the caller should resolve the host itself.
 */
export function getPinnedAddresses(
  hostname: string,
  family: number,
): LookupAddress[] | undefined {
  const answer = pinned.getStore();
  if (!answer || answer.hostname !== hostname.toLowerCase()) {
    return undefined;
  }
  const addresses = answer.addresses.filter(
    (entry) => family === 0 || entry.family === family,
  );
  return addresses.length > 0 ? addresses : undefined;
}

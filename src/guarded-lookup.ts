import dns from 'node:dns';

import {
  OPAQUE_ERROR_MESSAGE,
  GuardedFetchError,
  GuardedFetchErrorCode,
} from './errors';
import { isSafeIpAddress } from './ip-address';
import { HostnameUnsafeSubReason, recordUrlBlocked } from './url-blocked';

export interface GuardedLookupOptions {
  /**
   * Return an opaque error message when the resolved IP is rejected.
   * Mirrors the `opaqueErrors` flag on higher-level APIs to avoid leaking
   * which private range was hit.
   */
  opaqueErrors?: boolean;
}

/**
 * Callback signature compatible with `dns.lookup`, Node's `net.connect`
 * `lookup` option, `https.Agent`'s `lookup` option, and undici's
 * `Agent.connect.lookup`. Using one function in all these places guarantees
 * the IP that the socket actually connects to is the same one we validated.
 */
type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | dns.LookupAddress[],
  family?: number,
) => void;

/**
 * Creates a DNS `lookup` function that validates the resolved IP against
 * {@link isSafeIpAddress} **inline** — the validation runs inside the same
 * call that returns the IP the socket will connect to, closing the
 * DNS-rebinding TOCTOU window that a two-step "resolve → validate → resolve
 * again → connect" sequence leaves open.
 *
 * The returned function:
 * - Delegates the actual resolution to Node's `dns.lookup`.
 * - In single-result mode (`all` unset/false), validates the one returned IP.
 * - In `all: true` mode, validates **every** returned IP.
 * - On any unsafe IP, invokes the callback with a {@link GuardedFetchError}
 *   whose `code` is `HOSTNAME_UNSAFE`. The socket `connect` then fails.
 *
 * **This only covers hosts that get resolved.** Node's socket APIs skip DNS
 * entirely when the host is already an IP literal, so a `lookup` function is
 * never called for `net.connect({ host: '127.0.0.1' })` — no `lookup`
 * implementation can guard that case, including this one. On its own this is
 * a rebinding guard, not a complete SSRF guard.
 *
 * For a complete guard, use {@link guardedFetch}, or
 * {@link getSharedGuardedDispatcher} / {@link createGuardedDispatcher}, which
 * pair this lookup with a pre-connect IP-literal check. If you are wiring
 * sockets by hand, run {@link assertUrlIsSafeToFetch} (or
 * {@link isSafeIpAddress} for a bare host) on the target first:
 *
 * ```ts
 * await assertUrlIsSafeToFetch(target);
 * net.connect({ host, port, lookup: createGuardedLookup() });
 * ```
 */
export function createGuardedLookup(
  options: GuardedLookupOptions = {},
): (
  hostname: string,
  opts: dns.LookupOneOptions | dns.LookupAllOptions | number | undefined,
  callback: LookupCallback,
) => void {
  const { opaqueErrors = false } = options;

  const reject = (
    hostname: string,
    address: string,
    cb: LookupCallback,
  ): void => {
    recordUrlBlocked(
      GuardedFetchErrorCode.HOSTNAME_UNSAFE,
      hostname.toLowerCase(),
      HostnameUnsafeSubReason.CONNECT_TIME_IP_REJECTED,
    );
    // We pass a `GuardedFetchError` up through the `dns.lookup` callback; this
    // causes the socket `connect` to fail and the error to bubble up through
    // undici as the `.cause` of a generic fetch error. `guardedFetch`'s cause
    // walker then surfaces it to the caller with `code: HOSTNAME_UNSAFE`
    // intact. We deliberately do NOT overwrite `err.code` with a POSIX-style
    // string — doing so would shadow the GuardedFetchErrorCode on the class.
    const err = new GuardedFetchError(
      GuardedFetchErrorCode.HOSTNAME_UNSAFE,
      opaqueErrors
        ? OPAQUE_ERROR_MESSAGE
        : `Refusing to connect to ${address}: private, loopback, or link-local address.`,
      { hostname },
    );
    cb(err as unknown as NodeJS.ErrnoException, '', 0);
  };

  return function guardedLookup(hostname, opts, callback) {
    dns.lookup(
      hostname,
      // `dns.lookup`'s overloads differ on the 2nd arg; passing through is
      // safe because we never construct this value ourselves.
      opts as dns.LookupOneOptions,
      (err, address, family) => {
        if (err) {
          callback(err, address as string, family);
          return;
        }

        if (Array.isArray(address)) {
          for (const entry of address) {
            if (!isSafeIpAddress(entry.address)) {
              reject(hostname, entry.address, callback);
              return;
            }
          }
          callback(null, address);
          return;
        }

        if (typeof address === 'string' && !isSafeIpAddress(address)) {
          reject(hostname, address, callback);
          return;
        }

        callback(null, address as string, family);
      },
    );
  };
}

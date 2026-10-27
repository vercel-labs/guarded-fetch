import dns from 'node:dns';
import net from 'node:net';

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
 * - Always resolves and validates **every** returned IP before connecting.
 * - Returns one address or the whole list, matching the connector's `all` option.
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
    message: string,
    subReason: HostnameUnsafeSubReason,
    cb: LookupCallback,
  ): void => {
    recordUrlBlocked(
      GuardedFetchErrorCode.HOSTNAME_UNSAFE,
      hostname.toLowerCase(),
      subReason,
    );
    // We pass a `GuardedFetchError` up through the `dns.lookup` callback; this
    // causes the socket `connect` to fail and the error to bubble up through
    // undici as the `.cause` of a generic fetch error. `guardedFetch`'s cause
    // walker then surfaces it to the caller with `code: HOSTNAME_UNSAFE`
    // intact. We deliberately do NOT overwrite `err.code` with a POSIX-style
    // string — doing so would shadow the GuardedFetchErrorCode on the class.
    const err = new GuardedFetchError(
      GuardedFetchErrorCode.HOSTNAME_UNSAFE,
      opaqueErrors ? OPAQUE_ERROR_MESSAGE : message,
      { hostname },
    );
    cb(err as unknown as NodeJS.ErrnoException, '', 0);
  };

  return function guardedLookup(hostname, opts, callback) {
    const lookupOptions = typeof opts === 'number' ? { family: opts } : opts;
    dns.lookup(hostname, { ...lookupOptions, all: true }, (err, addresses) => {
      if (err) {
        callback(err, '');
        return;
      }

      const first = Array.isArray(addresses) ? addresses[0] : undefined;
      if (!first) {
        reject(
          hostname,
          `Refusing to connect to "${hostname}": DNS returned no addresses.`,
          HostnameUnsafeSubReason.DNS_RESOLUTION_FAILED,
          callback,
        );
        return;
      }

      for (const entry of addresses) {
        if (
          (entry.family !== 4 && entry.family !== 6) ||
          net.isIP(entry.address) !== entry.family
        ) {
          reject(
            hostname,
            `Refusing to connect to "${hostname}": DNS returned a malformed address.`,
            HostnameUnsafeSubReason.DNS_RESOLUTION_FAILED,
            callback,
          );
          return;
        }
        if (!isSafeIpAddress(entry.address)) {
          reject(
            hostname,
            `Refusing to connect to ${entry.address}: private, loopback, or link-local address.`,
            HostnameUnsafeSubReason.CONNECT_TIME_IP_REJECTED,
            callback,
          );
          return;
        }
      }

      if (lookupOptions?.all) {
        callback(null, addresses);
      } else {
        callback(null, first.address, first.family);
      }
    });
  };
}

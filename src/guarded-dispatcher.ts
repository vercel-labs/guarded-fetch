import net, { type LookupFunction } from 'node:net';

import { Agent, buildConnector, type Dispatcher } from 'undici';

import {
  OPAQUE_ERROR_MESSAGE,
  GuardedFetchError,
  GuardedFetchErrorCode,
} from './errors';
import {
  createGuardedLookup,
  type GuardedLookupOptions,
} from './guarded-lookup';
import { isSafeIpAddress } from './ip-address';
import { HostnameUnsafeSubReason, recordUrlBlocked } from './url-blocked';

let sharedDispatcher: Agent | undefined;

/**
 * Builds the undici connector used by both dispatchers.
 *
 * Two checks, because `connect.lookup` alone is not enough: Node skips DNS
 * resolution entirely when the host is already an IP literal, so a `lookup`
 * function never runs for `http://127.0.0.1/`. The pre-connect check below
 * covers that case; {@link createGuardedLookup} covers hosts that do resolve.
 */
function createGuardedConnector(
  options: GuardedLookupOptions = {},
): buildConnector.connector {
  const { opaqueErrors = false } = options;

  const connect = buildConnector({
    lookup: createGuardedLookup(options) as unknown as LookupFunction,
  });

  return function guardedConnect(connectOptions, callback) {
    const host = (connectOptions.hostname ?? '')
      .replace(/^\[/, '')
      .replace(/\]$/, '');

    // IP literals never reach `lookup` — validate before the socket opens.
    if (net.isIP(host) && !isSafeIpAddress(host)) {
      recordUrlBlocked(
        GuardedFetchErrorCode.HOSTNAME_UNSAFE,
        host.toLowerCase(),
        HostnameUnsafeSubReason.IP_LITERAL_UNSAFE,
      );
      callback(
        new GuardedFetchError(
          GuardedFetchErrorCode.HOSTNAME_UNSAFE,
          opaqueErrors
            ? OPAQUE_ERROR_MESSAGE
            : `Refusing to connect to ${host}: private, loopback, or link-local address.`,
          { hostname: host },
        ),
        null,
      );
      return;
    }

    connect(connectOptions, callback);
  };
}

/**
 * Returns the process-wide shared safe dispatcher, constructing it lazily
 * on first use. Reuses the connection pool across calls for efficiency.
 *
 * Validates the connection target two ways: IP literals are rejected before
 * the socket opens, and resolved hostnames are re-validated inside the same
 * DNS call the socket connects with — see {@link createGuardedLookup}. The
 * latter closes the DNS-rebinding TOCTOU window.
 *
 * Prefer this over {@link createGuardedDispatcher} unless you need a
 * disposable agent (e.g. for `opaqueErrors: true`).
 */
export function getSharedGuardedDispatcher(): Dispatcher {
  if (!sharedDispatcher) {
    sharedDispatcher = new Agent({ connect: createGuardedConnector() });
  }
  return sharedDispatcher;
}

/**
 * Constructs a new undici {@link Agent} that validates and pins the
 * connection target: IP literals are rejected before the socket opens, and
 * resolved hostnames are re-validated inside the DNS call the socket
 * connects with. The caller **must** close the returned agent via
 * `agent.close()` when done to release socket resources — otherwise the
 * connection pool leaks for the lifetime of the process.
 *
 * Prefer {@link getSharedGuardedDispatcher} unless you specifically need a
 * per-request dispatcher (e.g. to carry `opaqueErrors: true` through the
 * rejection message).
 */
export function createGuardedDispatcher(
  options: GuardedLookupOptions = {},
): Agent {
  return new Agent({ connect: createGuardedConnector(options) });
}

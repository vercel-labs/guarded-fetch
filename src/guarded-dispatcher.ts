import type { LookupFunction } from 'node:net';

import { Agent, type Dispatcher } from 'undici';

import {
  createGuardedLookup,
  type GuardedLookupOptions,
} from './guarded-lookup';

let sharedDispatcher: Agent | undefined;

/**
 * Returns the process-wide shared safe dispatcher, constructing it lazily
 * on first use. Reuses the connection pool across calls for efficiency.
 *
 * This dispatcher closes the DNS-rebinding TOCTOU window by installing a
 * custom `lookup` function on socket connect — see {@link createGuardedLookup}.
 *
 * Prefer this over {@link createGuardedDispatcher} unless you need a
 * disposable agent (e.g. for `opaqueErrors: true`).
 */
export function getSharedGuardedDispatcher(): Dispatcher {
  if (!sharedDispatcher) {
    sharedDispatcher = new Agent({
      connect: {
        lookup: createGuardedLookup() as unknown as LookupFunction,
      },
    });
  }
  return sharedDispatcher;
}

/**
 * Constructs a new undici {@link Agent} whose `connect.lookup` validates
 * and pins the resolved IP address. The caller **must** close the returned
 * agent via `agent.close()` when done to release socket resources —
 * otherwise the connection pool leaks for the lifetime of the process.
 *
 * Prefer {@link getSharedGuardedDispatcher} unless you specifically need a
 * per-request dispatcher (e.g. to carry `opaqueErrors: true` through the
 * rejection message).
 */
export function createGuardedDispatcher(
  options: GuardedLookupOptions = {},
): Agent {
  return new Agent({
    connect: {
      lookup: createGuardedLookup(options) as unknown as LookupFunction,
    },
  });
}

import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { fetch as undiciFetch } from 'undici';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { GuardedFetchErrorCode } from './errors';
import {
  createGuardedDispatcher,
  getSharedGuardedDispatcher,
} from './guarded-dispatcher';

/**
 * A loopback server stands in for any internal service an SSRF target could
 * reach. Reaching it at all means the dispatcher failed to guard the connect.
 */
let server: http.Server;
let loopbackUrl: string;

beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.end('internal');
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  loopbackUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
});

/** Walks the `cause` chain undici wraps connect errors in. */
function causeChainIncludes(error: unknown, code: string): boolean {
  let current: unknown = error;
  for (let i = 0; i < 5 && current; i += 1) {
    if ((current as { code?: string }).code === code) {
      return true;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return false;
}

describe('guarded dispatchers reject IP literals at connect time', () => {
  // Node skips `dns.lookup` for IP literals, so `connect.lookup` never runs
  // for these hosts — the dispatcher has to check before the socket opens.
  it('blocks a loopback literal through the shared dispatcher', async () => {
    await expect(
      undiciFetch(loopbackUrl, { dispatcher: getSharedGuardedDispatcher() }),
    ).rejects.toSatisfy((error) =>
      causeChainIncludes(error, GuardedFetchErrorCode.HOSTNAME_UNSAFE),
    );
  });

  it('blocks a loopback literal through a created dispatcher', async () => {
    const dispatcher = createGuardedDispatcher();
    try {
      await expect(undiciFetch(loopbackUrl, { dispatcher })).rejects.toSatisfy(
        (error) =>
          causeChainIncludes(error, GuardedFetchErrorCode.HOSTNAME_UNSAFE),
      );
    } finally {
      await dispatcher.close();
    }
  });

  it.each([
    ['link-local metadata', 'http://169.254.169.254/latest/meta-data/'],
    ['private range', 'http://10.0.0.1/'],
    ['IPv6 loopback', 'http://[::1]/'],
  ])('blocks %s before opening a socket', async (_label, url) => {
    const dispatcher = createGuardedDispatcher();
    try {
      await expect(undiciFetch(url, { dispatcher })).rejects.toSatisfy(
        (error) =>
          causeChainIncludes(error, GuardedFetchErrorCode.HOSTNAME_UNSAFE),
      );
    } finally {
      await dispatcher.close();
    }
  });

  it('does not veto a public literal', async () => {
    // The guard rejects before any socket work, so a veto always resolves
    // faster than the timer below. Whether the connection itself succeeds is
    // the network's business and is deliberately not asserted — that keeps
    // this test offline and deterministic.
    const dispatcher = createGuardedDispatcher();
    const pending = Symbol('pending');
    try {
      const outcome = await Promise.race([
        undiciFetch('http://93.184.215.14/', { dispatcher }).catch(
          (error: unknown) => error,
        ),
        new Promise((resolve) => setTimeout(() => resolve(pending), 1_000)),
      ]);

      if (outcome !== pending) {
        expect(
          causeChainIncludes(outcome, GuardedFetchErrorCode.HOSTNAME_UNSAFE),
        ).toBe(false);
      }
    } finally {
      await dispatcher.destroy();
    }
  });
});

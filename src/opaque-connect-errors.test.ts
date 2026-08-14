import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  OPAQUE_ERROR_MESSAGE,
  GuardedFetchError,
  GuardedFetchErrorCode,
} from './errors';
import { guardedFetch } from './guarded-fetch';

/**
 * `skipSsrfCheckForAllowedHosts` short-circuits the preflight, which is the
 * only way to reach the connect-time guard from `guardedFetch` — otherwise
 * `assertUrlIsSafeToFetch` rejects these targets first and applies
 * `opaqueErrors` itself.
 */
let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.end('internal');
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
});

describe('opaqueErrors covers connect-time rejections', () => {
  it.each([
    ['IP literal', '127.0.0.1'],
    ['hostname resolving to loopback', 'localhost'],
  ])('does not leak the address for a %s', async (_label, host) => {
    const error = await guardedFetch(`http://${host}:${port}/`, {
      allowedHosts: [host],
      skipSsrfCheckForAllowedHosts: true,
      opaqueErrors: true,
      timeoutMs: 3_000,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(GuardedFetchError);
    const guarded = error as GuardedFetchError;
    expect(guarded.code).toBe(GuardedFetchErrorCode.HOSTNAME_UNSAFE);
    expect(guarded.message).toBe(OPAQUE_ERROR_MESSAGE);
    expect(guarded.message).not.toMatch(/127\.0\.0\.1|::1/);
  });

  it('keeps the descriptive message when opaqueErrors is off', async () => {
    const error = await guardedFetch(`http://127.0.0.1:${port}/`, {
      allowedHosts: ['127.0.0.1'],
      skipSsrfCheckForAllowedHosts: true,
      timeoutMs: 3_000,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(GuardedFetchError);
    const guarded = error as GuardedFetchError;
    expect(guarded.code).toBe(GuardedFetchErrorCode.HOSTNAME_UNSAFE);
    expect(guarded.message).toMatch(/127\.0\.0\.1/);
  });

  it('preserves the original rejection as the cause for internal logging', async () => {
    const error = (await guardedFetch(`http://127.0.0.1:${port}/`, {
      allowedHosts: ['127.0.0.1'],
      skipSsrfCheckForAllowedHosts: true,
      opaqueErrors: true,
      timeoutMs: 3_000,
    }).catch((caught: unknown) => caught)) as GuardedFetchError;

    expect(error.message).toBe(OPAQUE_ERROR_MESSAGE);
    expect((error.cause as Error | undefined)?.message).toMatch(/127\.0\.0\.1/);
  });
});

import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

vi.mock('node:dns/promises', () => ({ lookup: vi.fn() }));

import { lookup } from 'node:dns/promises';

import { GuardedFetchError, GuardedFetchErrorCode } from './errors';
import { guardedFetch } from './guarded-fetch';

const mockLookup = lookup as unknown as Mock;

/** A resolver that accepts the query and simply never answers. */
function neverResolves(): Promise<never> {
  return new Promise<never>(() => {
    // Intentionally never settles.
  });
}

beforeEach(() => {
  mockLookup.mockReset();
});

describe('timeoutMs covers hostname validation', () => {
  it('times out while the preflight DNS lookup is still pending', async () => {
    // Whoever supplied the URL may also control its DNS, so the resolver is
    // allowed to simply never answer.
    mockLookup.mockImplementation(neverResolves);

    const startedAt = Date.now();
    const error = await guardedFetch('https://slow-dns.example/', {
      timeoutMs: 100,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(GuardedFetchError);
    expect((error as GuardedFetchError).code).toBe(
      GuardedFetchErrorCode.TIMEOUT,
    );
    // Without the deadline covering the preflight this never settles at all.
    expect(Date.now() - startedAt).toBeLessThan(3_000);
  });

  it('reports the supplied URL when it times out before validation', async () => {
    mockLookup.mockImplementation(neverResolves);

    const error = (await guardedFetch('https://slow-dns.example/path', {
      timeoutMs: 50,
    }).catch((caught: unknown) => caught)) as GuardedFetchError;

    expect(error.message).toMatch(/slow-dns\.example/);
    expect(error.url).toMatch(/slow-dns\.example/);
  });

  it('honours an already-aborted signal before running the preflight', async () => {
    const reason = new Error('caller aborted');
    const error = await guardedFetch('http://127.0.0.1/', {
      signal: AbortSignal.abort(reason),
    }).catch((caught: unknown) => caught);

    // Previously the preflight ran first and this surfaced as hostname_unsafe.
    expect(error).toBe(reason);
    expect(mockLookup).not.toHaveBeenCalled();
  });
});

import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

import { lookup } from 'node:dns/promises';

import { GuardedFetchErrorCode } from './errors';
import { guardedFetchJson, guardedFetchText } from './guarded-fetch-helpers';

const mockLookup = lookup as unknown as Mock;

type MockFetch = ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

function fetchWithTricklingBody(
  chunks: string[],
  chunkDelayMs: number,
): MockFetch {
  return vi.fn(async () => {
    let index = 0;
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (index >= chunks.length) {
          controller.close();
          return;
        }
        await new Promise((resolve) => {
          setTimeout(resolve, chunkDelayMs);
        });
        controller.enqueue(new TextEncoder().encode(chunks[index]));
        index += 1;
      },
    });
    return new Response(stream, { status: 200 });
  }) as unknown as MockFetch;
}

beforeEach(() => {
  vi.clearAllMocks();
  mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
});

describe(guardedFetchJson, () => {
  it('parses a JSON body from a safe URL', async () => {
    const fetch = vi.fn(
      async () => new Response(JSON.stringify({ greeting: 'hi' })),
    ) as unknown as MockFetch;
    await expect(
      guardedFetchJson<{ greeting: string }>('https://example.com', { fetch }),
    ).resolves.toEqual({ greeting: 'hi' });
  });

  it('throws on non-2xx when throwOnHttpError=true', async () => {
    const fetch = vi.fn(
      async () => new Response('server error', { status: 500 }),
    ) as unknown as MockFetch;
    await expect(
      guardedFetchJson('https://example.com', {
        fetch,
        throwOnHttpError: true,
      }),
    ).rejects.toMatchObject({
      code: GuardedFetchErrorCode.NETWORK_ERROR,
      status: 500,
    });
  });

  it('returns body on non-2xx by default', async () => {
    const fetch = vi.fn(
      async () =>
        new Response(JSON.stringify({ error: 'nope' }), { status: 400 }),
    ) as unknown as MockFetch;
    await expect(
      guardedFetchJson('https://example.com', { fetch }),
    ).resolves.toEqual({ error: 'nope' });
  });

  it('enforces maxResponseBytes', async () => {
    const big = JSON.stringify({ pad: 'x'.repeat(4096) });
    const fetch = vi.fn(async () => new Response(big)) as unknown as MockFetch;
    await expect(
      guardedFetchJson('https://example.com', {
        fetch,
        maxResponseBytes: 200,
      }),
    ).rejects.toMatchObject({
      code: GuardedFetchErrorCode.RESPONSE_TOO_LARGE,
    });
  });

  it('throws TIMEOUT when headers arrive quickly but the body trickles', async () => {
    // Fake timers: advanceTimersByTimeAsync fires timeoutMs without wall-clock sleep; long chunk delays stay pending until advanced that far.
    vi.useFakeTimers();
    const fetch = fetchWithTricklingBody(
      [JSON.stringify({ greeting: 'hi' })],
      60_000,
    );
    const fetchPromise = guardedFetchJson('https://example.com', {
      fetch,
      timeoutMs: 25,
    });
    const assertion = expect(fetchPromise).rejects.toMatchObject({
      code: GuardedFetchErrorCode.TIMEOUT,
    });
    await flushMicrotasks();
    await vi.advanceTimersByTimeAsync(25);
    await assertion;
    vi.useRealTimers();
  });
});

describe(guardedFetchText, () => {
  it('returns the body as text', async () => {
    const fetch = vi.fn(
      async () => new Response('plain body'),
    ) as unknown as MockFetch;
    await expect(
      guardedFetchText('https://example.com', { fetch }),
    ).resolves.toBe('plain body');
  });

  it('throws TIMEOUT when headers arrive quickly but the body trickles', async () => {
    vi.useFakeTimers();
    const fetch = fetchWithTricklingBody(['plain', ' body'], 60_000);
    const fetchPromise = guardedFetchText('https://example.com', {
      fetch,
      timeoutMs: 25,
    });
    const assertion = expect(fetchPromise).rejects.toMatchObject({
      code: GuardedFetchErrorCode.TIMEOUT,
    });
    await flushMicrotasks();
    await vi.advanceTimersByTimeAsync(25);
    await assertion;
    vi.useRealTimers();
  });
});

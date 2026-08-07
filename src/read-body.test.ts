import { afterEach, describe, expect, it, vi } from 'vitest';

import { SafeFetchErrorCode } from './errors';
import { readBodyAsBytes, readBodyAsJson, readBodyAsText } from './read-body';

function responseFromString(text: string, init?: ResponseInit): Response {
  return new Response(text, init);
}

function responseWithDelayedChunks(
  chunks: string[],
  delayMs: number,
  init?: ResponseInit,
): Response {
  let index = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (index >= chunks.length) {
        controller.close();
        return;
      }
      await new Promise((resolve) => {
        setTimeout(resolve, delayMs);
      });
      controller.enqueue(new TextEncoder().encode(chunks[index]));
      index += 1;
    },
  });
  return new Response(stream, init);
}

describe('body read deadlines', () => {
  // Fake timers: advanceTimersByTimeAsync fires deadlineAt without wall-clock sleep; long chunk delays stay pending until advanced that far.
  afterEach(() => {
    vi.useRealTimers();
  });

  it('throws TIMEOUT when body streaming exceeds deadlineAt', async () => {
    vi.useFakeTimers();
    const res = responseWithDelayedChunks(['hello', ' world'], 60_000);
    const readPromise = readBodyAsText(res, {
      deadlineAt: Date.now() + 25,
    });
    const assertion = expect(readPromise).rejects.toMatchObject({
      code: SafeFetchErrorCode.TIMEOUT,
    });
    await vi.advanceTimersByTimeAsync(25);
    await assertion;
  });

  it('reads a trickling body when it finishes before deadlineAt', async () => {
    vi.useFakeTimers();
    const res = responseWithDelayedChunks(['hello', ' world'], 5);
    const readPromise = readBodyAsText(res, {
      deadlineAt: Date.now() + 50,
    });
    await vi.advanceTimersByTimeAsync(15);
    await expect(readPromise).resolves.toBe('hello world');
  });

  it('throws TIMEOUT for bytes and JSON readers', async () => {
    vi.useFakeTimers();
    const bytesResponse = responseWithDelayedChunks(['aa', 'bb'], 60_000);
    const bytesPromise = readBodyAsBytes(bytesResponse, {
      deadlineAt: Date.now() + 25,
    });
    const bytesAssertion = expect(bytesPromise).rejects.toMatchObject({
      code: SafeFetchErrorCode.TIMEOUT,
    });

    const jsonResponse = responseWithDelayedChunks(
      [JSON.stringify({ ok: true })],
      60_000,
    );
    const jsonPromise = readBodyAsJson(jsonResponse, {
      deadlineAt: Date.now() + 25,
    });
    const jsonAssertion = expect(jsonPromise).rejects.toMatchObject({
      code: SafeFetchErrorCode.TIMEOUT,
    });

    await vi.advanceTimersByTimeAsync(25);
    await bytesAssertion;
    await jsonAssertion;
  });
});

describe(readBodyAsText, () => {
  it('reads full body when under the size limit', async () => {
    const res = responseFromString('hello world');
    await expect(readBodyAsText(res, { maxResponseBytes: 1024 })).resolves.toBe(
      'hello world',
    );
  });

  it('throws RESPONSE_TOO_LARGE when body exceeds the limit', async () => {
    const big = 'x'.repeat(2048);
    const res = responseFromString(big);
    await expect(
      readBodyAsText(res, { maxResponseBytes: 100 }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.RESPONSE_TOO_LARGE,
    });
  });

  it('returns empty string when body is absent', async () => {
    const res = new Response(null);
    await expect(readBodyAsText(res)).resolves.toBe('');
  });
});

describe(readBodyAsBytes, () => {
  it('reads full body as a Buffer when under the size limit', async () => {
    const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]);
    const res = new Response(new Uint8Array(bytes));
    const result = await readBodyAsBytes(res, { maxResponseBytes: 1024 });
    expect(result.equals(bytes as unknown as Uint8Array)).toBe(true);
  });

  it('throws RESPONSE_TOO_LARGE when body exceeds the limit', async () => {
    const res = new Response(new Uint8Array(2048));
    await expect(
      readBodyAsBytes(res, { maxResponseBytes: 100 }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.RESPONSE_TOO_LARGE,
    });
  });

  it('returns an empty Buffer when body is absent', async () => {
    const res = new Response(null);
    await expect(readBodyAsBytes(res)).resolves.toEqual(Buffer.alloc(0));
  });
});

describe(readBodyAsJson, () => {
  it('parses JSON body', async () => {
    const res = responseFromString(JSON.stringify({ ok: true, n: 1 }));
    await expect(
      readBodyAsJson<{ ok: boolean; n: number }>(res),
    ).resolves.toEqual({
      ok: true,
      n: 1,
    });
  });

  it('throws NETWORK_ERROR on invalid JSON', async () => {
    const res = responseFromString('{not json');
    await expect(readBodyAsJson(res)).rejects.toMatchObject({
      code: SafeFetchErrorCode.NETWORK_ERROR,
    });
  });

  it('propagates RESPONSE_TOO_LARGE from the underlying reader', async () => {
    const big = JSON.stringify({ pad: 'x'.repeat(4096) });
    const res = responseFromString(big);
    await expect(
      readBodyAsJson(res, { maxResponseBytes: 100 }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.RESPONSE_TOO_LARGE,
    });
  });
});

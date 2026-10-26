import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { describe, expect, it, vi } from 'vitest';

import { guardedFetch } from './guarded-fetch';

describe('cancellation after response headers', () => {
  it('aborts an in-progress response body and closes the connection', async () => {
    let disconnected!: () => void;
    const closed = new Promise<void>((resolve) => {
      disconnected = resolve;
    });
    const server = http.createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/event-stream' });
      response.write('data: first\n\n');
      response.on('close', disconnected);
    });
    await new Promise<void>((resolve) =>
      server.listen(0, '127.0.0.1', resolve),
    );
    const controller = new AbortController();
    try {
      const response = await guardedFetch(
        `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        {
          allowedHosts: ['127.0.0.1'],
          skipSsrfCheckForAllowedHosts: true,
          dispatcher: null,
          signal: controller.signal,
        },
      );
      if (!response.body) {
        throw new Error('Missing streaming body');
      }
      const reader = response.body.getReader();
      expect((await reader.read()).done).toBe(false);
      const pending = reader.read();
      controller.abort();
      await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
      reader.releaseLock();
      await closed;
    } finally {
      controller.abort();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('rejects with the caller reason when the signal is already aborted', async () => {
    const fetch = vi.fn();
    const reason = new Error('caller gave up');
    await expect(
      guardedFetch('https://1.1.1.1/', {
        fetch,
        signal: AbortSignal.abort(reason),
      }),
    ).rejects.toBe(reason);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('aborts a redirect hop in flight as network_error', async () => {
    const controller = new AbortController();
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, { status: 302, headers: { location: '/next' } }),
      )
      .mockImplementationOnce(
        (_url: string, init: RequestInit) =>
          new Promise((_resolve, reject) => {
            init.signal?.addEventListener('abort', () =>
              reject(new DOMException('aborted', 'AbortError')),
            );
            controller.abort();
          }),
      );
    await expect(
      guardedFetch('https://1.1.1.1/', { fetch, signal: controller.signal }),
    ).rejects.toMatchObject({ code: 'network_error' });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

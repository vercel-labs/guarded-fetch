import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { describe, expect, it } from 'vitest';

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
      if (!response.body) throw new Error('Missing streaming body');
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
});

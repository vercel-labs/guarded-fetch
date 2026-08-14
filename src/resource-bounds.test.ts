import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterEach, describe, expect, it } from 'vitest';

import { guardedFetchText } from './guarded-fetch-helpers';

const BODY_BYTES = 16 * 1024 * 1024;
const CHUNK = Buffer.alloc(256 * 1024, 0x41);

/**
 * Streams `BODY_BYTES` and reports how much actually made it out, plus whether
 * the connection was closed. A client that stops reading leaves the byte count
 * well short of the total; one that cancels closes the socket outright.
 */
function createStreamingServer(respond: (res: http.ServerResponse) => void): {
  server: http.Server;
  sent: () => number;
  socketClosed: () => boolean;
} {
  let sent = 0;
  let socketClosed = false;

  const server = http.createServer((_req, res) => {
    res.socket?.on('close', () => {
      socketClosed = true;
    });
    res.on('error', () => {
      // Client hung up mid-write; expected on the cancel paths under test.
    });
    respond(res);

    let written = 0;
    const pump = () => {
      while (written < BODY_BYTES) {
        written += CHUNK.length;
        sent = written;
        if (!res.write(CHUNK)) {
          res.once('drain', pump);
          return;
        }
      }
      res.end();
    };
    pump();
  });

  return { server, sent: () => sent, socketClosed: () => socketClosed };
}

async function listen(server: http.Server): Promise<number> {
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  return (server.address() as AddressInfo).port;
}

let active: http.Server | undefined;

afterEach(async () => {
  if (active) {
    await new Promise<void>((resolve) => {
      active?.close(() => {
        resolve();
      });
    });
    active = undefined;
  }
});

describe('discarded bodies are bounded', () => {
  it('cancels the body when throwOnHttpError rejects a response', async () => {
    const { server, socketClosed } = createStreamingServer((res) => {
      res.writeHead(500, { 'content-length': String(BODY_BYTES) });
    });
    active = server;
    const port = await listen(server);

    await expect(
      guardedFetchText(`http://127.0.0.1:${port}/`, {
        allowedHosts: ['127.0.0.1'],
        skipSsrfCheckForAllowedHosts: true,
        dispatcher: null,
        throwOnHttpError: true,
        timeoutMs: 30_000,
      }),
    ).rejects.toThrow();

    // An unread body leaves the socket parked in the pool instead.
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(socketClosed()).toBe(true);
  });
});

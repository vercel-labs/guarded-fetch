import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';

import { Headers, Request } from 'undici';
import { describe, expect, it } from 'vitest';

import {
  OPAQUE_ERROR_MESSAGE,
  guardedFetch,
  guardedFetchJson,
  guardedFetchText,
  GuardedFetchErrorCode,
  type GuardedFetchBodyOptions,
  type GuardedFetchOptions,
} from './index';

interface RecordedRequest {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
  body: string;
}

interface TestServer {
  baseUrl: string;
  requests: RecordedRequest[];
  close: () => Promise<void>;
}

type TestServerHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  body: string,
) => unknown | Promise<unknown>;

const localGuardedFetchOptions = {
  allowedHosts: ['127.0.0.1'],
  skipSsrfCheckForAllowedHosts: true,
  dispatcher: null,
} satisfies GuardedFetchOptions;

function options(overrides: GuardedFetchOptions = {}): GuardedFetchOptions {
  return { ...localGuardedFetchOptions, ...overrides };
}

function bodyOptions(
  overrides: GuardedFetchBodyOptions = {},
): GuardedFetchBodyOptions {
  return { ...localGuardedFetchOptions, ...overrides };
}

async function startTestServer(
  handler: TestServerHandler,
): Promise<TestServer> {
  const requests: RecordedRequest[] = [];
  const server = createServer(async (req, res) => {
    const body = await readRequestBody(req);
    requests.push({
      method: req.method ?? '',
      url: req.url ?? '',
      headers: req.headers,
      body,
    });

    try {
      await handler(req, res, body);
    } catch (error) {
      res.statusCode = 500;
      res.end(error instanceof Error ? error.message : String(error));
    }
  });

  await listen(server);
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    close: () => close(server),
  };
}

function readRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    req.on('data', (chunk: Uint8Array) => chunks.push(chunk));
    req.on('error', reject);
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

function listen(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

describe('guardedFetch HTTP integration behavior', () => {
  it('performs a real GET request with the expected path, query, and headers', async () => {
    const server = await startTestServer((_req, res) => {
      res.setHeader('content-type', 'text/plain');
      res.end('ok');
    });

    try {
      const response = await guardedFetch(
        `${server.baseUrl}/hello?one=1&two=space%20value`,
        options({ headers: { 'X-Custom': 'kept' } }),
      );

      await expect(response.text()).resolves.toBe('ok');
      expect(response.status).toBe(200);
      expect(server.requests).toEqual([
        expect.objectContaining({
          method: 'GET',
          url: '/hello?one=1&two=space%20value',
          body: '',
        }),
      ]);
      expect(server.requests[0]?.headers['x-custom']).toBe('kept');
      expect(server.requests[0]?.headers.host).toBe(
        new URL(server.baseUrl).host,
      );
    } finally {
      await server.close();
    }
  });

  it('sends a POST body without changing its formatting', async () => {
    const server = await startTestServer((_req, res) => {
      res.statusCode = 201;
      res.end('created');
    });
    const body = JSON.stringify({ z: 1, nested: { keep: 'format' } }, null, 2);

    try {
      const response = await guardedFetch(
        new URL('/submit', server.baseUrl),
        options({
          method: 'POST',
          headers: { 'Content-Type': 'application/json; charset=utf-8' },
          body,
        }),
      );

      await expect(response.text()).resolves.toBe('created');
      expect(response.status).toBe(201);
      expect(server.requests[0]).toEqual(
        expect.objectContaining({ method: 'POST', url: '/submit', body }),
      );
      expect(server.requests[0]?.headers['content-type']).toBe(
        'application/json; charset=utf-8',
      );
      expect(server.requests[0]?.headers['content-length']).toBe(
        String(Buffer.byteLength(body)),
      );
    } finally {
      await server.close();
    }
  });

  it('strips blocked request headers before making a real request', async () => {
    const server = await startTestServer((_req, res) => res.end('ok'));

    try {
      await guardedFetch(
        `${server.baseUrl}/headers`,
        options({
          headers: {
            Cookie: 'session=secret',
            Forwarded: 'for=1.2.3.4',
            'Metadata-Flavor': 'Google',
            'X-Aws-Ec2-Metadata-Token': 'token',
            'X-Custom': 'safe',
            'X-Forwarded-For': '1.2.3.4',
            'X-Real-Ip': '1.2.3.4',
          },
        }),
      );

      const headers = server.requests[0]?.headers;
      expect(headers?.cookie).toBeUndefined();
      expect(headers?.forwarded).toBeUndefined();
      expect(headers?.['metadata-flavor']).toBeUndefined();
      expect(headers?.['x-aws-ec2-metadata-token']).toBeUndefined();
      expect(headers?.['x-forwarded-for']).toBeUndefined();
      expect(headers?.['x-real-ip']).toBeUndefined();
      expect(headers?.['x-custom']).toBe('safe');
    } finally {
      await server.close();
    }
  });

  it('accepts array-style headers and preserves repeated safe header values', async () => {
    const server = await startTestServer((_req, res) => res.end('ok'));

    try {
      await guardedFetch(
        `${server.baseUrl}/array-headers`,
        options({
          headers: [
            ['X-Multi', 'one'],
            ['X-Multi', 'two'],
            ['Cookie', 'blocked'],
          ],
        }),
      );

      expect(server.requests[0]?.headers['x-multi']).toBe('one, two');
      expect(server.requests[0]?.headers.cookie).toBeUndefined();
    } finally {
      await server.close();
    }
  });

  it('accepts a Headers instance and sends its values when sanitization is disabled', async () => {
    const server = await startTestServer((_req, res) => res.end('ok'));
    const headers = new Headers([
      ['X-Multi', 'one'],
      ['X-Multi', 'two'],
      ['Content-Type', 'text/plain'],
      ['Cookie', 'session=kept'],
    ]);

    try {
      await guardedFetch(
        `${server.baseUrl}/headers-instance`,
        options({ sanitizeHeaders: false, headers }),
      );

      expect(server.requests[0]?.headers['x-multi']).toBe('one, two');
      expect(server.requests[0]?.headers['content-type']).toBe('text/plain');
      expect(server.requests[0]?.headers.cookie).toBe('session=kept');
    } finally {
      await server.close();
    }
  });

  it('accepts headers from a Request instance and sends them when sanitization is disabled', async () => {
    const server = await startTestServer((_req, res) => res.end('ok'));
    const request = new Request(`${server.baseUrl}/request-headers`, {
      headers: {
        'Content-Type': 'application/json',
        Cookie: 'session=kept',
        'X-Custom': 'from-request',
      },
    });

    try {
      await guardedFetch(
        request.url,
        options({ sanitizeHeaders: false, headers: request.headers }),
      );

      expect(server.requests[0]).toEqual(
        expect.objectContaining({ method: 'GET', url: '/request-headers' }),
      );
      expect(server.requests[0]?.headers['content-type']).toBe(
        'application/json',
      );
      expect(server.requests[0]?.headers.cookie).toBe('session=kept');
      expect(server.requests[0]?.headers['x-custom']).toBe('from-request');
    } finally {
      await server.close();
    }
  });

  it('can opt out of request header sanitization', async () => {
    const server = await startTestServer((_req, res) => res.end('ok'));

    try {
      await guardedFetch(
        `${server.baseUrl}/headers`,
        options({
          sanitizeHeaders: false,
          headers: {
            Cookie: 'session=secret',
            'X-Forwarded-For': '1.2.3.4',
          },
        }),
      );

      expect(server.requests[0]?.headers.cookie).toBe('session=secret');
      expect(server.requests[0]?.headers['x-forwarded-for']).toBe('1.2.3.4');
    } finally {
      await server.close();
    }
  });

  it('returns redirect responses without following them when disabled', async () => {
    const server = await startTestServer((req, res) => {
      if (req.url === '/start') {
        res.statusCode = 302;
        res.setHeader('location', '/final');
        res.end('redirecting');
        return;
      }
      res.end('final');
    });

    try {
      const response = await guardedFetch(
        `${server.baseUrl}/start`,
        options({ followRedirects: false }),
      );

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe('/final');
      await expect(response.text()).resolves.toBe('redirecting');
      expect(server.requests.map((req) => req.url)).toEqual(['/start']);
    } finally {
      await server.close();
    }
  });

  it('throws when a redirect response is missing Location', async () => {
    const server = await startTestServer((_req, res) => {
      res.statusCode = 302;
      res.end('missing location');
    });

    try {
      await expect(
        guardedFetch(`${server.baseUrl}/missing-location`, options()),
      ).rejects.toMatchObject({ code: GuardedFetchErrorCode.REDIRECT_INVALID });
      expect(server.requests).toHaveLength(1);
    } finally {
      await server.close();
    }
  });

  it('throws when a redirect Location is not a valid URL', async () => {
    const server = await startTestServer((_req, res) => {
      res.statusCode = 302;
      res.setHeader('location', 'http://%');
      res.end('bad location');
    });

    try {
      await expect(
        guardedFetch(`${server.baseUrl}/bad-location`, options()),
      ).rejects.toMatchObject({ code: GuardedFetchErrorCode.REDIRECT_INVALID });
      expect(server.requests).toHaveLength(1);
    } finally {
      await server.close();
    }
  });

  it('follows relative redirects and returns the final response', async () => {
    const server = await startTestServer((req, res) => {
      if (req.url === '/dir/start') {
        res.statusCode = 302;
        res.setHeader('location', '../final?ok=1');
        res.end('redirecting');
        return;
      }
      res.end('final body');
    });

    try {
      const response = await guardedFetch(
        `${server.baseUrl}/dir/start`,
        options(),
      );

      await expect(response.text()).resolves.toBe('final body');
      expect(server.requests.map((req) => req.url)).toEqual([
        '/dir/start',
        '/final?ok=1',
      ]);
    } finally {
      await server.close();
    }
  });

  it('enforces maxRedirects against a real redirect loop', async () => {
    const server = await startTestServer((_req, res) => {
      res.statusCode = 302;
      res.setHeader('location', '/loop');
      res.end('loop');
    });

    try {
      await expect(
        guardedFetch(`${server.baseUrl}/loop`, options({ maxRedirects: 2 })),
      ).rejects.toMatchObject({
        code: GuardedFetchErrorCode.TOO_MANY_REDIRECTS,
      });
      expect(server.requests.map((req) => req.url)).toEqual([
        '/loop',
        '/loop',
        '/loop',
      ]);
    } finally {
      await server.close();
    }
  });

  it('changes POST to GET and drops content headers on a 302 redirect', async () => {
    const server = await startTestServer((req, res) => {
      if (req.url === '/result') {
        res.end('done');
        return;
      }
      res.statusCode = 302;
      res.setHeader('location', '/result');
      res.end('found');
    });

    try {
      await guardedFetch(
        `${server.baseUrl}/submit`,
        options({
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: 'drop on redirect',
        }),
      );

      expect(server.requests[0]).toEqual(
        expect.objectContaining({ method: 'POST', body: 'drop on redirect' }),
      );
      expect(server.requests[1]).toEqual(
        expect.objectContaining({ method: 'GET', url: '/result', body: '' }),
      );
      expect(server.requests[1]?.headers['content-type']).toBeUndefined();
    } finally {
      await server.close();
    }
  });

  it('changes POST to GET and drops content headers on a 303 redirect', async () => {
    const server = await startTestServer((req, res) => {
      if (req.url === '/submit') {
        res.statusCode = 303;
        res.setHeader('location', '/result');
        res.end('see other');
        return;
      }
      res.end('done');
    });

    try {
      await guardedFetch(
        `${server.baseUrl}/submit`,
        options({
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Keep': 'yes' },
          body: '{"ok":true}',
        }),
      );

      expect(server.requests[0]).toEqual(
        expect.objectContaining({ method: 'POST', body: '{"ok":true}' }),
      );
      expect(server.requests[1]).toEqual(
        expect.objectContaining({ method: 'GET', url: '/result', body: '' }),
      );
      expect(server.requests[1]?.headers['content-type']).toBeUndefined();
      expect(server.requests[1]?.headers['content-length']).toBeUndefined();
      expect(server.requests[1]?.headers['x-keep']).toBe('yes');
    } finally {
      await server.close();
    }
  });

  it('preserves method, body, and content headers on a 307 redirect', async () => {
    const server = await startTestServer((req, res) => {
      if (req.url === '/retry') {
        res.end('retried');
        return;
      }
      res.statusCode = 307;
      res.setHeader('location', '/retry');
      res.end('temporary redirect');
    });

    try {
      await guardedFetch(
        `${server.baseUrl}/submit`,
        options({
          method: 'PUT',
          headers: { 'Content-Type': 'text/plain' },
          body: 'retry-body',
        }),
      );

      expect(server.requests.map((req) => req.method)).toEqual(['PUT', 'PUT']);
      expect(server.requests[1]).toEqual(
        expect.objectContaining({ url: '/retry', body: 'retry-body' }),
      );
      expect(server.requests[1]?.headers['content-type']).toBe('text/plain');
    } finally {
      await server.close();
    }
  });

  it('keeps HEAD as HEAD and bodyless across a 302 redirect', async () => {
    const server = await startTestServer((req, res) => {
      if (req.url === '/head-result') {
        res.statusCode = 204;
        res.end();
        return;
      }
      res.statusCode = 302;
      res.setHeader('location', '/head-result');
      res.end();
    });

    try {
      const response = await guardedFetch(
        `${server.baseUrl}/head-start`,
        options({ method: 'HEAD' }),
      );

      expect(response.status).toBe(204);
      expect(server.requests).toEqual([
        expect.objectContaining({
          method: 'HEAD',
          url: '/head-start',
          body: '',
        }),
        expect.objectContaining({
          method: 'HEAD',
          url: '/head-result',
          body: '',
        }),
      ]);
    } finally {
      await server.close();
    }
  });

  it('keeps Authorization on same-origin redirects', async () => {
    const server = await startTestServer((req, res) => {
      if (req.url === '/next') {
        res.end('next');
        return;
      }
      res.statusCode = 308;
      res.setHeader('location', '/next');
      res.end('redirecting');
    });

    try {
      await guardedFetch(
        `${server.baseUrl}/start`,
        options({ headers: { Authorization: 'Bearer same-origin' } }),
      );

      expect(server.requests[0]?.headers.authorization).toBe(
        'Bearer same-origin',
      );
      expect(server.requests[1]?.headers.authorization).toBe(
        'Bearer same-origin',
      );
    } finally {
      await server.close();
    }
  });

  it('drops Authorization on cross-origin redirects', async () => {
    const target = await startTestServer((_req, res) => res.end('target'));
    const source = await startTestServer((_req, res) => {
      res.statusCode = 302;
      res.setHeader('location', `${target.baseUrl}/target`);
      res.end('redirecting');
    });

    try {
      await guardedFetch(
        `${source.baseUrl}/start`,
        options({ headers: { Authorization: 'Bearer secret' } }),
      );

      expect(source.requests[0]?.headers.authorization).toBe('Bearer secret');
      expect(target.requests[0]?.headers.authorization).toBeUndefined();
    } finally {
      await source.close();
      await target.close();
    }
  });

  it('rejects redirects outside the configured host allowlist before calling them', async () => {
    const source = await startTestServer((_req, res) => {
      res.statusCode = 302;
      res.setHeader('location', 'http://example.com/blocked');
      res.end('redirecting');
    });

    try {
      await expect(
        guardedFetch(`${source.baseUrl}/start`, options()),
      ).rejects.toMatchObject({
        code: GuardedFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
      });
      expect(source.requests).toHaveLength(1);
    } finally {
      await source.close();
    }
  });

  it('rejects disallowed original hosts before making a request', async () => {
    const server = await startTestServer((_req, res) =>
      res.end('should not run'),
    );

    try {
      await expect(
        guardedFetch(
          `${server.baseUrl}/blocked`,
          options({ allowedHosts: ['example.com'] }),
        ),
      ).rejects.toMatchObject({ code: GuardedFetchErrorCode.HOST_NOT_ALLOWED });
      expect(server.requests).toHaveLength(0);
    } finally {
      await server.close();
    }
  });

  it('rejects http when httpsOnly is true', async () => {
    const server = await startTestServer((_req, res) =>
      res.end('should not run'),
    );

    try {
      await expect(
        guardedFetch(`${server.baseUrl}/https-only`, {
          httpsOnly: true,
          allowedHosts: ['127.0.0.1'],
          skipSsrfCheckForAllowedHosts: true,
          dispatcher: null,
        }),
      ).rejects.toMatchObject({
        code: GuardedFetchErrorCode.PROTOCOL_NOT_ALLOWED,
      });
      expect(server.requests).toHaveLength(0);
    } finally {
      await server.close();
    }
  });

  it('parses JSON responses from real HTTP responses', async () => {
    const server = await startTestServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end('{"ok":true,"count":2}');
    });

    try {
      await expect(
        guardedFetchJson<{ ok: boolean; count: number }>(
          `${server.baseUrl}/json`,
          bodyOptions(),
        ),
      ).resolves.toEqual({ ok: true, count: 2 });
    } finally {
      await server.close();
    }
  });

  it('returns an empty string for a real empty response body', async () => {
    const server = await startTestServer((_req, res) => {
      res.statusCode = 204;
      res.end();
    });

    try {
      await expect(
        guardedFetchText(`${server.baseUrl}/empty`, bodyOptions()),
      ).resolves.toBe('');
    } finally {
      await server.close();
    }
  });

  it('allows response bodies exactly at maxResponseBytes', async () => {
    const server = await startTestServer((_req, res) => res.end('abcdef'));

    try {
      await expect(
        guardedFetchText(
          `${server.baseUrl}/exact-limit`,
          bodyOptions({ maxResponseBytes: 6 }),
        ),
      ).resolves.toBe('abcdef');
    } finally {
      await server.close();
    }
  });

  it('returns text for non-2xx responses unless throwOnHttpError is enabled', async () => {
    const server = await startTestServer((_req, res) => {
      res.statusCode = 418;
      res.end('short and stout');
    });

    try {
      await expect(
        guardedFetchText(`${server.baseUrl}/teapot`, bodyOptions()),
      ).resolves.toBe('short and stout');

      await expect(
        guardedFetchText(
          `${server.baseUrl}/teapot`,
          bodyOptions({ throwOnHttpError: true }),
        ),
      ).rejects.toMatchObject({
        code: GuardedFetchErrorCode.NETWORK_ERROR,
        status: 418,
      });
    } finally {
      await server.close();
    }
  });

  it('enforces maxResponseBytes while reading a real response body', async () => {
    const server = await startTestServer((_req, res) => res.end('abcdef'));

    try {
      await expect(
        guardedFetchText(
          `${server.baseUrl}/too-large`,
          bodyOptions({ maxResponseBytes: 3 }),
        ),
      ).rejects.toMatchObject({
        code: GuardedFetchErrorCode.RESPONSE_TOO_LARGE,
      });
    } finally {
      await server.close();
    }
  });

  it('wraps invalid JSON parse failures as network errors', async () => {
    const server = await startTestServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end('{not-json');
    });

    try {
      await expect(
        guardedFetchJson(`${server.baseUrl}/bad-json`, bodyOptions()),
      ).rejects.toMatchObject({ code: GuardedFetchErrorCode.NETWORK_ERROR });
    } finally {
      await server.close();
    }
  });

  it('uses opaque messages for real HTTP helper failures when requested', async () => {
    const server = await startTestServer((_req, res) => {
      res.statusCode = 500;
      res.end('internal details');
    });

    try {
      await expect(
        guardedFetchText(
          `${server.baseUrl}/opaque`,
          bodyOptions({ opaqueErrors: true, throwOnHttpError: true }),
        ),
      ).rejects.toMatchObject({
        code: GuardedFetchErrorCode.NETWORK_ERROR,
        message: OPAQUE_ERROR_MESSAGE,
        status: 500,
      });
    } finally {
      await server.close();
    }
  });

  it('times out a real slow HTTP response', async () => {
    const server = await startTestServer((_req, res) => {
      setTimeout(() => {
        if (!res.destroyed) {
          res.end('too late');
        }
      }, 200);
    });

    try {
      await expect(
        guardedFetch(`${server.baseUrl}/slow`, options({ timeoutMs: 20 })),
      ).rejects.toMatchObject({ code: GuardedFetchErrorCode.TIMEOUT });
      expect(server.requests.map((req) => req.url)).toEqual(['/slow']);
    } finally {
      await server.close();
    }
  });
});

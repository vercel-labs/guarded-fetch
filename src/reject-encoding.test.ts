import dns from 'node:dns';
import net, { type AddressInfo } from 'node:net';
import zlib from 'node:zlib';

import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from 'vitest';

import {
  createGuardedFetch,
  guardedFetch,
  GuardedFetchError,
  GuardedFetchErrorCode,
  isSafeIpAddress,
} from './index';

// Lets one test reach the local server through the guarded agent. Every other
// test runs the real check.
vi.mock('./ip-address', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./ip-address')>();
  return { ...actual, isSafeIpAddress: vi.fn(actual.isSafeIpAddress) };
});

/**
 * Counts brotli decoder activity. zlib exports are read-only, so the hook is
 * on the shared `ZlibBase.prototype` and filters by class.
 */
const brotli = { instances: 0, bytes: 0 };
let proto = zlib.BrotliDecompress.prototype as unknown as Record<
  string,
  unknown
>;
while (!Object.hasOwn(proto, '_transform')) {
  proto = Object.getPrototypeOf(proto) as Record<string, unknown>;
}
const realTransform = proto._transform as (...args: unknown[]) => unknown;
const realWrite = proto.write as (...args: unknown[]) => unknown;
const seen = new WeakSet<object>();

beforeAll(() => {
  proto._transform = function (
    this: object,
    chunk: Buffer,
    ...rest: unknown[]
  ) {
    if (this instanceof zlib.BrotliDecompress) {
      brotli.bytes += chunk.length;
    }
    return realTransform.call(this, chunk, ...rest);
  };
  proto.write = function (this: object, ...args: unknown[]) {
    if (this instanceof zlib.BrotliDecompress && !seen.has(this)) {
      seen.add(this);
      brotli.instances += 1;
    }
    return realWrite.apply(this, args);
  };
});

afterAll(() => {
  proto._transform = realTransform;
  proto.write = realWrite;
});

const body = zlib.brotliCompressSync('x'.repeat(64));
const tail = `Content-Length: ${body.length}\r\nConnection: close\r\n\r\n`;

/** Headers and body in one write, so they arrive in one TCP segment. */
const responses: Record<string, Buffer> = {
  '/200': Buffer.concat([
    Buffer.from(`HTTP/1.1 200 OK\r\nContent-Encoding: BR\r\n${tail}`),
    body,
  ]),
  '/302': Buffer.concat([
    Buffer.from(
      `HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Encoding: br\r\n${tail}`,
    ),
    body,
  ]),
  '/dup': Buffer.concat([
    Buffer.from(
      `HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Encoding: br\r\n${tail}`,
    ),
    body,
  ]),
  '/chunked': Buffer.concat([
    Buffer.from(
      `HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${body.length.toString(16)}\r\n`,
    ),
    body,
    Buffer.from('\r\n0\r\n\r\n'),
  ]),
};

let baseUrl = '';
const server = net.createServer((socket) => {
  socket.once('data', (data) => {
    const path = data.toString().split(' ')[1] ?? '';
    socket.end(responses[path] ?? '');
  });
});

beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => {
  server.close();
});

const base = {
  allowedHosts: ['127.0.0.1'],
  skipSsrfCheckForAllowedHosts: true,
  dispatcher: null,
} as const;

describe('blockedEncodings keeps bytes out of the brotli decoder', () => {
  it('feeds the decoder when br is not blocked (hook sanity check)', async () => {
    const response = await guardedFetch(`${baseUrl}/200`, base);
    await response.arrayBuffer();
    expect(brotli.instances).toBe(1);
    expect(brotli.bytes).toBeGreaterThan(0);
  });

  it.each(Object.keys(responses))(
    'never constructs a decoder for %s',
    async (path) => {
      const before = { ...brotli };
      await expect(
        guardedFetch(`${baseUrl}${path}`, {
          ...base,
          blockedEncodings: ['br'],
        }),
      ).rejects.toMatchObject({
        code: GuardedFetchErrorCode.RESPONSE_ENCODING_NOT_ALLOWED,
      });
      expect(brotli).toEqual(before);
    },
  );
});

/** The documented shape: fetch's `TypeError`, with the guard's error on `.cause`. */
function expectEncodingRejected(error: unknown): void {
  expect(error).toBeInstanceOf(TypeError);
  expect((error as Error).cause).toBeInstanceOf(GuardedFetchError);
  expect((error as Error).cause).toMatchObject({
    code: GuardedFetchErrorCode.RESPONSE_ENCODING_NOT_ALLOWED,
  });
}

describe('createGuardedFetch blockedEncodings keeps bytes out of the brotli decoder', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.mocked(isSafeIpAddress).mockClear();
  });

  it('feeds the decoder when br is not blocked (hook sanity check)', async () => {
    const fetch = createGuardedFetch({ trustedOrigins: [baseUrl] });
    const before = brotli.instances;
    await (await fetch(`${baseUrl}/200`)).arrayBuffer();
    await fetch.close();
    expect(brotli.instances).toBe(before + 1);
  });

  it.each(['/200', '/dup', '/chunked'])(
    'never constructs a decoder for %s from a trusted origin',
    async (path) => {
      const fetch = createGuardedFetch({
        trustedOrigins: [baseUrl],
        blockedEncodings: ['br'],
      });
      const before = { ...brotli };
      const error = await fetch(`${baseUrl}${path}`).catch((e: unknown) => e);
      await fetch.close();
      expectEncodingRejected(error);
      expect(brotli).toEqual(before);
    },
  );

  it('never constructs a decoder through the guarded agent', async () => {
    vi.mocked(isSafeIpAddress).mockImplementation((ip) => ip === '127.0.0.1');
    vi.spyOn(dns, 'lookup').mockImplementation(((
      _host: string,
      _options: dns.LookupOptions,
      callback: (
        error: NodeJS.ErrnoException | null,
        addresses: dns.LookupAddress[],
      ) => void,
    ) => {
      queueMicrotask(() =>
        callback(null, [{ address: '127.0.0.1', family: 4 }]),
      );
    }) as typeof dns.lookup);
    const fetch = createGuardedFetch({ blockedEncodings: ['BR'] });
    const before = { ...brotli };
    const url = baseUrl.replace('127.0.0.1', 'files.example.com');
    const error = await fetch(`${url}/200`).catch((e: unknown) => e);
    await fetch.close();
    expect(isSafeIpAddress).toHaveBeenCalledWith('127.0.0.1');
    expectEncodingRejected(error);
    expect(brotli).toEqual(before);
  });
});

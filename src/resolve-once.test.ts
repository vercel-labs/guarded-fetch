import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { fetch as undiciFetch, type Agent } from 'undici';
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest';

vi.mock('./resolve-host', () => ({ resolveHost: vi.fn() }));

// The test server listens on loopback. Treat 127.0.0.1 as public here so the
// guarded connect path can reach it; everything else is classified as usual.
vi.mock('./ip-address', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./ip-address')>();
  return {
    ...actual,
    isSafeIpAddress: (ip: string) =>
      ip === '127.0.0.1' || actual.isSafeIpAddress(ip),
    isAddressUnsafeForServerSideFetch: (ip: string) =>
      ip !== '127.0.0.1' && actual.isAddressUnsafeForServerSideFetch(ip),
  };
});

import { createGuardedDispatcher } from './guarded-dispatcher';
import { guardedFetch } from './guarded-fetch';
import { getPinnedAddresses, withPinnedAddresses } from './pinned-addresses';
import { resolveHost } from './resolve-host';

const mockResolveHost = resolveHost as unknown as Mock;

let server: Server;
let port: number;
let dispatcher: Agent;

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { location: `http://other.test:${port}/final` });
      res.end();
      return;
    }
    res.end('ok');
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  ({ port } = server.address() as AddressInfo);
});

afterAll(async () => {
  await new Promise((resolve) => {
    server.close(resolve);
  });
});

beforeEach(() => {
  mockResolveHost.mockReset();
  mockResolveHost.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
  // A fresh pool per test, so every request opens a new connection.
  dispatcher = createGuardedDispatcher();
});

afterEach(async () => {
  await dispatcher.close();
});

function resolvedHosts(): string[] {
  return mockResolveHost.mock.calls.map(([hostname]) => hostname as string);
}

describe('guardedFetch resolves each hop once', () => {
  it('connects with the preflight answer instead of resolving again', async () => {
    const response = await guardedFetch(`http://pinned.test:${port}/`, {
      dispatcher,
    });
    expect(await response.text()).toBe('ok');
    expect(resolvedHosts()).toEqual(['pinned.test']);
  });

  it('resolves each redirect hop once', async () => {
    const response = await guardedFetch(`http://pinned.test:${port}/redirect`, {
      dispatcher,
    });
    expect(await response.text()).toBe('ok');
    expect(resolvedHosts()).toEqual(['pinned.test', 'other.test']);
  });

  it('still resolves at connect time when nothing is pinned', async () => {
    const response = await undiciFetch(`http://pinned.test:${port}/`, {
      dispatcher,
    });
    expect(await response.text()).toBe('ok');
    expect(resolvedHosts()).toEqual(['pinned.test']);
  });

  it('validates the pinned answer again at connect time', async () => {
    // Preflight sees a public answer; pin a private one directly to show the
    // connect-time checks still apply to whatever is pinned.
    await expect(
      withPinnedAddresses(
        'pinned.test',
        [{ address: '10.0.0.1', family: 4 }],
        () => undiciFetch(`http://pinned.test:${port}/`, { dispatcher }),
      ),
    ).rejects.toMatchObject({
      cause: { code: 'hostname_unsafe' },
    });
    expect(mockResolveHost).not.toHaveBeenCalled();
  });
});

describe(getPinnedAddresses, () => {
  const ipv4 = { address: '93.184.216.34', family: 4 };
  const ipv6 = { address: '2606:2800:220:1::1', family: 6 };
  const addresses = [ipv4, ipv6];

  it('returns nothing outside a pinned scope', () => {
    expect(getPinnedAddresses('example.com', 0)).toBeUndefined();
  });

  it('matches the hostname case-insensitively', () => {
    withPinnedAddresses('Example.COM', addresses, () => {
      expect(getPinnedAddresses('example.com', 0)).toEqual(addresses);
      expect(getPinnedAddresses('other.com', 0)).toBeUndefined();
    });
  });

  it('narrows to the requested family', () => {
    withPinnedAddresses('example.com', addresses, () => {
      expect(getPinnedAddresses('example.com', 6)).toEqual([ipv6]);
    });
    withPinnedAddresses('example.com', [ipv4], () => {
      expect(getPinnedAddresses('example.com', 6)).toBeUndefined();
    });
  });
});

import dns from 'node:dns';

import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';

import { clearResolveHostCache, resolveHost } from './resolve-host';
import {
  startDnsStubServer,
  type DnsStubServer,
} from './test-utils/dns-stub-server';

let stub: DnsStubServer;
let originalServers: string[];

beforeAll(async () => {
  originalServers = dns.getServers();
  stub = await startDnsStubServer();
  dns.setServers([stub.address]);
});

afterAll(async () => {
  dns.setServers(originalServers);
  await stub.close();
});

beforeEach(() => {
  clearResolveHostCache();
  stub.records.clear();
  stub.queries.clear();
});

describe(resolveHost, () => {
  it('returns A and AAAA records, IPv4 first', async () => {
    stub.records.set('both.test', {
      A: ['93.184.216.34'],
      AAAA: ['2606:2800:220:1::1'],
    });
    await expect(resolveHost('both.test')).resolves.toEqual([
      { address: '93.184.216.34', family: 4 },
      { address: '2606:2800:220:1::1', family: 6 },
    ]);
  });

  it('returns one family when the other has no records', async () => {
    stub.records.set('v4only.test', { A: ['93.184.216.34'] });
    await expect(resolveHost('v4only.test')).resolves.toEqual([
      { address: '93.184.216.34', family: 4 },
    ]);
  });

  it('queries only the requested family', async () => {
    stub.records.set('both.test', {
      A: ['93.184.216.34'],
      AAAA: ['2606:2800:220:1::1'],
    });
    await expect(resolveHost('both.test', { family: 6 })).resolves.toEqual([
      { address: '2606:2800:220:1::1', family: 6 },
    ]);
    expect(stub.queries.get('both.test/A')).toBeUndefined();
  });

  it('rejects with ENOTFOUND for a name that does not exist', async () => {
    await expect(resolveHost('missing.test')).rejects.toMatchObject({
      code: dns.NOTFOUND,
    });
  });

  it('returns IP literals without querying', async () => {
    await expect(resolveHost('93.184.216.34')).resolves.toEqual([
      { address: '93.184.216.34', family: 4 },
    ]);
    expect(stub.queries.size).toBe(0);
  });

  it('rejects with ETIMEOUT when the nameserver never answers', async () => {
    stub.records.set('blackhole.test', { blackhole: true });
    const startedAt = Date.now();
    await expect(
      resolveHost('blackhole.test', { timeoutMs: 200 }),
    ).rejects.toMatchObject({ code: dns.TIMEOUT });
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  it('rejects with the abort reason when the signal aborts', async () => {
    stub.records.set('blackhole.test', { blackhole: true });
    const reason = new Error('caller aborted');
    const controller = new AbortController();
    const pending = resolveHost('blackhole.test', {
      signal: controller.signal,
    });
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });

  it('does not hold up dns.lookup while queries are pending', async () => {
    stub.records.set('blackhole.test', { blackhole: true });
    // getaddrinfo may use at most half of libuv's thread pool. Had these gone
    // through dns.lookup, each would hold a slot for the full resolver
    // timeout and the lookup below would queue behind them.
    const pending = Array.from({ length: 16 }, () =>
      resolveHost('blackhole.test', { timeoutMs: 1_500 }).catch(
        (error: unknown) => error,
      ),
    );

    const startedAt = Date.now();
    await dns.promises.lookup('localhost');
    expect(Date.now() - startedAt).toBeLessThan(500);

    await Promise.all(pending);
  });

  it('follows dns.setServers() changes', async () => {
    const other = await startDnsStubServer();
    other.records.set('other.test', { A: ['93.184.216.35'] });
    try {
      dns.setServers([other.address]);
      await expect(resolveHost('other.test')).resolves.toEqual([
        { address: '93.184.216.35', family: 4 },
      ]);
    } finally {
      dns.setServers([stub.address]);
      await other.close();
    }
  });
});

describe('resolveHost sharing and caching', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function queryCount(name: string): number {
    return stub.queries.get(`${name}/A`) ?? 0;
  }

  it('shares one query between concurrent callers', async () => {
    stub.records.set('shared.test', { A: ['93.184.216.34'], delayMs: 50 });
    const results = await Promise.all(
      Array.from({ length: 10 }, () => resolveHost('shared.test')),
    );
    expect(new Set(results.map((r) => JSON.stringify(r))).size).toBe(1);
    expect(queryCount('shared.test')).toBe(1);
  });

  it('lets one caller abort without failing the others', async () => {
    stub.records.set('shared.test', { A: ['93.184.216.34'], delayMs: 50 });
    const controller = new AbortController();
    const reason = new Error('caller aborted');
    const aborted = resolveHost('shared.test', { signal: controller.signal });
    const waiting = resolveHost('shared.test');
    controller.abort(reason);
    await expect(aborted).rejects.toBe(reason);
    await expect(waiting).resolves.toEqual([
      { address: '93.184.216.34', family: 4 },
    ]);
    expect(queryCount('shared.test')).toBe(1);
  });

  it('reuses an answer for its TTL', async () => {
    stub.records.set('cached.test', { A: ['93.184.216.34'], ttl: 10 });
    const now = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now);

    await resolveHost('cached.test');
    clock.mockReturnValue(now + 9_000);
    await resolveHost('cached.test');
    expect(queryCount('cached.test')).toBe(1);

    clock.mockReturnValue(now + 10_001);
    await resolveHost('cached.test');
    expect(queryCount('cached.test')).toBe(2);
  });

  it('caps the TTL at 30 seconds', async () => {
    stub.records.set('cached.test', { A: ['93.184.216.34'], ttl: 3_600 });
    const now = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now);

    await resolveHost('cached.test');
    clock.mockReturnValue(now + 30_001);
    await resolveHost('cached.test');
    expect(queryCount('cached.test')).toBe(2);
  });

  it('does not cache an answer with a zero TTL', async () => {
    stub.records.set('uncached.test', { A: ['93.184.216.34'], ttl: 0 });
    await resolveHost('uncached.test');
    await resolveHost('uncached.test');
    expect(queryCount('uncached.test')).toBe(2);
  });

  it('reuses a failure for 2 seconds', async () => {
    const now = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now);

    await expect(resolveHost('missing.test')).rejects.toMatchObject({
      code: dns.NOTFOUND,
    });
    clock.mockReturnValue(now + 1_000);
    await expect(resolveHost('missing.test')).rejects.toMatchObject({
      code: dns.NOTFOUND,
    });
    expect(queryCount('missing.test')).toBe(1);

    clock.mockReturnValue(now + 2_001);
    await expect(resolveHost('missing.test')).rejects.toMatchObject({
      code: dns.NOTFOUND,
    });
    expect(queryCount('missing.test')).toBe(2);
  });

  it('keeps families apart', async () => {
    stub.records.set('both.test', {
      A: ['93.184.216.34'],
      AAAA: ['2606:2800:220:1::1'],
    });
    await resolveHost('both.test', { family: 4 });
    await expect(resolveHost('both.test', { family: 6 })).resolves.toEqual([
      { address: '2606:2800:220:1::1', family: 6 },
    ]);
  });

  it('hands each caller its own copy of a cached answer', async () => {
    stub.records.set('cached.test', { A: ['93.184.216.34'] });
    const first = await resolveHost('cached.test');
    first.push({ address: '10.0.0.1', family: 4 });
    await expect(resolveHost('cached.test')).resolves.toEqual([
      { address: '93.184.216.34', family: 4 },
    ]);
  });

  it('drops cached answers when dns.setServers() changes', async () => {
    stub.records.set('moved.test', { A: ['93.184.216.34'] });
    await resolveHost('moved.test');

    const other = await startDnsStubServer();
    other.records.set('moved.test', { A: ['93.184.216.35'] });
    try {
      dns.setServers([other.address]);
      await expect(resolveHost('moved.test')).resolves.toEqual([
        { address: '93.184.216.35', family: 4 },
      ]);
    } finally {
      dns.setServers([stub.address]);
      await other.close();
    }
  });
});

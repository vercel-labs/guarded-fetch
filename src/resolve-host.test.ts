import dns from 'node:dns';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { resolveHost } from './resolve-host';
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

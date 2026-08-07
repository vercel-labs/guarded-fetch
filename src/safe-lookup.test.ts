import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

vi.mock('node:dns', () => {
  const lookup = vi.fn();
  return { default: { lookup }, lookup };
});

import dns from 'node:dns';

import { SafeFetchError, SafeFetchErrorCode } from './errors';
import { createSafeLookup, isSafeIpAddress } from './safe-lookup';
import { HostnameUnsafeSubReason, setUrlBlockedHandler } from './url-blocked';

const mockDnsLookup = dns.lookup as unknown as Mock;
const blockedEvents = vi.fn();

type LookupResult = {
  err: unknown;
  addr?: string | dns.LookupAddress[];
  family?: number;
};

function callLookup(
  lookup: ReturnType<typeof createSafeLookup>,
  hostname: string,
  options: Parameters<ReturnType<typeof createSafeLookup>>[1],
): Promise<LookupResult> {
  return new Promise((resolve) => {
    lookup(hostname, options, (err, addr, family) => {
      resolve({ err, addr, family });
    });
  });
}

beforeEach(() => {
  mockDnsLookup.mockReset();
  blockedEvents.mockClear();
  setUrlBlockedHandler(blockedEvents);
});

describe(isSafeIpAddress, () => {
  it('accepts public IPv4', () => {
    expect(isSafeIpAddress('8.8.8.8')).toBe(true);
    expect(isSafeIpAddress('93.184.216.34')).toBe(true);
  });

  it('rejects loopback IPv4', () => {
    expect(isSafeIpAddress('127.0.0.1')).toBe(false);
  });

  it('rejects RFC1918 private IPv4', () => {
    expect(isSafeIpAddress('10.0.0.1')).toBe(false);
    expect(isSafeIpAddress('172.16.0.1')).toBe(false);
    expect(isSafeIpAddress('192.168.1.1')).toBe(false);
  });

  it('rejects AWS / GCP metadata link-local address', () => {
    expect(isSafeIpAddress('169.254.169.254')).toBe(false);
    expect(isSafeIpAddress('169.254.0.1')).toBe(false);
  });

  it('rejects IPv6 loopback and link-local', () => {
    expect(isSafeIpAddress('::1')).toBe(false);
    expect(isSafeIpAddress('fe80::1')).toBe(false);
    expect(isSafeIpAddress('fc00::1')).toBe(false);
  });

  it('rejects IPv4-mapped IPv6 addresses of private ranges', () => {
    // ::ffff:10.0.0.1, ::ffff:127.0.0.1, ::ffff:169.254.169.254 would all be
    // reachable as the underlying IPv4 if permitted; classification is based
    // on the embedded v4.
    expect(isSafeIpAddress('::ffff:10.0.0.1')).toBe(false);
    expect(isSafeIpAddress('::ffff:127.0.0.1')).toBe(false);
    expect(isSafeIpAddress('::ffff:169.254.169.254')).toBe(false);
  });

  it('rejects empty input', () => {
    expect(isSafeIpAddress('')).toBe(false);
  });

  it('rejects local wildcard addresses', () => {
    expect(isSafeIpAddress('0.0.0.0')).toBe(false);
    expect(isSafeIpAddress('::ffff:0.0.0.0')).toBe(false);
  });

  it('rejects WHATWG-normalized IPv4-mapped IPv6 hex addresses', () => {
    expect(isSafeIpAddress('::ffff:a9fe:a9fe')).toBe(false);
  });
});

describe(createSafeLookup, () => {
  it('passes through when dns.lookup returns a public IPv4', async () => {
    mockDnsLookup.mockImplementationOnce(
      (
        _host,
        _opts,
        cb: (err: unknown, addr: string, family: number) => void,
      ) => {
        cb(null, '8.8.8.8', 4);
      },
    );
    const lookup = createSafeLookup();
    const { err, addr, family } = await callLookup(lookup, 'example.com', {});
    expect(err).toBeNull();
    expect(addr).toBe('8.8.8.8');
    expect(family).toBe(4);
  });

  it('rejects with HOSTNAME_UNSAFE when dns.lookup returns a private IP', async () => {
    mockDnsLookup.mockImplementationOnce(
      (
        _host,
        _opts,
        cb: (err: unknown, addr: string, family: number) => void,
      ) => {
        cb(null, '10.0.0.1', 4);
      },
    );
    const lookup = createSafeLookup();
    const { err } = await callLookup(lookup, 'attacker.com', {});
    expect(err).toBeInstanceOf(SafeFetchError);
    expect((err as SafeFetchError).code).toBe(
      SafeFetchErrorCode.HOSTNAME_UNSAFE,
    );
    expect(blockedEvents).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      domain: 'attacker.com',
      subReason: HostnameUnsafeSubReason.CONNECT_TIME_IP_REJECTED,
    });
  });

  it('rejects the AWS metadata IP even if resolved from a public hostname (DNS rebinding)', async () => {
    // Simulates a TTL=0 attacker DNS flip: the FIRST resolution (outside
    // our codepath) returned a public IP and passed our assertUrlIsSafeToFetch
    // preflight. By the time the socket connects, the attacker's server
    // returned 169.254.169.254. The safe lookup catches this.
    mockDnsLookup.mockImplementationOnce(
      (
        _host,
        _opts,
        cb: (err: unknown, addr: string, family: number) => void,
      ) => {
        cb(null, '169.254.169.254', 4);
      },
    );
    const lookup = createSafeLookup();
    const { err } = await callLookup(lookup, 'attacker.com', {});
    expect(err).toBeInstanceOf(SafeFetchError);
    expect((err as SafeFetchError).code).toBe(
      SafeFetchErrorCode.HOSTNAME_UNSAFE,
    );
  });

  it('propagates the underlying dns.lookup error unchanged', async () => {
    const dnsErr = Object.assign(new Error('ENOTFOUND'), {
      code: 'ENOTFOUND',
    }) as NodeJS.ErrnoException;
    mockDnsLookup.mockImplementationOnce(
      (_host, _opts, cb: (err: unknown) => void) => {
        cb(dnsErr);
      },
    );
    const lookup = createSafeLookup();
    const { err } = await callLookup(lookup, 'nx.invalid', {});
    expect(err).toBe(dnsErr);
  });

  it('in all:true mode, rejects when ANY entry is unsafe', async () => {
    mockDnsLookup.mockImplementationOnce(
      (_host, _opts, cb: (err: unknown, addr: dns.LookupAddress[]) => void) => {
        cb(null, [
          { address: '8.8.8.8', family: 4 },
          { address: '10.0.0.1', family: 4 },
        ]);
      },
    );
    const lookup = createSafeLookup();
    const { err } = await callLookup(lookup, 'multi.example.com', {
      all: true,
    });
    expect(err).toBeInstanceOf(SafeFetchError);
    expect((err as SafeFetchError).code).toBe(
      SafeFetchErrorCode.HOSTNAME_UNSAFE,
    );
  });

  it('in all:true mode, accepts when every entry is public', async () => {
    const results: dns.LookupAddress[] = [
      { address: '8.8.8.8', family: 4 },
      { address: '2001:4860:4860::8888', family: 6 },
    ];
    mockDnsLookup.mockImplementationOnce(
      (_host, _opts, cb: (err: unknown, addr: dns.LookupAddress[]) => void) => {
        cb(null, results);
      },
    );
    const lookup = createSafeLookup();
    const { err, addr } = await callLookup(lookup, 'example.com', {
      all: true,
    });
    expect(err).toBeNull();
    expect(addr).toEqual(results);
  });

  it('opaqueErrors: true produces a generic message while preserving code', async () => {
    mockDnsLookup.mockImplementationOnce(
      (
        _host,
        _opts,
        cb: (err: unknown, addr: string, family: number) => void,
      ) => {
        cb(null, '169.254.169.254', 4);
      },
    );
    const lookup = createSafeLookup({ opaqueErrors: true });
    const { err } = await callLookup(lookup, 'attacker.com', {});
    expect(err).toBeInstanceOf(SafeFetchError);
    const safeErr = err as SafeFetchError;
    expect(safeErr.code).toBe(SafeFetchErrorCode.HOSTNAME_UNSAFE);
    expect(safeErr.message).not.toContain('169.254.169.254');
  });
});

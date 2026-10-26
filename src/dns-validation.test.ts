import dns from 'node:dns';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createGuardedLookup } from './guarded-lookup';

afterEach(() => vi.restoreAllMocks());

function lookupResult(
  addresses: dns.LookupAddress[],
  options: dns.LookupOptions = {},
) {
  const resolve = vi
    .spyOn(dns, 'lookup')
    .mockImplementation(((
      _host: string,
      _options: unknown,
      callback: (
        error: NodeJS.ErrnoException | null,
        addresses: dns.LookupAddress[],
      ) => void,
    ) => callback(null, addresses)) as typeof dns.lookup);
  const result = new Promise<{
    address: string | dns.LookupAddress[];
    family?: number;
  }>((accept, reject) => {
    createGuardedLookup()(
      'files.example.com',
      options,
      (error, address, family) =>
        error ? reject(error) : accept({ address, family }),
    );
  });
  return { resolve, result };
}

describe('complete DNS result validation', () => {
  it('rejects a private secondary address even when the connector requests one result', async () => {
    const { resolve, result } = lookupResult([
      { address: '8.8.8.8', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
    await expect(result).rejects.toMatchObject({ code: 'hostname_unsafe' });
    expect(resolve).toHaveBeenCalledWith(
      'files.example.com',
      { all: true },
      expect.any(Function),
    );
  });

  it.each(
    [
      [],
      [{ address: 'not-an-ip', family: 4 }],
      [{ address: '8.8.8.8', family: 6 }],
      [{ address: '8.8.8.8', family: 0 }],
    ].map((addresses) => ({ addresses })),
  )('rejects empty or invalid results: $addresses', async ({ addresses }) => {
    await expect(lookupResult(addresses).result).rejects.toMatchObject({
      code: 'hostname_unsafe',
    });
  });

  it('preserves the callback shape and lookup settings for a single result', async () => {
    const { resolve, result } = lookupResult(
      [{ address: '8.8.8.8', family: 4 }],
      { family: 4, hints: dns.ADDRCONFIG },
    );
    await expect(result).resolves.toEqual({ address: '8.8.8.8', family: 4 });
    expect(resolve).toHaveBeenCalledWith(
      'files.example.com',
      { family: 4, hints: dns.ADDRCONFIG, all: true },
      expect.any(Function),
    );
  });
});

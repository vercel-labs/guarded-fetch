import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

import { lookup } from 'node:dns/promises';

import { checkHostnameSafetyForServerSideFetch } from './hostname-safety';
import { HostnameUnsafeSubReason } from './url-blocked';

const mockLookup = lookup as unknown as Mock;

beforeEach(() => {
  mockLookup.mockReset();
});

describe(checkHostnameSafetyForServerSideFetch, () => {
  it('classifies empty hostname', async () => {
    await expect(checkHostnameSafetyForServerSideFetch('')).resolves.toEqual({
      safe: false,
      subReason: HostnameUnsafeSubReason.INVALID,
    });
  });

  it('classifies localhost', async () => {
    await expect(
      checkHostnameSafetyForServerSideFetch('localhost'),
    ).resolves.toEqual({
      safe: false,
      subReason: HostnameUnsafeSubReason.LOCALHOST,
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('classifies .localhost suffix', async () => {
    await expect(
      checkHostnameSafetyForServerSideFetch('app.localhost'),
    ).resolves.toEqual({
      safe: false,
      subReason: HostnameUnsafeSubReason.LOCALHOST,
    });
  });

  it('classifies .local mDNS names', async () => {
    await expect(
      checkHostnameSafetyForServerSideFetch('printer.local'),
    ).resolves.toEqual({
      safe: false,
      subReason: HostnameUnsafeSubReason.LOCAL_DOMAIN,
    });
  });

  it('classifies unsafe IP literals', async () => {
    await expect(
      checkHostnameSafetyForServerSideFetch('10.0.0.1'),
    ).resolves.toEqual({
      safe: false,
      subReason: HostnameUnsafeSubReason.IP_LITERAL_UNSAFE,
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('accepts public IP literals', async () => {
    await expect(
      checkHostnameSafetyForServerSideFetch('8.8.8.8'),
    ).resolves.toEqual({
      safe: true,
    });
  });

  it('classifies DNS resolution failure', async () => {
    mockLookup.mockRejectedValueOnce(new Error('ENOTFOUND'));
    await expect(
      checkHostnameSafetyForServerSideFetch('nx.invalid'),
    ).resolves.toEqual({
      safe: false,
      subReason: HostnameUnsafeSubReason.DNS_RESOLUTION_FAILED,
    });
  });

  it('classifies empty DNS answers', async () => {
    mockLookup.mockResolvedValueOnce([]);
    await expect(
      checkHostnameSafetyForServerSideFetch('empty.example'),
    ).resolves.toEqual({
      safe: false,
      subReason: HostnameUnsafeSubReason.DNS_RESOLUTION_FAILED,
    });
  });

  it('classifies private addresses from DNS', async () => {
    mockLookup.mockResolvedValueOnce([{ address: '10.0.0.1', family: 4 }]);
    await expect(
      checkHostnameSafetyForServerSideFetch('metadata.internal'),
    ).resolves.toEqual({
      safe: false,
      subReason: HostnameUnsafeSubReason.DNS_UNSAFE_ADDRESS,
    });
  });

  it('accepts public DNS answers', async () => {
    mockLookup.mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }]);
    await expect(
      checkHostnameSafetyForServerSideFetch('example.com'),
    ).resolves.toEqual({
      safe: true,
    });
  });
});

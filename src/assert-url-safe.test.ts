import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

import { lookup } from 'node:dns/promises';

import { assertUrlIsSafeToFetch, isHostInAllowlist } from './assert-url-safe';
import {
  SafeFetchError,
  SafeFetchErrorCode,
  OPAQUE_ERROR_MESSAGE,
} from './errors';
import { HostnameUnsafeSubReason, setUrlBlockedHandler } from './url-blocked';

const mockLookup = lookup as unknown as Mock;
const blockedEvents = vi.fn();

beforeEach(() => {
  mockLookup.mockReset();
  blockedEvents.mockClear();
  setUrlBlockedHandler(blockedEvents);
  mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
});

describe(assertUrlIsSafeToFetch, () => {
  it('resolves for a valid public HTTPS URL', async () => {
    const result = await assertUrlIsSafeToFetch('https://example.com/foo');
    expect(result.hostname).toBe('example.com');
    expect(result.url.toString()).toBe('https://example.com/foo');
    expect(mockLookup).toHaveBeenCalledWith('example.com', {
      all: true,
      verbatim: true,
    });
  });

  it('rejects unparseable URLs', async () => {
    await expect(assertUrlIsSafeToFetch('not a url')).rejects.toMatchObject({
      code: SafeFetchErrorCode.INVALID_URL,
    });
  });

  it('accepts http and https by default', async () => {
    await expect(
      assertUrlIsSafeToFetch('http://example.com'),
    ).resolves.toMatchObject({ hostname: 'example.com' });
    await expect(
      assertUrlIsSafeToFetch('https://example.com'),
    ).resolves.toMatchObject({ hostname: 'example.com' });
  });

  it('rejects non-HTTP(S) protocols by default', async () => {
    await expect(
      assertUrlIsSafeToFetch('ftp://example.com'),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.PROTOCOL_NOT_ALLOWED,
    });
    await expect(
      assertUrlIsSafeToFetch('file:///etc/passwd'),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.PROTOCOL_NOT_ALLOWED,
    });
  });

  it('rejects http when httpsOnly is true', async () => {
    await expect(
      assertUrlIsSafeToFetch('http://example.com', { httpsOnly: true }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.PROTOCOL_NOT_ALLOWED,
    });
    await expect(
      assertUrlIsSafeToFetch('https://example.com', { httpsOnly: true }),
    ).resolves.toMatchObject({ hostname: 'example.com' });
  });

  it('rejects when hostname fails SSRF check', async () => {
    mockLookup.mockResolvedValueOnce([{ address: '10.0.0.1', family: 4 }]);
    await expect(
      assertUrlIsSafeToFetch('https://metadata.internal'),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      hostname: 'metadata.internal',
    });
    expect(blockedEvents).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      domain: 'metadata.internal',
      subReason: HostnameUnsafeSubReason.DNS_UNSAFE_ADDRESS,
    });
  });

  it('emits ip_literal_unsafe for private IP hostnames', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://10.0.0.1/'),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      hostname: '10.0.0.1',
    });
    expect(blockedEvents).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      domain: '10.0.0.1',
      subReason: HostnameUnsafeSubReason.IP_LITERAL_UNSAFE,
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('emits hostname_localhost without DNS lookup', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://localhost/secret'),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOSTNAME_UNSAFE,
    });
    expect(blockedEvents).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      domain: 'localhost',
      subReason: HostnameUnsafeSubReason.LOCALHOST,
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('rejects when host is outside the allowlist', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://example.com', {
        allowedHosts: ['allowed.example'],
      }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOST_NOT_ALLOWED,
      hostname: 'example.com',
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('accepts exact match in allowlist', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://allowed.example/api', {
        allowedHosts: ['allowed.example'],
      }),
    ).resolves.toMatchObject({ hostname: 'allowed.example' });
  });

  it('accepts subdomain match in allowlist', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://api.allowed.example', {
        allowedHosts: ['allowed.example'],
      }),
    ).resolves.toMatchObject({ hostname: 'api.allowed.example' });
  });

  it('does not match allowlist suffix across unrelated domain', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://notallowed.example', {
        allowedHosts: ['allowed.example'],
      }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOST_NOT_ALLOWED,
    });
  });

  it('skips SSRF check when skipSsrfCheckForAllowedHosts is set', async () => {
    const result = await assertUrlIsSafeToFetch('https://api.allowed.example', {
      allowedHosts: ['allowed.example'],
      skipSsrfCheckForAllowedHosts: true,
    });
    expect(result.hostname).toBe('api.allowed.example');
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('returns opaque error messages when opaqueErrors is true', async () => {
    mockLookup.mockResolvedValueOnce([{ address: '10.0.0.1', family: 4 }]);
    const err = await assertUrlIsSafeToFetch('https://internal.local', {
      opaqueErrors: true,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(SafeFetchError);
    expect(err.code).toBe(SafeFetchErrorCode.HOSTNAME_UNSAFE);
    expect(err.message).toBe(OPAQUE_ERROR_MESSAGE);
  });

  it('preserves code field even in opaque mode', async () => {
    const err = await assertUrlIsSafeToFetch('ftp://example.com', {
      opaqueErrors: true,
    }).catch((e) => e);
    expect(err.code).toBe(SafeFetchErrorCode.PROTOCOL_NOT_ALLOWED);
    expect(err.message).toBe(OPAQUE_ERROR_MESSAGE);
  });
});

// The common thread across these: naive string checks (startsWith, prefix,
// literal-IP blocklists) are bypassable; safe-fetch validates the
// WHATWG-parsed hostname instead, which these lock in.
describe('assertUrlIsSafeToFetch — SSRF bypass edge cases', () => {
  // Userinfo authority confusion. A `startsWith`-style check reading the raw
  // string sees the allowlisted prefix, but the real request host is what
  // follows the `@`.
  it('validates the host after userinfo, not the userinfo itself (allowlist)', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://allowed.example@attacker.com/path', {
        allowedHosts: ['allowed.example'],
      }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOST_NOT_ALLOWED,
      hostname: 'attacker.com',
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('runs the SSRF check on the real host when credentials are embedded', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://user:pass@10.0.0.1/'),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      hostname: '10.0.0.1',
    });
    expect(blockedEvents).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      domain: '10.0.0.1',
      subReason: HostnameUnsafeSubReason.IP_LITERAL_UNSAFE,
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  // A `startsWith`-style allowlist check without a trailing-dot boundary lets
  // `allowed.example.evil.com` pass. The allowlist matcher is right-anchored
  // on a dot boundary, so it must not.
  it('rejects a look-alike domain that only suffix-matches the allowlist', async () => {
    await expect(
      assertUrlIsSafeToFetch('https://allowed.example.evil.com/', {
        allowedHosts: ['allowed.example'],
      }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOST_NOT_ALLOWED,
      hostname: 'allowed.example.evil.com',
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });

  // Loopback written in alternate IPv4 encodings: decimal, hex, octal, and
  // short-form literals all normalize to 127.0.0.1 and must be blocked as IP
  // literals without ever hitting DNS.
  it.each([
    ['decimal', 'http://2130706433/'],
    ['hex', 'http://0x7f000001/'],
    ['octal', 'http://0177.0.0.1/'],
    ['short-form', 'http://127.1/'],
  ])('blocks loopback written in %s form', async (_label, url) => {
    await expect(assertUrlIsSafeToFetch(url)).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      hostname: '127.0.0.1',
    });
    expect(mockLookup).not.toHaveBeenCalled();
  });
});

describe(isHostInAllowlist, () => {
  it('returns true for exact match (case-insensitive)', () => {
    expect(isHostInAllowlist('allowed.example', ['Allowed.example'])).toBe(
      true,
    );
  });

  it('returns true for subdomain', () => {
    expect(isHostInAllowlist('a.b.allowed.example', ['allowed.example'])).toBe(
      true,
    );
  });

  it('returns false when suffix does not follow a dot boundary', () => {
    expect(isHostInAllowlist('notallowed.example', ['allowed.example'])).toBe(
      false,
    );
    expect(isHostInAllowlist('xallowed.example', ['allowed.example'])).toBe(
      false,
    );
  });

  it('ignores empty entries', () => {
    expect(isHostInAllowlist('example.com', ['', 'allowed.example'])).toBe(
      false,
    );
  });

  it('returns false for empty allowlist', () => {
    expect(isHostInAllowlist('allowed.example', [])).toBe(false);
  });
});

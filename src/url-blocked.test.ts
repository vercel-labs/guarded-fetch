import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SafeFetchErrorCode } from './errors';
import {
  HostnameUnsafeSubReason,
  recordUrlBlocked,
  resolveBlockedDomain,
  setUrlBlockedHandler,
  URL_BLOCKED_REASONS,
} from './url-blocked';

const events = vi.fn();

beforeEach(() => {
  events.mockClear();
  setUrlBlockedHandler(events);
});

describe(resolveBlockedDomain, () => {
  it('prefers hostname when present', () => {
    expect(
      resolveBlockedDomain({
        hostname: 'Example.COM',
        url: 'https://other.example/',
      }),
    ).toBe('example.com');
  });

  it('parses hostname from url', () => {
    expect(resolveBlockedDomain({ url: 'https://api.example.com/path' })).toBe(
      'api.example.com',
    );
  });

  it('returns unknown for unparseable url', () => {
    expect(resolveBlockedDomain({ url: 'not a url' })).toBe('unknown');
  });

  it('returns unknown when no details', () => {
    expect(resolveBlockedDomain({})).toBe('unknown');
  });
});

describe(recordUrlBlocked, () => {
  it('dispatches a block event with reason and domain', () => {
    recordUrlBlocked(SafeFetchErrorCode.HOSTNAME_UNSAFE, 'metadata.internal');

    expect(events).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      domain: 'metadata.internal',
    });
  });

  it('includes subReason when provided', () => {
    recordUrlBlocked(
      SafeFetchErrorCode.HOSTNAME_UNSAFE,
      'attacker.com',
      HostnameUnsafeSubReason.CONNECT_TIME_IP_REJECTED,
    );

    expect(events).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      domain: 'attacker.com',
      subReason: HostnameUnsafeSubReason.CONNECT_TIME_IP_REJECTED,
    });
  });

  it('does not emit for non-security codes', () => {
    recordUrlBlocked(SafeFetchErrorCode.TIMEOUT, 'example.com');
    recordUrlBlocked(SafeFetchErrorCode.NETWORK_ERROR, 'example.com');
    expect(events).not.toHaveBeenCalled();
  });

  it('emits redirect abuse codes', () => {
    recordUrlBlocked(SafeFetchErrorCode.REDIRECT_INVALID, 'redirector.example');
    recordUrlBlocked(SafeFetchErrorCode.TOO_MANY_REDIRECTS, 'probe.example');

    expect(events).toHaveBeenCalledTimes(2);
    expect(events).toHaveBeenNthCalledWith(1, {
      reason: SafeFetchErrorCode.REDIRECT_INVALID,
      domain: 'redirector.example',
    });
    expect(events).toHaveBeenNthCalledWith(2, {
      reason: SafeFetchErrorCode.TOO_MANY_REDIRECTS,
      domain: 'probe.example',
    });
  });

  it('uses unknown for empty domain', () => {
    recordUrlBlocked(SafeFetchErrorCode.INVALID_URL, '');
    expect(events).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.INVALID_URL,
      domain: 'unknown',
    });
  });

  it('invokes the module-level handler', () => {
    recordUrlBlocked(SafeFetchErrorCode.HOST_NOT_ALLOWED, 'evil.example');

    expect(events).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.HOST_NOT_ALLOWED,
      domain: 'evil.example',
    });
  });

  it('prefers a per-call handler over the module-level handler', () => {
    const localHandler = vi.fn();

    recordUrlBlocked(
      SafeFetchErrorCode.HOST_NOT_ALLOWED,
      'evil.example',
      undefined,
      localHandler,
    );

    expect(localHandler).toHaveBeenCalledTimes(1);
    expect(events).not.toHaveBeenCalled();
  });

  it('is a no-op without any handler', () => {
    setUrlBlockedHandler(undefined);

    expect(() =>
      recordUrlBlocked(SafeFetchErrorCode.HOST_NOT_ALLOWED, 'evil.example'),
    ).not.toThrow();
  });

  it('does not throw when a handler throws', () => {
    setUrlBlockedHandler(() => {
      throw new Error('logging failed');
    });

    expect(() =>
      recordUrlBlocked(SafeFetchErrorCode.HOST_NOT_ALLOWED, 'evil.example'),
    ).not.toThrow();
  });
});

describe('URL_BLOCKED_REASONS', () => {
  it('includes SSRF, allowlist, and redirect-target codes', () => {
    expect(URL_BLOCKED_REASONS.has(SafeFetchErrorCode.HOSTNAME_UNSAFE)).toBe(
      true,
    );
    expect(
      URL_BLOCKED_REASONS.has(SafeFetchErrorCode.REDIRECT_TO_UNSAFE_HOST),
    ).toBe(true);
    expect(URL_BLOCKED_REASONS.has(SafeFetchErrorCode.REDIRECT_INVALID)).toBe(
      true,
    );
    expect(URL_BLOCKED_REASONS.has(SafeFetchErrorCode.TOO_MANY_REDIRECTS)).toBe(
      true,
    );
    expect(URL_BLOCKED_REASONS.has(SafeFetchErrorCode.NETWORK_ERROR)).toBe(
      false,
    );
    expect(URL_BLOCKED_REASONS.has(SafeFetchErrorCode.TIMEOUT)).toBe(false);
  });
});

import { describe, expect, it } from 'vitest';

import {
  isPermanentGuardedFetchError,
  isGuardedFetchError,
  GuardedFetchError,
  GuardedFetchErrorCode,
} from './errors';

describe('GuardedFetchError', () => {
  it('exposes code, hostname, url, status, and cause', () => {
    const cause = new Error('root cause');
    const err = new GuardedFetchError(
      GuardedFetchErrorCode.TIMEOUT,
      'timed out',
      {
        hostname: 'example.com',
        url: 'https://example.com/x',
        status: 0,
        cause,
      },
    );
    expect(err.name).toBe('GuardedFetchError');
    expect(err.code).toBe(GuardedFetchErrorCode.TIMEOUT);
    expect(err.hostname).toBe('example.com');
    expect(err.url).toBe('https://example.com/x');
    expect(err.status).toBe(0);
    expect(err.cause).toBe(cause);
  });

  it('is identifiable by isGuardedFetchError', () => {
    const err = new GuardedFetchError(GuardedFetchErrorCode.INVALID_URL, 'bad');
    expect(isGuardedFetchError(err)).toBe(true);
    expect(isGuardedFetchError(new Error('something'))).toBe(false);
    expect(isGuardedFetchError(null)).toBe(false);
    expect(isGuardedFetchError('string')).toBe(false);
  });

  it('isGuardedFetchError matches duplicate package copies by shape', () => {
    const impostor = Object.assign(new Error('x'), {
      name: 'GuardedFetchError',
      code: 'invalid_url',
    });
    expect(isGuardedFetchError(impostor)).toBe(true);
  });
});

describe(isPermanentGuardedFetchError, () => {
  it.each([
    GuardedFetchErrorCode.INVALID_URL,
    GuardedFetchErrorCode.PROTOCOL_NOT_ALLOWED,
    GuardedFetchErrorCode.HOST_NOT_ALLOWED,
    GuardedFetchErrorCode.HOSTNAME_UNSAFE,
    GuardedFetchErrorCode.TOO_MANY_REDIRECTS,
    GuardedFetchErrorCode.REDIRECT_INVALID,
    GuardedFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
    GuardedFetchErrorCode.RESPONSE_TOO_LARGE,
  ])('treats %s as permanent', (code) => {
    expect(isPermanentGuardedFetchError(new GuardedFetchError(code, 'x'))).toBe(
      true,
    );
  });

  it.each([GuardedFetchErrorCode.TIMEOUT, GuardedFetchErrorCode.NETWORK_ERROR])(
    'treats %s as potentially transient',
    (code) => {
      expect(
        isPermanentGuardedFetchError(new GuardedFetchError(code, 'x')),
      ).toBe(false);
    },
  );

  it('treats non-GuardedFetch errors as potentially transient', () => {
    expect(isPermanentGuardedFetchError(new Error('socket reset'))).toBe(false);
    expect(isPermanentGuardedFetchError(null)).toBe(false);
  });
});

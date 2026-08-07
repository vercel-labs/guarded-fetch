import { describe, expect, it } from 'vitest';

import {
  isPermanentSafeFetchError,
  isSafeFetchError,
  SafeFetchError,
  SafeFetchErrorCode,
} from './errors';

describe('SafeFetchError', () => {
  it('exposes code, hostname, url, status, and cause', () => {
    const cause = new Error('root cause');
    const err = new SafeFetchError(SafeFetchErrorCode.TIMEOUT, 'timed out', {
      hostname: 'example.com',
      url: 'https://example.com/x',
      status: 0,
      cause,
    });
    expect(err.name).toBe('SafeFetchError');
    expect(err.code).toBe(SafeFetchErrorCode.TIMEOUT);
    expect(err.hostname).toBe('example.com');
    expect(err.url).toBe('https://example.com/x');
    expect(err.status).toBe(0);
    expect(err.cause).toBe(cause);
  });

  it('is identifiable by isSafeFetchError', () => {
    const err = new SafeFetchError(SafeFetchErrorCode.INVALID_URL, 'bad');
    expect(isSafeFetchError(err)).toBe(true);
    expect(isSafeFetchError(new Error('something'))).toBe(false);
    expect(isSafeFetchError(null)).toBe(false);
    expect(isSafeFetchError('string')).toBe(false);
  });

  it('isSafeFetchError matches duplicate package copies by shape', () => {
    const impostor = Object.assign(new Error('x'), {
      name: 'SafeFetchError',
      code: 'invalid_url',
    });
    expect(isSafeFetchError(impostor)).toBe(true);
  });
});

describe(isPermanentSafeFetchError, () => {
  it.each([
    SafeFetchErrorCode.INVALID_URL,
    SafeFetchErrorCode.PROTOCOL_NOT_ALLOWED,
    SafeFetchErrorCode.HOST_NOT_ALLOWED,
    SafeFetchErrorCode.HOSTNAME_UNSAFE,
    SafeFetchErrorCode.TOO_MANY_REDIRECTS,
    SafeFetchErrorCode.REDIRECT_INVALID,
    SafeFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
    SafeFetchErrorCode.RESPONSE_TOO_LARGE,
  ])('treats %s as permanent', (code) => {
    expect(isPermanentSafeFetchError(new SafeFetchError(code, 'x'))).toBe(true);
  });

  it.each([SafeFetchErrorCode.TIMEOUT, SafeFetchErrorCode.NETWORK_ERROR])(
    'treats %s as potentially transient',
    (code) => {
      expect(isPermanentSafeFetchError(new SafeFetchError(code, 'x'))).toBe(
        false,
      );
    },
  );

  it('treats non-SafeFetch errors as potentially transient', () => {
    expect(isPermanentSafeFetchError(new Error('socket reset'))).toBe(false);
    expect(isPermanentSafeFetchError(null)).toBe(false);
  });
});

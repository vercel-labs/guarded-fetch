import { Headers as UndiciHeaders } from 'undici';
import { describe, expect, it } from 'vitest';

import { sanitizeRequestHeaders } from './sanitize-headers';

describe(sanitizeRequestHeaders, () => {
  it('returns an empty Headers for undefined input', () => {
    const out = sanitizeRequestHeaders(undefined);
    expect([...out.entries()]).toEqual([]);
  });

  it('strips blocked headers from a Headers instance', () => {
    const input = new UndiciHeaders([
      ['host', 'internal.example.com'],
      ['x-forwarded-for', '10.0.0.1'],
      ['metadata-flavor', 'Google'],
      ['x-aws-ec2-metadata-token', 'abc'],
      ['cookie', 'sid=secret'],
      ['authorization', 'Bearer tok'],
      ['content-type', 'application/json'],
    ]);
    const out = sanitizeRequestHeaders(input);
    expect(out.get('host')).toBeNull();
    expect(out.get('x-forwarded-for')).toBeNull();
    expect(out.get('metadata-flavor')).toBeNull();
    expect(out.get('x-aws-ec2-metadata-token')).toBeNull();
    expect(out.get('cookie')).toBeNull();
    // Non-blocked headers are preserved.
    expect(out.get('authorization')).toBe('Bearer tok');
    expect(out.get('content-type')).toBe('application/json');
  });

  it('preserves non-blocked headers from a global Headers instance', () => {
    const input = new globalThis.Headers({
      'Content-Type': 'application/json',
      Cookie: 'sid=secret',
    });
    const out = sanitizeRequestHeaders(input);
    expect(out.get('cookie')).toBeNull();
    expect(out.get('content-type')).toBe('application/json');
  });

  it('preserves global Headers values after set()', () => {
    const init: RequestInit | undefined = {
      headers: { 'Content-Type': 'application/json' },
    };
    const input = new Headers(init?.headers);
    input.set('User-Agent', 'test-agent');

    const out = sanitizeRequestHeaders(input);

    expect(out.get('content-type')).toBe('application/json');
    expect(out.get('user-agent')).toBe('test-agent');
  });

  it('strips blocked headers case-insensitively from a record', () => {
    const out = sanitizeRequestHeaders({
      Host: 'evil',
      'X-Forwarded-For': '1.2.3.4',
      'X-Real-IP': '1.2.3.4',
      'X-Custom': 'keep',
    });
    expect(out.get('host')).toBeNull();
    expect(out.get('x-forwarded-for')).toBeNull();
    expect(out.get('x-real-ip')).toBeNull();
    expect(out.get('x-custom')).toBe('keep');
  });

  it('accepts tuple arrays and ignores non-string values', () => {
    const out = sanitizeRequestHeaders([
      ['accept', 'application/json'],
      ['cookie', 'bad'],
    ]);
    expect(out.get('accept')).toBe('application/json');
    expect(out.get('cookie')).toBeNull();
  });

  it('handles record values that are string arrays', () => {
    const out = sanitizeRequestHeaders({ 'x-trace': ['a', 'b'] });
    expect(out.get('x-trace')).toBe('a, b');
  });

  it('ignores undefined values in records', () => {
    const out = sanitizeRequestHeaders({
      'x-missing': undefined,
      'x-keep': 'v',
    });
    expect(out.get('x-missing')).toBeNull();
    expect(out.get('x-keep')).toBe('v');
  });
});

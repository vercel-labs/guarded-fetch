import { describe, expect, it, vi } from 'vitest';

import { isPermanentGuardedFetchError } from './errors';
import { guardedFetch } from './guarded-fetch';

const start = 'https://1.1.1.1/start';

describe('standard redirect policies', () => {
  it('returns a manual redirect without requesting the target', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(null, { status: 302, headers: { location: '/next' } }),
      );
    const response = await guardedFetch(start, { fetch, redirect: 'manual' });
    expect(response.status).toBe(302);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('rejects redirects in error mode and cancels the discarded body', async () => {
    const cancel = vi.fn();
    const fetch = vi.fn().mockResolvedValue(
      new Response(new ReadableStream({ cancel }), {
        status: 302,
        headers: { location: '/next' },
      }),
    );
    const error = await guardedFetch(start, { fetch, redirect: 'error' }).catch(
      (failure) => failure,
    );
    expect(error).toMatchObject({ code: 'redirect_not_allowed' });
    expect(isPermanentGuardedFetchError(error)).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it('lets an explicit redirect policy override the legacy option', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, { status: 302, headers: { location: '/next' } }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    const response = await guardedFetch(start, {
      fetch,
      redirect: 'follow',
      followRedirects: false,
    });
    expect(await response.text()).toBe('ok');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('drops arbitrary credentials at a cross-origin hop and never restores them', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 307,
          headers: { location: 'https://8.8.8.8/next' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(null, { status: 307, headers: { location: start } }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    await guardedFetch(start, {
      fetch,
      headers: {
        'x-provider-secret': 'synthetic',
        'api-key': 'synthetic',
        authorization: 'synthetic',
        'user-agent': 'test-agent',
      },
    });
    for (const [, init] of fetch.mock.calls.slice(1)) {
      expect(Object.fromEntries(init.headers)).toEqual({
        'user-agent': 'test-agent',
      });
    }
  });
});

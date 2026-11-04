import { describe, expect, it, vi } from 'vitest';

import { isPermanentGuardedFetchError, OPAQUE_ERROR_MESSAGE } from './errors';
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

  it('uses the opaque message for rejected redirects when opaqueErrors is set', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(null, { status: 302, headers: { location: '/next' } }),
      );
    const error = await guardedFetch(start, {
      fetch,
      redirect: 'error',
      opaqueErrors: true,
    }).catch((failure) => failure);
    expect(error).toMatchObject({
      code: 'redirect_not_allowed',
      message: OPAQUE_ERROR_MESSAGE,
    });
  });

  it('rejects an unknown redirect policy before sending a request', async () => {
    const fetch = vi.fn();
    await expect(
      guardedFetch(start, {
        fetch,
        redirect: 'bogus' as never,
      }),
    ).rejects.toThrow(TypeError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('lets an explicit redirect policy override followRedirects', async () => {
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

  it('keeps body-describing headers on a cross-origin 307 that preserves the body', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 307,
          headers: { location: 'https://8.8.8.8/next' },
        }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    await guardedFetch(start, {
      fetch,
      method: 'POST',
      body: '{"a":1}',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'x-api-key': 'synthetic',
      },
    });
    const init = fetch.mock.calls[1]?.[1];
    expect(init.method).toBe('POST');
    expect(init.body).toBe('{"a":1}');
    expect(Object.fromEntries(init.headers)).toEqual({
      accept: 'application/json',
      'content-type': 'application/json',
    });
  });

  it('keeps every caller header on a same-origin redirect', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, { status: 307, headers: { location: '/next' } }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    const headers = {
      authorization: 'synthetic',
      'x-api-key': 'synthetic',
      'user-agent': 'test-agent',
    };
    await guardedFetch(start, { fetch, headers });
    const init = fetch.mock.calls[1]?.[1];
    expect(Object.fromEntries(init.headers)).toEqual(headers);
  });
});

import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

import { lookup } from 'node:dns/promises';

import { SafeFetchError, SafeFetchErrorCode } from './errors';
import { safeFetch } from './safe-fetch';
import { HostnameUnsafeSubReason, setUrlBlockedHandler } from './url-blocked';

const mockLookup = lookup as unknown as Mock;
const blockedEvents = vi.fn();

type MockFetch = ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

function mockFetch(): MockFetch {
  return vi.fn() as MockFetch;
}

beforeEach(() => {
  mockLookup.mockReset();
  blockedEvents.mockClear();
  setUrlBlockedHandler(blockedEvents);
  mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
});

describe(safeFetch, () => {
  it('performs a basic GET against a safe host', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(
      new Response('ok', { status: 200 }),
    );
    const res = await safeFetch('https://example.com/x', { fetch });
    expect(res.status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(1);
    const call = fetch.mock.calls[0];
    if (!call) throw new Error('fetch not called');
    const [url, init] = call;
    expect(url).toBe('https://example.com/x');
    expect(init?.method).toBe('GET');
    expect(init?.redirect).toBe('manual');
  });

  it('rejects before fetching when SSRF check fails', async () => {
    const fetch = mockFetch();
    await expect(
      safeFetch('https://169.254.169.254/', { fetch }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOSTNAME_UNSAFE,
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('strips blocked headers from the outgoing request', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(new Response(null));
    await safeFetch('https://example.com', {
      fetch,
      headers: {
        Host: 'evil',
        'X-Forwarded-For': '1.2.3.4',
        'Metadata-Flavor': 'Google',
        'X-Custom': 'keep',
      },
    });
    const init = fetch.mock.calls[0]?.[1];
    const headers = init?.headers as Headers;
    expect(headers.get('host')).toBeNull();
    expect(headers.get('x-forwarded-for')).toBeNull();
    expect(headers.get('metadata-flavor')).toBeNull();
    expect(headers.get('x-custom')).toBe('keep');
  });

  it('does not strip headers when sanitizeHeaders=false', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(new Response(null));
    await safeFetch('https://example.com', {
      fetch,
      sanitizeHeaders: false,
      headers: { 'X-Forwarded-For': '1.2.3.4' },
    });
    const headers = fetch.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get('x-forwarded-for')).toBe('1.2.3.4');
  });

  it('follows a redirect to a safe host', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: { location: 'https://other.example.com/next' },
        }),
      )
      .mockResolvedValueOnce(new Response('final', { status: 200 }));

    const res = await safeFetch('https://example.com', { fetch });
    expect(res.status).toBe(200);
    await expect(res.text()).resolves.toBe('final');
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[1]?.[0]).toBe('https://other.example.com/next');
  });

  it('rejects a redirect to an unsafe host', async () => {
    mockLookup
      .mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }])
      .mockResolvedValueOnce([{ address: '10.0.0.1', family: 4 }]);

    const fetch = mockFetch().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { location: 'https://metadata.internal/latest/meta-data/' },
      }),
    );

    await expect(
      safeFetch('https://example.com', { fetch }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(blockedEvents).toHaveBeenCalledTimes(2);
    expect(blockedEvents).toHaveBeenNthCalledWith(1, {
      reason: SafeFetchErrorCode.HOSTNAME_UNSAFE,
      domain: 'metadata.internal',
      subReason: HostnameUnsafeSubReason.DNS_UNSAFE_ADDRESS,
    });
    expect(blockedEvents).toHaveBeenNthCalledWith(2, {
      reason: SafeFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
      domain: 'example.com',
    });
  });

  // A redirect whose Location hides a private target behind userinfo
  // (`https://public@127.0.0.1/...`) must be caught before the next hop fires —
  // the redirect is validated on the real host, and the internal request is
  // never made.
  it('rejects a redirect to a private host obscured by userinfo', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: {
          location: 'https://example.com@127.0.0.1/latest/meta-data/',
        },
      }),
    );
    await expect(
      safeFetch('https://example.com', { fetch }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
    });
    expect(fetch).toHaveBeenCalledTimes(1); // second hop never issued
  });

  it('rejects a redirect to a non-allowlisted protocol', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { location: 'file:///etc/passwd' },
      }),
    );
    await expect(
      safeFetch('https://example.com', { fetch }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.REDIRECT_TO_UNSAFE_HOST,
    });
  });

  it('does not follow redirects when followRedirects=false', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { location: 'https://other.example.com/' },
      }),
    );
    const res = await safeFetch('https://example.com', {
      fetch,
      followRedirects: false,
    });
    expect(res.status).toBe(302);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('throws TOO_MANY_REDIRECTS when chain exceeds maxRedirects', async () => {
    const fetch = mockFetch().mockImplementation(
      async () =>
        new Response(null, {
          status: 302,
          headers: { location: 'https://example.com/loop' },
        }),
    );
    await expect(
      safeFetch('https://example.com/loop', { fetch, maxRedirects: 2 }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.TOO_MANY_REDIRECTS,
    });
    expect(fetch).toHaveBeenCalledTimes(3); // initial + 2 redirect hops
    expect(blockedEvents).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.TOO_MANY_REDIRECTS,
      domain: 'example.com',
    });
  });

  it('throws REDIRECT_INVALID when Location header is missing', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(
      new Response(null, { status: 302 }),
    );
    await expect(
      safeFetch('https://example.com', { fetch }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.REDIRECT_INVALID,
    });
    expect(blockedEvents).toHaveBeenCalledWith({
      reason: SafeFetchErrorCode.REDIRECT_INVALID,
      domain: 'example.com',
    });
  });

  it('drops body and switches method to GET on 303', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 303,
          headers: { location: 'https://other.example.com/result' },
        }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    await safeFetch('https://example.com/submit', {
      fetch,
      method: 'POST',
      body: 'some-body',
      headers: { 'content-type': 'application/json' },
    });
    const secondInit = fetch.mock.calls[1]?.[1];
    expect(secondInit?.method).toBe('GET');
    expect(secondInit?.body).toBeUndefined();
    const headers = secondInit?.headers as Headers;
    expect(headers.get('content-type')).toBeNull();
  });

  it('preserves method and body on 307 redirect', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 307,
          headers: { location: 'https://other.example.com/retry' },
        }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    await safeFetch('https://example.com/submit', {
      fetch,
      method: 'POST',
      body: 'keep-me',
    });
    const secondInit = fetch.mock.calls[1]?.[1];
    expect(secondInit?.method).toBe('POST');
    expect(secondInit?.body).toBe('keep-me');
  });

  it('drops Authorization header on cross-origin redirect', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 307,
          headers: { location: 'https://other.example.com/' },
        }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    await safeFetch('https://example.com', {
      fetch,
      headers: { Authorization: 'Bearer secret' },
    });
    const secondHeaders = fetch.mock.calls[1]?.[1]?.headers as Headers;
    expect(secondHeaders.get('authorization')).toBeNull();
  });

  it('keeps Authorization header on same-origin redirect', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 307,
          headers: { location: 'https://example.com/next' },
        }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    await safeFetch('https://example.com', {
      fetch,
      headers: { Authorization: 'Bearer secret' },
    });
    const secondHeaders = fetch.mock.calls[1]?.[1]?.headers as Headers;
    expect(secondHeaders.get('authorization')).toBe('Bearer secret');
  });

  it('sends the allowed cookie as a Cookie header on the initial request', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(new Response(null));
    await safeFetch('https://example.com', {
      fetch,
      allowedCookie: 'session=abc123',
    });
    const headers = fetch.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get('cookie')).toBe('session=abc123');
  });

  it('drops the allowed cookie on a cross-origin redirect', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 307,
          headers: { location: 'https://other.example.com/' },
        }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    await safeFetch('https://example.com', {
      fetch,
      allowedCookie: 'session=abc123',
    });
    const firstHeaders = fetch.mock.calls[0]?.[1]?.headers as Headers;
    expect(firstHeaders.get('cookie')).toBe('session=abc123');
    const secondHeaders = fetch.mock.calls[1]?.[1]?.headers as Headers;
    expect(secondHeaders.get('cookie')).toBeNull();
  });

  it('preserves the allowed cookie on a same-origin redirect', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 307,
          headers: { location: 'https://example.com/next' },
        }),
      )
      .mockResolvedValueOnce(new Response('ok'));
    await safeFetch('https://example.com', {
      fetch,
      allowedCookie: 'session=abc123',
    });
    const secondHeaders = fetch.mock.calls[1]?.[1]?.headers as Headers;
    expect(secondHeaders.get('cookie')).toBe('session=abc123');
  });

  it('still runs SSRF checks when the allowed cookie is set', async () => {
    const fetch = mockFetch();
    await expect(
      safeFetch('https://169.254.169.254/', {
        fetch,
        allowedCookie: 'session=abc123',
      }),
    ).rejects.toMatchObject({ code: SafeFetchErrorCode.HOSTNAME_UNSAFE });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('overrides a Cookie header supplied via the headers option', async () => {
    // Cookie is in BLOCKED_REQUEST_HEADERS so it would normally be stripped;
    // verify the explicit opt-in value wins regardless.
    const fetch = mockFetch().mockResolvedValueOnce(new Response(null));
    await safeFetch('https://example.com', {
      fetch,
      headers: { Cookie: 'attacker=1' },
      allowedCookie: 'session=abc123',
    });
    const headers = fetch.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get('cookie')).toBe('session=abc123');
  });

  it('maps timeout to SafeFetchError with code TIMEOUT', async () => {
    const fetch = vi.fn(
      (_url: unknown, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const s = init?.signal;
          if (s?.aborted) {
            const err = new Error('Aborted');
            err.name = 'AbortError';
            reject(err);
            return;
          }
          s?.addEventListener('abort', () => {
            const err = new Error('Aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }),
    ) as MockFetch;

    await expect(
      safeFetch('https://example.com', { fetch, timeoutMs: 20 }),
    ).rejects.toMatchObject({ code: SafeFetchErrorCode.TIMEOUT });
  });

  it('wraps unexpected fetch errors as NETWORK_ERROR', async () => {
    const fetch = mockFetch().mockRejectedValueOnce(
      new TypeError('connect ECONNREFUSED'),
    );
    await expect(
      safeFetch('https://example.com', { fetch }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.NETWORK_ERROR,
    });
  });

  it('respects an externally-supplied AbortSignal', async () => {
    const controller = new AbortController();
    const fetch = vi.fn(
      (_url: unknown, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const s = init?.signal;
          const abort = () => {
            const err = new Error('Aborted');
            err.name = 'AbortError';
            reject(err);
          };
          if (s?.aborted) {
            abort();
          } else {
            s?.addEventListener('abort', abort);
          }
        }),
    ) as MockFetch;

    // Fire abort after a microtask so the request has actually begun.
    const promise = safeFetch('https://example.com', {
      fetch,
      signal: controller.signal,
    });
    setImmediate(() => controller.abort());
    await expect(promise).rejects.toMatchObject({
      code: SafeFetchErrorCode.NETWORK_ERROR,
    });
  });

  it('defaults to the shared safe dispatcher for undici-compatible fetch', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(new Response(null));
    await safeFetch('https://example.com', { fetch });
    const init = fetch.mock.calls[0]?.[1] as
      | (RequestInit & { dispatcher?: unknown })
      | undefined;
    expect(init?.dispatcher).toBeDefined();
  });

  it('honors dispatcher: null to explicitly disable IP pinning', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(new Response(null));
    await safeFetch('https://example.com', { fetch, dispatcher: null });
    const init = fetch.mock.calls[0]?.[1] as
      | (RequestInit & { dispatcher?: unknown })
      | undefined;
    expect(init?.dispatcher).toBeUndefined();
  });

  it('propagates SafeFetchError thrown by the dispatcher lookup (DNS rebinding block)', async () => {
    // Simulate undici's connect wrapping our lookup-side SafeFetchError in
    // a TypeError('fetch failed') with the real error on `.cause` (sometimes
    // nested). The executeFetch cause-walker must surface the original
    // HOSTNAME_UNSAFE so callers see the rebinding block, not a generic
    // network error.
    const rebindingError = new SafeFetchError(
      SafeFetchErrorCode.HOSTNAME_UNSAFE,
      'blocked by safe lookup',
    );
    const fetchFailed = new TypeError('fetch failed');
    // Two levels of wrapping, matching real undici behavior.
    (fetchFailed as { cause?: unknown }).cause = new Error('connect failed');
    ((fetchFailed as { cause: Error }).cause as { cause?: unknown }).cause =
      rebindingError;

    const fetch = mockFetch().mockRejectedValueOnce(fetchFailed);
    await expect(
      safeFetch('https://example.com', { fetch }),
    ).rejects.toMatchObject({
      code: SafeFetchErrorCode.HOSTNAME_UNSAFE,
    });
  });
});

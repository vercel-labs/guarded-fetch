import dns, { type LookupAddress } from 'node:dns';
import net from 'node:net';

/**
 * Upper bound on a single {@link resolveHost} call. The query is abandoned
 * and the call rejects with `ETIMEOUT` once this passes.
 */
export const DEFAULT_DNS_TIMEOUT_MS = 5_000;

/** c-ares per-attempt timeout. c-ares backs off between attempts. */
const ATTEMPT_TIMEOUT_MS = 2_000;
const ATTEMPTS = 2;

/** Longest a successful answer is reused, whatever its TTL says. */
const MAX_CACHE_TTL_MS = 30_000;
/** How long a failed resolution is reused. */
const NEGATIVE_CACHE_TTL_MS = 2_000;
/** Oldest entries are evicted beyond this. */
const MAX_CACHE_ENTRIES = 1_000;

export interface ResolveHostOptions {
  /** `4` or `6` to resolve a single family; `0` (default) resolves both. */
  family?: number;
  /** Rejects with the signal's reason as soon as it aborts. */
  signal?: AbortSignal;
  /** Overall deadline for the call. Defaults to {@link DEFAULT_DNS_TIMEOUT_MS}. */
  timeoutMs?: number;
}

/**
 * Resolves a hostname's A and AAAA records with c-ares (`dns.Resolver`).
 *
 * This deliberately avoids `dns.lookup`. `dns.lookup` calls getaddrinfo(3) on
 * libuv's thread pool, and a getaddrinfo call cannot be cancelled: it holds
 * its thread until the OS resolver gives up, which takes many seconds against
 * a nameserver that never answers. libuv lets DNS use at most half the pool
 * (2 of the default 4 threads), so two such lookups are enough to queue every
 * other `dns.lookup` in the process behind them, which stalls every new
 * outbound connection made by hostname, not only guarded ones. Whoever
 * supplies a URL usually controls its DNS. c-ares runs on the event loop and
 * holds no thread while it waits.
 *
 * Differences from `dns.lookup`, by design: `/etc/hosts`, nsswitch, and
 * resolv.conf `search` domains are not consulted; only DNS is. Nameservers
 * come from the system configuration or from `dns.setServers()`.
 *
 * When one family resolves and the other fails, the addresses that did
 * resolve are returned. When neither yields addresses, the most informative
 * error is thrown (a timeout or server failure in preference to "no
 * records"). IP literals are returned as-is without a query.
 *
 * Concurrent calls for the same host and family share one query, and its
 * outcome is reused for the record TTL (capped at 30 seconds) or, for a
 * failure, for 2 seconds. A caller that times out or aborts stops waiting
 * without affecting the others. Every caller still validates the addresses
 * it gets, so a reused answer is checked just like a fresh one.
 */
export async function resolveHost(
  hostname: string,
  options: ResolveHostOptions = {},
): Promise<LookupAddress[]> {
  const { family = 0, signal, timeoutMs = DEFAULT_DNS_TIMEOUT_MS } = options;
  signal?.throwIfAborted();

  const literalFamily = net.isIP(hostname);
  if (literalFamily) {
    return [{ address: hostname, family: literalFamily }];
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  const stopped = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(dnsError(dns.TIMEOUT, 'queryA', hostname)),
      timeoutMs,
    );
    if (signal) {
      onAbort = () => reject(signal.reason);
      signal.addEventListener('abort', onAbort, { once: true });
    }
  });
  stopped.catch(() => {
    // Settling after the race is decided is harmless; keep it from surfacing
    // as an unhandled rejection.
  });

  try {
    const outcome = await Promise.race([
      resolveShared(hostname, family),
      stopped,
    ]);
    if ('error' in outcome) {
      throw outcome.error;
    }
    return [...outcome.addresses];
  } finally {
    clearTimeout(timer);
    if (onAbort) {
      signal?.removeEventListener('abort', onAbort);
    }
  }
}

type Outcome = { addresses: readonly LookupAddress[] } | { error: unknown };

interface CacheEntry {
  outcome: Outcome;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();
const inflight = new Map<string, Promise<Outcome>>();

/**
 * Returns the cached outcome for `hostname`, joins a query already in
 * flight, or starts one. Never rejects: failures are returned as outcomes so
 * they can be cached and shared like answers.
 */
function resolveShared(hostname: string, family: number): Promise<Outcome> {
  // First, so that a `dns.setServers()` change drops answers from the old
  // servers before the cache is read.
  const resolver = getResolver();
  const key = `${family}/${hostname.toLowerCase()}`;

  const cached = cache.get(key);
  if (cached) {
    if (cached.expiresAt > Date.now()) {
      return Promise.resolve(cached.outcome);
    }
    cache.delete(key);
  }

  const joined = inflight.get(key);
  if (joined) {
    return joined;
  }

  const pending = query(resolver, hostname, family).then(
    ({ addresses, ttlMs }) => settle({ addresses }, ttlMs),
    (error: unknown) => settle({ error }, NEGATIVE_CACHE_TTL_MS),
  );
  function settle(outcome: Outcome, ttlMs: number): Outcome {
    if (inflight.get(key) === pending) {
      inflight.delete(key);
    }
    // Answers from servers that `dns.setServers()` has since replaced are
    // handed to the callers that waited for them, but not reused.
    if (ttlMs > 0 && resolver === sharedResolver) {
      cacheOutcome(key, outcome, ttlMs);
    }
    return outcome;
  }
  inflight.set(key, pending);
  return pending;
}

function cacheOutcome(key: string, outcome: Outcome, ttlMs: number): void {
  cache.delete(key);
  if (cache.size >= MAX_CACHE_ENTRIES) {
    const oldest = cache.keys().next();
    if (!oldest.done) {
      cache.delete(oldest.value);
    }
  }
  cache.set(key, { outcome, expiresAt: Date.now() + ttlMs });
}

/** Forgets every cached and in-flight resolution. For tests. */
export function clearResolveHostCache(): void {
  cache.clear();
  inflight.clear();
}

const NO_RECORDS: ReadonlySet<string> = new Set([dns.NODATA, dns.NOTFOUND]);

async function query(
  resolver: dns.promises.Resolver,
  hostname: string,
  family: number,
): Promise<{ addresses: LookupAddress[]; ttlMs: number }> {
  const none = Promise.resolve<dns.RecordWithTtl[]>([]);
  const [v4, v6] = await Promise.allSettled([
    family === 6 ? none : resolver.resolve4(hostname, { ttl: true }),
    family === 4 ? none : resolver.resolve6(hostname, { ttl: true }),
  ]);

  const v4Records = v4.status === 'fulfilled' ? v4.value : [];
  const v6Records = v6.status === 'fulfilled' ? v6.value : [];
  const ipv4 = toAddresses(v4Records, 4);
  const ipv6 = toAddresses(v6Records, 6);
  const addresses =
    dns.getDefaultResultOrder() === 'ipv6first'
      ? [...ipv6, ...ipv4]
      : [...ipv4, ...ipv6];
  if (addresses.length > 0) {
    const ttlSeconds = Math.min(
      ...[...v4Records, ...v6Records].map((record) => record.ttl),
    );
    return {
      addresses,
      ttlMs: Math.min(Math.max(ttlSeconds, 0) * 1_000, MAX_CACHE_TTL_MS),
    };
  }

  const failures = [v4, v6].flatMap((result) =>
    result.status === 'rejected'
      ? [result.reason as NodeJS.ErrnoException]
      : [],
  );
  throw (
    failures.find((error) => !NO_RECORDS.has(String(error?.code))) ??
    failures[0] ??
    dnsError(dns.NOTFOUND, 'queryA', hostname)
  );
}

function toAddresses(
  records: dns.RecordWithTtl[],
  family: 4 | 6,
): LookupAddress[] {
  return records.map(({ address }) => ({ address, family }));
}

let sharedResolver: dns.promises.Resolver | undefined;
let sharedResolverServers = '';

/**
 * One resolver for the process, multiplexing every query over a single
 * socket per nameserver. Rebuilt when `dns.setServers()` changes the
 * servers, because a resolver's servers cannot change while it has queries
 * in flight; queries already running finish on the old one.
 */
function getResolver(): dns.promises.Resolver {
  const servers = dns.getServers();
  const key = servers.join(',');
  if (!sharedResolver || key !== sharedResolverServers) {
    const resolver = new dns.promises.Resolver({
      timeout: ATTEMPT_TIMEOUT_MS,
      tries: ATTEMPTS,
    });
    if (servers.length > 0) {
      resolver.setServers(servers);
    }
    clearResolveHostCache();
    sharedResolver = resolver;
    sharedResolverServers = key;
  }
  return sharedResolver;
}

function dnsError(
  code: string,
  syscall: string,
  hostname: string,
): NodeJS.ErrnoException {
  return Object.assign(new Error(`${syscall} ${code} ${hostname}`), {
    code,
    syscall,
    hostname,
  });
}

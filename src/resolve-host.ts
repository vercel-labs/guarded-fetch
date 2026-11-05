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
    return await Promise.race([
      query(getResolver(), hostname, family),
      stopped,
    ]);
  } finally {
    clearTimeout(timer);
    if (onAbort) {
      signal?.removeEventListener('abort', onAbort);
    }
  }
}

const NO_RECORDS: ReadonlySet<string> = new Set([dns.NODATA, dns.NOTFOUND]);

async function query(
  resolver: dns.promises.Resolver,
  hostname: string,
  family: number,
): Promise<LookupAddress[]> {
  const none = Promise.resolve<string[]>([]);
  const [v4, v6] = await Promise.allSettled([
    family === 6 ? none : resolver.resolve4(hostname),
    family === 4 ? none : resolver.resolve6(hostname),
  ]);

  const ipv4 = v4.status === 'fulfilled' ? toAddresses(v4.value, 4) : [];
  const ipv6 = v6.status === 'fulfilled' ? toAddresses(v6.value, 6) : [];
  const addresses =
    dns.getDefaultResultOrder() === 'ipv6first'
      ? [...ipv6, ...ipv4]
      : [...ipv4, ...ipv6];
  if (addresses.length > 0) {
    return addresses;
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

function toAddresses(records: string[], family: 4 | 6): LookupAddress[] {
  return records.map((address) => ({ address, family }));
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

import type { LookupAddress } from 'node:dns';
import { lookup } from 'node:dns/promises';
import net from 'node:net';

import { isAddressUnsafeForServerSideFetch } from './ip-address';
import {
  HostnameUnsafeSubReason,
  type HostnameUnsafeSubReason as HostnameUnsafeSubReasonType,
} from './url-blocked';

/**
 * Normalizes a host or `https://host:port`-style value to a hostname for DNS
 * lookup. Kept package-local so guarded-fetch does not rely on monorepo helpers.
 */
export function parseHostnameForOutboundLookup(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    return '';
  }
  try {
    if (trimmed.includes('://')) {
      return new URL(trimmed).hostname;
    }
    return new URL(`https://${trimmed}`).hostname;
  } catch {
    return trimmed.split(':')[0] ?? '';
  }
}

export type HostnameSafetyResult =
  | { safe: true }
  | { safe: false; subReason: HostnameUnsafeSubReasonType };

/**
 * Checks that need no DNS: reserved names and IP literals. Returns `undefined`
 * when the answer depends on what the name resolves to.
 *
 * Shared by {@link checkHostnameSafetyForServerSideFetch} and
 * `createGuardedFetch`, which leaves DNS to the connector, so both entry
 * points block the same names. Trailing dots are ignored for the name checks
 * (`localhost.` is still `localhost`).
 */
export function classifyHostnameWithoutDns(
  hostname: string,
): HostnameSafetyResult | undefined {
  const host = hostname
    .toLowerCase()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.+$/, '');
  if (!host) {
    return { safe: false, subReason: HostnameUnsafeSubReason.INVALID };
  }
  if (host === 'localhost' || host.endsWith('.localhost')) {
    return { safe: false, subReason: HostnameUnsafeSubReason.LOCALHOST };
  }
  // `.local` is mDNS; `.internal` is reserved for private use (ICANN, 2024).
  if (
    host === 'local' ||
    host.endsWith('.local') ||
    host === 'internal' ||
    host.endsWith('.internal')
  ) {
    return { safe: false, subReason: HostnameUnsafeSubReason.LOCAL_DOMAIN };
  }

  if (net.isIP(host)) {
    return isAddressUnsafeForServerSideFetch(host)
      ? { safe: false, subReason: HostnameUnsafeSubReason.IP_LITERAL_UNSAFE }
      : { safe: true };
  }

  return undefined;
}

/**
 * Classifies whether `hostname` is safe for server-side outbound HTTP(S).
 * Uses the same OS resolver path that undici's connect-time lookup uses.
 */
export async function checkHostnameSafetyForServerSideFetch(
  hostname: string,
): Promise<HostnameSafetyResult> {
  const withoutDns = classifyHostnameWithoutDns(hostname);
  if (withoutDns) {
    return withoutDns;
  }

  // Resolve the name as given: `intranet.` and `intranet` can resolve
  // differently once resolver search domains apply.
  const host = hostname.toLowerCase();
  let addresses: LookupAddress[];
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    return {
      safe: false,
      subReason: HostnameUnsafeSubReason.DNS_RESOLUTION_FAILED,
    };
  }

  if (addresses.length === 0) {
    return {
      safe: false,
      subReason: HostnameUnsafeSubReason.DNS_RESOLUTION_FAILED,
    };
  }

  if (
    addresses.some(({ address }) => isAddressUnsafeForServerSideFetch(address))
  ) {
    return {
      safe: false,
      subReason: HostnameUnsafeSubReason.DNS_UNSAFE_ADDRESS,
    };
  }

  return { safe: true };
}

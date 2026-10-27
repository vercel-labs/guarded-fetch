import net from 'node:net';

import ipaddr from 'ipaddr.js';

/**
 * Fallback classifier: anything `ipaddr.js` does not consider plain global
 * `unicast` (private, loopback, link-local, unique-local, multicast,
 * unspecified, broadcast, CGNAT, reserved, documentation, …) is unsafe.
 * Unparseable input is unsafe.
 */
function isNonUnicastAddress(address: string): boolean {
  try {
    return ipaddr.parse(address).range() !== 'unicast';
  } catch {
    return true;
  }
}

/**
 * IPv4 ranges checked explicitly so classification does not depend on any
 * one library's range table: `0.0.0.0/8` (Linux routes `0.0.0.0` to
 * loopback), `100.64.0.0/10` CGNAT, `192.0.0.0/24` (IETF protocol
 * assignments), `198.18.0.0/15` (benchmark), `224.0.0.0/4` multicast, and
 * `240.0.0.0/4` reserved (which includes `255.255.255.255`).
 */
function isUnsafeIpv4Address(v4: string): boolean {
  const parts = v4.split('.');
  if (parts.length !== 4) {
    return false;
  }
  const octets = parts.map((p) => Number.parseInt(p, 10));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  const a = octets[0] as number;
  const b = octets[1] as number;
  const c = octets[2] as number;
  if (a === 0) {
    return true;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return true;
  }
  if (a === 192 && b === 0 && c === 0) {
    return true;
  }
  if (a === 198 && b >= 18 && b <= 19) {
    return true;
  }
  if (a >= 224) {
    return true;
  }
  return isNonUnicastAddress(v4);
}

function normalizeIpv6Literal(address: string): string {
  if (net.isIP(address) !== 6) {
    return address.toLowerCase();
  }
  try {
    return new URL(`https://[${address}]/`).hostname.slice(1, -1).toLowerCase();
  } catch {
    return address.toLowerCase();
  }
}

function expandIpv6Hextets(v6: string): number[] | null {
  const withoutZone = normalizeIpv6Literal(v6).split('%')[0] ?? '';
  if (!withoutZone.includes('::')) {
    const parts = withoutZone.split(':');
    if (parts.length !== 8) {
      return null;
    }
    return parts.map((part) => Number.parseInt(part, 16));
  }

  const [head, tail] = withoutZone.split('::');
  const headParts = head ? head.split(':') : [];
  const tailParts = tail ? tail.split(':') : [];
  const missing = 8 - headParts.length - tailParts.length;
  if (missing < 0) {
    return null;
  }
  const all = [...headParts, ...Array(missing).fill('0'), ...tailParts];
  if (all.length !== 8) {
    return null;
  }
  return all.map((part) => Number.parseInt(part || '0', 16));
}

function ipv4FromHextetPair(hi: number, lo: number): string {
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

/**
 * Decodes IPv4 addresses embedded in IPv4-mapped (`::ffff:0:0/96`), 6to4
 * (`2002::/16`), and NAT64 well-known prefix (`64:ff9b::/96`) literals so
 * they can be checked with the same IPv4 classifier as native IPv4.
 *
 * The RFC 8215 local-use prefix `64:ff9b:1::/48` is not decoded here — it is
 * rejected wholesale by {@link isUnsafeIpv6Address}. Its translation-prefix
 * length is chosen by the deployment, so the embedded IPv4 could sit at any
 * of the RFC 6052 §2.2 offsets and there is no way to tell which from the
 * literal alone.
 */
function tryDecodeEmbeddedIpv4FromIpv6(v6: string): string | null {
  const hextets = expandIpv6Hextets(v6);
  if (!hextets) {
    return null;
  }

  const [h0, h1, h2, h3, h4, h5, h6, h7] = hextets;

  // IPv4-mapped — RFC 4291: ::ffff:<ipv4>, in any spelling (expanded,
  // dotted, or hex).
  if (
    h0 === 0 &&
    h1 === 0 &&
    h2 === 0 &&
    h3 === 0 &&
    h4 === 0 &&
    h5 === 0xffff
  ) {
    return ipv4FromHextetPair(h6 as number, h7 as number);
  }

  // 6to4 — RFC 3056: 2002:<ipv4-high>:<ipv4-low>:...
  if (h0 === 0x2002) {
    return ipv4FromHextetPair(h1 as number, h2 as number);
  }

  // NAT64 well-known prefix — RFC 6052: 64:ff9b::<ipv4>
  if (
    h0 === 0x0064 &&
    h1 === 0xff9b &&
    h2 === 0 &&
    h3 === 0 &&
    h4 === 0 &&
    h5 === 0
  ) {
    return ipv4FromHextetPair(h6 as number, h7 as number);
  }

  return null;
}

/**
 * IPv6 ranges checked explicitly: unique local `fc00::/7`, link-local
 * `fe80::/10`, deprecated site-local `fec0::/10`, multicast `ff00::/8`,
 * documentation `2001:db8::/32` and `3fff::/20`, the NAT64 local-use prefix
 * `64:ff9b:1::/48`, IPv4-compatible `::/96`, and IPv4-translated
 * `::ffff:0:0:0/96`.
 */
function isUnsafeIpv6Address(v6: string): boolean {
  const lower = normalizeIpv6Literal(v6);

  if (lower === '::' || lower === '::1') {
    return true;
  }

  // 64:ff9b:1::/48 — RFC 8215 local-use NAT64. `ipaddr.js` classifies this as
  // ordinary unicast, but a translator on the path rewrites it to whatever
  // IPv4 address is encoded in the low bits — including private and metadata
  // space. The prefix length is deployment-defined, so the embedded IPv4 can
  // sit at any RFC 6052 §2.2 offset and cannot be recovered reliably from the
  // literal. Reject the range outright: it addresses a local translator and
  // is never a legitimate target for an outbound fetch.
  if (/^64:ff9b:1(?::|$)/i.test(lower)) {
    return true;
  }

  // fc00::/7 — unique local
  if (lower.startsWith('fc') || lower.startsWith('fd')) {
    return true;
  }

  // fe80::/10 — link-local
  if (/^fe[89ab]/i.test(lower)) {
    return true;
  }

  // fec0::/10 — deprecated site-local
  if (/^fe[c-f]/i.test(lower)) {
    return true;
  }

  // ff00::/8 — multicast
  if (lower.startsWith('ff')) {
    return true;
  }

  // 2001:db8::/32 — documentation
  if (/^2001:0?db8(?::|$)/i.test(lower)) {
    return true;
  }

  const hextets = expandIpv6Hextets(v6);

  // 3fff::/20 — RFC 9637 documentation range.
  if (hextets?.[0] === 0x3fff && ((hextets[1] ?? 0) & 0xf000) === 0) {
    return true;
  }

  // ::/96 IPv4-compatible (deprecated, RFC 4291 §2.5.5.1) and
  // ::ffff:0:0:0/96 IPv4-translated (RFC 2765 SIIT). Neither is a routable
  // destination; both only make sense to a local stack or translator, which
  // may forward to whatever IPv4 sits in the low bits. Reject the ranges
  // outright rather than decoding, so a public-looking embedded IPv4 cannot
  // unlock them.
  if (
    hextets?.slice(0, 4).every((h) => h === 0) &&
    ((hextets[4] === 0 && hextets[5] === 0) ||
      (hextets[4] === 0xffff && hextets[5] === 0))
  ) {
    return true;
  }

  return isNonUnicastAddress(v6);
}

/**
 * IP-classification primitive for SSRF guards. Explicitly handles ranges
 * unsafe for server-side fetches (`0.0.0.0/8`, CGNAT, multicast,
 * reserved/broadcast, benchmark, IETF assignments), the WHATWG-normalized
 * IPv4-mapped IPv6 forms (dotted `::ffff:a.b.c.d` and hex `::ffff:a9fe:a9fe`),
 * and 6to4 (`2002::/16`) / NAT64 (`64:ff9b::/96`) embedded IPv4 literals,
 * with `ipaddr.js` non-unicast classification as the fallback.
 */
export function isAddressUnsafeForServerSideFetch(address: string): boolean {
  if (!address) {
    return true;
  }

  if (net.isIP(address) === 4) {
    return isUnsafeIpv4Address(address);
  }

  if (net.isIP(address) === 6) {
    const embeddedIpv4 = tryDecodeEmbeddedIpv4FromIpv6(address);
    if (embeddedIpv4 !== null) {
      return isUnsafeIpv4Address(embeddedIpv4);
    }
    return isUnsafeIpv6Address(address);
  }

  return isNonUnicastAddress(address);
}

/**
 * Returns `true` if `address` is safe to connect to from server-side code
 * (i.e. not loopback, not private, not link-local).
 */
export function isSafeIpAddress(address: string): boolean {
  return !isAddressUnsafeForServerSideFetch(address);
}

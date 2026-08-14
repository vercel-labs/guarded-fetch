import { describe, expect, it } from 'vitest';

import {
  isAddressUnsafeForServerSideFetch,
  isSafeIpAddress,
} from './ip-address';

describe(isAddressUnsafeForServerSideFetch, () => {
  it('treats empty input as unsafe', () => {
    expect(isAddressUnsafeForServerSideFetch('')).toBe(true);
  });

  it.each([
    ['127.0.0.1', 'loopback'],
    ['10.0.0.1', 'RFC1918'],
    ['169.254.169.254', 'link-local metadata'],
    ['0.0.0.0', 'unspecified'],
    ['0.0.0.1', '0.0.0.0/8'],
    ['0.255.255.255', '0.0.0.0/8 upper boundary'],
    ['100.64.0.1', 'CGNAT 100.64.0.0/10'],
    ['100.127.255.255', 'CGNAT upper boundary'],
    ['192.0.0.1', '192.0.0.0/24'],
    ['192.0.0.255', '192.0.0.0/24 upper boundary'],
    ['198.18.0.1', '198.18.0.0/15'],
    ['198.19.255.255', '198.18.0.0/15 upper boundary'],
    ['224.0.0.1', 'multicast 224.0.0.0/4'],
    ['239.255.255.255', 'multicast upper boundary'],
    ['240.0.0.1', 'reserved 240.0.0.0/4'],
    ['255.255.255.255', 'limited broadcast'],
  ])('blocks unsafe IPv4: %s (%s)', (address: string) => {
    expect(isAddressUnsafeForServerSideFetch(address)).toBe(true);
    expect(isSafeIpAddress(address)).toBe(false);
  });

  it.each([
    ['100.63.255.255'],
    ['100.128.0.0'],
    ['192.0.1.1'],
    ['8.8.8.8'],
    ['93.184.216.34'],
  ])('allows public IPv4: %s', (address: string) => {
    expect(isAddressUnsafeForServerSideFetch(address)).toBe(false);
    expect(isSafeIpAddress(address)).toBe(true);
  });

  it('allows IPv4-mapped IPv6 hex form of a public address', () => {
    expect(isAddressUnsafeForServerSideFetch('::ffff:0808:0808')).toBe(false);
  });

  it.each([
    ['::ffff:0.0.0.1', '0.0.0.0/8 dotted mapped'],
    ['::ffff:6440:1', 'CGNAT mapped hex'],
    ['::ffff:a9fe:a9fe', 'metadata mapped hex'],
    ['::ffff:7f00:1', 'loopback mapped hex'],
  ])('blocks IPv4-mapped IPv6 hex form: %s (%s)', (address: string) => {
    expect(isAddressUnsafeForServerSideFetch(address)).toBe(true);
  });

  it('blocks IPv4-mapped IPv6 dotted form of private address', () => {
    expect(isAddressUnsafeForServerSideFetch('::ffff:10.0.0.1')).toBe(true);
  });

  it.each([
    ['::1', 'loopback'],
    ['fe80::1', 'link-local fe80::/10'],
    ['fc00::1', 'unique local fc00::/7'],
    ['fec0::1', 'deprecated site-local fec0::/10'],
    ['ff02::1', 'multicast ff00::/8'],
    ['2001:db8::1', 'documentation 2001:db8::/32'],
    ['::', 'unspecified'],
  ])('blocks unsafe IPv6: %s (%s)', (address: string) => {
    expect(isAddressUnsafeForServerSideFetch(address)).toBe(true);
  });

  it('allows public IPv6', () => {
    expect(isAddressUnsafeForServerSideFetch('2001:4860:4860::8888')).toBe(
      false,
    );
  });

  it.each([
    ['2002:7f00:0001::', '6to4 loopback'],
    ['2002:0a00:0001::', '6to4 RFC1918'],
    ['64:ff9b::a9fe:a9fe', 'NAT64 metadata'],
    ['64:ff9b::7f00:0001', 'NAT64 loopback'],
  ])('blocks embedded IPv4 in IPv6 encodings: %s (%s)', (address: string) => {
    expect(isAddressUnsafeForServerSideFetch(address)).toBe(true);
    expect(isSafeIpAddress(address)).toBe(false);
  });

  it.each([
    ['2002:0808:0808::', '6to4 public'],
    ['64:ff9b::0808:0808', 'NAT64 public'],
  ])(
    'allows public embedded IPv4 in IPv6 encodings: %s (%s)',
    (address: string) => {
      expect(isAddressUnsafeForServerSideFetch(address)).toBe(false);
      expect(isSafeIpAddress(address)).toBe(true);
    },
  );

  // RFC 8215 local-use NAT64 (64:ff9b:1::/48) is rejected as a whole range.
  // The translation prefix length is deployment-defined, so the embedded IPv4
  // can sit at any RFC 6052 §2.2 offset — including the public-looking ones,
  // which is why the last two cases are blocked too.
  it.each([
    ['64:ff9b:1::a9fe:a9fe', '/96 metadata'],
    ['64:ff9b:1:a9fe:0:a9fe::', '/48 metadata'],
    ['64:ff9b:1:0:a9:fea9:fe00:0', '/64 metadata'],
    ['64:ff9b:1::7f00:1', '/96 loopback'],
    ['64:ff9b:1::a00:1', '/96 RFC1918'],
    ['64:ff9b:1::', 'bare prefix'],
    ['64:ff9b:1::0808:0808', '/96 public-looking'],
    ['64:ff9b:1:0808:0:0808::', '/48 public-looking'],
  ])('blocks local-use NAT64 prefix: %s (%s)', (address: string) => {
    expect(isAddressUnsafeForServerSideFetch(address)).toBe(true);
    expect(isSafeIpAddress(address)).toBe(false);
  });

  it.each([
    ['64:ff9b:10::0808:0808', 'distinct prefix, not 64:ff9b:1::/48'],
    ['64:ff9c:1::0808:0808', 'distinct prefix, not NAT64'],
  ])(
    'does not over-block neighbouring prefixes: %s (%s)',
    (address: string) => {
      expect(isAddressUnsafeForServerSideFetch(address)).toBe(false);
      expect(isSafeIpAddress(address)).toBe(true);
    },
  );
});

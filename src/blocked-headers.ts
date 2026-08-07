/**
 * Headers that must never be forwarded on outbound requests driven by
 * user-supplied configuration (webhooks, log drains, OIDC, image registries,
 * HAR proxying, etc.).
 *
 * Forwarding these enables four classes of abuse:
 *
 * 1. **Virtual-host routing confusion** — a user-supplied `Host` header can
 *    cause a proxy or load balancer to dispatch the request to an unintended
 *    internal backend that would normally be unreachable.
 * 2. **Proxy / origin-IP spoofing** — `X-Forwarded-*`, `Forwarded`, `Via`, and
 *    `X-Real-IP` can be used to impersonate a trusted client IP to a downstream
 *    service that trusts those headers.
 * 3. **SSRF escalation via cloud metadata services** — `Metadata-Flavor: Google`
 *    and `X-aws-ec2-metadata-token` are required by GCP and AWS IMDSv2 to serve
 *    instance credentials. A user that can control headers on an outbound
 *    request can use them to exfiltrate cloud credentials if the SSRF check is
 *    ever bypassed.
 * 4. **Session / cookie hijacking** — `Cookie` and `Set-Cookie` may leak
 *    internal session state to the destination.
 *
 * Additionally, hop-by-hop headers are stripped because they apply only to a
 * single transport connection and forwarding them corrupts connection
 * semantics (RFC 7230 §6.1).
 *
 * All comparisons are case-insensitive.
 */
export const BLOCKED_REQUEST_HEADERS: ReadonlySet<string> = new Set([
  // Hop-by-hop / transport (RFC 7230 §6.1)
  'connection',
  'keep-alive',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',

  // Host / virtual-host routing
  'host',

  // Proxy / origin spoofing
  'forwarded',
  'proxy-authorization',
  'via',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',

  // Cloud metadata (GCP, AWS IMDSv1/v2, Azure, Alibaba, DigitalOcean)
  'metadata',
  'metadata-flavor',
  'x-aws-ec2-metadata-token',
  'x-metadata-token',

  // Session / cookie
  'cookie',
  'set-cookie',
]);

import { BadRequestException } from '@nestjs/common';
import { isIP } from 'net';
import { lookup } from 'dns/promises';

/**
 * SSRF protection for outbound URLs (webhooks).
 *
 * Webhook URLs are attacker-controlled (anyone with an OPERATOR key can register one),
 * so an unvalidated URL lets a caller make the server issue requests to internal
 * services / cloud metadata endpoints. This module rejects non-http(s) schemes and
 * any target that resolves to a private, loopback, link-local or metadata address.
 *
 * Set OPENWA_ALLOW_PRIVATE_WEBHOOKS=true to bypass (development / trusted LAN only).
 */

const CLOUD_METADATA_HOSTS = new Set(['metadata.google.internal', 'metadata.goog']);

function allowsPrivate(): boolean {
  return process.env.OPENWA_ALLOW_PRIVATE_WEBHOOKS === 'true';
}

/** Returns true if the given IPv4/IPv6 literal is private, loopback, link-local, etc. */
export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);

  if (version === 4) {
    const parts = ip.split('.').map(n => parseInt(n, 10));
    if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) {
      return true; // malformed → treat as unsafe
    }
    const [a, b] = parts;
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // loopback 127.0.0.0/8
    if (a === 0) return true; // 0.0.0.0/8 "this host"
    if (a === 169 && b === 254) return true; // link-local 169.254.0.0/16 (incl. cloud metadata 169.254.169.254)
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    if (a >= 224) return true; // multicast / reserved
    return false;
  }

  if (version === 6) {
    const v6 = ip.toLowerCase().replace(/^\[|\]$/g, '');
    if (v6 === '::1' || v6 === '::') return true; // loopback / unspecified
    if (v6.startsWith('fe80')) return true; // link-local
    if (v6.startsWith('fc') || v6.startsWith('fd')) return true; // unique-local fc00::/7
    if (v6.startsWith('::ffff:')) {
      // IPv4-mapped IPv6 → re-check the embedded IPv4
      return isPrivateAddress(v6.substring(7));
    }
    return false;
  }

  // Not a literal IP → caller must resolve DNS first
  return false;
}

/**
 * Validate that a webhook URL is safe to call. Throws BadRequestException otherwise.
 * Resolves DNS at registration time to catch hostnames pointing at internal hosts.
 */
export async function assertSafeWebhookUrl(rawUrl: string): Promise<void> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new BadRequestException('Webhook URL is not a valid URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new BadRequestException(`Webhook URL scheme '${url.protocol}' is not allowed (use http or https)`);
  }

  if (allowsPrivate()) return;

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (host === 'localhost' || host.endsWith('.localhost') || CLOUD_METADATA_HOSTS.has(host)) {
    throw new BadRequestException('Webhook URL points to a disallowed (internal) host');
  }

  // Literal IP → check directly
  if (isIP(host)) {
    if (isPrivateAddress(host)) {
      throw new BadRequestException('Webhook URL points to a private or reserved IP address');
    }
    return;
  }

  // Hostname → resolve and verify every returned address is public
  let addresses: { address: string }[];
  try {
    addresses = await lookup(host, { all: true });
  } catch {
    throw new BadRequestException(`Webhook URL host '${host}' could not be resolved`);
  }

  if (addresses.some(a => isPrivateAddress(a.address))) {
    throw new BadRequestException('Webhook URL host resolves to a private or reserved IP address');
  }
}

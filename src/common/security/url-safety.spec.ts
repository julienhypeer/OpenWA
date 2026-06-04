import { BadRequestException } from '@nestjs/common';
import { isPrivateAddress, assertSafeWebhookUrl } from './url-safety';

describe('url-safety', () => {
  describe('isPrivateAddress', () => {
    it.each([
      ['127.0.0.1', true],
      ['10.1.2.3', true],
      ['172.16.0.1', true],
      ['172.31.255.255', true],
      ['192.168.1.1', true],
      ['169.254.169.254', true], // cloud metadata
      ['100.64.0.1', true], // CGNAT
      ['0.0.0.0', true],
      ['8.8.8.8', false],
      ['1.1.1.1', false],
      ['172.32.0.1', false], // just outside 172.16/12
    ])('IPv4 %s -> private=%s', (ip, expected) => {
      expect(isPrivateAddress(ip)).toBe(expected);
    });

    it.each([
      ['::1', true],
      ['fe80::1', true],
      ['fc00::1', true],
      ['fd12::1', true],
      ['::ffff:127.0.0.1', true], // IPv4-mapped loopback
      ['2606:4700:4700::1111', false], // public (cloudflare)
    ])('IPv6 %s -> private=%s', (ip, expected) => {
      expect(isPrivateAddress(ip)).toBe(expected);
    });

    it('does not classify non-IP strings (handled via DNS resolution upstream)', () => {
      expect(isPrivateAddress('999.1.1.1')).toBe(false);
      expect(isPrivateAddress('example.com')).toBe(false);
    });
  });

  describe('assertSafeWebhookUrl', () => {
    const orig = process.env.OPENWA_ALLOW_PRIVATE_WEBHOOKS;
    afterEach(() => {
      process.env.OPENWA_ALLOW_PRIVATE_WEBHOOKS = orig;
    });

    it('rejects non-http(s) schemes', async () => {
      await expect(assertSafeWebhookUrl('file:///etc/passwd')).rejects.toBeInstanceOf(BadRequestException);
      await expect(assertSafeWebhookUrl('ftp://example.com')).rejects.toBeInstanceOf(BadRequestException);
    });

    it('rejects malformed URLs', async () => {
      await expect(assertSafeWebhookUrl('not a url')).rejects.toBeInstanceOf(BadRequestException);
    });

    it('rejects loopback / metadata literal IPs', async () => {
      await expect(assertSafeWebhookUrl('http://127.0.0.1:9000/x')).rejects.toBeInstanceOf(BadRequestException);
      await expect(assertSafeWebhookUrl('http://169.254.169.254/latest/meta-data/')).rejects.toBeInstanceOf(
        BadRequestException,
      );
      await expect(assertSafeWebhookUrl('http://192.168.0.5/hook')).rejects.toBeInstanceOf(BadRequestException);
    });

    it('rejects localhost hostname', async () => {
      await expect(assertSafeWebhookUrl('http://localhost:3000/hook')).rejects.toBeInstanceOf(BadRequestException);
    });

    it('allows public literal IP', async () => {
      await expect(assertSafeWebhookUrl('https://1.1.1.1/hook')).resolves.toBeUndefined();
    });

    it('bypasses all checks when OPENWA_ALLOW_PRIVATE_WEBHOOKS=true', async () => {
      process.env.OPENWA_ALLOW_PRIVATE_WEBHOOKS = 'true';
      await expect(assertSafeWebhookUrl('http://127.0.0.1:9000/x')).resolves.toBeUndefined();
    });
  });
});

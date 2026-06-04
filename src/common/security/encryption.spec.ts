// Use a fixed env key so tests never touch the filesystem key fallback.
process.env.OPENWA_ENCRYPTION_KEY = 'unit-test-master-key-please-ignore';

import { encryptSecret, decryptSecret, EncryptedTransformer } from './encryption';

describe('encryption', () => {
  it('round-trips a secret', () => {
    const plain = 'super-secret-hmac-key-123';
    const enc = encryptSecret(plain);
    expect(enc).not.toBe(plain);
    expect(enc.startsWith('enc:v1:')).toBe(true);
    expect(decryptSecret(enc)).toBe(plain);
  });

  it('produces a different ciphertext each time (random IV)', () => {
    const a = encryptSecret('same');
    const b = encryptSecret('same');
    expect(a).not.toBe(b);
    expect(decryptSecret(a)).toBe('same');
    expect(decryptSecret(b)).toBe('same');
  });

  it('returns legacy plaintext unchanged (backward compatible)', () => {
    expect(decryptSecret('plain-old-secret')).toBe('plain-old-secret');
  });

  it('keeps ciphertext within 255 chars for a 128-char secret', () => {
    const plain = 'x'.repeat(128);
    expect(encryptSecret(plain).length).toBeLessThanOrEqual(255);
  });

  describe('EncryptedTransformer', () => {
    it('encrypts on write and decrypts on read', () => {
      const stored = EncryptedTransformer.to('hello') as string;
      expect(stored.startsWith('enc:v1:')).toBe(true);
      expect(EncryptedTransformer.from(stored)).toBe('hello');
    });

    it('passes null/empty through untouched', () => {
      expect(EncryptedTransformer.to(null)).toBeNull();
      expect(EncryptedTransformer.from(null)).toBeNull();
      expect(EncryptedTransformer.to('')).toBeNull();
    });
  });
});

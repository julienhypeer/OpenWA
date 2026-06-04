import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import { existsSync, readFileSync, writeFileSync, chmodSync } from 'fs';
import { join } from 'path';
import { ValueTransformer } from 'typeorm';
import { createLogger } from '../services/logger.service';

/**
 * Symmetric encryption for secrets stored at rest (e.g. webhook HMAC secrets).
 *
 * AES-256-GCM with a per-value random IV. Encrypted values are tagged with a
 * version prefix so plaintext written before this change still decrypts
 * (decrypt() returns unrecognised input verbatim — backward compatible).
 *
 * Key resolution (in order):
 *   1. OPENWA_ENCRYPTION_KEY env — derived via scrypt (portable across hosts; recommended).
 *   2. data/.encryption-key file — auto-generated (0600) on first use if absent.
 *
 * NOTE: this module is intentionally framework-agnostic (no Nest DI) so it can
 * back a TypeORM ValueTransformer, which is constructed at entity-load time.
 */

const PREFIX = 'enc:v1:';
const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_FILE = join(process.cwd(), 'data', '.encryption-key');
const SCRYPT_SALT = 'openwa.enc.v1';

const logger = createLogger('Encryption');

let cachedKey: Buffer | null = null;

function loadKey(): Buffer {
  if (cachedKey) return cachedKey;

  const envKey = process.env.OPENWA_ENCRYPTION_KEY?.trim();
  if (envKey) {
    cachedKey = scryptSync(envKey, SCRYPT_SALT, 32);
    return cachedKey;
  }

  // Fall back to a persisted random key. Portable only as long as data/ survives,
  // so we warn the operator to set OPENWA_ENCRYPTION_KEY for real deployments.
  try {
    if (existsSync(KEY_FILE)) {
      const hex = readFileSync(KEY_FILE, 'utf-8').trim();
      const key = Buffer.from(hex, 'hex');
      if (key.length === 32) {
        cachedKey = key;
        return cachedKey;
      }
      logger.warn('Encryption key file is malformed, regenerating');
    }
    const generated = randomBytes(32);
    writeFileSync(KEY_FILE, generated.toString('hex'), { encoding: 'utf-8', mode: 0o600 });
    chmodSync(KEY_FILE, 0o600);
    logger.warn(
      'Generated a local encryption key at data/.encryption-key. Set OPENWA_ENCRYPTION_KEY in the environment for a portable, backup-safe key.',
    );
    cachedKey = generated;
    return cachedKey;
  } catch (err) {
    throw new Error(`Unable to initialise encryption key: ${String(err)}`);
  }
}

/** Encrypt a UTF-8 string. Returns a versioned, base64-encoded token. */
export function encryptSecret(plain: string): string {
  const key = loadKey();
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

/** Decrypt a token produced by encryptSecret(). Unrecognised input is returned as-is. */
export function decryptSecret(value: string): string {
  if (!value.startsWith(PREFIX)) {
    return value; // legacy plaintext written before encryption was enabled
  }
  const key = loadKey();
  const raw = Buffer.from(value.slice(PREFIX.length), 'base64');
  const iv = raw.subarray(0, IV_LEN);
  const tag = raw.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ciphertext = raw.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8');
}

/**
 * TypeORM transformer that transparently encrypts on write and decrypts on read.
 * Null/empty values pass through untouched.
 */
export const EncryptedTransformer: ValueTransformer = {
  to: (value: string | null): string | null => (value ? encryptSecret(value) : null),
  from: (value: string | null): string | null => (value ? decryptSecret(value) : null),
};

import crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 100_000;
const KEY_LENGTH = 32;
const DIGEST = 'sha512';

/**
 * Derives a 256-bit encryption key from a master password and salt.
 */
export function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, DIGEST);
}

/**
 * Encrypts a plaintext buffer using AES-256-GCM with authenticated metadata.
 * Payload layout: [ Salt (32B) | IV (16B) | AuthTag (16B) | Ciphertext (NB) ]
 */
export function encryptBuffer(buffer, password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, authTag, ciphertext]);
}

/**
 * Decrypts a payload previously encrypted with encryptBuffer.
 * Throws an error if tampered with or if password is incorrect.
 */
export function decryptBuffer(encryptedBuffer, password) {
  if (encryptedBuffer.length < SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error('Invalid ciphertext payload: Buffer too small.');
  }

  const salt = encryptedBuffer.subarray(0, SALT_LENGTH);
  const iv = encryptedBuffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = encryptedBuffer.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH
  );
  const ciphertext = encryptedBuffer.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new Error('Decryption failed: Authentication tag verification error (invalid password or corrupted data).');
  }
}

/**
 * Calculates SHA-256 file fingerprint for integrity verification.
 */
export function calculateChecksum(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

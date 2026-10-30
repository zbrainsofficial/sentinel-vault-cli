import crypto from 'node:crypto';

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}<>?~';

/**
 * Generates a cryptographically secure random password.
 */
export function generateSecurePassword(length = 24, includeSymbols = true) {
  const charset = UPPER + LOWER + DIGITS + (includeSymbols ? SYMBOLS : '');
  const bytes = crypto.randomBytes(length);
  let result = '';

  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }

  // Ensure minimum character variety
  const hasUpper = /[A-Z]/.test(result);
  const hasLower = /[a-z]/.test(result);
  const hasDigit = /[0-9]/.test(result);
  const hasSymbol = /[^A-Za-z0-9]/.test(result);

  if (!hasUpper || !hasLower || !hasDigit || (includeSymbols && !hasSymbol)) {
    return generateSecurePassword(length, includeSymbols);
  }

  return result;
}

/**
 * Measures entropy bits and strength category.
 */
export function evaluateEntropy(password) {
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^A-Za-z0-9]/.test(password)) poolSize += 32;

  const entropyBits = Math.floor(password.length * Math.log2(poolSize || 1));
  let level = 'Weak';
  if (entropyBits >= 80) level = 'Very Strong';
  else if (entropyBits >= 60) level = 'Strong';
  else if (entropyBits >= 40) level = 'Moderate';

  return { entropyBits, poolSize, level };
}

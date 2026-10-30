import assert from 'node:assert';
import { encryptBuffer, decryptBuffer, calculateChecksum } from '../lib/crypto.mjs';
import { generateSecurePassword, evaluateEntropy } from '../lib/pass-gen.mjs';

console.log('\x1b[35m=== Running SentinelVault Test Suite ===\x1b[0m\n');

// Test 1: Encryption & Decryption Roundtrip
const message = Buffer.from('Antigravity Automated Security Payload 2026!');
const password = 'SuperSecretMasterKey#2026';

const encrypted = encryptBuffer(message, password);
assert(encrypted.length > message.length, 'Encrypted buffer must include metadata');

const decrypted = decryptBuffer(encrypted, password);
assert.strictEqual(decrypted.toString(), message.toString(), 'Decrypted payload must match original');
assert.strictEqual(calculateChecksum(message), calculateChecksum(decrypted), 'SHA-256 fingerprints must match');
console.log('  [PASS] Encryption and Decryption Roundtrip verified.');

// Test 2: Tamper Protection (Authentication Tag failure)
let tampered = Buffer.from(encrypted);
tampered[tampered.length - 1] ^= 0x01; // flip last bit
let failed = false;
try {
  decryptBuffer(tampered, password);
} catch (e) {
  failed = true;
}
assert.strictEqual(failed, true, 'Tampered ciphertext must fail authentication');
console.log('  [PASS] Tamper protection (AEAD Authentication Tag) verified.');

// Test 3: Password Generator Entropy
const generatedPass = generateSecurePassword(32);
assert.strictEqual(generatedPass.length, 32);
const entropy = evaluateEntropy(generatedPass);
assert(entropy.entropyBits >= 150, '32-char complex password must have high entropy');
console.log(`  [PASS] Password Generator & Entropy rating verified (${entropy.entropyBits} bits).`);

console.log('\n\x1b[32m[ALL TESTS PASSED SUCCESSFULLY!]\x1b[0m');

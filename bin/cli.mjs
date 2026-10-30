#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { encryptBuffer, decryptBuffer, calculateChecksum } from '../lib/crypto.mjs';
import { generateSecurePassword, evaluateEntropy } from '../lib/pass-gen.mjs';

const [,, command, ...args] = process.argv;

function printHelp() {
  console.log(`
\x1b[36m=== SentinelVault CLI v1.0.0 ===\x1b[0m
Modern AES-256-GCM Zero-Knowledge Security Tool

\x1b[33mCommands:\x1b[0m
  encrypt <inputFile> <outputFile> <passphrase>   Encrypt file with AES-256-GCM
  decrypt <inputFile> <outputFile> <passphrase>   Decrypt & verify file integrity
  genpass [length]                               Generate high-entropy password
  audit <password>                               Evaluate password entropy score

\x1b[33mExamples:\x1b[0m
  node bin/cli.mjs encrypt secret.txt secret.enc "MyMasterPassword"
  node bin/cli.mjs decrypt secret.enc secret.dec "MyMasterPassword"
  node bin/cli.mjs genpass 32
  node bin/cli.mjs audit "X$9kL#2026@Safe!"
`);
}

switch (command) {
  case 'encrypt': {
    const [inputFile, outputFile, password] = args;
    if (!inputFile || !outputFile || !password) {
      console.error('\x1b[31mError: Missing arguments for encrypt.\x1b[0m');
      printHelp();
      process.exit(1);
    }
    const plain = fs.readFileSync(path.resolve(inputFile));
    const encrypted = encryptBuffer(plain, password);
    fs.writeFileSync(path.resolve(outputFile), encrypted);
    console.log(`\x1b[32m[✓] Encrypted successfully!\x1b[0m Output: ${outputFile}`);
    console.log(`    Original SHA-256: ${calculateChecksum(plain)}`);
    break;
  }

  case 'decrypt': {
    const [inputFile, outputFile, password] = args;
    if (!inputFile || !outputFile || !password) {
      console.error('\x1b[31mError: Missing arguments for decrypt.\x1b[0m');
      printHelp();
      process.exit(1);
    }
    try {
      const encrypted = fs.readFileSync(path.resolve(inputFile));
      const plain = decryptBuffer(encrypted, password);
      fs.writeFileSync(path.resolve(outputFile), plain);
      console.log(`\x1b[32m[✓] Decrypted and verified!\x1b[0m Output: ${outputFile}`);
      console.log(`    Decrypted SHA-256: ${calculateChecksum(plain)}`);
    } catch (err) {
      console.error(`\x1b[31m[✗] Decryption failed:\x1b[0m ${err.message}`);
      process.exit(1);
    }
    break;
  }

  case 'genpass': {
    const length = parseInt(args[0] || '24', 10);
    const pass = generateSecurePassword(length);
    const audit = evaluateEntropy(pass);
    console.log(`\x1b[32m[✓] Generated Password:\x1b[0m ${pass}`);
    console.log(`    Entropy: ${audit.entropyBits} bits (${audit.level})`);
    break;
  }

  case 'audit': {
    const password = args[0];
    if (!password) {
      console.error('\x1b[31mError: Provide a password to audit.\x1b[0m');
      process.exit(1);
    }
    const audit = evaluateEntropy(password);
    console.log(`\x1b[34m[Audit Report]\x1b[0m`);
    console.log(`  Length:        ${password.length}`);
    console.log(`  Entropy:       ${audit.entropyBits} bits`);
    console.log(`  Pool Size:     ${audit.poolSize} characters`);
    console.log(`  Rating:        ${audit.level}`);
    break;
  }

  default:
    printHelp();
}

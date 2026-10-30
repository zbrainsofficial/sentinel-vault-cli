# SentinelVault CLI 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: AES-256-GCM](https://img.shields.io/badge/Security-AES--256--GCM-green.svg)](#security-architecture)
[![Node.js Version](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)

> Zero-knowledge, authenticated symmetric encryption CLI and cryptographic password generator built with Node.js standard primitives.

---

## ⚡ Features

- **Authenticated AEAD Encryption:** Utilizes **AES-256-GCM** to ensure both confidentiality and cryptographic integrity. Tampered data is instantly rejected.
- **Key Derivation (PBKDF2):** 100,000 iterations of SHA-512 with a unique 32-byte salt per encryption to protect against rainbow-table attacks.
- **High-Entropy Password Generator:** Cryptographically secure pseudo-random number generator (CSPRNG) with built-in character diversity verification.
- **Entropy Analyzer:** Calculates Shannon entropy and strength classifications for arbitrary passphrases.
- **Zero External Dependencies:** Built entirely with native Node.js `crypto` primitives for maximum auditability and zero supply-chain risk.

---

## 🏗️ Security Architecture

```
[ Plaintext File ]
        │
        ▼
   PBKDF2 (100k rounds, Salt 32B, SHA-512) ──► Key (256-bit)
        │
        ▼
   AES-256-GCM (IV 16B) ──► Ciphertext + Auth Tag (16B)
        │
        ▼
[ Encrypted Output: Salt (32B) | IV (16B) | AuthTag (16B) | Ciphertext ]
```

---

## 🚀 Quick Start

### Prerequisites
- Node.js >= 18.0.0

### Run Tests
```bash
node test/test.mjs
```

### Encrypt a File
```bash
node bin/cli.mjs encrypt sensitive-data.txt sensitive-data.enc "YourSecretPassword"
```

### Decrypt a File
```bash
node bin/cli.mjs decrypt sensitive-data.enc recovered-data.txt "YourSecretPassword"
```

### Generate a Secure Passphrase
```bash
node bin/cli.mjs genpass 32
```

### Audit Passphrase Entropy
```bash
node bin/cli.mjs audit "MySuperComplexPassword#2026"
```

---

## 📜 License
MIT License. Free for open-source and commercial use.

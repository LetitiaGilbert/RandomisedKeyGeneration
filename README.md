# Randomised Key Generation

A Python project exploring secure cryptographic key generation using **ECDH, multiple entropy sources, HKDF-SHA512, and AES-256-GCM**.

## Features

- ECDH key exchange using **SECP256R1 (P-256)**
- Multiple entropy sources
- HKDF-SHA512 key derivation
- AES-256-GCM encryption and decryption
- Experimental image-based key generation

## How It Works

```text
ECDH Shared Secret
       +
System Entropy
       +
Secrets Entropy
       +
User Timing Entropy
       ↓
   HKDF-SHA512
       ↓
  AES-256 Key
       ↓
  AES-256-GCM
```

# Randomised Key Generation

A Python-based cryptographic project demonstrating **structured key derivation using HKDF (HMAC-based Key Derivation Function)** combined with **AES-256-GCM authenticated encryption**.

This project improves entropy of key generation by using a **cryptographically sound key derivation process** to securely generate AES keys.

---

## Project Overview

This implementation demonstrates:

- Multi-source entropy collection
- HKDF-based key derivation using SHA-512
- AES-256-GCM authenticated encryption (AEAD)
- Secure nonce generation
- Encryption + decryption workflow
- Integrity verification

---

## Entropy Sources

The AES-256 key is derived using three independent entropy sources:

### 1 User Timing Entropy
- Measures typing latency in nanoseconds.
- Captures human interaction randomness.
- Converted into 8 bytes of entropy.

### 2 System Entropy
- Generated using:
  ```python
  os.urandom(32)
  ```
- Cryptographically secure OS-level randomness.

### 3 Secrets Module Entropy
- Generated using:
  ```python
  secrets.token_bytes(32)
  ```
- Designed for secure token and key generation.

---

## Key Derivation Method (HKDF)

Instead of simple concatenation + hashing, this project uses **HKDF with SHA-512**.

### Why HKDF?

- Structured entropy extraction
- Secure key expansion
- Salt support (prevents precomputation attacks)
- Domain separation via `info` parameter
- Standardized cryptographic construction (RFC 5869)

### Key Derivation Process

1. Combine entropy sources → Input Keying Material (IKM)
2. Generate random salt (16 bytes)
3. Apply HKDF using SHA-512
4. Derive a 256-bit (32-byte) AES key

```python
hkdf = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    info=b"AES-256-GCM key derivation",
    backend=default_backend()
)
```

---

## Encryption Method: AES-256-GCM

AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** mode.

### Security Properties

- Confidentiality
- Integrity
- Authentication

### Nonce Generation

A secure 96-bit (12-byte) nonce is generated:

```python
secrets.token_bytes(12)
```

---

## Encryption & Decryption Flow

1. Generate secure AES-256 key using HKDF
2. Accept plaintext input
3. Generate secure random nonce
4. Encrypt plaintext
5. Decrypt ciphertext
6. Verify integrity

Integrity verification:

```python
decrypted == plaintext
```

If `True`, the ciphertext was not tampered with.

---

## Technologies Used

- Python 3.x
- `cryptography` library
- HKDF (SHA-512)
- AES-256-GCM
- `secrets`
- `os`
- `hashlib`
- `base64`
- `time`

---

## Installation

Install dependencies:

```bash
pip install cryptography
```

---

## How to Run

```bash
python keygen.py
```

Execution steps:

1. Provide random input for timing entropy.
2. Enter plaintext to encrypt.
3. View:
   - Combined entropy (IKM)
   - Salt
   - Derived AES key (Hex + Base64)
   - Nonce (Hex + Base64)
   - Ciphertext (Hex + Base64)
   - Decrypted output
   - Integrity check result

---

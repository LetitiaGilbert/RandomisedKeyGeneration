import secrets
import os
import hashlib
import time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

# Constants
KEY_SIZE = 32      # 256 bits
NONCE_SIZE = 12    # 96 bits for GCM

def user_entropy():
    print("\nStep 1a) Collect user entropy:")
    print("    Type some random text quickly and hit Enter:")
    start = time.time()
    _ = input()
    end = time.time()
    interval_ns = int((end - start) * 1e9)  # nanoseconds
    print(f"    Timing interval (ns): {interval_ns}")
    return interval_ns.to_bytes(8, 'big')   # 8 bytes

def generate_secure_key():
    timing_entropy = user_entropy()
    print("\nStep 1b) Collect system entropy:")
    system_entropy = os.urandom(KEY_SIZE)
    print("    System entropy (hex):", system_entropy.hex())

    print("\nStep 1c) Collect secrets entropy:")
    secret_entropy = secrets.token_bytes(KEY_SIZE)
    print("    Secrets entropy (hex):", secret_entropy.hex())

    print("\nStep 1d) Using HKDF for structured key derivation...")

    # Combine as input keying material (IKM)
    ikm = system_entropy + secret_entropy + timing_entropy
    print("    Combined IKM (hex):", ikm.hex())

    # Optional salt (adds randomness + protects against precomputation)
    salt = os.urandom(16)
    print("    Salt (hex):", salt.hex())
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=salt,
        info=b"AES-256-GCM key derivation",
        backend=default_backend()
    )

    key = hkdf.derive(ikm)

    print("    Final AES-256 key (hex):", key.hex())
    print("    Final AES-256 key (Base64):", base64.b64encode(key).decode())
    return key

def main():
    print("\n--- AES-256-GCM Key Generation ---\n")

    # Generate the AES key
    key = generate_secure_key()

    # Step 2: Define plaintext
    plaintext = input("\nStep 2) Enter text to encrypt: ").encode()
    print("    Plaintext (bytes):", plaintext)

    # Step 3: Create AES-GCM cipher
    aesgcm = AESGCM(key)

    # Step 4: Generate random nonce
    print("\nStep 3) Generate random nonce (12 bytes for GCM)...")
    nonce = secrets.token_bytes(NONCE_SIZE)
    print("    Nonce (hex):", nonce.hex())
    print("    Nonce (Base64):", base64.b64encode(nonce).decode())

    # Step 5: Encrypt
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    print("\nStep 4) Encrypt plaintext -> Ciphertext")
    print("    Ciphertext (hex):", ciphertext.hex())
    print("    Ciphertext (Base64):", base64.b64encode(ciphertext).decode())

    # Step 6: Decrypt
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    print("\nStep 5) Decrypt ciphertext -> Plaintext")
    print("    Decrypted text:", decrypted.decode())

    # Step 7: Verify integrity
    print("\nStep 6) Integrity check passed:", decrypted == plaintext)

if __name__ == "__main__":
    main()
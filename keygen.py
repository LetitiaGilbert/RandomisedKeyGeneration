import secrets
import os
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

# Constants
KEY_SIZE = 32      # 256 bits
NONCE_SIZE = 12    # 96 bits for GCM

def generate_dh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def user_entropy():
    print("\nStep 1a) Collect user entropy:")
    print("    Type some random text quickly and hit Enter:")
    start = time.time()
    _ = input()
    end = time.time()
    interval_ns = int((end - start) * 1e9)  # nanoseconds
    print(f"    Timing interval (ns): {interval_ns}")
    return interval_ns.to_bytes(8, 'big')   # 8 bytes

def generate_secure_key(shared_secret):
    timing_entropy = user_entropy()
    print("\nStep 1b) Collect system entropy:")
    system_entropy = os.urandom(KEY_SIZE)
    print("    System entropy (hex):", system_entropy.hex())

    print("\nStep 1c) Collect secrets entropy:")
    secret_entropy = secrets.token_bytes(KEY_SIZE)
    print("    Secrets entropy (hex):", secret_entropy.hex())

    print("\nStep 1d) Using HKDF for structured key derivation...")

    # Combine as input keying material (IKM)
    ikm = shared_secret + system_entropy + secret_entropy + timing_entropy
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

def generate_test_key():
    system_entropy = os.urandom(KEY_SIZE)
    secret_entropy = secrets.token_bytes(KEY_SIZE)
    timing_entropy = secrets.token_bytes(8)

    ikm = system_entropy + secret_entropy + timing_entropy

    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=os.urandom(16),
        info=b"AES-256-GCM key derivation",
        backend=default_backend()
    )

    return hkdf.derive(ikm)

def main():
    # Step 1: Diffie-Hellman Key Exchange

    print("\n--- Diffie-Hellman Key Exchange with entropy based key derivation ---\n")

    # Alice generates keys
    alice_private, alice_public = generate_dh_keys()
    print("Alice's public key (hex):", alice_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    print("\n")
    print("Alice's public key (Base64):", base64.b64encode(alice_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode().encode()).decode())
    print("\n")


    # Bob generates keys
    bob_private, bob_public = generate_dh_keys()
    print("Bob's public key (hex):", bob_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    print("\n")
    print("Bob's public key (Base64):", base64.b64encode(bob_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode().encode()).decode())
    print("\n")


    # Exchange public keys and compute shared secret
    alice_shared = compute_shared_secret(alice_private, bob_public)
    print("Alice's computed shared secret (hex):", alice_shared.hex())
    print("\n")
    print("Alice's computed shared secret (Base64):", base64.b64encode(alice_shared).decode())
    bob_shared = compute_shared_secret(bob_private, alice_public)
    print("Bob's computed shared secret (hex):", bob_shared.hex())
    print("\n")
    print("Bob's computed shared secret (Base64):", base64.b64encode(bob_shared).decode())

    print("Shared secrets match:", alice_shared == bob_shared)

    # Step 2: Generate AES key (use shared secret)
    key = generate_secure_key(alice_shared)

    # Step 3: Create AES-GCM cipher
    aesgcm = AESGCM(key)

    # Step 4: Input plaintext
    plaintext = input("\nEnter text to encrypt: ").encode()

    # Step 5: Generate nonce
    nonce = secrets.token_bytes(NONCE_SIZE)

    # Step 6: Encrypt
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    print("\nNonce (hex):", nonce.hex())

    print("\nCiphertext:", base64.b64encode(ciphertext).decode())

    # Step 7: Decrypt (same key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)

    print("Decrypted:", decrypted.decode())
    print("Integrity check:", decrypted == plaintext)

if __name__ == "__main__":
    main()
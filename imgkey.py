import base64
import hashlib
import os
import secrets
import cv2
import numpy as np
from PIL import Image

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from keygen import KEY_SIZE


AES_KEY_SIZE = 32  # 256-bit AES key

def generate_dh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def compute_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

def generate_otp():
    """Generate secure 6-digit OTP"""
    return f"{secrets.randbelow(10**6):06d}"


def extract_image_features(image_path, verbose=True):
    """Extract multiple image features and convert them to bytes"""

    # Read image using OpenCV
    img = cv2.imread(image_path)

    if img is None:
        raise ValueError("Image could not be loaded")

    features = []

    # 1️⃣ Raw image bytes hash
    with open(image_path, "rb") as f:
        raw_bytes = f.read()
    raw_hash = hashlib.sha256(raw_bytes).digest()
    if verbose:
        print("Raw Image Hash:", raw_hash.hex())
    features.append(raw_hash)

    # 2️⃣ Image dimensions
    height, width, channels = img.shape
    dimension_bytes = f"{height}-{width}-{channels}".encode()
    if verbose:
        print("Image Dimensions Hash:", hashlib.sha256(dimension_bytes).digest().hex())
    features.append(hashlib.sha256(dimension_bytes).digest())

    # 3️⃣ Color histogram
    hist = cv2.calcHist([img], [0,1,2], None, [8,8,8], [0,256,0,256,0,256])
    hist = cv2.normalize(hist, hist).flatten()
    if verbose:
        print("Color Histogram Hash:", hashlib.sha256(hist.tobytes()).digest().hex())
    features.append(hashlib.sha256(hist.tobytes()).digest())

    # 4️⃣ Edge detection features
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 100, 200)
    edge_hash = hashlib.sha256(edges.tobytes()).digest()
    if verbose:
        print("Edge Detection Hash:", edge_hash.hex())
    features.append(edge_hash)

    # 5️⃣ Pixel statistics
    mean = np.mean(img)
    std = np.std(img)
    stats_bytes = f"{mean}-{std}".encode()
    if verbose:
        print("Pixel Statistics Hash:", hashlib.sha256(stats_bytes).digest().hex())
    features.append(hashlib.sha256(stats_bytes).digest())

    # 6️⃣ ORB keypoints
    orb = cv2.ORB_create()
    keypoints, descriptors = orb.detectAndCompute(gray, None)

    if descriptors is not None:
        orb_hash = hashlib.sha256(descriptors.tobytes()).digest()
    else:
        orb_hash = hashlib.sha256(b"no_features").digest()
    if verbose:print("ORB Keypoints Hash:", orb_hash.hex())

    features.append(orb_hash)

    # Combine all features
    combined_features = b''.join(features)

    return hashlib.sha512(combined_features).digest()


def derive_aes_key(shared_secret, image_path, otp, verbose=True):
    """Derive AES key from image features + OTP"""

    image_features = extract_image_features(image_path, verbose)

    combined = image_features + otp.encode()

    master_material = hashlib.sha512(combined).digest()

    ikm = shared_secret + image_features + otp.encode()
    print("    Combined IKM (hex):", ikm.hex())

    # Optional salt (adds randomness + protects against precomputation)
    salt = hashlib.sha256(shared_secret).digest()[:16]
    print("    Salt (hex):", salt.hex())
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=salt,
        info=b"AES-256-GCM key derivation",
        backend=default_backend()
    )

    key = hkdf.derive(ikm)

    return key


# Example Usage
if __name__ == "__main__":

    image_path = "apple.png"
    otp = generate_otp()

    print("OTP:", otp)

    # Alice
    alice_priv, alice_pub = generate_dh_keys()
    print("Alice's public key (hex):", alice_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    print("\n")
    print("Alice's public key (Base64):", base64.b64encode(alice_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).decode())
    print("\n")

    # Bob
    bob_priv, bob_pub = generate_dh_keys()
    print("Bob's public key (hex):", bob_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    print("\n")
    print("Bob's public key (Base64):", base64.b64encode(bob_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).decode())
    print("\n")

    # Shared secrets
    alice_shared = compute_shared_secret(alice_priv, bob_pub)
    print("Alice's shared secret (hex):",
            alice_shared.hex())
    print("\n")
    print("Alice's shared secret (Base64):", base64.b64encode(alice_shared).decode())
    print("\n")
    bob_shared = compute_shared_secret(bob_priv, alice_pub)
    print("Bob's shared secret (hex):", bob_shared.hex())
    print("\n")
    print("Bob's shared secret (Base64):", base64.b64encode(bob_shared).decode())
    print("\n")

    print("Shared secrets match:", alice_shared == bob_shared)

    # Both derive SAME key
    alice_key = derive_aes_key(alice_shared, image_path, otp)
    print("Alice's derived AES key (hex):", alice_key.hex())
    print("\n")
    bob_key = derive_aes_key(bob_shared, image_path, otp)
    print("Bob's derived AES key (hex):", bob_key.hex())
    print("\n")

    print("Keys match:", alice_key == bob_key)
    print("Final Key:", alice_key.hex())
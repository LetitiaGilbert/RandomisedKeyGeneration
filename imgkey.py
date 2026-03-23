import hashlib
import secrets
import cv2
import numpy as np
from PIL import Image

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


AES_KEY_SIZE = 32  # 256-bit AES key


def generate_otp():
    """Generate secure 6-digit OTP"""
    return f"{secrets.randbelow(10**6):06d}"


def extract_image_features(image_path, verbose=False):
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


def derive_aes_key(image_path, otp, verbose=False):
    """Derive AES key from image features + OTP"""

    image_features = extract_image_features(image_path, verbose)

    combined = image_features + otp.encode()

    master_material = hashlib.sha512(combined).digest()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b"AES-256 image+otp key derivation",
        backend=default_backend()
    )

    aes_key = hkdf.derive(master_material)

    return aes_key


# Example Usage
if __name__ == "__main__":

    image_path = "apple.png"

    otp = generate_otp()
    print("Generated OTP:", otp)

    key = derive_aes_key(image_path, otp)

    print("Derived AES-256 Key:", key.hex())
import numpy as np
import os
import random

from imgkey import derive_aes_key, generate_otp
from keygen import generate_test_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────
# Deterministic derivation wrappers for BIT
# (fixed input → fixed output, no internal randomness)
# ─────────────────────────────────────────

def derive_entropy_key_from_input(input_bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=b'\x00' * 16,
        info=b"AES-256-GCM key derivation",
        backend=default_backend()
    )
    return hkdf.derive(input_bytes)


def derive_image_key_from_input(input_bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\x00' * 16,
        info=b"AES-256 image+otp key derivation",
        backend=default_backend()
    )
    return hkdf.derive(input_bytes)


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def key_to_bits(key):
    bits = []
    for byte in key:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def flip_bit_at_position(byte_array, bit_pos):
    arr = bytearray(byte_array)
    byte_index = bit_pos // 8
    bit_index  = 7 - (bit_pos % 8)
    arr[byte_index] ^= (1 << bit_index)
    return bytes(arr)


# ─────────────────────────────────────────
# Tests
# ─────────────────────────────────────────

def frequency_test(bit_array, label):
    n = len(bit_array)
    ones = sum(bit_array)
    zeros = n - ones
    Z = ((zeros - ones) ** 2) / n
    ratio = ones / n

    print("\n==============================")
    print(label)
    print("==============================")
    print("Total bits:", n)
    print("Ones:", ones)
    print("Zeros:", zeros)
    print("Z statistic:", Z)
    print("One ratio:", ratio)

    if 0.48 <= ratio <= 0.52:
        print("PASS: Bit distribution close to 50%")
    else:
        print("WARNING: Distribution deviates from ideal")


def bit_independence_tests(derive_func, input_size, label, trials=50):
    KEY_BITS   = 32 * 8
    INPUT_BITS = input_size * 8

    all_avalanche  = []
    sac_pass_count = 0
    completeness_matrix = np.zeros((INPUT_BITS, KEY_BITS), dtype=bool)

    for _ in range(trials):
        base_input = os.urandom(input_size)
        base_key   = derive_func(base_input)
        base_bits  = key_to_bits(base_key)

        trial_ratios = []

        for bit_pos in range(INPUT_BITS):
            flipped_input = flip_bit_at_position(base_input, bit_pos)
            flipped_key   = derive_func(flipped_input)
            flipped_bits  = key_to_bits(flipped_key)

            changed    = [b1 != b2 for b1, b2 in zip(base_bits, flipped_bits)]
            diff_count = sum(changed)
            ratio      = diff_count / KEY_BITS

            trial_ratios.append(ratio)

            if ratio > 0.5:
                sac_pass_count += 1

            for out_bit, was_changed in enumerate(changed):
                if was_changed:
                    completeness_matrix[bit_pos][out_bit] = True

        all_avalanche.append(np.mean(trial_ratios))

    da  = np.mean(all_avalanche)
    dsa = sac_pass_count / (trials * INPUT_BITS)
    dc  = 1 if completeness_matrix.all() else 0

    print("\n====================================")
    print(label)
    print("====================================")
    print("Completeness     (dc) :", dc,          "  (ideal = 1)")
    print("Avalanche Effect (da) :", round(da, 4), "  (ideal ≈ 0.5)")
    print("SAC              (dsa):", round(dsa, 4),"  (ideal ≈ 0.5)")

    if da >= 0.45:
        print("PASS: Strong avalanche effect")
    else:
        print("WARNING: Weak avalanche effect")
    if dsa >= 0.45:
        print("PASS: SAC satisfied")
    else:
        print("WARNING: SAC not satisfied")
    if dc == 1:
        print("PASS: Completeness satisfied")
    else:
        print("WARNING: Completeness not fully satisfied")


def bitwise_uncorrelation_test(bit_array, label):
    x = np.array(bit_array[:-1])
    y = np.array(bit_array[1:])
    corr = np.corrcoef(x, y)[0, 1]

    print("\n======================================")
    print(label)
    print("======================================")
    print("Correlation coefficient:", corr)

    if np.isnan(corr):
        print("Result invalid (zero variance)")
        return
    if abs(corr) < 0.05:
        print("PASS: Bits appear independent")
    else:
        print("WARNING: Possible correlation detected")


def poker_test(bit_array, label, p=4):
    blocks = []
    for i in range(0, len(bit_array) - p, p):
        block = bit_array[i:i+p]
        blocks.append(tuple(block))

    B = len(blocks)
    freq = {}
    for b in blocks:
        freq[b] = freq.get(b, 0) + 1

    sum_sq = sum(v*v for v in freq.values())
    Z = (2**p / B) * sum_sq - B

    print("\n====================================")
    print(label)
    print("====================================")
    print("Block size (p):", p)
    print("Blocks:", B)
    print("Poker Statistic Z:", Z)
    print("Unique patterns:", len(freq), "/", 2**p)

    if len(freq) > 0.9 * 2**p:
        print("PASS: High diversity of patterns")
    else:
        print("WARNING: Low diversity, possible bias")


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

if __name__ == "__main__":

    img_bits     = []
    entropy_bits = []
    TEST_ROUNDS  = 200

    print("Generating keys for frequency, uncorrelation and poker tests...")

    for _ in range(TEST_ROUNDS):
        otp = generate_otp()
        key = derive_aes_key("apple.png", otp)
        img_bits.extend(key_to_bits(key))

    for _ in range(TEST_ROUNDS):
        key = generate_test_key()
        entropy_bits.extend(key_to_bits(key))

    # Frequency tests
    frequency_test(img_bits,     "Image + OTP Frequency Test")
    frequency_test(entropy_bits, "Entropy-based Frequency Test")

    # Bit independence tests (corrected)
    print("\nRunning bit independence tests (this may take ~30 seconds)...")
    bit_independence_tests(
        derive_func=derive_entropy_key_from_input,
        input_size=72,
        label="Entropy-based Bit Independence Test",
        trials=50
    )
    bit_independence_tests(
        derive_func=derive_image_key_from_input,
        input_size=64,
        label="Image + OTP Bit Independence Test",
        trials=50
    )

    # Uncorrelation tests
    bitwise_uncorrelation_test(img_bits,     "Image + OTP Bitwise Uncorrelation Test")
    bitwise_uncorrelation_test(entropy_bits, "Entropy-based Bitwise Uncorrelation Test")

    # Poker tests
    poker_test(img_bits,     "Image + OTP Poker Test",     p=4)
    poker_test(entropy_bits, "Entropy-based Poker Test",   p=4)
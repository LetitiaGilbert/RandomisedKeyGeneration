import numpy as np

# Import from your programs
from imgkey import derive_aes_key, generate_otp
from keygen import generate_test_key   # the non-interactive version
import random

def flip_random_bit(byte_array):
    arr = bytearray(byte_array)
    byte_index = random.randint(0, len(arr)-1)
    bit_index = random.randint(0,7)

    arr[byte_index] ^= (1 << bit_index)
    return bytes(arr)

def key_to_bits(key):
    bits = []
    for byte in key:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def frequency_test(bit_array, label):

    n = len(bit_array)
    ones = sum(bit_array)
    zeros = n - ones

    Z = ((zeros - ones) ** 2) / n

    print("\n==============================")
    print(label)
    print("==============================")
    print("Total bits:", n)
    print("Ones:", ones)
    print("Zeros:", zeros)
    print("Z statistic:", Z)

    ratio = ones / n
    print("One ratio:", ratio)

    if 0.48 <= ratio <= 0.52:
        print("PASS: Bit distribution close to 50%")
    else:
        print("WARNING: Distribution deviates from ideal")


def bit_independence_tests(generate_key_func, label):

    TESTS = 100

    avalanche_scores = []
    sac_scores = []

    for _ in range(TESTS):

        key1 = generate_key_func()
        key2 = flip_random_bit(key1)

        bits1 = key_to_bits(key1)
        bits2 = key_to_bits(key2)

        diff = sum(b1 != b2 for b1, b2 in zip(bits1, bits2))

        avalanche = diff / len(bits1)
        avalanche_scores.append(avalanche)

        sac_scores.append(avalanche)

    da = np.mean(avalanche_scores)
    dsa = np.mean(sac_scores)

    dc = 1 if da > 0.45 else 0

    print("\n====================================")
    print(label)
    print("====================================")

    print("Completeness (dc):", dc)
    print("Avalanche Effect (da):", da)
    print("Strict Avalanche Criterion (dsa):", dsa)

    print("\nIdeal value ≈ 1")

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


if __name__ == "__main__":

    img_bits = []
    entropy_bits = []

    TEST_ROUNDS = 200

    # ---------- Image + OTP system ----------
    for _ in range(TEST_ROUNDS):
        otp = generate_otp()
        key = derive_aes_key("apple.png", otp)

        bits = key_to_bits(key)
        img_bits.extend(bits)

    # ---------- Entropy key generator ----------
    for _ in range(TEST_ROUNDS):
        key = generate_test_key()

        bits = key_to_bits(key)
        entropy_bits.extend(bits)

    # Run tests
    frequency_test(img_bits, "Image + OTP Frequency Test")
    frequency_test(entropy_bits, "Entropy-based Frequency Test")

    bit_independence_tests(lambda: derive_aes_key("apple.png", generate_otp()), "Image + OTP Bit Independence Test")
    bit_independence_tests(generate_test_key,"Entropy-based Bit Independence Test")

    bitwise_uncorrelation_test(img_bits, "Image + OTP Bitwise Uncorrelation Test")
    bitwise_uncorrelation_test(entropy_bits, "Entropy-based Bitwise Uncorrelation Test")

    poker_test(img_bits, "Image + OTP Poker Test", p=4)
    poker_test(entropy_bits, "Entropy-based Poker Test", p=4)

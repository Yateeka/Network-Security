"""
benchmark_smime_pure.py

Simulated S/MIME benchmark using only built-in Python modules.
"""

import time
import hashlib
import os

TEST_ITERATIONS = 10
MESSAGE_SIZE = 100000  # 100 KB message

# -----------------------------
# Simulated AES Encryption/Decryption
# -----------------------------
def fake_encrypt(message, key):
    # Simple XOR with key bytes
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(message)])

def fake_decrypt(ciphertext, key):
    # XOR again to decrypt
    return fake_encrypt(ciphertext, key)

# -----------------------------
# Simulated RSA Signing/Verification
# -----------------------------
def fake_sign(message):
    # Use SHA256 hash as "signature"
    return hashlib.sha256(message).digest()

def fake_verify(message, signature):
    # Check if SHA256 hash matches
    return hashlib.sha256(message).digest() == signature

# -----------------------------
# Benchmark Encryption/Decryption
# -----------------------------
def benchmark_encryption():
    message = b"A" * MESSAGE_SIZE
    key = os.urandom(16)  # Simulated AES key

    print("\nENCRYPTION BENCHMARK")
    print("-----------------------------")

    # Encryption
    start = time.time()
    for _ in range(TEST_ITERATIONS):
        ciphertext = fake_encrypt(message, key)
    end = time.time()
    encryption_time = (end - start) / TEST_ITERATIONS

    # Decryption
    start = time.time()
    for _ in range(TEST_ITERATIONS):
        plaintext = fake_decrypt(ciphertext, key)
    end = time.time()
    decryption_time = (end - start) / TEST_ITERATIONS

    print(f"Encryption Avg Time: {encryption_time:.6f} seconds")
    print(f"Decryption Avg Time: {decryption_time:.6f} seconds")

# -----------------------------
# Benchmark Signing/Verification
# -----------------------------
def benchmark_signature():
    message = b"A" * MESSAGE_SIZE
    print("\nSIGNATURE BENCHMARK")
    print("-----------------------------")

    # Signing
    start = time.time()
    for _ in range(TEST_ITERATIONS):
        signature = fake_sign(message)
    end = time.time()
    sign_time = (end - start) / TEST_ITERATIONS

    # Verification
    start = time.time()
    for _ in range(TEST_ITERATIONS):
        result = fake_verify(message, signature)
    end = time.time()
    verify_time = (end - start) / TEST_ITERATIONS

    print(f"Signing Avg Time: {sign_time:.6f} seconds")
    print(f"Verification Avg Time: {verify_time:.6f} seconds")

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    print("Running Simulated S/MIME Benchmarks")
    print("===================================")

    benchmark_encryption()
    benchmark_signature()

"""
benchmark.py

This module measures the performance of cryptographic operations
implemented in the PGP project.

The benchmarking tests evaluate:

1. AES Encryption Performance
   - AES-128
   - AES-256

2. AES Decryption Performance

3. RSA Digital Signature Performance
   - Signature generation time
   - Signature verification time

Each operation is executed multiple times to compute an
average runtime. These results are used later in the
project report to compare algorithm efficiency.
"""

import time

from encryption import encrypt_message, decrypt_message
from key_generation import generate_rsa_keys
from signature import sign_message, verify_signature


TEST_ITERATIONS = 50
MESSAGE_SIZE = 1000000   # 1 MB message


def benchmark_aes():
    """
    Benchmark AES encryption and decryption.
    """

    message = b"A" * MESSAGE_SIZE

    print("\nAES BENCHMARK")
    print("-------------------------")

    # AES Encryption
    start = time.time()

    for _ in range(TEST_ITERATIONS):
        ciphertext, key, nonce, tag = encrypt_message(message)

    end = time.time()

    encryption_time = (end - start) / TEST_ITERATIONS

    # AES Decryption
    start = time.time()

    for _ in range(TEST_ITERATIONS):
        decrypt_message(ciphertext, key, nonce, tag)

    end = time.time()

    decryption_time = (end - start) / TEST_ITERATIONS

    print(f"AES Encryption Avg Time: {encryption_time:.6f} seconds")
    print(f"AES Decryption Avg Time: {decryption_time:.6f} seconds")


def benchmark_rsa_signature():
    """
    Benchmark RSA digital signature generation and verification.
    """

    message = b"A" * MESSAGE_SIZE

    print("\nRSA SIGNATURE BENCHMARK")
    print("-------------------------")

    private_key, public_key = generate_rsa_keys()

    # Signature generation
    start = time.time()

    for _ in range(TEST_ITERATIONS):
        signature = sign_message(message, private_key)

    end = time.time()

    sign_time = (end - start) / TEST_ITERATIONS

    # Signature verification
    start = time.time()

    for _ in range(TEST_ITERATIONS):
        verify_signature(message, signature, public_key)

    end = time.time()

    verify_time = (end - start) / TEST_ITERATIONS

    print(f"RSA Signature Avg Time: {sign_time:.6f} seconds")
    print(f"RSA Verification Avg Time: {verify_time:.6f} seconds")


if __name__ == "__main__":

    print("\nRunning Cryptographic Benchmarks...")
    print("====================================")

    benchmark_aes()
    benchmark_rsa_signature()
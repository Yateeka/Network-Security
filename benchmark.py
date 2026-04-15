"""
benchmark.py

Graduate-level benchmarking for the PGP project.

This module measures:
    1. AES-128 and AES-256 encryption/decryption time
    2. RSA signature generation and verification time
    3. RSA session key encryption/decryption time
    4. Message size overhead
    5. Structured result export to CSV

The output can be used directly in report tables.
"""

import csv
import os
import statistics
import time

from compression import compress_message
from encryption import (
    encrypt_message,
    decrypt_message,
    encrypt_session_key,
    decrypt_session_key,
)
from key_generation import generate_rsa_keys
from signature import sign_message, verify_signature


TEST_ITERATIONS = 50
DEFAULT_MESSAGE_SIZES = [1024, 100 * 1024, 1024 * 1024]  # 1 KB, 100 KB, 1 MB
RESULTS_DIR = "results"


def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def save_results_to_csv(filename, rows, headers):
    ensure_results_dir()
    path = os.path.join(RESULTS_DIR, filename)

    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)

    return path


def _average_runtime(func, iterations):
    samples = []

    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        samples.append(end - start)

    return {
        "avg_seconds": statistics.mean(samples),
        "min_seconds": min(samples),
        "max_seconds": max(samples),
        "std_seconds": statistics.pstdev(samples),
    }


def benchmark_aes_variants(
    iterations=TEST_ITERATIONS,
    message_sizes=DEFAULT_MESSAGE_SIZES,
):
    """
    Benchmark AES-128 and AES-256 for multiple message sizes.

    Returns
    -------
    list[dict]
    """
    results = []

    for message_size in message_sizes:
        message = b"A" * message_size

        for key_size in (16, 32):
            ciphertext, session_key, nonce, tag = encrypt_message(
                message,
                key_size=key_size,
            )

            enc_stats = _average_runtime(
                lambda: encrypt_message(message, key_size=key_size),
                iterations,
            )

            dec_stats = _average_runtime(
                lambda: decrypt_message(ciphertext, session_key, nonce, tag),
                iterations,
            )

            results.append(
                {
                    "operation": "AES Encryption",
                    "algorithm": f"AES-{key_size * 8}",
                    "message_size_bytes": message_size,
                    "avg_seconds": enc_stats["avg_seconds"],
                    "min_seconds": enc_stats["min_seconds"],
                    "max_seconds": enc_stats["max_seconds"],
                    "std_seconds": enc_stats["std_seconds"],
                }
            )

            results.append(
                {
                    "operation": "AES Decryption",
                    "algorithm": f"AES-{key_size * 8}",
                    "message_size_bytes": message_size,
                    "avg_seconds": dec_stats["avg_seconds"],
                    "min_seconds": dec_stats["min_seconds"],
                    "max_seconds": dec_stats["max_seconds"],
                    "std_seconds": dec_stats["std_seconds"],
                }
            )

    return results


def benchmark_rsa_signature(
    iterations=TEST_ITERATIONS,
    message_sizes=DEFAULT_MESSAGE_SIZES,
    rsa_key_size=2048,
):
    """
    Benchmark RSA signing and verification for multiple message sizes.

    Returns
    -------
    list[dict]
    """
    private_key, public_key = generate_rsa_keys(key_size=rsa_key_size)
    results = []

    for message_size in message_sizes:
        message = b"A" * message_size
        signature = sign_message(message, private_key)

        sign_stats = _average_runtime(
            lambda: sign_message(message, private_key),
            iterations,
        )

        verify_stats = _average_runtime(
            lambda: verify_signature(message, signature, public_key),
            iterations,
        )

        results.append(
            {
                "operation": "RSA Signature Generation",
                "algorithm": f"RSA-{rsa_key_size}",
                "message_size_bytes": message_size,
                "avg_seconds": sign_stats["avg_seconds"],
                "min_seconds": sign_stats["min_seconds"],
                "max_seconds": sign_stats["max_seconds"],
                "std_seconds": sign_stats["std_seconds"],
            }
        )

        results.append(
            {
                "operation": "RSA Signature Verification",
                "algorithm": f"RSA-{rsa_key_size}",
                "message_size_bytes": message_size,
                "avg_seconds": verify_stats["avg_seconds"],
                "min_seconds": verify_stats["min_seconds"],
                "max_seconds": verify_stats["max_seconds"],
                "std_seconds": verify_stats["std_seconds"],
            }
        )

    return results


def benchmark_rsa_session_key(
    iterations=TEST_ITERATIONS,
    rsa_key_size=2048,
    aes_key_sizes=(16, 32),
):
    """
    Benchmark RSA-OAEP session key encryption and decryption.

    Returns
    -------
    list[dict]
    """
    private_key, public_key = generate_rsa_keys(key_size=rsa_key_size)
    results = []

    for aes_key_size in aes_key_sizes:
        sample_message = b"A" * 128
        _, session_key, _, _ = encrypt_message(sample_message, key_size=aes_key_size)
        encrypted_key = encrypt_session_key(session_key, public_key)

        enc_stats = _average_runtime(
            lambda: encrypt_session_key(session_key, public_key),
            iterations,
        )

        dec_stats = _average_runtime(
            lambda: decrypt_session_key(encrypted_key, private_key),
            iterations,
        )

        results.append(
            {
                "operation": "RSA Session Key Encryption",
                "algorithm": f"RSA-{rsa_key_size} + AES-{aes_key_size * 8}",
                "message_size_bytes": len(session_key),
                "avg_seconds": enc_stats["avg_seconds"],
                "min_seconds": enc_stats["min_seconds"],
                "max_seconds": enc_stats["max_seconds"],
                "std_seconds": enc_stats["std_seconds"],
            }
        )

        results.append(
            {
                "operation": "RSA Session Key Decryption",
                "algorithm": f"RSA-{rsa_key_size} + AES-{aes_key_size * 8}",
                "message_size_bytes": len(session_key),
                "avg_seconds": dec_stats["avg_seconds"],
                "min_seconds": dec_stats["min_seconds"],
                "max_seconds": dec_stats["max_seconds"],
                "std_seconds": dec_stats["std_seconds"],
            }
        )

    return results


def benchmark_size_overhead(message_sizes=DEFAULT_MESSAGE_SIZES, rsa_key_size=2048):
    """
    Measure size overhead introduced by compression, signature,
    AES encryption, and RSA-encrypted session key.

    Returns
    -------
    list[dict]
    """
    private_key, public_key = generate_rsa_keys(key_size=rsa_key_size)
    results = []

    for message_size in message_sizes:
        message = b"A" * message_size
        compressed = compress_message(message)
        signature = sign_message(compressed, private_key)

        ciphertext, session_key, nonce, tag = encrypt_message(compressed, key_size=32)
        encrypted_session_key = encrypt_session_key(session_key, public_key)

        total_package_size = (
            len(ciphertext)
            + len(encrypted_session_key)
            + len(nonce)
            + len(tag)
            + len(signature)
        )

        results.append(
            {
                "original_size_bytes": len(message),
                "compressed_size_bytes": len(compressed),
                "ciphertext_size_bytes": len(ciphertext),
                "signature_size_bytes": len(signature),
                "encrypted_session_key_size_bytes": len(encrypted_session_key),
                "nonce_size_bytes": len(nonce),
                "tag_size_bytes": len(tag),
                "total_package_size_bytes": total_package_size,
                "expansion_ratio": total_package_size / max(1, len(message)),
            }
        )

    return results


def export_benchmark_results():
    """
    Run all benchmarks and export CSV files.

    Returns
    -------
    dict
        Paths of generated result files.
    """
    aes_results = benchmark_aes_variants()
    rsa_sig_results = benchmark_rsa_signature()
    rsa_key_results = benchmark_rsa_session_key()
    size_results = benchmark_size_overhead()

    timing_headers = [
        "operation",
        "algorithm",
        "message_size_bytes",
        "avg_seconds",
        "min_seconds",
        "max_seconds",
        "std_seconds",
    ]

    timing_rows = []
    for row in aes_results + rsa_sig_results + rsa_key_results:
        timing_rows.append(
            [
                row["operation"],
                row["algorithm"],
                row["message_size_bytes"],
                row["avg_seconds"],
                row["min_seconds"],
                row["max_seconds"],
                row["std_seconds"],
            ]
        )

    size_headers = [
        "original_size_bytes",
        "compressed_size_bytes",
        "ciphertext_size_bytes",
        "signature_size_bytes",
        "encrypted_session_key_size_bytes",
        "nonce_size_bytes",
        "tag_size_bytes",
        "total_package_size_bytes",
        "expansion_ratio",
    ]

    size_rows = []
    for row in size_results:
        size_rows.append(
            [
                row["original_size_bytes"],
                row["compressed_size_bytes"],
                row["ciphertext_size_bytes"],
                row["signature_size_bytes"],
                row["encrypted_session_key_size_bytes"],
                row["nonce_size_bytes"],
                row["tag_size_bytes"],
                row["total_package_size_bytes"],
                row["expansion_ratio"],
            ]
        )

    paths = {
        "timing_csv": save_results_to_csv(
            "timing_results.csv",
            timing_rows,
            timing_headers,
        ),
        "size_csv": save_results_to_csv(
            "size_results.csv",
            size_rows,
            size_headers,
        ),
    }

    return paths


def print_benchmark_summary():
    aes_results = benchmark_aes_variants(message_sizes=[1024 * 1024])
    rsa_sig_results = benchmark_rsa_signature(message_sizes=[1024 * 1024])
    rsa_key_results = benchmark_rsa_session_key()
    size_results = benchmark_size_overhead(message_sizes=[1024 * 1024])

    print("\n========== BENCHMARK SUMMARY ==========")
    for row in aes_results + rsa_sig_results + rsa_key_results:
        print(
            f"{row['operation']} | {row['algorithm']} | "
            f"message={row['message_size_bytes']} bytes | "
            f"avg={row['avg_seconds']:.6f} s"
        )

    print("\n========== SIZE OVERHEAD SUMMARY ==========")
    for row in size_results:
        print(
            f"Original={row['original_size_bytes']} bytes | "
            f"Compressed={row['compressed_size_bytes']} bytes | "
            f"Package={row['total_package_size_bytes']} bytes | "
            f"Expansion ratio={row['expansion_ratio']:.4f}"
        )


if __name__ == "__main__":
    generated_files = export_benchmark_results()
    print_benchmark_summary()

    print("\nGenerated files:")
    for label, path in generated_files.items():
        print(f"{label}: {path}")
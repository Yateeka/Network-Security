from compression import compress_message, decompress_message
from encryption import decrypt_message, decrypt_session_key, encrypt_message, encrypt_session_key
from signature import sign_message, verify_signature
from benchmark import export_benchmark_results, print_benchmark_summary
from key_generation import generate_rsa_keys


def pgp_demo(message=None, aes_key_size=32, rsa_key_size=2048):
    """
    Simulate a simplified PGP workflow:
        1. Compress
        2. Sign
        3. Encrypt message with AES
        4. Encrypt AES session key with RSA
        5. Decrypt AES session key
        6. Decrypt message
        7. Verify signature
        8. Decompress
    """
    if message is None:
        message = b"This is a secure PGP test message."

    print("\n========== PGP WORKFLOW DEMO ==========")
    print(f"Original message: {message}")

    private_key, public_key = generate_rsa_keys(key_size=rsa_key_size)

    compressed = compress_message(message)
    signature = sign_message(compressed, private_key)

    ciphertext, session_key, nonce, tag = encrypt_message(
        compressed,
        key_size=aes_key_size,
    )
    encrypted_session_key = encrypt_session_key(session_key, public_key)

    decrypted_session_key = decrypt_session_key(encrypted_session_key, private_key)
    decrypted_compressed = decrypt_message(
        ciphertext,
        decrypted_session_key,
        nonce,
        tag,
    )

    signature_valid = verify_signature(
        decrypted_compressed,
        signature,
        public_key,
    )

    final_message = decompress_message(decrypted_compressed)

    print(f"\nCompressed size: {len(compressed)} bytes")
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(f"Encrypted session key size: {len(encrypted_session_key)} bytes")
    print(f"Signature size: {len(signature)} bytes")
    print(f"\nRecovered message: {final_message}")
    print(f"Signature valid: {signature_valid}")

    return {
        "message": message,
        "compressed": compressed,
        "signature": signature,
        "ciphertext": ciphertext,
        "session_key": session_key,
        "nonce": nonce,
        "tag": tag,
        "encrypted_session_key": encrypted_session_key,
        "private_key": private_key,
        "public_key": public_key,
        "signature_valid": signature_valid,
        "final_message": final_message,
    }


def size_analysis(message=None, aes_key_size=32, rsa_key_size=2048):
    """
    Measure total package size overhead.
    """
    if message is None:
        message = b"A" * 10000

    private_key, public_key = generate_rsa_keys(key_size=rsa_key_size)

    compressed = compress_message(message)
    signature = sign_message(compressed, private_key)
    ciphertext, session_key, nonce, tag = encrypt_message(
        compressed,
        key_size=aes_key_size,
    )
    encrypted_session_key = encrypt_session_key(session_key, public_key)

    total_package_size = (
        len(ciphertext)
        + len(encrypted_session_key)
        + len(nonce)
        + len(tag)
        + len(signature)
    )

    print("\n========== SIZE ANALYSIS ==========")
    print(f"Original size: {len(message)} bytes")
    print(f"Compressed size: {len(compressed)} bytes")
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(f"Signature size: {len(signature)} bytes")
    print(f"Encrypted session key size: {len(encrypted_session_key)} bytes")
    print(f"Nonce size: {len(nonce)} bytes")
    print(f"Tag size: {len(tag)} bytes")
    print(f"Total transmitted package size: {total_package_size} bytes")
    print(
        "Expansion ratio: "
        f"{total_package_size / max(1, len(message)):.4f}"
    )


def tampering_attack_demo():
    """
    Simulate ciphertext tampering to show AES-GCM integrity protection.
    """
    print("\n========== TAMPERING ATTACK DEMO ==========")

    state = pgp_demo(message=b"Attack detection test message.")

    tampered_ciphertext = bytearray(state["ciphertext"])
    tampered_ciphertext[0] ^= 1

    try:
        decrypt_message(
            bytes(tampered_ciphertext),
            state["session_key"],
            state["nonce"],
            state["tag"],
        )
        print("Tampering NOT detected (unexpected).")
    except Exception as exc:
        print("Tampering detected successfully.")
        print(f"Reason: {type(exc).__name__}")


def wrong_key_verification_demo():
    """
    Demonstrate signature verification failure with the wrong public key.
    """
    print("\n========== WRONG KEY VERIFICATION DEMO ==========")

    state = pgp_demo(message=b"Wrong key verification test.")
    _, fake_public_key = generate_rsa_keys()

    valid_with_fake_key = verify_signature(
        state["compressed"],
        state["signature"],
        fake_public_key,
    )

    print(f"Verification using wrong public key: {valid_with_fake_key}")


def run_all():
    pgp_demo()
    size_analysis()
    tampering_attack_demo()
    wrong_key_verification_demo()

    print("\n========== PERFORMANCE BENCHMARK ==========")
    generated_files = export_benchmark_results()
    print_benchmark_summary()

    print("\nCSV files generated:")
    for label, path in generated_files.items():
        print(f"{label}: {path}")


if __name__ == "__main__":
    run_all()
"""
This program simulates a simplified but realistic PGP workflow.

Sender:
1. Compress message
2. Sign message
3. Encrypt message with AES
4. Encrypt AES session key with RSA

Receiver:
5. Decrypt session key
6. Decrypt message
7. Verify signature
8. Decompress message
"""

from key_generation import generate_rsa_keys
from encryption import encrypt_message, decrypt_message, encrypt_session_key, decrypt_session_key
from signature import sign_message, verify_signature
from compression import compress_message, decompress_message
from benchmark import benchmark_aes, benchmark_rsa_signature



def pgp_demo():

    message = b"This is a secure PGP test message."

    print("\nOriginal message:", message)

    # Generate keys
    private_key, public_key = generate_rsa_keys()

    # Step 1: Compress message
    compressed = compress_message(message)

    # Step 2: Sign message
    signature = sign_message(compressed, private_key)

    # Step 3: Encrypt message using AES
    ciphertext, session_key, nonce, tag = encrypt_message(compressed)

    # Step 4: Encrypt session key with RSA
    encrypted_session_key = encrypt_session_key(session_key, public_key)

    print("\nEncrypted message:", ciphertext)

    # Receiver side

    # Step 5: Decrypt session key
    decrypted_session_key = decrypt_session_key(encrypted_session_key, private_key)

    # Step 6: Decrypt message
    decrypted_compressed = decrypt_message(ciphertext, decrypted_session_key, nonce, tag)

    # Step 7: Verify signature
    valid = verify_signature(decrypted_compressed, signature, public_key)

    # Step 8: Decompress message
    final_message = decompress_message(decrypted_compressed)

    print("\nDecrypted message:", final_message)

    print("\nSignature valid:", valid)


if __name__ == "__main__":
    print("\n========== PGP WORKFLOW DEMO ==========")
    pgp_demo()

    print("\n========== PERFORMANCE BENCHMARK ==========")
    benchmark_aes()
    benchmark_rsa_signature()
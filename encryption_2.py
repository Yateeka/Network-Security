"""
Simplified S/MIME-style hybrid encryption using only built-in libraries.
AES is simulated with XOR for demonstration (not secure in real life).
RSA uses small numbers for demo purposes.
"""

import os

# ---------------- RSA Functions ----------------
def generate_rsa_keys():
    """
    Generate small RSA keys for demonstration.
    Returns (public_key, private_key)
    Each key is a tuple: (e_or_d, n)
    """
    # Use small primes for demo (not secure!)
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17  # public exponent
    # Compute d (private exponent)
    d = pow(e, -1, phi)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key


def rsa_encrypt(message_bytes, public_key):
    e, n = public_key
    ciphertext = [pow(b, e, n) for b in message_bytes]
    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    plaintext = bytes([pow(c, d, n) for c in ciphertext])
    return plaintext


# ---------------- AES (Demo XOR) ----------------
def xor_encrypt(message_bytes, key_bytes):
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(message_bytes)])


def xor_decrypt(ciphertext_bytes, key_bytes):
    return xor_encrypt(ciphertext_bytes, key_bytes)  # XOR symmetric


# ---------------- Hybrid Encryption ----------------
def encrypt_message(message, public_key):
    if isinstance(message, str):
        message = message.encode()

    # Generate random AES session key (16 bytes)
    session_key = os.urandom(16)

    # Encrypt message with “AES” (XOR demo)
    ciphertext = xor_encrypt(message, session_key)

    # Encrypt session key with RSA
    encrypted_session_key = rsa_encrypt(session_key, public_key)

    return ciphertext, encrypted_session_key


def decrypt_message(ciphertext, encrypted_session_key, private_key):
    # Decrypt session key with RSA
    session_key = rsa_decrypt(encrypted_session_key, private_key)

    # Decrypt message
    plaintext = xor_decrypt(ciphertext, session_key)
    return plaintext


# ------------------ TEST / DEMO ------------------
if __name__ == "__main__":
    pub, priv = generate_rsa_keys()

    message = "Hello pure Python S/MIME!"
    ciphertext, encrypted_key = encrypt_message(message, pub)

    plaintext = decrypt_message(ciphertext, encrypted_key, priv)
    print("Decrypted message:", plaintext.decode())  # Hello pure Python S/MIME!

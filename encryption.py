"""

This module implements AES encryption for the message and RSA encryption
for the AES session key. This combination is called hybrid encryption,
which is the core design used in PGP.
"""

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


def encrypt_message(message):

    session_key = get_random_bytes(32)

    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)

    return ciphertext, session_key, cipher_aes.nonce, tag


def decrypt_message(ciphertext, session_key, nonce, tag):

    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext


def encrypt_session_key(session_key, public_key):

    rsa_key = RSA.import_key(public_key)

    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    encrypted_key = cipher_rsa.encrypt(session_key)

    return encrypted_key


def decrypt_session_key(encrypted_key, private_key):

    rsa_key = RSA.import_key(private_key)

    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    session_key = cipher_rsa.decrypt(encrypted_key)

    return session_key
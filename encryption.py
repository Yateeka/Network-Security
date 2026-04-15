from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


VALID_AES_KEY_SIZES = {16, 24, 32}


def encrypt_message(message, key_size=32):
    """
    Encrypt a message using AES-GCM.

    Parameters
    ----------
    message : bytes
    key_size : int
        AES key size in bytes:
        16 = AES-128, 24 = AES-192, 32 = AES-256

    Returns
    -------
    tuple[bytes, bytes, bytes, bytes]
        (ciphertext, session_key, nonce, tag)
    """
    if key_size not in VALID_AES_KEY_SIZES:
        raise ValueError("AES key_size must be one of: 16, 24, 32 bytes")

    session_key = get_random_bytes(key_size)
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)

    return ciphertext, session_key, cipher_aes.nonce, tag


def decrypt_message(ciphertext, session_key, nonce, tag):
    """
    Decrypt and authenticate an AES-GCM message.

    Parameters
    ----------
    ciphertext : bytes
    session_key : bytes
    nonce : bytes
    tag : bytes

    Returns
    -------
    bytes
        Plaintext
    """
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext


def encrypt_session_key(session_key, public_key):
    """
    Encrypt a session key using RSA-OAEP.

    Parameters
    ----------
    session_key : bytes
    public_key : bytes

    Returns
    -------
    bytes
        RSA-encrypted session key
    """
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(session_key)
    return encrypted_key


def decrypt_session_key(encrypted_key, private_key):
    """
    Decrypt a session key using RSA-OAEP.

    Parameters
    ----------
    encrypted_key : bytes
    private_key : bytes

    Returns
    -------
    bytes
        Original AES session key
    """
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    session_key = cipher_rsa.decrypt(encrypted_key)
    return session_key
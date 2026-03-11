"""
This module implements basic S/MIME-style encryption and decryption.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return public_key, private_key


def encrypt_message(message, public_key):

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


def decrypt_message(ciphertext, private_key):

    message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message


# Driver code
if __name__ == "__main__":

    public_key, private_key = generate_keys()

    message = b"Hello secure email!"

    ciphertext = encrypt_message(message, public_key)
    print("Encrypted:", ciphertext)

    decrypted_message = decrypt_message(ciphertext, private_key)
    print("Decrypted:", decrypted_message)

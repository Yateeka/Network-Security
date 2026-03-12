"""
This module implements message hashing using SHA-256
for use in S/MIME secure email.
In S/MIME, a hash is made before creating a digital signature. The sender makes a hash of the email and then signs that hash with their private key.

When the receiver gets the email, they make a hash of the message again and compare it with the signed hash. If the two match, the message was not changed.

If someone changed the email while it was being sent, the hashes will not match, and the signature check will fail.
"""

from hashlib import sha256


def generate_hash(message):
    """
    Generate SHA-256 hash of a message for S/MIME signing.

    Parameters
    ----------
    message : bytes
        Email message content

    Returns
    -------
    bytes
        SHA-256 digest
    """

    return sha256(message).digest()


# Example usage
email_message = b"Hello, this is a secure S/MIME email."

hash_value = generate_hash(email_message)

print("SHA-256 Hash:", hash_value)

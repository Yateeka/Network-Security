"""
This module implements message hashing using SHA-256
for use in S/MIME secure email.

In S/MIME, hashing is used before generating a digital
signature. The sender computes a hash of the email
message and then signs the hash using their private key.

When the receiver gets the message, they compute the
hash again and compare it with the decrypted signature.
If the values match, the message integrity is verified.

If the message was modified during transmission,
the hash values will not match and the signature
verification will fail.
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

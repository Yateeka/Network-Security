"""
This module implements message hashing using SHA-256.

Hashing is used in PGP for message integrity verification.
The sender creates a hash of the message before generating
a digital signature.

If the message changes during transmission, the hash value
will change and the signature verification will fail.
"""

from hashlib import sha256


def generate_hash(message):
    """
    Generate SHA-256 hash of a message.

    Parameters
    ----------
    message : bytes

    Returns
    -------
    bytes
        SHA-256 digest
    """

    return sha256(message).digest()
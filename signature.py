"""

This module implements digital signature generation and verification.

Digital signatures provide two important security properties:

1. Authentication
   Ensures the message was sent by the claimed sender.

2. Integrity
   Ensures the message has not been modified.

The process works as follows:

Sender:
    - Hash the message using SHA-256
    - Sign the hash using the sender's private key

Receiver:
    - Compute hash of received message
    - Verify signature using sender's public key
"""

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def sign_message(message, private_key):
    """
    Generate a digital signature for a message.
    """

    key = RSA.import_key(private_key)

    hash_obj = SHA256.new(message)

    signature = pkcs1_15.new(key).sign(hash_obj)

    return signature


def verify_signature(message, signature, public_key):
    """
    Verify digital signature.

    Returns
    -------
    bool
        True if signature is valid
    """

    key = RSA.import_key(public_key)

    hash_obj = SHA256.new(message)

    try:
        pkcs1_15.new(key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def sign_message(message, private_key):
    """
    Generate an RSA PKCS#1 v1.5 digital signature using SHA-256.

    Parameters
    ----------
    message : bytes
    private_key : bytes

    Returns
    -------
    bytes
        Signature
    """
    key = RSA.import_key(private_key)
    hash_obj = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(hash_obj)
    return signature


def verify_signature(message, signature, public_key):
    """
    Verify a digital signature.

    Parameters
    ----------
    message : bytes
    signature : bytes
    public_key : bytes

    Returns
    -------
    bool
        True if valid, False otherwise
    """
    key = RSA.import_key(public_key)
    hash_obj = SHA256.new(message)

    try:
        pkcs1_15.new(key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False
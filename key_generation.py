from Crypto.PublicKey import RSA, ECC


def generate_rsa_keys(key_size=2048):
    """
    Generate an RSA key pair.

    Parameters
    ----------
    key_size : int
        RSA modulus size in bits.

    Returns
    -------
    tuple[bytes, bytes]
        (private_key_pem, public_key_pem)
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def generate_ecc_keys(curve="P-256"):
    """
    Generate an ECC key pair.

    Parameters
    ----------
    curve : str
        ECC curve name.

    Returns
    -------
    tuple[str, str]
        (private_key_pem, public_key_pem)
    """
    key = ECC.generate(curve=curve)
    private_key = key.export_key(format="PEM")
    public_key = key.public_key().export_key(format="PEM")
    return private_key, public_key


if __name__ == "__main__":
    rsa_private, rsa_public = generate_rsa_keys()
    ecc_private, ecc_public = generate_ecc_keys()

    print("RSA public key generated:")
    print(rsa_public.decode() if isinstance(rsa_public, bytes) else rsa_public)

    print("\nECC public key generated:")
    print(ecc_public)
"""

This module implements message compression and decompression.
PGP compresses data before encryption to reduce size and improve security.

Compression helps:
1. Reduce message size
2. Remove patterns before encryption
"""

import zlib


def compress_message(message):
    """
    Compress a message using zlib.
    """

    return zlib.compress(message)


def decompress_message(compressed_message):
    """
    Decompress a message.
    """

    return zlib.decompress(compressed_message)
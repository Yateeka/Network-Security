import zlib


def compress_message(message, level=9):
    """
    Compress a message using zlib.

    Parameters
    ----------
    message : bytes
    level : int
        Compression level from 0 to 9.

    Returns
    -------
    bytes
        Compressed message
    """
    return zlib.compress(message, level)


def decompress_message(compressed_message):
    """
    Decompress a message.

    Parameters
    ----------
    compressed_message : bytes

    Returns
    -------
    bytes
        Original message
    """
    return zlib.decompress(compressed_message)
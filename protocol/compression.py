# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Compression of the order data.

EBICS specification V 3.0.2 (DE) ch. 3.2 and ch. 15: the order data are
compressed with the ZIP algorithm of RFC 1950 (zlib) before the encryption.
"""
import zlib

from .exceptions import EbicsCryptoError

_CHUNK_SIZE = 64 * 1024


def compress(data):
    """Return the data compressed with zlib (RFC 1950).

    Source: EBICS specification V 3.0.2 (DE) ch. 3.2, ch. 15."""
    return zlib.compress(bytes(data))


def decompress(data, max_size):
    """Return the decompressed data (RFC 1950).

    The data are decompressed in chunks; more than max_size bytes raise
    EbicsCryptoError (protection against compression bombs, specification
    account_ebics ch. 7.3 and ch. 12 max_zip_size).

    Source: EBICS specification V 3.0.2 (DE) ch. 3.2, ch. 15."""
    if max_size is None or max_size < 0:
        raise ValueError("max_size must be a positive number")
    decompressor = zlib.decompressobj()
    result = bytearray()
    view = memoryview(bytes(data))
    try:
        for start in range(0, len(view), _CHUNK_SIZE):
            chunk = view[start:start + _CHUNK_SIZE]
            while chunk:
                result += decompressor.decompress(
                    chunk, max_size + 1 - len(result))
                if len(result) > max_size:
                    raise EbicsCryptoError(
                        "Decompressed data exceed %s bytes" % max_size)
                chunk = decompressor.unconsumed_tail
        result += decompressor.flush()
    except zlib.error as exception:
        raise EbicsCryptoError(
            "Invalid compressed data (%s)" % exception) from None
    if len(result) > max_size:
        raise EbicsCryptoError(
            "Decompressed data exceed %s bytes" % max_size)
    if not decompressor.eof:
        raise EbicsCryptoError("Incomplete compressed data")
    return bytes(result)

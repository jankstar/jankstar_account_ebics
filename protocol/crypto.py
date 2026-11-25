# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Signature processes A006 and X002 and encryption process E002.

No Tryton imports (specification account_ebics ch. 4.1). Messages of the
exceptions never contain key material or decrypted data (ch. 8.1).
"""
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import EbicsCryptoError

#: Length of the SHA-256 hash value and of the salt of A006
DIGEST_LENGTH = 32
#: Block and key length of AES-128 in bytes
_BLOCK = 16
#: RSA key length for E002 (EBICS specification V 3.0.2 (DE) ch. 11.3.2.1)
_E002_MIN_BITS = 2048
_E002_MAX_BITS = 16384
# Initial chaining value of E002
_ICV = bytes(_BLOCK)


def _pss():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=DIGEST_LENGTH)


def _check_digest(digest):
    digest = bytes(digest)
    if len(digest) != DIGEST_LENGTH:
        raise EbicsCryptoError(
            "The hash value must have %s bytes" % DIGEST_LENGTH)
    return digest


def sign_a006(private_key, digest):
    """Return the A006 signature over the hash value HM = SHA-256(M).

    A006 is EMSA-PSS with SHA-256, salt length 32 bytes and MGF1 applied to
    HM as message: s = sign_EMSA-PSS(SK)[HM]. EMSA-PSS hashes its input
    again, so the order data are hashed twice as required by A006.
    The preprocessing of the order data (ch. 14.1) follows in block C.

    Source: EBICS specification V 3.0.2 (DE) ch. 14.1.4.2."""
    digest = _check_digest(digest)
    return private_key.sign(digest, _pss(), hashes.SHA256())


def verify_a006(public_key, digest, signature):
    """Check an A006 signature over the hash value HM = SHA-256(M);
    raise EbicsCryptoError if it is not valid.

    Source: EBICS specification V 3.0.2 (DE) ch. 14.1.4.2."""
    digest = _check_digest(digest)
    try:
        public_key.verify(bytes(signature), digest, _pss(), hashes.SHA256())
    except InvalidSignature:
        raise EbicsCryptoError("Invalid A006 signature") from None


def sign_x002(private_key, data):
    """Return the X002 signature over the data: RSA with PKCS #1 v1.5
    padding and SHA-256. The data are the canonicalised XML (E03).

    Source: EBICS specification V 3.0.2 (DE) ch. 11.1."""
    return private_key.sign(bytes(data), padding.PKCS1v15(), hashes.SHA256())


def verify_x002(public_key, data, signature):
    """Check an X002 signature; raise EbicsCryptoError if it is not valid.

    Source: EBICS specification V 3.0.2 (DE) ch. 11.1."""
    try:
        public_key.verify(
            bytes(signature), bytes(data), padding.PKCS1v15(),
            hashes.SHA256())
    except InvalidSignature:
        raise EbicsCryptoError("Invalid X002 signature") from None


def _check_e002_key(key):
    if not _E002_MIN_BITS <= key.key_size <= _E002_MAX_BITS:
        raise EbicsCryptoError(
            "The RSA key for E002 must have between %s and %s bits"
            % (_E002_MIN_BITS, _E002_MAX_BITS))


def _pad(data):
    # ISO 10126-2: random filler, the last byte is the number of padding
    # bytes (1-16); always at least one byte (decision F5 of E02)
    length = _BLOCK - len(data) % _BLOCK
    return data + os.urandom(length - 1) + bytes([length])


def _unpad(data):
    # ANSI X9.23 (zero filler) and ISO 10126-2 (random filler): only the
    # last byte is significant
    length = data[-1] if data else 0
    if not 1 <= length <= _BLOCK:
        raise EbicsCryptoError("Invalid padding of the E002 data")
    return data[:-length]


def encrypt_e002(data, recipient_public_key, transaction_key=None):
    """Encrypt the (compressed) order data with E002 and return
    (encrypted transaction key, ciphertext).

    A random 128-bit transaction key encrypts the data with AES-128 in CBC
    mode, ICV = 0, padding ANSI X9.23 / ISO 10126-2 (here ISO 10126-2);
    the transaction key is encrypted with RSA and PKCS #1 padding with the
    public key of the recipient (2048 to 16384 bits) and returned without
    padding to the length of the modulus (leading zero bytes removed).
    transaction_key is only for tests with fixed values.

    Source: EBICS specification V 3.0.2 (DE) ch. 11.3.2.1, ch. 11.3.2.2
    (TransactionKey not padded); ch. 3.2."""
    _check_e002_key(recipient_public_key)
    if transaction_key is None:
        transaction_key = os.urandom(_BLOCK)
    elif len(transaction_key) != _BLOCK:
        raise EbicsCryptoError("The transaction key must have 16 bytes")
    encryptor = Cipher(
        algorithms.AES128(transaction_key), modes.CBC(_ICV)).encryptor()
    ciphertext = encryptor.update(_pad(bytes(data))) + encryptor.finalize()
    encrypted_key = recipient_public_key.encrypt(
        transaction_key, padding.PKCS1v15())
    # ch. 11.3.2.2: no padding to the full length of the modulus
    encrypted_key = encrypted_key.lstrip(b'\x00') or b'\x00'
    return encrypted_key, ciphertext


def decrypt_e002(encrypted_key, ciphertext, private_key):
    """Decrypt E002 data and return the (still compressed) order data.

    The encrypted transaction key may be shorter than the modulus (it is
    not padded, ch. 11.3.2.2) and is padded with leading zero bytes before
    the decryption; longer is an error. PDEK is the RSA decryption with
    PKCS #1 padding; the 128 least significant bits (the last 16 bytes)
    form the key DEK for AES-128-CBC with ICV = 0; the padding (ANSI X9.23
    or ISO 10126-2) is removed.

    Source: EBICS specification V 3.0.2 (DE) ch. 11.3.2.1, ch. 11.3.2.2."""
    _check_e002_key(private_key)
    ciphertext = bytes(ciphertext)
    if not ciphertext or len(ciphertext) % _BLOCK:
        raise EbicsCryptoError(
            "The E002 data must be a multiple of %s bytes" % _BLOCK)
    encrypted_key = bytes(encrypted_key)
    length = (private_key.key_size + 7) // 8
    if not encrypted_key or len(encrypted_key) > length:
        raise EbicsCryptoError(
            "The encrypted transaction key has an invalid length")
    encrypted_key = encrypted_key.rjust(length, b'\x00')
    try:
        pdek = private_key.decrypt(encrypted_key, padding.PKCS1v15())
    except ValueError:
        raise EbicsCryptoError(
            "The transaction key cannot be decrypted") from None
    if len(pdek) < _BLOCK:
        raise EbicsCryptoError("The transaction key is too short")
    decryptor = Cipher(
        algorithms.AES128(pdek[-_BLOCK:]), modes.CBC(_ICV)).decryptor()
    return _unpad(decryptor.update(ciphertext) + decryptor.finalize())

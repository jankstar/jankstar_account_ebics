# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Exceptions of the protocol layer.

Messages never contain key material, decrypted data or the passphrase
(specification account_ebics ch. 8.1).
"""


class EbicsError(Exception):
    "Base class of the errors of the protocol layer"


class EbicsCryptoError(EbicsError):
    "Signature, encryption, padding or compression failed"


class EbicsKeyringError(EbicsError):
    "The key container cannot be created or read"

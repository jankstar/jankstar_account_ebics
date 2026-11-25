# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Tests of the protocol layer without database and without network.

Test keys and certificates are generated; tests/data contains only a
generated test certificate (no real data).
"""
import ast
import base64
import datetime
import functools
import hashlib
import io
import json
import os
import re
import unittest
import zipfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from lxml import etree

from trytond.modules.account_ebics.protocol import (
    client, compression, crypto, keys, returncodes, schema, transport)
from trytond.modules.account_ebics.protocol import xml as ebics_xml
from trytond.modules.account_ebics.protocol.exceptions import (
    EbicsAuthenticationError, EbicsCryptoError, EbicsError, EbicsKeyringError,
    EbicsProtocolError, EbicsTransportError)
from trytond.modules.account_ebics.tests.fake_bank import (
    BANK_SUBJECT, FakeBank, FakeBankTransport)

HERE = os.path.dirname(__file__)
XSD_DIR = os.environ.get('EBICS_XSD_DIR') or os.path.join(
    os.path.dirname(HERE), 'specs', 'referenz',
    'EBICS_3.0_schema_H005FinalVersion07-08-2017')
HAS_XSD = os.path.isfile(os.path.join(XSD_DIR, 'ebics_request_H005.xsd'))
SKIP_XSD = "EBICS schemas H005 not found (specs/referenz or EBICS_XSD_DIR)"
PROTOCOL = os.path.join(os.path.dirname(HERE), 'protocol')
SUBJECT = keys.Subject('TESTUSER', 'Testfirma GmbH (Testdaten)', 'DE')
PASSPHRASE = 'Test-Passphrase-nur-fuer-Tests'
# Hash value (D9) of tests/data/test_certificate_x002.der
TEST_CERTIFICATE_HASH = (
    '83AA1D9B24AC1C67CA645BB3AA913778215D2818B224FEB6406B9B878189A2D0')


# Slow key generation only once per test run
@functools.lru_cache(maxsize=None)
def cached_key(bits, number=0):
    return keys.generate_key(bits)


@functools.lru_cache(maxsize=None)
def cached_keyring():
    return keys.generate_keyring(2048, SUBJECT)


def private_der(private_key):
    return private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())


def zip_bytes(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as container:
        for name, data in members.items():
            container.writestr(name, data)
    return buffer.getvalue()


class ProtocolTestCase(unittest.TestCase):
    "Test the protocol layer (keys, crypto, compression)"

    # T1
    def test_generate_key(self):
        "Keys of 2048, 3072, 4096 bits with exponent 65537"
        for bits in keys.KEY_LENGTHS:
            with self.subTest(bits=bits):
                key = cached_key(bits)
                self.assertEqual(key.key_size, bits)
                self.assertEqual(
                    key.public_key().public_numbers().e, 65537)
        for bits in [1024, 2047, 2049, 8192, None]:
            with self.subTest(bits=bits):
                with self.assertRaises(ValueError):
                    keys.generate_key(bits)

    # T2
    def test_certificate(self):
        "Self-signed X.509v3 certificate as in working paper ch. 4.4"
        now = datetime.datetime(
            2028, 2, 29, 12, 0, tzinfo=datetime.timezone.utc)
        for purpose in keys.PURPOSES:
            with self.subTest(purpose=purpose):
                key = cached_key(2048, keys.PURPOSES.index(purpose))
                cert = keys.create_certificate(key, purpose, SUBJECT, now=now)
                self.assertEqual(cert.version, x509.Version.v3)
                self.assertEqual(cert.subject, cert.issuer)
                self.assertEqual(
                    cert.subject.get_attributes_for_oid(
                        NameOID.COMMON_NAME)[0].value, 'TESTUSER')
                self.assertEqual(
                    cert.subject.get_attributes_for_oid(
                        NameOID.ORGANIZATION_NAME)[0].value,
                    'Testfirma GmbH (Testdaten)')
                self.assertEqual(
                    cert.subject.get_attributes_for_oid(
                        NameOID.COUNTRY_NAME)[0].value, 'DE')
                self.assertIsInstance(
                    cert.signature_hash_algorithm, hashes.SHA256)
                # signed by its own key
                key.public_key().verify(
                    cert.signature, cert.tbs_certificate_bytes,
                    padding.PKCS1v15(), cert.signature_hash_algorithm)
                self.assertEqual(
                    cert.public_key().public_numbers(),
                    key.public_key().public_numbers())
                self.assertEqual(cert.not_valid_before_utc, now)
                self.assertEqual(
                    cert.not_valid_after_utc,
                    datetime.datetime(2033, 2, 28, 12, 0,
                        tzinfo=datetime.timezone.utc))
                constraints = cert.extensions.get_extension_for_class(
                    x509.BasicConstraints)
                self.assertTrue(constraints.critical)
                self.assertFalse(constraints.value.ca)
                usage = cert.extensions.get_extension_for_class(
                    x509.KeyUsage)
                self.assertTrue(usage.critical)
                signing = purpose in {'A006', 'X002'}
                self.assertEqual(usage.value.digital_signature, signing)
                self.assertEqual(usage.value.key_encipherment, not signing)
                self.assertFalse(usage.value.key_cert_sign)

    def test_certificate_without_country(self):
        "The country is optional; invalid subjects are rejected"
        key = cached_key(2048)
        cert = keys.create_certificate(
            key, 'A006', keys.Subject('TESTUSER', 'Testfirma'))
        self.assertFalse(cert.subject.get_attributes_for_oid(
                NameOID.COUNTRY_NAME))
        for subject in [
                keys.Subject('', 'Testfirma'),
                keys.Subject('TESTUSER', ''),
                keys.Subject('TESTUSER', 'Testfirma', 'DEU')]:
            with self.subTest(subject=subject):
                with self.assertRaises(ValueError):
                    keys.create_certificate(key, 'A006', subject)
        with self.assertRaises(ValueError):
            keys.create_certificate(key, 'A005', SUBJECT)

    # T3
    def test_certificate_hash(self):
        "Hash value D9: SHA-256 over DER, 64 hex characters, upper case"
        with open(os.path.join(
                    HERE, 'data', 'test_certificate_x002.der'), 'rb') as f:
            der = f.read()
        cert = x509.load_der_x509_certificate(der)
        value = keys.certificate_hash(cert)
        self.assertEqual(value, TEST_CERTIFICATE_HASH)
        self.assertEqual(value, hashlib.sha256(der).hexdigest().upper())
        self.assertEqual(len(value), 64)
        self.assertEqual(value, value.upper())

    def test_generate_keyring(self):
        "Three separate key pairs with certificates"
        keyring = cached_keyring()
        self.assertEqual(keyring.bits, 2048)
        moduli = set()
        for purpose in keys.PURPOSES:
            entry = keyring.keys[purpose]
            self.assertEqual(entry.source, keys.SOURCE_GENERATED)
            self.assertEqual(entry.private_key.key_size, 2048)
            moduli.add(entry.private_key.public_key().public_numbers().n)
        self.assertEqual(len(moduli), 3)

    # T4
    def test_keyring_roundtrip(self):
        "dump and load return the same keys and certificates"
        keyring = cached_keyring()
        data = keys.dump_keyring(keyring, PASSPHRASE)
        with zipfile.ZipFile(io.BytesIO(data)) as container:
            self.assertEqual(
                sorted(container.namelist()),
                ['A006.p12', 'E002.p12', 'X002.p12', 'manifest.json'])
            manifest = json.loads(container.read('manifest.json'))
            members = {n: container.read(n) for n in container.namelist()}
        self.assertEqual(manifest['version'], 1)
        self.assertEqual(manifest['bits'], 2048)
        self.assertEqual(
            manifest['keys'],
            {p: {'source': 'generated'} for p in keys.PURPOSES})
        self.assertNotIn(PASSPHRASE, json.dumps(manifest))

        loaded = keys.load_keyring(data, PASSPHRASE)
        self.assertEqual(loaded.bits, 2048)
        self.assertEqual(
            loaded.created.replace(microsecond=0),
            keyring.created.replace(microsecond=0))
        for purpose in keys.PURPOSES:
            with self.subTest(purpose=purpose):
                self.assertEqual(
                    private_der(loaded.private_key(purpose)),
                    private_der(keyring.private_key(purpose)))
                self.assertEqual(
                    loaded.certificate(purpose), keyring.certificate(purpose))
                # each file readable on its own with the passphrase
                p12 = pkcs12.load_pkcs12(
                    members[purpose + '.p12'], PASSPHRASE.encode())
                self.assertEqual(
                    private_der(p12.key),
                    private_der(keyring.private_key(purpose)))
                self.assertEqual(
                    p12.cert.friendly_name, ('%s TESTUSER' % purpose).encode())
                with self.assertRaises(ValueError):
                    pkcs12.load_pkcs12(members[purpose + '.p12'], None)
                # no clear private key in the container
                self.assertNotIn(
                    private_der(keyring.private_key(purpose)), data)
                for member in members.values():
                    self.assertNotIn(
                        private_der(keyring.private_key(purpose)), member)
                    self.assertNotIn(b'PRIVATE KEY', member)

    def test_keyring_wrong_passphrase(self):
        "Wrong or empty passphrase is rejected"
        data = keys.dump_keyring(cached_keyring(), PASSPHRASE)
        with self.assertRaises(EbicsKeyringError):
            keys.load_keyring(data, 'wrong')
        for passphrase in ['', b'', None]:
            with self.subTest(passphrase=passphrase):
                with self.assertRaises(EbicsKeyringError):
                    keys.load_keyring(data, passphrase)
                with self.assertRaises(EbicsKeyringError):
                    keys.dump_keyring(cached_keyring(), passphrase)

    def test_keyring_damaged(self):
        "Unknown version, unexpected or too big files are rejected"
        data = keys.dump_keyring(cached_keyring(), PASSPHRASE)
        with zipfile.ZipFile(io.BytesIO(data)) as container:
            members = {n: container.read(n) for n in container.namelist()}
        manifest = json.loads(members['manifest.json'])

        def variant(**changes):
            result = dict(members)
            result.update(changes)
            return zip_bytes({k: v for k, v in result.items()
                    if v is not None})

        cases = {
            'unknown version': variant(**{'manifest.json': json.dumps(
                        dict(manifest, version=2))}),
            'no version': variant(**{'manifest.json': json.dumps(
                        {k: v for k, v in manifest.items()
                            if k != 'version'})}),
            'manifest no json': variant(**{'manifest.json': b'{'}),
            'no manifest': variant(**{'manifest.json': None}),
            'missing p12': variant(**{'E002.p12': None}),
            'unexpected file': variant(**{'other.txt': b'x'}),
            'path in name': variant(**{'../A006.p12': b'x'}),
            'too big': variant(**{
                        'A006.p12': b'0' * (keys._MAX_MEMBER_SIZE + 1)}),
            'additional pem': variant(**{'A006.pem': b'x'}),
            'unknown source': variant(**{'manifest.json': json.dumps(
                        dict(manifest, keys=dict(manifest['keys'],
                                E002={'source': 'token'})))}),
            'damaged p12': variant(**{'X002.p12': b'not a p12'}),
            'no zip': b'not a zip file',
            }
        for name, blob in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(EbicsKeyringError):
                    keys.load_keyring(blob, PASSPHRASE)

    def test_keyring_external(self):
        "An external key is stored and loaded with its certificate only"
        keyring = cached_keyring()
        external = keys.Keyring(keyring.bits, dict(keyring.keys,
                X002=keys.KeyEntry(
                    keys.SOURCE_EXTERNAL, None,
                    keyring.certificate('X002'))))
        data = keys.dump_keyring(external, PASSPHRASE)
        with zipfile.ZipFile(io.BytesIO(data)) as container:
            self.assertEqual(
                sorted(container.namelist()),
                ['A006.p12', 'E002.p12', 'X002.pem', 'manifest.json'])
        loaded = keys.load_keyring(data, PASSPHRASE)
        self.assertEqual(loaded.keys['X002'].source, keys.SOURCE_EXTERNAL)
        self.assertIsNone(loaded.private_key('X002'))
        self.assertEqual(
            loaded.certificate('X002'), keyring.certificate('X002'))
        self.assertIsNotNone(loaded.private_key('A006'))

    def test_public_parts(self):
        "Public parts per purpose for INI, HIA and the letters"
        keyring = cached_keyring()
        parts = keys.public_parts(keyring)
        self.assertEqual(sorted(parts), sorted(keys.PURPOSES))
        for purpose, values in parts.items():
            with self.subTest(purpose=purpose):
                cert = keyring.certificate(purpose)
                numbers = keyring.private_key(
                    purpose).public_key().public_numbers()
                self.assertEqual(values['modulus'], numbers.n)
                self.assertEqual(values['exponent'], 65537)
                self.assertEqual(values['bits'], 2048)
                self.assertEqual(
                    values['certificate_der'],
                    cert.public_bytes(serialization.Encoding.DER))
                self.assertTrue(values['certificate_pem'].startswith(
                        b'-----BEGIN CERTIFICATE-----'))
                self.assertEqual(values['hash'], keys.certificate_hash(cert))
                self.assertNotIn(b'PRIVATE', values['certificate_pem'])

    # T5
    def test_a006(self):
        "A006: EMSA-PSS, SHA-256, salt 32, MGF1 over HM = SHA-256(M)"
        keyring = cached_keyring()
        private_key = keyring.private_key('A006')
        public_key = private_key.public_key()
        digest = hashlib.sha256(b'order data (test)').digest()
        signature = crypto.sign_a006(private_key, digest)
        self.assertEqual(len(signature), 256)
        crypto.verify_a006(public_key, digest, signature)
        # independent check: PSS with salt length exactly 32 over HM
        public_key.verify(
            signature, digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256())
        with self.assertRaises(InvalidSignature):
            public_key.verify(
                signature, digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=20),
                hashes.SHA256())
        # HM is hashed again by EMSA-PSS (double hashing, ch. 14.1.4.2):
        # treating HM as the PSS hash itself does not verify
        with self.assertRaises(InvalidSignature):
            public_key.verify(
                signature, digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                utils.Prehashed(hashes.SHA256()))
        # randomised salt
        self.assertNotEqual(signature, crypto.sign_a006(private_key, digest))
        with self.assertRaises(EbicsCryptoError):
            crypto.verify_a006(
                keyring.private_key('X002').public_key(), digest, signature)
        changed = bytes([digest[0] ^ 1]) + digest[1:]
        with self.assertRaises(EbicsCryptoError):
            crypto.verify_a006(public_key, changed, signature)
        for wrong in [b'', digest[:31], digest + b'0']:
            with self.assertRaises(EbicsCryptoError):
                crypto.sign_a006(private_key, wrong)

    # T6
    def test_x002(self):
        "X002: RSA PKCS #1 v1.5 with SHA-256"
        keyring = cached_keyring()
        private_key = keyring.private_key('X002')
        public_key = private_key.public_key()
        data = b'<ds:SignedInfo>test</ds:SignedInfo>'
        signature = crypto.sign_x002(private_key, data)
        crypto.verify_x002(public_key, data, signature)
        public_key.verify(
            signature, data, padding.PKCS1v15(), hashes.SHA256())
        # deterministic
        self.assertEqual(signature, crypto.sign_x002(private_key, data))
        with self.assertRaises(EbicsCryptoError):
            crypto.verify_x002(public_key, data + b' ', signature)
        with self.assertRaises(EbicsCryptoError):
            crypto.verify_x002(
                keyring.private_key('A006').public_key(), data, signature)

    # T7
    def test_e002_roundtrip(self):
        "E002 round trip for several lengths"
        keyring = cached_keyring()
        private_key = keyring.private_key('E002')
        public_key = private_key.public_key()
        for length in [0, 1, 15, 16, 17, 1000000]:
            with self.subTest(length=length):
                data = os.urandom(length)
                encrypted_key, ciphertext = crypto.encrypt_e002(
                    data, public_key)
                # not padded to the modulus (ch. 11.3.2.2)
                self.assertLessEqual(len(encrypted_key), 256)
                self.assertNotEqual(encrypted_key[:1], b'\x00')
                self.assertEqual(len(ciphertext) % 16, 0)
                # padding always 1-16 bytes
                self.assertEqual(len(ciphertext), (length // 16 + 1) * 16)
                self.assertEqual(
                    crypto.decrypt_e002(
                        encrypted_key, ciphertext, private_key), data)

    def test_e002_padding(self):
        "E002 accepts ANSI X9.23 and ISO 10126-2, rejects wrong padding"
        keyring = cached_keyring()
        private_key = keyring.private_key('E002')
        key = bytes(range(16))
        encrypted_key = private_key.public_key().encrypt(
            key, padding.PKCS1v15())

        def encrypt(padded):
            encryptor = Cipher(
                algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
            return encryptor.update(padded) + encryptor.finalize()

        data = b'0123456789'
        x923 = data + bytes(5) + bytes([6])
        iso = data + b'\x17\x2a\x99\x01\xfe' + bytes([6])
        full = bytes(16) + bytes(15) + bytes([16])
        for name, padded, expected in [
                ('X9.23', x923, data), ('ISO 10126-2', iso, data),
                ('full block', full, bytes(16))]:
            with self.subTest(padding=name):
                self.assertEqual(
                    crypto.decrypt_e002(
                        encrypted_key, encrypt(padded), private_key),
                    expected)
        for name, padded in [
                ('zero', data + bytes(6)),
                ('17', bytes(15) + bytes([17]))]:
            with self.subTest(padding=name):
                with self.assertRaises(EbicsCryptoError):
                    crypto.decrypt_e002(
                        encrypted_key, encrypt(padded), private_key)
        for ciphertext in [b'', bytes(15), bytes(17)]:
            with self.assertRaises(EbicsCryptoError):
                crypto.decrypt_e002(encrypted_key, ciphertext, private_key)

    def test_e002_other_key(self):
        "Data for another key cannot be decrypted"
        keyring = cached_keyring()
        data = b'order data (test) ' * 10
        encrypted_key, ciphertext = crypto.encrypt_e002(
            data, keyring.private_key('E002').public_key())
        try:
            result = crypto.decrypt_e002(
                encrypted_key, ciphertext, keyring.private_key('X002'))
        except EbicsCryptoError:
            result = None
        self.assertNotEqual(result, data)

    def test_e002_key_length(self):
        "E002 needs RSA keys of at least 2048 bits"
        from cryptography.hazmat.primitives.asymmetric import rsa
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with self.assertRaises(EbicsCryptoError):
            crypto.encrypt_e002(b'x', small.public_key())
        with self.assertRaises(EbicsCryptoError):
            crypto.decrypt_e002(bytes(128), bytes(16), small)
        with self.assertRaises(EbicsCryptoError):
            crypto.encrypt_e002(
                b'x', cached_key(2048).public_key(), transaction_key=bytes(8))

    def test_e002_transaction_key_not_padded(self):
        "TransactionKey without padding to the modulus (ch. 11.3.2.2)"
        private_key = cached_keyring().private_key('E002')
        public_key = private_key.public_key()
        key = bytes(range(16))
        data = b'<Document>test</Document>'
        encryptor = Cipher(
            algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
        padded = data + bytes(15 - len(data) % 16) + bytes(
            [16 - len(data) % 16])
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        # fixed case: an RSA ciphertext with a leading zero byte
        for _ in range(10000):
            full = public_key.encrypt(key, padding.PKCS1v15())
            if full[0] == 0:
                break
        else:
            self.fail("No ciphertext with leading zero byte")
        self.assertEqual(len(full), 256)
        short = full.lstrip(b'\x00')
        self.assertLess(len(short), 256)
        for name, encrypted_key in [('short', short), ('full', full)]:
            with self.subTest(transaction_key=name):
                self.assertEqual(crypto.decrypt_e002(
                        encrypted_key, ciphertext, private_key), data)
        for name, encrypted_key in [
                ('longer than modulus', b'\x00' + full), ('empty', b'')]:
            with self.subTest(transaction_key=name):
                with self.assertRaises(EbicsCryptoError):
                    crypto.decrypt_e002(
                        encrypted_key, ciphertext, private_key)
        # encrypt_e002 never sends a leading zero byte
        lengths = set()
        for _ in range(600):
            encrypted_key, _ = crypto.encrypt_e002(b'x', public_key)
            self.assertNotEqual(encrypted_key[:1], b'\x00')
            lengths.add(len(encrypted_key))
        self.assertIn(256, lengths)

    # T8
    def test_e002_known_values(self):
        "E002 with fixed transaction key equals independent AES-128-CBC"
        keyring = cached_keyring()
        private_key = keyring.private_key('E002')
        # AES-128 known answer (FIPS 197, appendix C.1); with ICV = 0 the
        # first CBC block equals the ECB block
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        block = bytes.fromhex('00112233445566778899aabbccddeeff')
        encrypted_key, ciphertext = crypto.encrypt_e002(
            block, private_key.public_key(), transaction_key=key)
        self.assertEqual(
            ciphertext[:16].hex(), '69c4e0d86a7b0430d8cdb78070b4c55a')
        self.assertEqual(len(ciphertext), 32)
        # independent computation of the full blocks
        data = os.urandom(64)
        encrypted_key, ciphertext = crypto.encrypt_e002(
            data, private_key.public_key(), transaction_key=key)
        encryptor = Cipher(
            algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
        self.assertEqual(ciphertext[:64], encryptor.update(data))
        # the transaction key is RSA PKCS #1 v1.5 encrypted
        self.assertEqual(
            private_key.decrypt(encrypted_key, padding.PKCS1v15()), key)
        self.assertEqual(
            crypto.decrypt_e002(encrypted_key, ciphertext, private_key),
            data)

    # T9
    def test_compression(self):
        "RFC 1950 round trip and size limit"
        data = b'<Document>' + b'test ' * 100000 + b'</Document>'
        compressed = compression.compress(data)
        self.assertEqual(compressed[:1], b'\x78')  # zlib header
        self.assertEqual(
            compression.decompress(compressed, len(data)), data)
        with self.assertRaises(EbicsCryptoError):
            compression.decompress(compressed, len(data) - 1)
        with self.assertRaises(EbicsCryptoError):
            compression.decompress(b'not compressed', 1000)
        with self.assertRaises(EbicsCryptoError):
            compression.decompress(compressed[:-10], len(data))
        self.assertEqual(
            compression.decompress(compression.compress(b''), 0), b'')
        # compression bomb: 100 MB of zeros, limit 1 MB
        bomb = compression.compress(bytes(100 * 1024 * 1024))
        with self.assertRaises(EbicsCryptoError):
            compression.decompress(bomb, 1024 * 1024)

    # T10
    def test_no_tryton_imports(self):
        "The protocol layer does not import Tryton"
        for name in sorted(os.listdir(PROTOCOL)):
            if not name.endswith('.py'):
                continue
            with self.subTest(file=name):
                with open(os.path.join(PROTOCOL, name)) as f:
                    tree = ast.parse(f.read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        modules = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom):
                        modules = [node.module or '']
                    else:
                        continue
                    for module in modules:
                        self.assertFalse(
                            module.split('.')[0] == 'trytond',
                            '%s imports %s' % (name, module))

    # T11
    def test_messages_without_secrets(self):
        "Exceptions contain neither key material nor the passphrase"
        keyring = cached_keyring()
        data = keys.dump_keyring(keyring, PASSPHRASE)
        secrets = [PASSPHRASE, PASSPHRASE.encode().hex()]
        for purpose in keys.PURPOSES:
            numbers = keyring.private_key(purpose).private_numbers()
            secrets += [str(numbers.d), '%x' % numbers.d,
                str(numbers.p), str(numbers.q)]
        key = bytes(range(16))
        bad_key = keyring.private_key('E002').public_key().encrypt(
            key, padding.PKCS1v15())
        encryptor = Cipher(
            algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
        bad_padding = encryptor.update(bytes(16)) + encryptor.finalize()
        errors = []
        for call in [
                lambda: keys.load_keyring(data, PASSPHRASE + 'x'),
                lambda: keys.load_keyring(data[:-20], PASSPHRASE),
                lambda: crypto.decrypt_e002(
                    bad_key, bad_padding, keyring.private_key('E002')),
                lambda: crypto.verify_a006(
                    keyring.private_key('A006').public_key(),
                    bytes(32), bytes(256)),
                lambda: crypto.verify_x002(
                    keyring.private_key('X002').public_key(),
                    b'x', bytes(256)),
                lambda: compression.decompress(b'x', 10),
                ]:
            try:
                call()
            except (EbicsCryptoError, EbicsKeyringError) as exception:
                errors.append(exception)
            else:
                self.fail("No exception")
        for exception in errors:
            with self.subTest(exception=type(exception).__name__):
                text = '%s %r' % (exception, exception)
                for secret in secrets:
                    self.assertNotIn(secret, text)
                # no chained exception of the library
                self.assertIsNone(exception.__cause__)
                self.assertTrue(exception.__suppress_context__
                    or exception.__context__ is None)
        text = repr(keyring)
        for secret in secrets:
            self.assertNotIn(secret, text)


def test_key_x002():
    "Generated test key (no real key) for reproducible X002 signatures"
    with open(os.path.join(HERE, 'data', 'test_key_x002.pem'), 'rb') as f:
        return serialization.load_pem_private_key(f.read(), None)


def hpb_request(nonce='0123456789ABCDEF0123456789ABCDEF'):
    """HPB request as the example of EBICS specification V 3.0.2 (DE)
    ch. 4.4.2 (Abbildung 26), with test values"""
    root = ebics_xml.root_element('ebicsNoPubKeyDigestsRequest')
    header = ebics_xml.sub_element(root, 'header', authenticate='true')
    static = ebics_xml.sub_element(header, 'static')
    for name, value in [
            ('HostID', 'TESTHOST'),
            ('Nonce', nonce),
            ('Timestamp', '2026-11-24T12:00:00.000Z'),
            ('PartnerID', 'TESTPARTNER'),
            ('UserID', 'TESTUSER')]:
        ebics_xml.sub_element(static, name, value)
    details = ebics_xml.sub_element(static, 'OrderDetails')
    ebics_xml.sub_element(details, 'AdminOrderType', 'HPB')
    ebics_xml.sub_element(static, 'SecurityMedium', '0000')
    ebics_xml.sub_element(header, 'mutable')
    ebics_xml.sub_element(root, 'body')
    return root


# Fixed values of the HPB example with tests/data/test_key_x002.pem
# (checked independently with openssl dgst -sha256 [-sign])
HPB_DIGEST = 'Cw+Usc0wwraLkVlobMNo5ZNgbpbsg+hjCaoTk7qboUA='
HPB_SIGNATURE = (
    'YWpGzRoVSnb0a+NfrThKjB7O2G5XBE6nnqMwQPbdpByRlj772dvFIIExekmYxh3sNriC'
    '9N77zr6expSBZQoT/wU3P0GLGcICiYuKGUN7ZXa6clkqZs/8L7Plkqw+UyKmGa0zKuMq'
    'f4Usvxu1+rddycoU7sXsOsXN7xpPucH36OcsgaqB5sp+1HYZBwPfRZbS7GIcMV8htLgS'
    'WqAy3EhrRC9iPH0czaSJalW1+AUw5S8NWe/gYv51jzpMy1fXkjC3n/UuLvt3GsuXhP5/'
    '/Aa4kiaEHG5pINLANyB7vu4sdfCX5TfuP/Fhcfzvl2OW9ehxpIPi3iilZHV0RZ3YD+YQ'
    'Dw==')
NONCE_LEADING_ZERO = '00000000000000000000000000000093'


class XmlTestCase(unittest.TestCase):
    "Test parser, C14N, authentication signature, identifiers (E03.1)"

    # T1
    def test_parse(self):
        "Secure parser: no entities, no network, no DOCTYPE, size limit"
        root = ebics_xml.parse(b'<a xmlns="urn:org:ebics:H005"><b>1</b></a>')
        self.assertEqual(root.tag, '{urn:org:ebics:H005}a')
        xxe = (b'<?xml version="1.0"?>'
            b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            b'<a>&x;</a>')
        remote = (b'<?xml version="1.0"?>'
            b'<!DOCTYPE a SYSTEM "http://example.invalid/a.dtd"><a/>')
        bomb = (b'<?xml version="1.0"?><!DOCTYPE a ['
            b'<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><a>&c;</a>')
        for name, data in [('xxe', xxe), ('remote dtd', remote),
                ('entity expansion', bomb)]:
            with self.subTest(case=name):
                with self.assertRaises(EbicsProtocolError):
                    ebics_xml.parse(data)
        # entities are not resolved even below the DOCTYPE check
        parser = ebics_xml._parser()
        tree = etree.fromstring(xxe, parser)
        self.assertNotIn('root:', etree.tostring(tree).decode())
        with self.assertRaises(EbicsProtocolError):
            ebics_xml.parse(b'<a>' + b'x' * 100 + b'</a>', max_size=50)
        with self.assertRaises(EbicsProtocolError) as cm:
            ebics_xml.parse(b'<a><b></a>')
        self.assertIn('line 1', str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)

    # T3
    def test_c14n(self):
        "C14N 1.0 inclusive without comments, inherited namespaces"
        data = (b'<r xmlns="urn:org:ebics:H005" '
            b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
            b'xmlns:x="urn:unused">'
            b'<header authenticate="true" b="2"   a="1"><!-- c -->'
            b'<v>a &amp; b</v><e/></header></r>')
        root = ebics_xml.parse(data)
        header = root[0]
        result = ebics_xml.c14n(header)
        self.assertEqual(result, etree.tostring(
                header, method='c14n', exclusive=False, with_comments=False))
        self.assertEqual(
            result,
            b'<header xmlns="urn:org:ebics:H005" '
            b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
            b'xmlns:x="urn:unused" a="1" authenticate="true" b="2">'
            b'<v>a &amp; b</v><e></e></header>')

    # T2
    def test_auth_signature_fixed(self):
        "AuthSignature of the HPB example is reproducible"
        key = test_key_x002()
        root = ebics_xml.sign_auth(hpb_request(), key)
        signed_info = ebics_xml.find(root, 'ebics:AuthSignature/ds:SignedInfo')
        self.assertEqual(
            ebics_xml.get_text(signed_info, 'ds:Reference/ds:DigestValue'),
            HPB_DIGEST)
        self.assertEqual(
            ebics_xml.get_text(root, 'ebics:AuthSignature/ds:SignatureValue'),
            HPB_SIGNATURE)
        # algorithms as in the example of the reference
        self.assertEqual(
            [(etree.QName(n).localname, n.get('Algorithm') or n.get('URI'))
                for n in signed_info.iter() if n is not signed_info
                and (n.get('Algorithm') or n.get('URI'))],
            [
                ('CanonicalizationMethod',
                    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'),
                ('SignatureMethod',
                    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'),
                ('Reference', "#xpointer(//*[@authenticate='true'])"),
                ('Transform',
                    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'),
                ('DigestMethod',
                    'http://www.w3.org/2001/04/xmlenc#sha256'),
                ])
        # position between header and body, no KeyInfo or Object
        self.assertEqual(
            [etree.QName(n).localname for n in root],
            ['header', 'AuthSignature', 'body'])
        self.assertEqual(
            [etree.QName(n).localname
                for n in ebics_xml.find(root, 'ebics:AuthSignature')],
            ['SignedInfo', 'SignatureValue'])
        # digest is SHA-256 over the canonical header
        self.assertEqual(
            base64.b64decode(HPB_DIGEST),
            hashlib.sha256(ebics_xml.c14n(root[0])).digest())
        ebics_xml.verify_auth(
            ebics_xml.parse(ebics_xml.to_bytes(root)), key.public_key())

    @unittest.skipUnless(HAS_XSD, SKIP_XSD)
    def test_auth_signature_schema(self):
        "The signed HPB example is valid according to the schema"
        root = ebics_xml.sign_auth(hpb_request(), test_key_x002())
        self.assertEqual(
            schema.validate(root, 'keymgmt_request', XSD_DIR), [])

    def test_auth_signature_changes(self):
        "Changes inside authenticated elements invalidate the signature"
        key = test_key_x002()
        signed = ebics_xml.to_bytes(ebics_xml.sign_auth(hpb_request(), key))

        def changed(function):
            root = ebics_xml.parse(signed)
            function(root)
            return ebics_xml.parse(ebics_xml.to_bytes(root))

        def set_text(path, value):
            def function(root):
                ebics_xml.find(root, path).text = value
            return function

        invalid = {
            'UserID': set_text(
                'ebics:header/ebics:static/ebics:UserID', 'OTHERUSER'),
            'new element in header': lambda r: ebics_xml.sub_element(
                ebics_xml.find(r, 'ebics:header/ebics:mutable'),
                'TransactionPhase', 'Initialisation'),
            'DigestValue': set_text(
                'ebics:AuthSignature/ds:SignedInfo/ds:Reference/'
                'ds:DigestValue', base64.b64encode(bytes(32)).decode()),
            'SignatureValue': set_text(
                'ebics:AuthSignature/ds:SignatureValue',
                base64.b64encode(bytes(256)).decode()),
            'algorithm': lambda r: ebics_xml.find(
                r, 'ebics:AuthSignature/ds:SignedInfo/ds:SignatureMethod'
                ).set('Algorithm',
                    'http://www.w3.org/2000/09/xmldsig#rsa-sha1'),
            'reference URI': lambda r: ebics_xml.find(
                r, 'ebics:AuthSignature/ds:SignedInfo/ds:Reference'
                ).set('URI', ''),
            'no AuthSignature': lambda r: r.remove(
                ebics_xml.find(r, 'ebics:AuthSignature')),
            'authenticate removed': lambda r: ebics_xml.find(
                r, 'ebics:header').attrib.pop('authenticate'),
            }
        for name, function in invalid.items():
            with self.subTest(change=name):
                with self.assertRaises(EbicsAuthenticationError):
                    ebics_xml.verify_auth(changed(function), key.public_key())
        # outside of the authenticated elements: still valid
        ebics_xml.verify_auth(
            changed(lambda r: ebics_xml.sub_element(
                    ebics_xml.find(r, 'ebics:body'), 'Extra', 'x')),
            key.public_key())
        # other key
        with self.assertRaises(EbicsAuthenticationError):
            ebics_xml.verify_auth(
                ebics_xml.parse(signed), cached_key(2048).public_key())

    def test_auth_signature_no_padding(self):
        "SignatureValue is not padded to the length of the modulus"
        key = test_key_x002()
        root = ebics_xml.sign_auth(hpb_request(NONCE_LEADING_ZERO), key)
        value = ebics_xml.get_base64(
            root, 'ebics:AuthSignature/ds:SignatureValue')
        self.assertEqual(len(value), 255)
        full = crypto.sign_x002(key, ebics_xml.c14n(ebics_xml.find(
                    root, 'ebics:AuthSignature/ds:SignedInfo')))
        self.assertEqual(full, b'\x00' + value)
        ebics_xml.verify_auth(root, key.public_key())

    def test_authenticated_elements(self):
        "Elements with authenticate=true in document order, not nested"
        root = ebics_xml.parse(
            b'<r xmlns="urn:org:ebics:H005"><header authenticate="true">'
            b'<x authenticate="true"/></header><body><a authenticate="true"/>'
            b'<b authenticate="false"/><c authenticate="true"/></body></r>')
        self.assertEqual(
            [etree.QName(n).localname
                for n in ebics_xml.authenticated_elements(root)],
            ['header', 'a', 'c'])
        self.assertEqual(
            ebics_xml.auth_digest(root),
            hashlib.sha256(b''.join(ebics_xml.c14n(n) for n in [
                        root[0], root[1][0], root[1][2]])).digest())
        with self.assertRaises(EbicsProtocolError):
            ebics_xml.auth_digest(ebics_xml.parse(b'<r/>'))

    # T5
    def test_validate_ids(self):
        "Identifiers as in EBICS specification ch. 12.4"
        self.assertEqual(ebics_xml.validate_ids(
                host_id='EBIXHOST', partner_id='KUNDE001', user_id='TLN100',
                order_id='A001'), {})
        self.assertEqual(ebics_xml.validate_ids(
                partner_id='a,b=C', user_id='X' * 35,
                host_id='Host 1'), {})
        self.assertEqual(ebics_xml.validate_ids(), {})
        for name, value in [
                ('user_id', ''), ('user_id', 'X' * 36),
                ('user_id', 'TLN 100'), ('user_id', 'TLN-100'),
                ('partner_id', 'KUNDE_001'), ('partner_id', 'Kunde.1'),
                ('order_id', 'a001'), ('order_id', '1001'),
                ('order_id', 'A01'), ('order_id', 'A0011'),
                ('order_id', 'A00a'),
                ('host_id', ''), ('host_id', 'H' * 36),
                ('host_id', ' HOST'), ('host_id', 'HO  ST'),
                ('host_id', 'HO\tST')]:
            with self.subTest(name=name, value=value):
                errors = ebics_xml.validate_ids(**{name: value})
                self.assertEqual(list(errors), [name])

    # T5b
    def test_defensive_reading(self):
        "Missing or invalid required elements raise with the element path"
        root = ebics_xml.parse(
            b'<ebicsResponse xmlns="urn:org:ebics:H005"><header '
            b'authenticate="true"><mutable><ReturnCode>000000</ReturnCode>'
            b'<ReportText></ReportText></mutable></header><body/>'
            b'</ebicsResponse>')
        self.assertEqual(ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:ReturnCode',
                pattern=r'\d{6}'), '000000')
        cases = {
            'ebicsResponse/body/ReturnCode': lambda: ebics_xml.get_text(
                root, 'ebics:body/ebics:ReturnCode'),
            'ebicsResponse/header/mutable/ReportText': lambda:
                ebics_xml.get_text(
                    root, 'ebics:header/ebics:mutable/ebics:ReportText'),
            'ebicsResponse/header/mutable/ReturnCode': lambda:
                ebics_xml.get_text(
                    root, 'ebics:header/ebics:mutable/ebics:ReturnCode',
                    pattern=r'\d{5}'),
            'ebicsResponse/header/static': lambda: ebics_xml.find(
                root, 'ebics:header/ebics:static'),
            'ebicsResponse/body/DataTransfer/OrderData': lambda:
                ebics_xml.get_base64(
                    root, 'ebics:body/ebics:DataTransfer/ebics:OrderData'),
            }
        for path, call in cases.items():
            with self.subTest(path=path):
                with self.assertRaises(EbicsProtocolError) as cm:
                    call()
                self.assertIn(path, str(cm.exception))
        self.assertIsNone(ebics_xml.get_text(
                root, 'ebics:body/ebics:ReturnCode', required=False))
        self.assertIsNone(ebics_xml.find(
                root, 'ebics:body/ebics:X', required=False))
        with self.assertRaises(EbicsProtocolError) as cm:
            ebics_xml.get_attribute(root, 'ebics:header', 'Version')
        self.assertIn('header', str(cm.exception))
        bad = ebics_xml.parse(
            b'<r xmlns="urn:org:ebics:H005"><d>not base64!</d></r>')
        with self.assertRaises(EbicsProtocolError):
            ebics_xml.get_base64(bad, 'ebics:d')


class ReturnCodeTestCase(unittest.TestCase):
    "Test the return codes of annex 1 (E03.1)"

    # T4
    def test_all_codes(self):
        "All codes of annex 1 with symbol, text and class"
        self.assertEqual(len(returncodes.TECHNICAL_CODES), 30)
        self.assertEqual(len(returncodes.BUSINESS_CODES), 37)
        for table in [returncodes.TECHNICAL_CODES,
                returncodes.BUSINESS_CODES]:
            for code, value in table.items():
                with self.subTest(code=code, kind=value.kind):
                    self.assertRegex(code, r'^\d{6}$')
                    self.assertTrue(value.symbol.startswith('EBICS_'))
                    self.assertTrue(value.text)
                    self.assertIn(value.klass, returncodes.CLASSES)
                    self.assertEqual(
                        returncodes.lookup(code, value.kind), value)

    def test_classes(self):
        "Classes as in working paper E03 ch. 4.5"
        technical, business = returncodes.TECHNICAL, returncodes.BUSINESS
        for code, kind, klass, symbol in [
                ('000000', technical, 'ok', 'EBICS_OK'),
                ('000000', business, 'ok', 'EBICS_OK'),
                ('011000', technical, 'info',
                    'EBICS_DOWNLOAD_POSTPROCESS_DONE'),
                ('011001', technical, 'info',
                    'EBICS_DOWNLOAD_POSTPROCESS_SKIPPED'),
                ('031001', technical, 'info', 'EBICS_ORDER_PARAMS_IGNORED'),
                ('090005', business, 'no_data',
                    'EBICS_NO_DOWNLOAD_DATA_AVAILABLE'),
                ('091002', technical, 'user_state',
                    'EBICS_INVALID_USER_OR_USER_STATE'),
                ('091004', technical, 'user_state',
                    'EBICS_INVALID_USER_STATE'),
                ('091008', technical, 'bank_keys',
                    'EBICS_BANK_PUBKEY_UPDATE_REQUIRED'),
                ('061001', technical, 'error', 'EBICS_AUTHENTICATION_FAILED'),
                ('091003', technical, 'error', 'EBICS_USER_UNKNOWN'),
                # same value, other meaning in the business table
                ('091002', business, 'error', 'EBICS_DOWNLOAD_UNSIGNED_ONLY'),
                ('091116', business, 'error', 'EBICS_PROCESSING_ERROR')]:
            with self.subTest(code=code, kind=kind):
                value = returncodes.lookup(code, kind)
                self.assertEqual((value.klass, value.symbol), (klass, symbol))
        self.assertEqual(
            returncodes.report_text(returncodes.lookup('011000')),
            '[EBICS_DOWNLOAD_POSTPROCESS_DONE] positive Quittung erhalten')

    def test_unknown(self):
        "Unknown or malformed codes are errors with the code in the text"
        value = returncodes.lookup('099999')
        self.assertEqual((value.klass, value.symbol), ('error', None))
        self.assertIn('099999', value.text)
        # 090005 exists only as business code
        self.assertEqual(returncodes.lookup('090005').klass, 'error')
        for code in ['', None, 'abc', '12345']:
            with self.subTest(code=code):
                self.assertEqual(returncodes.lookup(code).klass, 'error')
        self.assertEqual(returncodes.lookup(' 000000 ').klass, 'ok')
        with self.assertRaises(ValueError):
            returncodes.lookup('000000', 'other')


class SchemaTestCase(unittest.TestCase):
    "Test the schema validation (E03.1, T5a)"

    @unittest.skipUnless(HAS_XSD, SKIP_XSD)
    def test_load_and_validate(self):
        "Schemas are loaded locally once; valid and invalid documents"
        schemas = schema.load_schemas(XSD_DIR)
        self.assertEqual(sorted(schemas), sorted(schema.SCHEMA_FILES))
        self.assertIs(schema.load_schemas(XSD_DIR), schemas)
        valid = ebics_xml.parse(
            b'<ebicsHEVRequest xmlns="http://www.ebics.org/H000">'
            b'<HostID>TESTHOST</HostID></ebicsHEVRequest>')
        invalid = ebics_xml.parse(
            b'<ebicsHEVRequest xmlns="http://www.ebics.org/H000">'
            b'<Host>TESTHOST</Host></ebicsHEVRequest>')
        self.assertEqual(schema.validate(valid, 'hev', XSD_DIR), [])
        deviations = schema.validate(invalid, 'hev', XSD_DIR)
        self.assertEqual(len(deviations), 1)
        self.assertIn('line 1', deviations[0])
        # modes
        self.assertEqual(schema.check(invalid, 'hev', XSD_DIR, 'off'), [])
        warnings = schema.check(invalid, 'hev', XSD_DIR, 'warn')
        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith('Schema hev:'))
        with self.assertRaises(EbicsProtocolError):
            schema.check(invalid, 'hev', XSD_DIR, 'strict')
        self.assertEqual(schema.check(valid, 'hev', XSD_DIR, 'strict'), [])
        self.assertEqual(schema.default_mode(XSD_DIR), 'warn')
        self.assertEqual(schema.default_mode(''), 'off')
        self.assertEqual(schema.check(invalid, 'hev', None), [])
        with self.assertRaises(ValueError):
            schema.check(valid, 'hev', XSD_DIR, 'other')
        with self.assertRaises(ValueError):
            schema.validate(valid, 'other', XSD_DIR)

    def test_no_network(self):
        "Imports only from the schema directory, never from the network"
        import tempfile
        valid = ('<schema xmlns="http://www.w3.org/2001/XMLSchema" '
            'targetNamespace="urn:x"><element name="x" type="string"/>'
            '</schema>')
        with tempfile.TemporaryDirectory() as base:
            directory = os.path.join(base, 'xsd')
            os.mkdir(directory)
            # an existing, valid schema outside of the directory
            with open(os.path.join(base, 'outside.xsd'), 'w') as f:
                f.write(valid)
            for name, location in [
                    ('remote', 'http://example.invalid/types.xsd'),
                    ('outside', '../outside.xsd'),
                    ('absolute', os.path.join(base, 'outside.xsd'))]:
                with self.subTest(case=name):
                    for filename in schema.SCHEMA_FILES.values():
                        with open(os.path.join(directory, filename),
                                'w') as f:
                            f.write(
                                '<schema xmlns="http://www.w3.org/2001/'
                                'XMLSchema" targetNamespace="urn:t">'
                                '<import namespace="urn:x" '
                                'schemaLocation="%s"/></schema>' % location)
                    schema._cache.pop(os.path.realpath(directory), None)
                    with self.assertRaises(EbicsProtocolError) as cm:
                        schema.load_schemas(directory)
                    # the resolver refuses; lxml reports the import
                    self.assertIn('cannot be loaded', str(cm.exception))
                    self.assertIn('Failed to parse', str(cm.exception))
            # control: the same import from inside the directory works
            with open(os.path.join(directory, 'inside.xsd'), 'w') as f:
                f.write(valid)
            for filename in schema.SCHEMA_FILES.values():
                with open(os.path.join(directory, filename), 'w') as f:
                    f.write(
                        '<schema xmlns="http://www.w3.org/2001/XMLSchema" '
                        'targetNamespace="urn:t"><import namespace="urn:x" '
                        'schemaLocation="inside.xsd"/></schema>')
            schema._cache.pop(os.path.realpath(directory), None)
            self.assertEqual(
                sorted(schema.load_schemas(directory)),
                sorted(schema.SCHEMA_FILES))
            schema._cache.pop(os.path.realpath(directory), None)
        with self.assertRaises(EbicsProtocolError):
            schema.load_schemas(os.path.join(HERE, 'no-such-directory'))


@functools.lru_cache(maxsize=None)
def cached_bank_keyring():
    return keys.generate_keyring(2048, BANK_SUBJECT)


def new_bank(**kwargs):
    kwargs.setdefault('xsd_dir', XSD_DIR if HAS_XSD else None)
    return FakeBank(keyring=cached_bank_keyring(), **kwargs)


def new_client(bank, transport_=None, **kwargs):
    connection = client.Connection(
        'TESTHOST', 'TESTPARTNER', 'TESTUSER',
        'https://ebics.example.invalid/ebics')
    kwargs.setdefault('xsd_dir', bank.xsd_dir)
    return client.EbicsClient(
        connection, cached_keyring(), transport_ or bank.transport(),
        **kwargs)


def initialised_client(**kwargs):
    bank = new_bank()
    ebics = new_client(bank, **kwargs)
    ebics.ini()
    ebics.hia()
    return bank, ebics


class ClientTestCase(unittest.TestCase):
    "Test the client with HEV, INI, HIA, HPB against the fake bank (E03.2)"

    def test_connection(self):
        "Connection data are checked; product text after F7"
        connection = client.Connection(
            'TESTHOST', 'TESTPARTNER', 'TESTUSER', 'https://x.invalid')
        self.assertEqual(
            connection.product, 'tryton account_ebics %s'
            % client.module_version())
        self.assertTrue(client.module_version())
        for args in [
                ('TESTHOST', 'TEST_PARTNER', 'TESTUSER', 'https://x.invalid'),
                ('TESTHOST', 'TESTPARTNER', 'TEST USER', 'https://x.invalid'),
                (' HOST', 'TESTPARTNER', 'TESTUSER', 'https://x.invalid'),
                ('TESTHOST', 'TESTPARTNER', 'TESTUSER', 'http://x.invalid')]:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    client.Connection(*args)
        with self.assertRaises(ValueError):
            client.Connection(
                'TESTHOST', 'TESTPARTNER', 'TESTUSER', 'https://x.invalid',
                product='x' * 65)

    # T6
    @unittest.skipUnless(HAS_XSD, SKIP_XSD)
    def test_requests_schema(self):
        "HEV, INI, HIA and HPB requests are valid according to the XSD"
        bank = new_bank()
        transport_ = FakeBankTransport(bank)
        ebics = new_client(bank, transport_)
        ebics.hev()
        ebics.ini()
        ebics.hia()
        ebics.hpb()
        kinds = ['hev', 'keymgmt_request', 'keymgmt_request',
            'keymgmt_request']
        for request, kind in zip(transport_.requests, kinds):
            with self.subTest(kind=kind):
                self.assertEqual(schema.validate(
                        ebics_xml.parse(request), kind, XSD_DIR), [])
        self.assertEqual(
            schema.validate(ebics.ini_order_data(), 'signature', XSD_DIR),
            [])
        self.assertEqual(
            schema.validate(ebics.hia_order_data(), 'orders', XSD_DIR), [])
        # the responses of the fake bank are valid as well
        for response, kind in zip(transport_.responses, [
                    'hev', 'keymgmt_response', 'keymgmt_response',
                    'keymgmt_response']):
            with self.subTest(response=kind):
                self.assertEqual(schema.validate(
                        ebics_xml.parse(response), kind, XSD_DIR), [])
        self.assertEqual(bank.schema_errors, [])

    def test_hev(self):
        "HEV returns the supported versions"
        bank = new_bank()
        result = new_client(bank).hev()
        self.assertTrue(result.ok)
        self.assertEqual(result.technical.code, '000000')
        self.assertEqual(result.data['versions'], [('H005', '03.00')])
        root = ebics_xml.parse(result.request)
        self.assertEqual(
            root.tag, '{http://www.ebics.org/H000}ebicsHEVRequest')
        bank.host_id = 'OTHERHOST'
        result = new_client(bank).hev()
        self.assertEqual(
            (result.technical.code, result.klass), ('091011', 'error'))

    # T7
    def test_ini_hia(self):
        "INI and HIA deliver the certificates; hash values D9; F8"
        bank = new_bank()
        ebics = new_client(bank)
        parts = keys.public_parts(cached_keyring())
        ini = ebics.ini()
        hia = ebics.hia()
        for result in [ini, hia]:
            self.assertTrue(result.ok)
            self.assertEqual(result.technical.code, '000000')
            self.assertEqual(result.business.code, '000000')
            self.assertEqual(result.report_text, '[EBICS_OK] OK')
            self.assertRegex(result.order_id, r'^[A-Z][A-Z0-9]{3}$')
        (ini_type, ini_data), (hia_type, hia_data) = bank.received
        self.assertEqual((ini_type, hia_type), ('INI', 'HIA'))
        self.assertEqual(ini_data['hashes'], {'A006': parts['A006']['hash']})
        self.assertEqual(hia_data['hashes'], {
                'X002': parts['X002']['hash'],
                'E002': parts['E002']['hash']})
        self.assertEqual(ini_data['static']['security_medium'], '0400')
        self.assertEqual(hia_data['static']['security_medium'], '0000')
        for data in [ini_data, hia_data]:
            static = data['static']
            self.assertEqual(
                (data['partner_id'], data['user_id']),
                ('TESTPARTNER', 'TESTUSER'))
            self.assertIsNone(static['nonce'])
            self.assertIsNone(static['timestamp'])
            self.assertEqual(static['product_language'], 'de')
            self.assertTrue(
                static['product'].startswith('tryton account_ebics '))
        # unsigned, order data compressed and base64, not encrypted
        root = ebics_xml.parse(ini.request)
        self.assertIsNone(
            ebics_xml.find(root, 'ebics:AuthSignature', required=False))
        order_data = compression.decompress(ebics_xml.get_base64(
                root, 'ebics:body/ebics:DataTransfer/ebics:OrderData'),
            1000000)
        self.assertIn(b'SignaturePubKeyOrderData', order_data)
        self.assertNotIn(b'PRIVATE', ini.request + hia.request)
        # INI twice: state not allowed -> 091002 without details
        again = ebics.ini()
        self.assertEqual(
            (again.technical.code, again.klass), ('091002', 'user_state'))

    # T8
    def test_hpb(self):
        "HPB: bank certificates decrypted, hash values D9"
        bank, ebics = initialised_client()
        result = ebics.hpb()
        self.assertTrue(result.ok)
        bank_keys = result.data['bank_keys']
        self.assertEqual(sorted(bank_keys), ['E002', 'X002'])
        for purpose in ['X002', 'E002']:
            with self.subTest(purpose=purpose):
                self.assertEqual(
                    bank_keys[purpose]['hash'], bank.bank_hash(purpose))
                self.assertEqual(
                    bank_keys[purpose]['certificate'],
                    bank.certificate(purpose))
                self.assertEqual(bank_keys[purpose]['version'], purpose)
        # request signed with X002, Nonce and Timestamp, verified by bank
        root = ebics_xml.parse(result.request)
        ebics_xml.verify_auth(
            root, cached_keyring().certificate('X002').public_key())
        self.assertRegex(ebics_xml.get_text(
                root, 'ebics:header/ebics:static/ebics:Nonce'),
            r'^[0-9A-F]{32}$')
        self.assertRegex(ebics_xml.get_text(
                root, 'ebics:header/ebics:static/ebics:Timestamp'),
            r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$')
        self.assertEqual(ebics_xml.get_text(
                root, 'ebics:header/ebics:static/ebics:SecurityMedium'),
            '0000')
        # a new request gets a new nonce
        self.assertNotEqual(ebics.hpb_request(), ebics.hpb_request())

    def test_hpb_decryption_failed(self):
        "Wrongly encrypted HPB response -> Entschlüsselung fehlgeschlagen"
        for fault in ['HPB_wrong_key', 'HPB_garbage']:
            with self.subTest(fault=fault):
                bank, ebics = initialised_client()
                bank.faults[fault] = True
                with self.assertRaises(EbicsCryptoError) as cm:
                    ebics.hpb()
                self.assertIn(
                    'Entschlüsselung fehlgeschlagen', str(cm.exception))
                self.assertIsNone(cm.exception.__cause__)
                # request and response remain available for the log
                result = cm.exception.result
                self.assertTrue(result.request and result.response)
                self.assertEqual(result.technical.code, '000000')

    def test_hpb_digest_mismatch(self):
        "A response for another encryption key is rejected before decrypting"
        bank, ebics = initialised_client()
        bank.participant('TESTPARTNER', 'TESTUSER').certificates['E002'] = \
            cached_bank_keyring().certificate('E002')
        with self.assertRaises(EbicsCryptoError) as cm:
            ebics.hpb()
        self.assertIn('another encryption key', str(cm.exception))

    def test_hpb_authentication_failed(self):
        "The bank rejects an HPB request with a wrong signature"
        bank, ebics = initialised_client()
        bank.participant('TESTPARTNER', 'TESTUSER').certificates['X002'] = \
            cached_bank_keyring().certificate('X002')
        result = ebics.hpb()
        self.assertEqual(
            (result.technical.code, result.technical.symbol, result.klass),
            ('061001', 'EBICS_AUTHENTICATION_FAILED', 'error'))
        self.assertNotIn('bank_keys', result.data)

    # T9
    def test_return_codes(self):
        "091002 at HPB -> user_state; other codes keep their class"
        bank, ebics = initialised_client()
        for code, klass in [('091002', 'user_state'),
                ('091008', 'bank_keys'), ('091003', 'error'),
                ('091004', 'user_state')]:
            with self.subTest(code=code):
                bank.faults['HPB'] = code
                result = ebics.hpb()
                self.assertEqual(result.technical.code, code)
                self.assertEqual(result.klass, klass)
                self.assertFalse(result.ok)
                self.assertEqual(
                    result.report_text,
                    returncodes.report_text(returncodes.lookup(code)))
                self.assertNotIn('bank_keys', result.data)
        # not yet released by the bank (letters not checked)
        bank = new_bank(auto_release=False)
        ebics = new_client(bank)
        ebics.ini()
        ebics.hia()
        self.assertEqual(ebics.hpb().klass, 'user_state')
        bank.release('TESTPARTNER', 'TESTUSER')
        self.assertTrue(ebics.hpb().ok)

    def test_transport_error(self):
        "Transport errors raise EbicsTransportError with the request"
        bank = new_bank()
        ebics = new_client(bank, FakeBankTransport(
                bank, error=EbicsTransportError("Timeout with test")))
        for order in ['hev', 'ini', 'hia', 'hpb']:
            with self.subTest(order=order):
                with self.assertRaises(EbicsTransportError) as cm:
                    getattr(ebics, order)()
                self.assertTrue(cm.exception.result.request)
                self.assertIsNone(cm.exception.result.response)

    def test_invalid_responses(self):
        "Defensive reading and schema modes for responses"
        bank = new_bank()

        class Broken(FakeBankTransport):
            def __init__(self, bank, change):
                super().__init__(bank)
                self.change = change

            def post(self, data):
                return self.change(super().post(data))

        cases = {
            'not xml': lambda r: b'<html>',
            'other root': lambda r: (
                b'<ebicsResponse xmlns="urn:org:ebics:H005"/>'),
            'no return code': lambda r: r.replace(
                b'<ReturnCode authenticate="true">000000</ReturnCode>', b''),
            'bad return code': lambda r: r.replace(
                b'>000000</ReturnCode>', b'>OK</ReturnCode>', 1),
            }
        for name, change in cases.items():
            with self.subTest(case=name):
                ebics = new_client(bank, Broken(bank, change), xsd_dir=None)
                with self.assertRaises(EbicsProtocolError) as cm:
                    ebics.ini()
                self.assertTrue(cm.exception.result.response)
                bank.participants.clear()

    @unittest.skipUnless(HAS_XSD, SKIP_XSD)
    def test_schema_modes(self):
        "warn records deviations, strict raises, off ignores"
        bank = new_bank()

        def extra(response):
            return response.replace(
                b'<static/>', b'<static><Unknown>x</Unknown></static>')

        class Changing(FakeBankTransport):
            def post(self, data):
                return extra(super().post(data))

        for mode in ['off', 'warn', 'strict']:
            with self.subTest(mode=mode):
                bank.participants.clear()
                ebics = new_client(
                    bank, Changing(bank), xsd_dir=XSD_DIR, xsd_mode=mode)
                if mode == 'strict':
                    with self.assertRaises(EbicsProtocolError):
                        ebics.ini()
                    continue
                result = ebics.ini()
                self.assertTrue(result.ok)
                if mode == 'off':
                    self.assertEqual(result.warnings, [])
                else:
                    self.assertEqual(len(result.warnings), 1)
                    self.assertIn('keymgmt_response', result.warnings[0])
        # default: warn with directory, off without
        self.assertEqual(new_client(bank, xsd_dir=XSD_DIR).xsd_mode, 'warn')
        self.assertEqual(new_client(bank, xsd_dir=None).xsd_mode, 'off')

    def test_no_secrets(self):
        "Results, requests and repr contain no private key material"
        bank, ebics = initialised_client()
        result = ebics.hpb()
        secrets = []
        for purpose in keys.PURPOSES:
            numbers = cached_keyring().private_key(purpose).private_numbers()
            secrets += [str(numbers.d), '%x' % numbers.d]
        text = '%r %r %r' % (result, ebics, ebics.connection)
        for secret in secrets:
            self.assertNotIn(secret, text)
        self.assertNotIn(b'PRIVATE KEY', result.request + result.response)


class FakeResponse:
    "Stand-in for requests.Response"

    def __init__(self, status=200, chunks=(b'<ok/>',), headers=None,
            error=None):
        self.status_code = status
        self.chunks = chunks
        self.headers = headers or {}
        self.error = error
        self.closed = False

    def iter_content(self, size):
        for chunk in self.chunks:
            yield chunk
        if self.error:
            raise self.error

    def close(self):
        self.closed = True


class FakeSession:
    "Stand-in for requests.Session: records the calls, no network"

    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error = error
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


class TransportTestCase(unittest.TestCase):
    "Test the HTTPS transport without network (E03.2, T10)"

    URL = 'https://ebics.example.invalid/ebics'

    # T10
    def test_only_https(self):
        "Only https URLs"
        for url in ['http://ebics.example.invalid', 'ftp://x.invalid',
                'ebics.example.invalid', '', None, 'https://']:
            with self.subTest(url=url):
                with self.assertRaises(EbicsTransportError):
                    transport.HttpsTransport(url, session=FakeSession())

    def test_post(self):
        "POST with verification, timeout, content type, no redirects"
        session = FakeSession(FakeResponse(chunks=(b'<a>', b'</a>')))
        https = transport.HttpsTransport(self.URL, timeout=7, session=session)
        self.assertEqual(https.post(b'<request/>'), b'<a></a>')
        (url, kwargs), = session.calls
        self.assertEqual(url, self.URL)
        self.assertIs(kwargs['verify'], True)
        self.assertEqual(kwargs['timeout'], 7)
        self.assertIs(kwargs['allow_redirects'], False)
        self.assertIs(kwargs['stream'], True)
        self.assertEqual(kwargs['data'], b'<request/>')
        self.assertEqual(
            kwargs['headers']['Content-Type'], 'text/xml; charset=UTF-8')
        self.assertTrue(session.response.closed)

    def test_ca_bundle(self):
        "An own CA bundle replaces the default, verification stays on"
        session = FakeSession()
        bundle = os.path.join(HERE, 'data', 'test_certificate_x002.der')
        https = transport.HttpsTransport(
            self.URL, ca_bundle=bundle, session=session)
        https.post(b'x')
        self.assertEqual(session.calls[0][1]['verify'], bundle)
        with self.assertRaises(EbicsTransportError):
            transport.HttpsTransport(
                self.URL, ca_bundle='/no/such/bundle', session=session)

    def test_never_verify_false(self):
        "The source has no way to switch off the TLS verification"
        with open(os.path.join(PROTOCOL, 'transport.py')) as f:
            source = f.read()
        self.assertNotIn('verify=False', source.replace(' ', ''))
        self.assertNotIn('CERT_NONE', source)
        https = transport.HttpsTransport(self.URL, ca_bundle='',
            session=FakeSession())
        self.assertIs(https.verify, True)

    def test_size_limit(self):
        "Responses above max_response_size are rejected"
        cases = {
            'streamed': FakeResponse(chunks=(b'x' * 60, b'x' * 60)),
            'content length': FakeResponse(
                chunks=(b'x',), headers={'Content-Length': '1000'}),
            }
        for name, response in cases.items():
            with self.subTest(case=name):
                https = transport.HttpsTransport(
                    self.URL, max_response_size=100,
                    session=FakeSession(response))
                with self.assertRaises(EbicsTransportError):
                    https.post(b'x')
                self.assertTrue(response.closed)
        https = transport.HttpsTransport(
            self.URL, max_response_size=100,
            session=FakeSession(FakeResponse(chunks=(b'x' * 100,))))
        self.assertEqual(len(https.post(b'x')), 100)

    def test_errors(self):
        "Network, TLS, timeout and HTTP errors without order data"
        import requests
        payload = b'<secret order data/>'
        cases = {
            'tls': FakeSession(error=requests.exceptions.SSLError(
                    'certificate verify failed')),
            'timeout': FakeSession(error=requests.exceptions.ReadTimeout()),
            'connection': FakeSession(
                error=requests.exceptions.ConnectionError()),
            'other': FakeSession(error=requests.exceptions.RequestException()),
            'status 500': FakeSession(FakeResponse(status=500)),
            'redirect': FakeSession(FakeResponse(
                    status=302, headers={'Location': 'http://x.invalid'})),
            'broken stream': FakeSession(FakeResponse(
                    error=requests.exceptions.ChunkedEncodingError())),
            }
        for name, session in cases.items():
            with self.subTest(case=name):
                https = transport.HttpsTransport(self.URL, session=session)
                with self.assertRaises(EbicsTransportError) as cm:
                    https.post(payload)
                self.assertNotIn('secret', str(cm.exception))
                self.assertIn('ebics.example.invalid', str(cm.exception))
                self.assertIsNone(cm.exception.__cause__)

    def test_default_session_without_retries(self):
        "The default session does not retry"
        https = transport.HttpsTransport(self.URL)
        adapter = https.session.get_adapter(self.URL)
        self.assertEqual(adapter.max_retries.total, 0)


class X509DataTestCase(unittest.TestCase):
    "ds:X509Data of INI and HIA (F16, T10a)"

    # T10a
    def test_x509_data(self):
        "Namespace, decimal serial, RFC 4514 issuer, base64 DER"
        subject = keys.Subject(
            'TESTUSER', 'Müller & Söhne, GmbH', 'DE')
        keyring = keys.Keyring(2048, {
                purpose: keys.KeyEntry(
                    keys.SOURCE_GENERATED, cached_key(2048, number),
                    keys.create_certificate(
                        cached_key(2048, number), purpose, subject))
                for number, purpose in enumerate(keys.PURPOSES)})
        ebics = client.EbicsClient(
            client.Connection(
                'TESTHOST', 'TESTPARTNER', 'TESTUSER',
                'https://ebics.example.invalid'),
            keyring, FakeBankTransport(None))
        documents = {
            'INI': ebics_xml.parse(
                ebics_xml.to_bytes(ebics.ini_order_data())),
            'HIA': ebics_xml.parse(
                ebics_xml.to_bytes(ebics.hia_order_data())),
            }
        expected = {'INI': ['A006'], 'HIA': ['X002', 'E002']}
        ds = '{%s}' % ebics_xml.NS_DS
        for order_type, document in documents.items():
            nodes = document.xpath(
                '//ds:X509Data', namespaces=ebics_xml.NSMAP)
            self.assertEqual(len(nodes), len(expected[order_type]))
            for node, purpose in zip(nodes, expected[order_type]):
                with self.subTest(order=order_type, purpose=purpose):
                    certificate = keyring.certificate(purpose)
                    for child in node.iter():
                        self.assertTrue(child.tag.startswith(ds), child.tag)
                    self.assertEqual(
                        [etree.QName(c).localname for c in node],
                        ['X509IssuerSerial', 'X509Certificate'])
                    serial = ebics_xml.get_text(
                        node, 'ds:X509IssuerSerial/ds:X509SerialNumber')
                    self.assertRegex(serial, r'^\d+$')
                    self.assertEqual(int(serial), certificate.serial_number)
                    text = ebics_xml.find(node, 'ds:X509Certificate').text
                    self.assertRegex(text, r'^[A-Za-z0-9+/]+={0,2}$')
                    self.assertNotIn('BEGIN', text)
                    der = base64.b64decode(text, validate=True)
                    self.assertEqual(der, certificate.public_bytes(
                            serialization.Encoding.DER))
                    embedded = x509.load_der_x509_certificate(der)
                    issuer = ebics_xml.get_text(
                        node, 'ds:X509IssuerSerial/ds:X509IssuerName')
                    self.assertEqual(issuer, embedded.issuer.rfc4514_string())
                    # special characters survive: escaped comma, umlauts, &
                    self.assertIn('O=Müller & Söhne\\, GmbH', issuer)
                    self.assertIn('CN=TESTUSER', issuer)
        # the raw XML escapes the ampersand
        self.assertIn(b'&amp;', ebics_xml.to_bytes(ebics.ini_order_data()))

    @unittest.skipUnless(HAS_XSD, SKIP_XSD)
    def test_x509_data_schema(self):
        "Order data with special characters stay valid"
        subject = keys.Subject('TESTUSER', 'Müller & Söhne, GmbH', 'DE')
        keyring = keys.Keyring(2048, {
                purpose: keys.KeyEntry(
                    keys.SOURCE_GENERATED, cached_key(2048, number),
                    keys.create_certificate(
                        cached_key(2048, number), purpose, subject))
                for number, purpose in enumerate(keys.PURPOSES)})
        ebics = client.EbicsClient(
            client.Connection(
                'TESTHOST', 'TESTPARTNER', 'TESTUSER',
                'https://ebics.example.invalid'),
            keyring, FakeBankTransport(None))
        self.assertEqual(schema.validate(
                ebics.ini_order_data(), 'signature', XSD_DIR), [])
        self.assertEqual(schema.validate(
                ebics.hia_order_data(), 'orders', XSD_DIR), [])


def camt053():
    with open(os.path.join(HERE, 'data', 'camt053_test.xml'), 'rb') as f:
        return f.read()


CAMT053 = client.Btf('EOP', 'camt.053', scope='DE', container='ZIP')


def ready_client(files=None, **kwargs):
    "Fake bank with downloads and a client with confirmed bank keys"
    bank, ebics = initialised_client(**kwargs)
    ebics.bank_keys = ebics.hpb().data['bank_keys']
    if files is None:
        files = [('camt053_test.xml', camt053())]
    if files:
        bank.downloads['camt.053'] = list(files)
    return bank, ebics


class BtdTestCase(unittest.TestCase):
    "Download BTD with segments and receipt (E03.3)"

    # T11
    def test_one_segment(self):
        "One segment: file unpacked, bank signature checked, no receipt"
        bank, ebics = ready_client()
        transport_ = FakeBankTransport(bank)
        ebics.transport = transport_
        result = ebics.btd_download(CAMT053)
        self.assertTrue(result.ok)
        self.assertEqual(result.num_segments, 1)
        self.assertRegex(result.transaction_id, r'^[0-9A-F]{32}$')
        self.assertEqual(result.files, [('camt053_test.xml', camt053())])
        self.assertTrue(result.container.startswith(b'PK'))
        self.assertEqual(len(result.requests), 1)
        self.assertEqual(len(result.responses), 1)
        self.assertEqual(result.btf.text, 'EOP/DE/camt.053/ZIP')
        # no receipt sent by btd_download (D5)
        self.assertEqual(bank.receipts, [])
        self.assertFalse(any(
                b'TransferReceipt' in r for r in transport_.requests))
        # every response carries a valid bank signature
        for response in result.responses:
            ebics_xml.verify_auth(
                ebics_xml.parse(response),
                bank.certificate('X002').public_key())

    def test_request(self):
        "Initialisation request: BTF, BankPubKeyDigests, date range"
        bank, ebics = ready_client()
        request = ebics_xml.parse(ebics.btd_request(
                client.Btf('STM', 'camt.052', scope='DE',
                    service_option='COR', msg_version='08',
                    container='ZIP'),
                (datetime.date(2026, 11, 1), datetime.date(2026, 11, 24))))
        static = ebics_xml.find(request, 'ebics:header/ebics:static')
        service = ebics_xml.find(
            static, 'ebics:OrderDetails/ebics:BTDOrderParams/ebics:Service')
        self.assertEqual(
            [(etree.QName(n).localname, n.text, dict(n.attrib))
                for n in service],
            [('ServiceName', 'STM', {}), ('Scope', 'DE', {}),
                ('ServiceOption', 'COR', {}),
                ('Container', None, {'containerType': 'ZIP'}),
                ('MsgName', 'camt.052', {'version': '08'})])
        self.assertEqual(ebics_xml.get_text(
                static, 'ebics:OrderDetails/ebics:AdminOrderType'), 'BTD')
        self.assertEqual(
            [ebics_xml.get_text(static, 'ebics:OrderDetails/'
                    'ebics:BTDOrderParams/ebics:DateRange/ebics:' + n)
                for n in ['Start', 'End']],
            ['2026-11-01', '2026-11-24'])
        for name, purpose in [('Authentication', 'X002'),
                ('Encryption', 'E002')]:
            with self.subTest(digest=name):
                self.assertEqual(
                    ebics_xml.get_base64(
                        static, 'ebics:BankPubKeyDigests/ebics:' + name),
                    hashlib.sha256(bank.certificate(purpose).public_bytes(
                            serialization.Encoding.DER)).digest())
                self.assertEqual(ebics_xml.get_attribute(
                        static, 'ebics:BankPubKeyDigests/ebics:' + name,
                        'Version'), purpose)
        self.assertEqual(
            ebics_xml.get_text(static, 'ebics:SecurityMedium'), '0000')
        self.assertEqual(ebics_xml.get_text(
                request, 'ebics:header/ebics:mutable/ebics:TransactionPhase'),
            'Initialisation')
        ebics_xml.verify_auth(
            request, cached_keyring().certificate('X002').public_key())
        if HAS_XSD:
            self.assertEqual(
                schema.validate(request, 'request', XSD_DIR), [])

    @unittest.skipUnless(HAS_XSD, SKIP_XSD)
    def test_schema(self):
        "All BTD requests and responses are valid according to the XSD"
        bank, ebics = ready_client(xsd_mode='strict')
        bank.segment_size = 200
        transport_ = FakeBankTransport(bank)
        ebics.transport = transport_
        result = ebics.btd_download(CAMT053)
        ebics.btd_receipt(result.transaction_id)
        self.assertGreater(result.num_segments, 2)
        for request in transport_.requests:
            self.assertEqual(schema.validate(
                    ebics_xml.parse(request), 'request', XSD_DIR), [])
        for response in transport_.responses:
            self.assertEqual(schema.validate(
                    ebics_xml.parse(response), 'response', XSD_DIR), [])
        self.assertEqual(bank.schema_errors, [])

    # T12
    def test_segments(self):
        "Several segments are joined in order"
        bank, ebics = ready_client()
        bank.segment_size = 100
        result = ebics.btd_download(CAMT053)
        self.assertTrue(result.ok)
        self.assertGreater(result.num_segments, 5)
        self.assertEqual(len(result.requests), result.num_segments)
        self.assertEqual(result.files, [('camt053_test.xml', camt053())])
        numbers = [data['segment'] for kind, data in bank.received
            if kind == 'BTD' and data['phase'] == 'Transfer']
        self.assertEqual(numbers, list(range(2, result.num_segments + 1)))
        for request, number in zip(result.requests[1:], numbers):
            root = ebics_xml.parse(request)
            self.assertEqual(ebics_xml.get_text(
                    root, 'ebics:header/ebics:mutable/ebics:SegmentNumber'),
                str(number))
            self.assertEqual(ebics_xml.get_text(
                    root, 'ebics:header/ebics:static/ebics:TransactionID'),
                result.transaction_id)
        self.assertEqual(result.warnings, [])

    def test_max_segments(self):
        "Too many segments abort the download without receipt"
        cases = {
            # check at the initialisation
            'announced too many': (
                {'BTD_num_segments': 500}, 'announces 500 segments', 1),
            # lastSegment never true: the loop stops at max_segments
            'endless': (
                {'BTD_endless': True, 'BTD_num_segments': 2},
                'More than 4 segments', 4),
            # more segments than announced and than the limit
            'beyond announced': (
                {'BTD_num_segments': 2}, 'More than 4 segments', 4),
            }
        for name, (faults, message, steps) in cases.items():
            with self.subTest(case=name):
                bank, ebics = ready_client(max_segments=4)
                bank.segment_size = 100
                bank.faults.update(faults)
                with self.assertRaises(EbicsProtocolError) as cm:
                    ebics.btd_download(CAMT053)
                self.assertIn(message, str(cm.exception))
                result = cm.exception.result
                self.assertTrue(result.transaction_id)
                self.assertEqual(len(result.requests), steps)
                self.assertEqual(bank.receipts, [])
        # within the limit, more segments than announced give a warning
        bank, ebics = ready_client(max_segments=100)
        bank.segment_size = 300
        bank.faults['BTD_num_segments'] = 1
        result = ebics.btd_download(CAMT053)
        self.assertTrue(result.ok)
        self.assertEqual(result.files, [('camt053_test.xml', camt053())])
        self.assertTrue(result.warnings)
        self.assertIn('exceeds the announced', result.warnings[0])

    def test_fewer_segments(self):
        "Fewer segments than announced: warning, data complete"
        bank, ebics = ready_client()
        bank.segment_size = 300
        bank.faults['BTD_fewer'] = True
        result = ebics.btd_download(CAMT053)
        self.assertTrue(result.ok)
        self.assertEqual(result.files, [('camt053_test.xml', camt053())])
        self.assertEqual(len(result.warnings), 1)
        self.assertIn('announced', result.warnings[0])

    # T13
    def test_no_data(self):
        "090005: class no_data, no transaction, no receipt needed"
        bank, ebics = ready_client(files=[])
        result = ebics.btd_download(CAMT053)
        self.assertEqual(result.klass, 'no_data')
        self.assertFalse(result.ok)
        self.assertEqual(result.business.code, '090005')
        self.assertEqual(
            result.business.symbol, 'EBICS_NO_DOWNLOAD_DATA_AVAILABLE')
        self.assertEqual(result.technical.code, '000000')
        self.assertIsNone(result.transaction_id)
        self.assertEqual(result.files, [])
        self.assertEqual(len(result.requests), 1)
        self.assertEqual(bank.receipts, [])

    # T14
    def test_receipt(self):
        "Positive and negative receipt with ReceiptCode 0/1"
        for positive, code, receipt_code, symbol in [
                (True, '011000', '0', 'EBICS_DOWNLOAD_POSTPROCESS_DONE'),
                (False, '011001', '1', 'EBICS_DOWNLOAD_POSTPROCESS_SKIPPED')]:
            with self.subTest(positive=positive):
                bank, ebics = ready_client()
                download = ebics.btd_download(CAMT053)
                result = ebics.btd_receipt(download.transaction_id, positive)
                self.assertEqual(
                    (result.technical.code, result.technical.symbol,
                        result.technical.klass), (code, symbol, 'info'))
                self.assertTrue(result.ok)
                self.assertEqual(
                    result.receipt, 'positive' if positive else 'negative')
                self.assertEqual(result.warnings, [])
                request = ebics_xml.parse(result.request)
                self.assertEqual(ebics_xml.get_text(
                        request,
                        'ebics:body/ebics:TransferReceipt/ebics:ReceiptCode'),
                    receipt_code)
                self.assertEqual(ebics_xml.get_text(
                        request,
                        'ebics:header/ebics:mutable/ebics:TransactionPhase'),
                    'Receipt')
                self.assertEqual(
                    bank.receipts,
                    [(download.transaction_id, int(receipt_code))])
                # positive: delivered; negative: delivered again
                again = ebics.btd_download(CAMT053)
                self.assertEqual(
                    again.klass, 'no_data' if positive else 'ok')
        with self.assertRaises(ValueError):
            ebics.btd_receipt('not a transaction id')

    def test_receipt_unknown_transaction(self):
        "A receipt for an unknown transaction is an error"
        bank, ebics = ready_client()
        result = ebics.btd_receipt('0' * 32)
        self.assertEqual(
            (result.technical.code, result.klass), ('091101', 'error'))
        self.assertIsNone(result.receipt)

    # T15
    def test_manipulated_response(self):
        "A response with an invalid bank signature aborts without receipt"
        bank, ebics = ready_client()
        bank.faults['BTD_tamper'] = True
        with self.assertRaises(EbicsAuthenticationError):
            ebics.btd_download(CAMT053)
        self.assertEqual(bank.receipts, [])
        # wrong (unconfirmed) bank X002 key on the client side
        bank, ebics = ready_client()
        ebics.bank_keys = dict(
            ebics.bank_keys, X002=cached_keyring().certificate('X002'))
        with self.assertRaises(EbicsAuthenticationError) as cm:
            ebics.btd_download(CAMT053)
        self.assertTrue(cm.exception.result.responses)
        self.assertEqual(bank.receipts, [])

    def test_manipulated_transfer(self):
        "A manipulated transfer segment aborts as well"
        bank, ebics = ready_client()
        bank.segment_size = 200
        original = bank._response

        def tamper(phase, *args, **kwargs):
            bank.faults['BTD_tamper'] = phase == 'Transfer'
            return original(phase, *args, **kwargs)
        bank._response = tamper
        with self.assertRaises(EbicsAuthenticationError) as cm:
            ebics.btd_download(CAMT053)
        self.assertEqual(len(cm.exception.result.responses), 2)
        self.assertEqual(bank.receipts, [])

    def test_without_bank_keys(self):
        "No BTD without confirmed bank keys"
        bank, ebics = ready_client()
        ebics.bank_keys = {}
        with self.assertRaises(EbicsProtocolError):
            ebics.btd_download(CAMT053)
        with self.assertRaises(EbicsProtocolError):
            ebics.btd_receipt('0' * 32)
        self.assertFalse(any(
                kind == 'BTD' for kind, _ in bank.received))

    def test_bank_keys_changed(self):
        "Other bank keys than the confirmed ones -> 091008 bank_keys"
        bank, ebics = ready_client()
        ebics.bank_keys = dict(
            ebics.bank_keys, E002=cached_keyring().certificate('E002'))
        result = ebics.btd_download(CAMT053)
        self.assertEqual(
            (result.technical.code, result.klass), ('091008', 'bank_keys'))

    def test_decryption_failed(self):
        "Data for another key -> Entschlüsselung fehlgeschlagen, no receipt"
        bank, ebics = ready_client()
        bank.faults['BTD_wrong_key'] = True
        with self.assertRaises(EbicsCryptoError) as cm:
            ebics.btd_download(CAMT053)
        self.assertIn('Entschlüsselung fehlgeschlagen', str(cm.exception))
        self.assertTrue(cm.exception.result.transaction_id)
        self.assertEqual(bank.receipts, [])

    def test_container_limits(self):
        "ZIP container: number, size and names of the files"
        cases = {
            'too many files': (
                [('a.xml', b'<a/>'), ('b.xml', b'<b/>'), ('c.xml', b'<c/>')],
                {'max_zip_files': 2}, 'more than 2 files'),
            'too big': (
                [('a.xml', b'<a>' + b'x' * 5000 + b'</a>')],
                {'max_zip_size': 3000}, None),
            'path': ([('../a.xml', b'<a/>')], {}, 'Unsafe'),
            'directory': ([('dir/a.xml', b'<a/>')], {}, 'Unsafe'),
            'hidden': ([('.a.xml', b'<a/>')], {}, 'Unsafe'),
            'backslash': ([('dir\\a.xml', b'<a/>')], {}, 'Unsafe'),
            }
        for name, (files, limits, message) in cases.items():
            with self.subTest(case=name):
                bank, ebics = ready_client(files=files, **limits)
                with self.assertRaises(EbicsError) as cm:
                    ebics.btd_download(CAMT053)
                if message:
                    self.assertIn(message, str(cm.exception))
                self.assertEqual(bank.receipts, [])
        # several files are returned in the order of the container
        files = [('b.xml', b'<b/>'), ('a.xml', b'<a/>')]
        bank, ebics = ready_client(files=files)
        self.assertEqual(ebics.btd_download(CAMT053).files, files)

    def test_container_not_zip(self):
        "Without container type ZIP the order data are one file"
        bank, ebics = ready_client()
        btf = client.Btf('EOP', 'camt.053', scope='DE', container='XML')
        result = ebics.btd_download(btf)
        self.assertEqual([n for n, _ in result.files], ['camt.053.xml'])
        self.assertTrue(result.files[0][1].startswith(b'PK'))

    def test_no_secrets(self):
        "Download results contain no private key material"
        bank, ebics = ready_client()
        result = ebics.btd_download(CAMT053)
        text = repr(result).encode() + b''.join(
            result.requests + result.responses)
        for purpose in keys.PURPOSES:
            numbers = cached_keyring().private_key(purpose).private_numbers()
            self.assertNotIn(str(numbers.d).encode(), text)
        self.assertNotIn(b'PRIVATE KEY', text)
        self.assertFalse(re.search(rb'camt053_test', b''.join(
                    result.requests)))


class TransactionKeyTestCase(unittest.TestCase):
    "HPB and BTD with a short or full TransactionKey (ch. 11.3.2.2)"

    def test_hpb(self):
        "HPB with short and full TransactionKey"
        for fault in ['short_transaction_key', 'full_transaction_key']:
            with self.subTest(fault=fault):
                bank, ebics = initialised_client()
                bank.faults[fault] = True
                result = ebics.hpb()
                self.assertTrue(result.ok)
                self.assertEqual(
                    result.data['bank_keys']['E002']['hash'],
                    bank.bank_hash('E002'))
                key = ebics_xml.get_base64(
                    ebics_xml.parse(result.response),
                    'ebics:body/ebics:DataTransfer/ebics:DataEncryptionInfo/'
                    'ebics:TransactionKey')
                if fault == 'short_transaction_key':
                    self.assertLess(len(key), 256)
                else:
                    self.assertEqual(len(key), 256)

    def test_btd(self):
        "BTD with short and full TransactionKey"
        for fault in ['short_transaction_key', 'full_transaction_key']:
            with self.subTest(fault=fault):
                bank, ebics = ready_client()
                bank.faults[fault] = True
                result = ebics.btd_download(CAMT053)
                self.assertTrue(result.ok)
                self.assertEqual(
                    result.files, [('camt053_test.xml', camt053())])
                key = ebics_xml.get_base64(
                    ebics_xml.parse(result.responses[0]),
                    'ebics:body/ebics:DataTransfer/ebics:DataEncryptionInfo/'
                    'ebics:TransactionKey')
                if fault == 'short_transaction_key':
                    self.assertLess(len(key), 256)
                else:
                    self.assertEqual(len(key), 256)

    @unittest.skipUnless(HAS_XSD, SKIP_XSD)
    def test_schema(self):
        "A short TransactionKey is still valid according to the XSD"
        bank, ebics = ready_client(xsd_mode='strict')
        bank.faults['short_transaction_key'] = True
        result = ebics.btd_download(CAMT053)
        self.assertEqual(schema.validate(
                ebics_xml.parse(result.responses[0]), 'response', XSD_DIR),
            [])

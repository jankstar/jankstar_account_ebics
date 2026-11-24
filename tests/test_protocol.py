# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Tests of the protocol layer without database and without network.

Test keys and certificates are generated; tests/data contains only a
generated test certificate (no real data).
"""
import ast
import datetime
import functools
import hashlib
import io
import json
import os
import unittest
import zipfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from trytond.modules.account_ebics.protocol import compression, crypto, keys
from trytond.modules.account_ebics.protocol.exceptions import (
    EbicsCryptoError, EbicsKeyringError)

HERE = os.path.dirname(__file__)
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
                self.assertEqual(len(encrypted_key), 256)
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

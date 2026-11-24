# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Keys, certificates, hash values and the key container of a participant.

No Tryton imports (specification account_ebics ch. 4.1).
"""
import datetime
import hashlib
import io
import json
import zipfile
from collections import namedtuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from .exceptions import EbicsKeyringError

#: Purposes of the three key pairs of a participant
#: (EBICS specification V 3.0.2 (DE) ch. 4.1): bank-technical signature,
#: authentication signature, encryption
PURPOSES = ('A006', 'X002', 'E002')
#: Allowed key lengths (EBICS specification V 3.0.2 (DE) ch. 4.7, ch. 14.1:
#: at least 2048 bits, A005/A006 at most 4096 bits)
KEY_LENGTHS = (2048, 3072, 4096)
PUBLIC_EXPONENT = 65537
#: Validity of the self-signed certificates in years
CERTIFICATE_YEARS = 5

CONTAINER_VERSION = 1
MANIFEST = 'manifest.json'
SOURCE_GENERATED = 'generated'
SOURCE_EXTERNAL = 'external'
# Limits when reading a container (only the expected file names)
_MAX_MEMBER_SIZE = 1024 * 1024
_MAX_MEMBERS = 1 + 2 * len(PURPOSES)

#: Subject of the certificates: user ID of the participant, name and
#: country (ISO 3166 alpha-2, optional) of the company
Subject = namedtuple('Subject', ['user_id', 'organization', 'country'])
Subject.__new__.__defaults__ = (None,)

#: One key of the container; private_key is None for an external key
KeyEntry = namedtuple('KeyEntry', ['source', 'private_key', 'certificate'])


class Keyring:
    "The three keys of a participant with their certificates"

    def __init__(self, bits, keys, created=None):
        self.bits = bits
        self.keys = dict(keys)
        self.created = created or datetime.datetime.now(
            datetime.timezone.utc)

    def __repr__(self):
        # never show key material
        return '<Keyring %s bits %s>' % (self.bits, ', '.join(
                '%s:%s' % (p, self.keys[p].source) for p in self.keys))

    def private_key(self, purpose):
        """Return the private key of the purpose (None for an external key).

        Source: working paper E02 ch. 4.2, ch. 4.5 (decision F9)."""
        return self.keys[purpose].private_key

    def certificate(self, purpose):
        """Return the certificate of the purpose.

        Source: working paper E02 ch. 4.2, ch. 4.4."""
        return self.keys[purpose].certificate


def generate_key(bits):
    """Return a new RSA private key with public exponent 65537.

    bits must be 2048, 3072 or 4096.
    Source: EBICS specification V 3.0.2 (DE) ch. 4.1, ch. 4.7, ch. 14.1."""
    if bits not in KEY_LENGTHS:
        raise ValueError("Key length must be one of %s" % (KEY_LENGTHS,))
    return rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=bits)


def _name(subject):
    attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, subject.user_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organization),
        ]
    if subject.country:
        attributes.append(
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject.country))
    return x509.Name(attributes)


def _add_years(date, years):
    try:
        return date.replace(year=date.year + years)
    except ValueError:
        # 29 February
        return date.replace(year=date.year + years, day=28)


def create_certificate(private_key, purpose, subject, now=None):
    """Return a self-signed X.509v3 certificate for the key.

    Subject and issuer CN=<user ID>, O=<company>, C=<country>; random serial
    number; valid for 5 years from now; signed with SHA-256 by the key
    itself; BasicConstraints(ca=False); KeyUsage digitalSignature for A006
    and X002, keyEncipherment for E002.
    Source: EBICS specification V 3.0.2 (DE) ch. 3.9, ch. 4.4.1
    (self-signed certificates); working paper E02 ch. 4.4."""
    if purpose not in PURPOSES:
        raise ValueError("Unknown purpose %r" % purpose)
    if not subject.user_id or not subject.organization:
        raise ValueError("The subject needs a user ID and an organization")
    if subject.country and len(subject.country) != 2:
        raise ValueError("The country must be an ISO 3166 alpha-2 code")
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    now = now.replace(microsecond=0)
    name = _name(subject)
    signing = purpose in {'A006', 'X002'}
    builder = (x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(_add_years(now, CERTIFICATE_YEARS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=signing,
                content_commitment=False,
                key_encipherment=not signing,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False),
            critical=True))
    return builder.sign(private_key, hashes.SHA256())


def certificate_hash(certificate):
    """Return the hash value of the certificate for the initialisation
    letters: SHA-256 over the certificate in DER format, 64 hexadecimal
    characters in upper case (decision D9).

    Source: EBICS specification V 3.0.2 (DE) ch. 4.4.1.2.3."""
    der = certificate.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest().upper()


def generate_keyring(bits, subject):
    """Return a Keyring with three separate key pairs A006, X002 and E002,
    each with a self-signed certificate.

    Source: EBICS specification V 3.0.2 (DE) ch. 4.1 (A006 needs its own
    key pair; separate X002 and E002 pairs by decision F4 of E02)."""
    keys = {}
    for purpose in PURPOSES:
        private_key = generate_key(bits)
        keys[purpose] = KeyEntry(
            SOURCE_GENERATED, private_key,
            create_certificate(private_key, purpose, subject))
    return Keyring(bits, keys)


def _passphrase(passphrase):
    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')
    if not passphrase:
        raise EbicsKeyringError("A passphrase is required")
    return passphrase


def _friendly_name(purpose, certificate):
    user_ids = certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)
    user_id = user_ids[0].value if user_ids else ''
    return ('%s %s' % (purpose, user_id)).strip().encode('utf-8')


def dump_keyring(keyring, passphrase):
    """Return the key container as ZIP: per purpose a PKCS#12 file
    (<purpose>.p12, private key and certificate, encrypted with the
    passphrase) or for an external key only the certificate (<purpose>.pem),
    and manifest.json without secrets.

    Source: working paper E02 ch. 4.5 (decisions F2, F9); specification
    account_ebics ch. 8.1."""
    passphrase = _passphrase(passphrase)
    encryption = serialization.BestAvailableEncryption(passphrase)
    manifest = {
        'version': CONTAINER_VERSION,
        'bits': keyring.bits,
        'created': keyring.created.astimezone(
            datetime.timezone.utc).isoformat(),
        'keys': {},
        }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as container:
        for purpose in PURPOSES:
            entry = keyring.keys[purpose]
            manifest['keys'][purpose] = {'source': entry.source}
            if entry.source == SOURCE_GENERATED:
                container.writestr(
                    purpose + '.p12',
                    pkcs12.serialize_key_and_certificates(
                        _friendly_name(purpose, entry.certificate),
                        entry.private_key, entry.certificate, None,
                        encryption))
            elif entry.source == SOURCE_EXTERNAL:
                container.writestr(
                    purpose + '.pem',
                    entry.certificate.public_bytes(
                        serialization.Encoding.PEM))
            else:
                raise EbicsKeyringError(
                    "Unknown source of key %s" % purpose)
        container.writestr(
            MANIFEST, json.dumps(manifest, indent=2, sort_keys=True))
    return buffer.getvalue()


def _read_member(container, name):
    info = container.getinfo(name)
    if info.file_size > _MAX_MEMBER_SIZE:
        raise EbicsKeyringError("File %s of the container is too big" % name)
    with container.open(info) as member:
        data = member.read(_MAX_MEMBER_SIZE + 1)
    if len(data) > _MAX_MEMBER_SIZE:
        raise EbicsKeyringError("File %s of the container is too big" % name)
    return data


def load_keyring(data, passphrase):
    """Return the Keyring of a key container created by dump_keyring.

    Only the expected file names are read, each with a size limit. A wrong
    passphrase, an unknown container version or a damaged container raise
    EbicsKeyringError. For an external key only the certificate is returned.

    Source: working paper E02 ch. 4.5 (decisions F2, F9); specification
    account_ebics ch. 8.1."""
    passphrase = _passphrase(passphrase)
    try:
        container = zipfile.ZipFile(io.BytesIO(bytes(data)))
    except (zipfile.BadZipFile, ValueError):
        raise EbicsKeyringError("The key container is damaged") from None
    with container:
        names = set(container.namelist())
        allowed = {MANIFEST} | {
            p + s for p in PURPOSES for s in ('.p12', '.pem')}
        if len(names) > _MAX_MEMBERS or not names <= allowed:
            raise EbicsKeyringError(
                "The key container contains unexpected files")
        if MANIFEST not in names:
            raise EbicsKeyringError("The key container has no manifest")
        try:
            manifest = json.loads(_read_member(container, MANIFEST))
        except ValueError:
            raise EbicsKeyringError(
                "The manifest of the key container is damaged") from None
        if not isinstance(manifest, dict):
            raise EbicsKeyringError(
                "The manifest of the key container is damaged")
        if manifest.get('version') != CONTAINER_VERSION:
            raise EbicsKeyringError(
                "Unknown version of the key container")
        try:
            created = datetime.datetime.fromisoformat(manifest['created'])
            bits = int(manifest['bits'])
            sources = {
                p: manifest['keys'][p]['source'] for p in PURPOSES}
        except (KeyError, TypeError, ValueError):
            raise EbicsKeyringError(
                "The manifest of the key container is damaged") from None
        suffixes = {SOURCE_GENERATED: '.p12', SOURCE_EXTERNAL: '.pem'}
        if any(sources[p] not in suffixes for p in PURPOSES):
            raise EbicsKeyringError("Unknown source of a key")
        expected = {MANIFEST} | {
            p + suffixes[sources[p]] for p in PURPOSES}
        if names != expected:
            raise EbicsKeyringError(
                "The files of the key container do not match its manifest")
        keys = {}
        for purpose in PURPOSES:
            source = sources[purpose]
            if source == SOURCE_GENERATED:
                name = purpose + '.p12'
                if name not in names:
                    raise EbicsKeyringError(
                        "The key container has no file %s" % name)
                try:
                    loaded = pkcs12.load_pkcs12(
                        _read_member(container, name), passphrase)
                except ValueError:
                    raise EbicsKeyringError(
                        "Wrong passphrase or damaged file %s" % name
                        ) from None
                private_key = loaded.key
                certificate = (
                    loaded.cert.certificate if loaded.cert else None)
                if (not isinstance(private_key, rsa.RSAPrivateKey)
                        or certificate is None
                        or certificate.public_key().public_numbers()
                        != private_key.public_key().public_numbers()):
                    raise EbicsKeyringError(
                        "Key and certificate of %s do not match" % purpose)
            elif source == SOURCE_EXTERNAL:
                name = purpose + '.pem'
                if name not in names:
                    raise EbicsKeyringError(
                        "The key container has no file %s" % name)
                try:
                    certificate = x509.load_pem_x509_certificate(
                        _read_member(container, name))
                except ValueError:
                    raise EbicsKeyringError(
                        "Damaged certificate %s" % name) from None
                private_key = None
            else:
                raise EbicsKeyringError(
                    "Unknown source of key %s" % purpose)
            keys[purpose] = KeyEntry(source, private_key, certificate)
    return Keyring(bits, keys, created=created)


def public_parts(keyring):
    """Return per purpose the public parts for INI, HIA and the
    initialisation letters: certificate (DER and PEM), modulus and public
    exponent (int), key length and hash value (D9).

    Source: EBICS specification V 3.0.2 (DE) ch. 4.4.1.2 (INI, HIA,
    initialisation letters), ch. 4.4.1.2.3 (hash value)."""
    result = {}
    for purpose in PURPOSES:
        certificate = keyring.certificate(purpose)
        numbers = certificate.public_key().public_numbers()
        result[purpose] = {
            'source': keyring.keys[purpose].source,
            'certificate_der': certificate.public_bytes(
                serialization.Encoding.DER),
            'certificate_pem': certificate.public_bytes(
                serialization.Encoding.PEM),
            'modulus': numbers.n,
            'exponent': numbers.e,
            'bits': certificate.public_key().key_size,
            'hash': certificate_hash(certificate),
            }
    return result

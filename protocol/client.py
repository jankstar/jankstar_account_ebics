# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""EBICS client: orders HEV, INI, HIA, HPB (E03.2); BTD follows (E03.3).

The client builds the requests, sends them over a transport (interface
post(bytes) -> bytes) and reads the responses defensively. Results and
exceptions contain only public data: never private keys or passphrases.
No Tryton imports (specification account_ebics ch. 4.1).
"""
import base64
import configparser
import datetime
import hashlib
import hmac
import io
import os
import re
import zipfile
from dataclasses import dataclass, field
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import compression, crypto, keys, returncodes, schema
from . import xml as ebics_xml
from .exceptions import EbicsCryptoError, EbicsError, EbicsProtocolError
from .xml import NS_DS, NS_H005, NS_HEV, NS_S002

#: Text of the Product element (decision F7 of E03): at most 64 characters
PRODUCT_PREFIX = 'tryton account_ebics'
PRODUCT_LANGUAGE = 'de'
#: SecurityMedium (EBICS specification V 3.0.2 (DE) ch. 12.3; decision F8):
#: INI 04dd "nicht wechselbares Medium" (keys on the server), others 0000
SECURITY_MEDIUM_INI = '0400'
SECURITY_MEDIUM_NONE = '0000'
#: Versions of the processes (ch. 4.1, 11.1, 11.3.2, 14.1)
SIGNATURE_VERSION = 'A006'
AUTHENTICATION_VERSION = 'X002'
ENCRYPTION_VERSION = 'E002'
DIGEST_ALGORITHM = 'http://www.w3.org/2001/04/xmlenc#sha256'
#: Message of a failed decryption, unpacking or parsing of encrypted order
#: data (specification account_ebics ch. 4.3)
DECRYPTION_FAILED = "Entschlüsselung fehlgeschlagen"

DEFAULT_MAX_ZIP_SIZE = 104857600
DEFAULT_MAX_ZIP_FILES = 1000
DEFAULT_MAX_SEGMENTS = 100
#: Maximum size of one segment (base64): EBICS specification V 3.0.2 (DE)
#: ch. 3.3, ch. 7.1
MAX_SEGMENT_SIZE = 1048576
#: ReceiptCode of TransferReceipt (ch. 5.6.1.1.3): 0 positive, 1 negative
RECEIPT_POSITIVE = 0
RECEIPT_NEGATIVE = 1
_TRANSACTION_ID = r'[0-9A-Fa-f]{32}'
_SAFE_NAME = re.compile(r'^[^/\\\x00-\x1f]{1,255}$')
_RETURN_CODE = r'\d{6}'
_PUB_KEY_INFOS = {
    'X002': ('AuthenticationPubKeyInfo', 'AuthenticationVersion'),
    'E002': ('EncryptionPubKeyInfo', 'EncryptionVersion'),
    }


def module_version():
    """Return the version of the module from tryton.cfg (read as file,
    without Tryton imports).

    Source: working paper E03 decision F7 (version from tryton.cfg)."""
    config = configparser.ConfigParser()
    path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 'tryton.cfg')
    config.read(path)
    return config.get('tryton', 'version', fallback='')


def product_name(version=None):
    """Return the text of the Product element: "tryton account_ebics
    <version>", at most 64 characters (ProductType).

    Source: working paper E03 decision F7; ebics_types_H005.xsd
    ProductType."""
    version = module_version() if version is None else version
    return ('%s %s' % (PRODUCT_PREFIX, version)).strip()[:64]


@dataclass(frozen=True)
class Connection:
    """Access data of a participant: host ID, partner ID, user ID, URL and
    product text; checked with validate_ids and for https.

    Source: EBICS specification V 3.0.2 (DE) ch. 12.4; working paper E03
    ch. 4.7."""
    host_id: str
    partner_id: str
    user_id: str
    url: str
    product: str = field(default_factory=product_name)

    def __post_init__(self):
        errors = ebics_xml.validate_ids(
            host_id=self.host_id, partner_id=self.partner_id,
            user_id=self.user_id)
        if errors:
            raise ValueError(
                "Invalid identifiers: %s" % ', '.join(sorted(errors)))
        if urlparse(self.url or '').scheme != 'https':
            raise ValueError("The EBICS URL must use https://")
        if not self.product or len(self.product) > 64:
            raise ValueError("The product text needs 1 to 64 characters")


@dataclass
class OrderResult:
    """Result of an order: technical and business return code (with class),
    combined class, report text, order ID, request and response as bytes
    (public data only, for the EBICS log), schema warnings and further data
    (versions of HEV, bank keys of HPB).

    Source: working paper E03 ch. 4.5, ch. 4.7."""
    order_type: str
    technical: returncodes.ReturnCode = None
    business: returncodes.ReturnCode = None
    report_text: str = None
    order_id: str = None
    request: bytes = None
    response: bytes = None
    warnings: list = field(default_factory=list)
    data: dict = field(default_factory=dict)

    @property
    def klass(self):
        """Combined class: the technical one unless it is ok or info, then
        the business one.

        Source: working paper E03 ch. 4.5."""
        if self.technical is None:
            return returncodes.ERROR
        if (self.technical.klass not in {returncodes.OK, returncodes.INFO}
                or self.business is None):
            return self.technical.klass
        return self.business.klass

    @property
    def ok(self):
        """True if the order was processed (class ok or info).

        Source: working paper E03 ch. 4.5."""
        return self.klass in {returncodes.OK, returncodes.INFO}


@dataclass(frozen=True)
class Btf:
    """BTF parameters of an order (as account.ebics.format, without
    Tryton): service name, scope, service option, message name, message
    version and container (None, 'ZIP', 'XML', 'SVC').

    Source: EBICS specification V 3.0.2 (DE) ch. 5.6.1.1.4;
    ebics_orders_H005.xsd BTDParamsType, RestrictedServiceType;
    specification account_ebics ch. 5.5 (D15)."""
    service_name: str
    msg_name: str
    scope: str = None
    service_option: str = None
    msg_version: str = None
    container: str = None

    @property
    def text(self):
        """BTF parameters as text, e.g. EOP/DE/camt.053/ZIP (order of D15).

        Source: specification account_ebics ch. 5.5 (D15)."""
        parts = [self.service_name, self.scope, self.service_option,
            self.msg_name, self.msg_version, self.container]
        return '/'.join(p.strip() for p in parts if p and p.strip())


@dataclass
class DownloadResult(OrderResult):
    """Result of a BTD download without receipt: transaction ID, number of
    segments, decrypted and decompressed container, files [(name, data)],
    all requests and responses (bytes) of the transaction.

    Source: working paper E03 ch. 4.7 (decision F3); specification
    account_ebics ch. 7.3 (D5)."""
    btf: Btf = None
    transaction_id: str = None
    num_segments: int = None
    container: bytes = None
    files: list = field(default_factory=list)
    requests: list = field(default_factory=list)
    responses: list = field(default_factory=list)
    #: confirmation of the bank after btd_receipt: 'positive' (011000),
    #: 'negative' (011001) or None
    receipt: str = None


def _attach(exception, result):
    # the protocol log (E06/E08) needs request and response also on errors
    exception.result = result
    return exception


def _timestamp(now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    now = now.astimezone(datetime.timezone.utc)
    return now.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (
        now.microsecond // 1000)


def _nonce():
    # NonceType: hexBinary of 16 bytes
    return os.urandom(16).hex().upper()


def _x509_data(parent, certificate):
    """Append ds:X509Data with X509IssuerSerial and X509Certificate (DER,
    base64)"""
    data = ebics_xml.sub_element(parent, 'X509Data', namespace=NS_DS)
    issuer_serial = ebics_xml.sub_element(
        data, 'X509IssuerSerial', namespace=NS_DS)
    ebics_xml.sub_element(
        issuer_serial, 'X509IssuerName', certificate.issuer.rfc4514_string(),
        namespace=NS_DS)
    ebics_xml.sub_element(
        issuer_serial, 'X509SerialNumber', certificate.serial_number,
        namespace=NS_DS)
    ebics_xml.sub_element(
        data, 'X509Certificate',
        base64.b64encode(certificate.public_bytes(
                serialization.Encoding.DER)).decode('ascii'),
        namespace=NS_DS)
    return data


class EbicsClient:
    """Client for the orders of a participant.

    connection: Connection; keyring: protocol.keys.Keyring with the private
    keys; transport: object with post(bytes) -> bytes; bank_keys: confirmed
    bank keys ({'X002': certificate, 'E002': certificate} or the dict of
    hpb()), needed for BTD; xsd_dir/xsd_mode: schema validation of the
    responses (decision F5); max_response_size, max_zip_size,
    max_zip_files, max_segments: limits (specification ch. 12, decision
    F12).
    Source: working paper E03 ch. 4.7; specification account_ebics ch. 8.2.
    """

    def __init__(self, connection, keyring, transport, bank_keys=None,
            xsd_dir=None, xsd_mode=None,
            max_response_size=ebics_xml.DEFAULT_MAX_SIZE,
            max_zip_size=DEFAULT_MAX_ZIP_SIZE,
            max_zip_files=DEFAULT_MAX_ZIP_FILES,
            max_segments=DEFAULT_MAX_SEGMENTS):
        self.connection = connection
        self.keyring = keyring
        self.transport = transport
        self.bank_keys = dict(bank_keys or {})
        self.xsd_dir = xsd_dir or None
        self.xsd_mode = (
            xsd_mode if xsd_mode is not None
            else schema.default_mode(self.xsd_dir))
        if self.xsd_mode not in schema.MODES:
            raise ValueError("Unknown schema mode %r" % self.xsd_mode)
        self.max_response_size = max_response_size
        self.max_zip_size = max_zip_size
        self.max_zip_files = max_zip_files
        self.max_segments = max_segments

    def __repr__(self):
        return '<EbicsClient %s/%s@%s>' % (
            self.connection.partner_id, self.connection.user_id,
            self.connection.host_id)

    # Building blocks

    def _check_schema(self, document, kind, result):
        result.warnings.extend(
            schema.check(document, kind, self.xsd_dir, self.xsd_mode))

    def _post(self, request, result):
        result.request = request
        try:
            result.response = self.transport.post(request)
        except EbicsError as exception:
            raise _attach(exception, result)
        return result.response

    def _parse(self, data, result, root_tag):
        try:
            root = ebics_xml.parse(data, self.max_response_size)
            if root.tag != root_tag:
                raise EbicsProtocolError(
                    "Unexpected response %s" % ebics_xml.etree.QName(
                        root).localname)
        except EbicsError as exception:
            raise _attach(exception, result)
        return root

    def _static_header(self, header, order_type, security_medium,
            secured, order_params=None, bank_digests=False):
        static = ebics_xml.sub_element(header, 'static')
        ebics_xml.sub_element(static, 'HostID', self.connection.host_id)
        if secured:
            ebics_xml.sub_element(static, 'Nonce', _nonce())
            ebics_xml.sub_element(static, 'Timestamp', _timestamp())
        ebics_xml.sub_element(
            static, 'PartnerID', self.connection.partner_id)
        ebics_xml.sub_element(static, 'UserID', self.connection.user_id)
        ebics_xml.sub_element(
            static, 'Product', self.connection.product,
            Language=PRODUCT_LANGUAGE)
        details = ebics_xml.sub_element(static, 'OrderDetails')
        ebics_xml.sub_element(details, 'AdminOrderType', order_type)
        if order_params is not None:
            order_params(details)
        if bank_digests:
            digests = ebics_xml.sub_element(static, 'BankPubKeyDigests')
            for name, purpose in [
                    ('Authentication', 'X002'), ('Encryption', 'E002')]:
                ebics_xml.sub_element(
                    digests, name, base64.b64encode(
                        self._bank_digest(purpose)).decode('ascii'),
                    Version=purpose, Algorithm=DIGEST_ALGORITHM)
        ebics_xml.sub_element(static, 'SecurityMedium', security_medium)
        return static

    def _read_key_management_response(self, root, result):
        "Return codes, report text and order ID of a key management response"
        try:
            self._check_schema(root, 'keymgmt_response', result)
            technical = ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:ReturnCode',
                pattern=_RETURN_CODE)
            business = ebics_xml.get_text(
                root, 'ebics:body/ebics:ReturnCode', pattern=_RETURN_CODE)
            result.report_text = ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:ReportText',
                required=False)
            result.order_id = ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:OrderID',
                required=False)
        except EbicsError as exception:
            raise _attach(exception, result)
        result.technical = returncodes.lookup(
            technical, returncodes.TECHNICAL)
        result.business = returncodes.lookup(business, returncodes.BUSINESS)
        return result

    def _unsecured_request(self, order_type, security_medium, order_data):
        """ebicsUnsecuredRequest (INI, HIA): no Nonce/Timestamp, no
        AuthSignature, order data ZIP + base64 without encryption"""
        root = ebics_xml.root_element('ebicsUnsecuredRequest')
        header = ebics_xml.sub_element(root, 'header', authenticate='true')
        self._static_header(header, order_type, security_medium, False)
        ebics_xml.sub_element(header, 'mutable')
        body = ebics_xml.sub_element(root, 'body')
        transfer = ebics_xml.sub_element(body, 'DataTransfer')
        ebics_xml.sub_element(
            transfer, 'OrderData',
            base64.b64encode(compression.compress(
                    ebics_xml.to_bytes(order_data))).decode('ascii'))
        return ebics_xml.to_bytes(root)

    def _key_management_order(self, order_type, request):
        result = OrderResult(order_type)
        response = self._post(request, result)
        root = self._parse(
            response, result, ebics_xml.qname('ebicsKeyManagementResponse'))
        self._read_key_management_response(root, result)
        return result, root

    # Orders

    def hev(self):
        """HEV: return an OrderResult with the EBICS versions supported by
        the bank in data['versions'] as [(protocol version, version)].

        Request ebicsHEVRequest with HostID (namespace H000, no
        authentication); response with SystemReturnCode (technical code,
        English report text) and VersionNumber/@ProtocolVersion.
        Source: EBICS specification V 3.0.2 (DE) ch. 9.5; ebics_hev.xsd."""
        root = ebics_xml.element(
            'ebicsHEVRequest', namespace=NS_HEV, nsmap={None: NS_HEV})
        ebics_xml.sub_element(
            root, 'HostID', self.connection.host_id, namespace=NS_HEV)
        result = OrderResult('HEV')
        response = self._post(ebics_xml.to_bytes(root), result)
        root = self._parse(
            response, result, ebics_xml.qname('ebicsHEVResponse', NS_HEV))
        try:
            self._check_schema(root, 'hev', result)
            technical = ebics_xml.get_text(
                root, 'hev:SystemReturnCode/hev:ReturnCode',
                pattern=_RETURN_CODE)
            result.report_text = ebics_xml.get_text(
                root, 'hev:SystemReturnCode/hev:ReportText', required=False)
            versions = []
            for node in ebics_xml.find_all(root, 'hev:VersionNumber'):
                versions.append((
                        ebics_xml.get_attribute(node, '.', 'ProtocolVersion'),
                        (node.text or '').strip()))
        except EbicsError as exception:
            raise _attach(exception, result)
        result.technical = returncodes.lookup(
            technical, returncodes.TECHNICAL)
        result.data['versions'] = versions
        return result

    def ini_order_data(self):
        """Return the order data of INI: SignaturePubKeyOrderData (S002)
        with SignaturePubKeyInfo (ds:X509Data of the A006 certificate,
        SignatureVersion A006), PartnerID and UserID.

        Source: EBICS specification V 3.0.2 (DE) ch. 4.2, ch. 4.4.1.2.5.1;
        ebics_signature_S002.xsd SignaturePubKeyOrderData."""
        root = ebics_xml.element(
            'SignaturePubKeyOrderData', namespace=NS_S002,
            nsmap={None: NS_S002, 'ds': NS_DS})
        info = ebics_xml.sub_element(
            root, 'SignaturePubKeyInfo', namespace=NS_S002)
        _x509_data(info, self.keyring.certificate('A006'))
        ebics_xml.sub_element(
            info, 'SignatureVersion', SIGNATURE_VERSION, namespace=NS_S002)
        ebics_xml.sub_element(
            root, 'PartnerID', self.connection.partner_id, namespace=NS_S002)
        ebics_xml.sub_element(
            root, 'UserID', self.connection.user_id, namespace=NS_S002)
        return root

    def hia_order_data(self):
        """Return the order data of HIA: HIARequestOrderData (H005) with
        AuthenticationPubKeyInfo (X002) and EncryptionPubKeyInfo (E002),
        each with ds:X509Data and version, PartnerID and UserID.

        Source: EBICS specification V 3.0.2 (DE) ch. 4.2, ch. 4.4.1.2.5.1;
        ebics_orders_H005.xsd HIARequestOrderData."""
        root = ebics_xml.element(
            'HIARequestOrderData', nsmap={None: NS_H005, 'ds': NS_DS})
        for purpose, (name, version) in _PUB_KEY_INFOS.items():
            info = ebics_xml.sub_element(root, name)
            _x509_data(info, self.keyring.certificate(purpose))
            ebics_xml.sub_element(info, version, purpose)
        ebics_xml.sub_element(root, 'PartnerID', self.connection.partner_id)
        ebics_xml.sub_element(root, 'UserID', self.connection.user_id)
        return root

    def ini(self):
        """INI: send the public bank-technical key (A006 certificate).

        ebicsUnsecuredRequest without authentication signature, header
        without Nonce and Timestamp, SecurityMedium 0400 (decision F8),
        order data SignaturePubKeyOrderData compressed and base64 encoded,
        not encrypted; response ebicsKeyManagementResponse (unsigned).
        Source: EBICS specification V 3.0.2 (DE) ch. 3.2, ch. 4.4.1.2,
        ch. 12.3; ebics_keymgmt_request_H005.xsd ebicsUnsecuredRequest."""
        request = self._unsecured_request(
            'INI', SECURITY_MEDIUM_INI, self.ini_order_data())
        result, _ = self._key_management_order('INI', request)
        return result

    def hia(self):
        """HIA: send the public authentication (X002) and encryption (E002)
        keys; as INI with SecurityMedium 0000 and order data
        HIARequestOrderData.

        Source: EBICS specification V 3.0.2 (DE) ch. 4.4.1.2; ebics_orders_
        H005.xsd HIARequestOrderData."""
        request = self._unsecured_request(
            'HIA', SECURITY_MEDIUM_NONE, self.hia_order_data())
        result, _ = self._key_management_order('HIA', request)
        return result

    def hpb_request(self):
        """Return the HPB request: ebicsNoPubKeyDigestsRequest with Nonce,
        Timestamp, SecurityMedium 0000, empty body and the authentication
        signature X002 of the participant.

        Source: EBICS specification V 3.0.2 (DE) ch. 4.4.2.2 (Abbildung 26);
        ebics_keymgmt_request_H005.xsd ebicsNoPubKeyDigestsRequest."""
        root = ebics_xml.root_element('ebicsNoPubKeyDigestsRequest')
        header = ebics_xml.sub_element(root, 'header', authenticate='true')
        self._static_header(header, 'HPB', SECURITY_MEDIUM_NONE, True)
        ebics_xml.sub_element(header, 'mutable')
        ebics_xml.sub_element(root, 'body')
        ebics_xml.sign_auth(root, self.keyring.private_key('X002'))
        return ebics_xml.to_bytes(root)

    def hpb(self):
        """HPB: fetch the public keys of the bank.

        The response is not signed; its order data HPBResponseOrderData are
        compressed and E002 encrypted with the own encryption key. The
        digest of the own E002 certificate in DataEncryptionInfo is checked;
        decryption, decompression and parsing errors raise EbicsCryptoError
        "Entschlüsselung fehlgeschlagen". data['bank_keys'] holds per
        purpose (X002, E002) the certificate, its DER form, the version and
        the hash value (D9). The hash values are confirmed outside (E07).
        Source: EBICS specification V 3.0.2 (DE) ch. 4.4.2, ch. 11.3.2;
        ebics_orders_H005.xsd HPBResponseOrderData; specification
        account_ebics ch. 4.3, ch. 6.2."""
        result, root = self._key_management_order('HPB', self.hpb_request())
        if not result.ok:
            return result
        try:
            transfer = ebics_xml.find(root, 'ebics:body/ebics:DataTransfer')
            info = ebics_xml.find(transfer, 'ebics:DataEncryptionInfo')
            transaction_key = ebics_xml.get_base64(
                info, 'ebics:TransactionKey')
            order_data = ebics_xml.get_base64(transfer, 'ebics:OrderData')
        except EbicsError as exception:
            raise _attach(exception, result)
        self._check_encryption_digest(info, result)
        data = self._decrypt_order_data(transaction_key, order_data, result)
        try:
            document = ebics_xml.parse(data, self.max_zip_size)
        except EbicsError:
            raise _attach(EbicsCryptoError(
                    "%s (parse)" % DECRYPTION_FAILED), result) from None
        result.data['bank_keys'] = self._read_bank_keys(document, result)
        return result

    def _check_encryption_digest(self, info, result):
        "EncryptionPubKeyDigest must name the own E002 certificate"
        try:
            ebics_xml.get_attribute(
                info, 'ebics:EncryptionPubKeyDigest', 'Version',
                pattern=ENCRYPTION_VERSION)
            ebics_xml.get_attribute(
                info, 'ebics:EncryptionPubKeyDigest', 'Algorithm',
                pattern=DIGEST_ALGORITHM)
            digest = ebics_xml.get_base64(
                info, 'ebics:EncryptionPubKeyDigest')
        except EbicsError as exception:
            raise _attach(exception, result)
        own = hashlib.sha256(self.keyring.certificate('E002').public_bytes(
                serialization.Encoding.DER)).digest()
        if not hmac.compare_digest(digest, own):
            raise _attach(EbicsCryptoError(
                    "%s: the bank used another encryption key"
                    % DECRYPTION_FAILED), result)

    def _decrypt_order_data(self, transaction_key, order_data, result):
        """Decrypt and decompress order data; errors are reported as
        "Entschlüsselung fehlgeschlagen" (specification ch. 4.3)"""
        stage = 'decrypt'
        try:
            data = crypto.decrypt_e002(
                transaction_key, order_data, self.keyring.private_key('E002'))
            stage = 'decompress'
            return compression.decompress(data, self.max_zip_size)
        except EbicsError:
            raise _attach(EbicsCryptoError(
                    "%s (%s)" % (DECRYPTION_FAILED, stage)), result) from None

    def _read_bank_keys(self, document, result):
        try:
            if document.tag != ebics_xml.qname('HPBResponseOrderData'):
                raise EbicsProtocolError(
                    "Unexpected order data %s"
                    % ebics_xml.etree.QName(document).localname)
            self._check_schema(document, 'orders', result)
            host_id = ebics_xml.get_text(document, 'ebics:HostID')
            if host_id != self.connection.host_id:
                raise EbicsProtocolError(
                    "The bank keys belong to another host ID")
            bank_keys = {}
            for purpose, (name, version) in _PUB_KEY_INFOS.items():
                info = ebics_xml.find(document, 'ebics:' + name)
                ebics_xml.get_text(
                    info, 'ebics:' + version, pattern=purpose)
                der = ebics_xml.get_base64(
                    info, 'ds:X509Data/ds:X509Certificate')
                try:
                    certificate = x509.load_der_x509_certificate(der)
                except ValueError:
                    raise EbicsProtocolError(
                        "Invalid certificate %s of the bank"
                        % purpose) from None
                bank_keys[purpose] = {
                    'version': purpose,
                    'certificate': certificate,
                    'certificate_der': der,
                    'hash': keys.certificate_hash(certificate),
                    }
        except EbicsError as exception:
            raise _attach(exception, result)
        return bank_keys

    # BTD (EBICS specification V 3.0.2 (DE) ch. 5.6, ch. 7)

    def _bank_certificate(self, purpose):
        value = self.bank_keys.get(purpose)
        if isinstance(value, dict):
            value = value.get('certificate')
        if not isinstance(value, x509.Certificate):
            raise EbicsProtocolError(
                "The confirmed bank key %s is missing" % purpose)
        return value

    def _bank_digest(self, purpose):
        return hashlib.sha256(self._bank_certificate(purpose).public_bytes(
                serialization.Encoding.DER)).digest()

    def _require_bank_keys(self):
        # specification account_ebics ch. 8.2: without confirmed bank keys
        # no orders except INI, HIA, HPB
        for purpose in ('X002', 'E002'):
            self._bank_certificate(purpose)

    @staticmethod
    def _btd_order_params(btf, date_range):
        def _order_params(details):
            params = ebics_xml.sub_element(details, 'BTDOrderParams')
            service = ebics_xml.sub_element(params, 'Service')
            ebics_xml.sub_element(service, 'ServiceName', btf.service_name)
            if btf.scope:
                ebics_xml.sub_element(service, 'Scope', btf.scope)
            if btf.service_option:
                ebics_xml.sub_element(
                    service, 'ServiceOption', btf.service_option)
            if btf.container:
                ebics_xml.sub_element(
                    service, 'Container', containerType=btf.container)
            message = ebics_xml.sub_element(service, 'MsgName', btf.msg_name)
            if btf.msg_version:
                message.set('version', btf.msg_version)
            if date_range:
                start, end = date_range
                dates = ebics_xml.sub_element(params, 'DateRange')
                ebics_xml.sub_element(dates, 'Start', start.isoformat())
                ebics_xml.sub_element(dates, 'End', end.isoformat())
        return _order_params

    def btd_request(self, btf, date_range=None):
        """Return the request of the initialisation of a BTD download:
        ebicsRequest with Nonce, Timestamp, Product, OrderDetails
        (AdminOrderType BTD, BTDOrderParams with Service and optional
        DateRange), BankPubKeyDigests (SHA-256 of the DER bank certificates
        X002 and E002, base64), SecurityMedium 0000, TransactionPhase
        Initialisation and the authentication signature X002.

        Source: EBICS specification V 3.0.2 (DE) ch. 5.6.1.1.1
        (Abbildung 52), ch. 5.6.1.1.4; ebics_request_H005.xsd;
        ebics_orders_H005.xsd BTDParamsType."""
        root = ebics_xml.root_element('ebicsRequest')
        header = ebics_xml.sub_element(root, 'header', authenticate='true')
        self._static_header(
            header, 'BTD', SECURITY_MEDIUM_NONE, True,
            order_params=self._btd_order_params(btf, date_range),
            bank_digests=True)
        mutable = ebics_xml.sub_element(header, 'mutable')
        ebics_xml.sub_element(mutable, 'TransactionPhase', 'Initialisation')
        ebics_xml.sub_element(root, 'body')
        ebics_xml.sign_auth(root, self.keyring.private_key('X002'))
        return ebics_xml.to_bytes(root)

    def _transaction_request(self, transaction_id, phase, segment=None,
            last=False, receipt_code=None):
        """ebicsRequest of the transfer or receipt phase: header with HostID
        and TransactionID, TransactionPhase, SegmentNumber (transfer) or
        TransferReceipt/ReceiptCode (receipt), authentication signature"""
        root = ebics_xml.root_element('ebicsRequest')
        header = ebics_xml.sub_element(root, 'header', authenticate='true')
        static = ebics_xml.sub_element(header, 'static')
        ebics_xml.sub_element(static, 'HostID', self.connection.host_id)
        ebics_xml.sub_element(static, 'TransactionID', transaction_id)
        mutable = ebics_xml.sub_element(header, 'mutable')
        ebics_xml.sub_element(mutable, 'TransactionPhase', phase)
        if segment is not None:
            ebics_xml.sub_element(
                mutable, 'SegmentNumber', segment,
                lastSegment='true' if last else 'false')
        body = ebics_xml.sub_element(root, 'body')
        if receipt_code is not None:
            receipt = ebics_xml.sub_element(
                body, 'TransferReceipt', authenticate='true')
            ebics_xml.sub_element(receipt, 'ReceiptCode', receipt_code)
        ebics_xml.sign_auth(root, self.keyring.private_key('X002'))
        return ebics_xml.to_bytes(root)

    def _transaction_step(self, request, result, phase):
        """Send a request of the transaction, check the bank signature (F11)
        and the phase, read the return codes; return the response root"""
        result.requests.append(request)
        if result.request is None:
            result.request = request
        try:
            response = self.transport.post(request)
        except EbicsError as exception:
            raise _attach(exception, result)
        result.responses.append(response)
        result.response = response
        root = self._parse(response, result, ebics_xml.qname('ebicsResponse'))
        try:
            ebics_xml.verify_auth(
                root, self._bank_certificate('X002').public_key())
        except EbicsError as exception:
            raise _attach(exception, result)
        try:
            self._check_schema(root, 'response', result)
            technical = ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:ReturnCode',
                pattern=_RETURN_CODE)
            business = ebics_xml.get_text(
                root, 'ebics:body/ebics:ReturnCode', pattern=_RETURN_CODE)
            result.report_text = ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:ReportText',
                required=False)
            order_id = ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:OrderID',
                required=False)
            if order_id:
                result.order_id = order_id
            answered = ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:TransactionPhase')
        except EbicsError as exception:
            raise _attach(exception, result)
        result.technical = returncodes.lookup(
            technical, returncodes.TECHNICAL)
        result.business = returncodes.lookup(business, returncodes.BUSINESS)
        if result.ok and answered != phase:
            raise _attach(EbicsProtocolError(
                    "Unexpected transaction phase %s" % answered), result)
        return root

    def _segment(self, root, result, expected):
        "Return (order data segment, last) of a response"
        try:
            number = int(ebics_xml.get_text(
                    root, 'ebics:header/ebics:mutable/ebics:SegmentNumber',
                    pattern=r'\d{1,10}'))
            last = ebics_xml.get_attribute(
                root, 'ebics:header/ebics:mutable/ebics:SegmentNumber',
                'lastSegment', pattern=r'true|false|1|0') in {'true', '1'}
            node = ebics_xml.find(
                root, 'ebics:body/ebics:DataTransfer/ebics:OrderData')
            segment = ''.join((node.text or '').split())
        except EbicsError as exception:
            raise _attach(exception, result)
        if number != expected:
            raise _attach(EbicsProtocolError(
                    "Unexpected segment number %s" % number), result)
        if not segment:
            raise _attach(EbicsProtocolError(
                    "Empty order data segment %s" % number), result)
        if len(segment) > MAX_SEGMENT_SIZE:
            # ch. 7.2: the client should abort
            raise _attach(EbicsProtocolError(
                    "Segment %s exceeds %s bytes" % (
                        number, MAX_SEGMENT_SIZE)), result)
        return segment, last

    def btd_download(self, btf, date_range=None):
        """BTD download of the data of btf, optionally for date_range
        (start, end; both included). Returns a DownloadResult **without
        receipt**: the caller stores the data, commits and then calls
        btd_receipt() (specification ch. 7.3, D5).

        Initialisation (first segment, DataEncryptionInfo, TransactionID,
        NumSegments), transfer of the further segments (SegmentNumber,
        lastSegment) up to max_segments, every response checked with the
        confirmed bank X002 key; the base64 segments are concatenated,
        decoded, E002 decrypted (own key, EncryptionPubKeyDigest checked),
        decompressed (zlib, max_zip_size) and, for container ZIP, unpacked
        with limits (max_zip_files, max_zip_size, safe names).
        090005 returns the class no_data without transaction (no receipt
        needed); other bank errors return the result without data. Protocol,
        signature, decryption and limit errors raise (with exception.result)
        and must not be followed by a receipt.
        Source: EBICS specification V 3.0.2 (DE) ch. 3.3, 5.6.1, 7, 11.3.2;
        Annex 1; working paper E03 ch. 4.4, 4.7 (decisions F3, F11, F12);
        specification account_ebics ch. 7.2, 7.3, 8.2."""
        self._require_bank_keys()
        result = DownloadResult('BTD', btf=btf)
        root = self._transaction_step(
            self.btd_request(btf, date_range), result, 'Initialisation')
        if not result.ok:
            return result
        try:
            result.transaction_id = ebics_xml.get_text(
                root, 'ebics:header/ebics:static/ebics:TransactionID',
                pattern=_TRANSACTION_ID)
            result.num_segments = int(ebics_xml.get_text(
                    root, 'ebics:header/ebics:static/ebics:NumSegments',
                    pattern=r'\d{1,10}'))
            transfer = ebics_xml.find(root, 'ebics:body/ebics:DataTransfer')
            info = ebics_xml.find(transfer, 'ebics:DataEncryptionInfo')
            transaction_key = ebics_xml.get_base64(
                info, 'ebics:TransactionKey')
        except EbicsError as exception:
            raise _attach(exception, result)
        if not 1 <= result.num_segments <= self.max_segments:
            raise _attach(EbicsProtocolError(
                    "The bank announces %s segments (maximum %s)" % (
                        result.num_segments, self.max_segments)), result)
        self._check_encryption_digest(info, result)
        segment, last = self._segment(root, result, 1)
        segments = [segment]
        number = 1
        while not last:
            number += 1
            if number > self.max_segments:
                raise _attach(EbicsProtocolError(
                        "More than %s segments" % self.max_segments), result)
            if number > result.num_segments:
                # ch. 7.2: the client may continue
                result.warnings.append(
                    "Segment %s exceeds the announced %s segments"
                    % (number, result.num_segments))
            root = self._transaction_step(
                self._transaction_request(
                    result.transaction_id, 'Transfer', number,
                    last=number == result.num_segments),
                result, 'Transfer')
            if not result.ok:
                return result
            self._check_transaction_id(root, result)
            segment, last = self._segment(root, result, number)
            segments.append(segment)
        if number < result.num_segments:
            # ch. 7.2: the client should continue with the receipt
            result.warnings.append(
                "The bank sent %s of %s announced segments"
                % (number, result.num_segments))
        try:
            order_data = base64.b64decode(''.join(segments), validate=True)
        except ValueError:
            raise _attach(EbicsProtocolError(
                    "Invalid base64 order data"), result) from None
        result.container = self._decrypt_order_data(
            transaction_key, order_data, result)
        result.files = self._unpack(btf, result.container, result)
        return result

    def _check_transaction_id(self, root, result):
        try:
            transaction_id = ebics_xml.get_text(
                root, 'ebics:header/ebics:static/ebics:TransactionID',
                pattern=_TRANSACTION_ID)
        except EbicsError as exception:
            raise _attach(exception, result)
        if transaction_id.upper() != result.transaction_id.upper():
            raise _attach(EbicsProtocolError(
                    "Unexpected transaction ID"), result)

    def _unpack(self, btf, data, result):
        """Files of the order data: the members of a ZIP container (limits
        on number, size and names) or the order data as one file"""
        if (btf.container or '').upper() != 'ZIP':
            return [('%s.xml' % btf.msg_name, data)]
        try:
            container = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, ValueError):
            raise _attach(EbicsCryptoError(
                    "%s (zip)" % DECRYPTION_FAILED), result) from None
        files, total = [], 0
        with container:
            members = [i for i in container.infolist() if not i.is_dir()]
            if len(members) > self.max_zip_files:
                raise _attach(EbicsProtocolError(
                        "The container has more than %s files"
                        % self.max_zip_files), result)
            for info in members:
                name = info.filename
                if (not _SAFE_NAME.match(name) or name.startswith('.')):
                    raise _attach(EbicsProtocolError(
                            "Unsafe file name in the container"), result)
                if info.flag_bits & 0x1:
                    raise _attach(EbicsProtocolError(
                            "Encrypted file in the container"), result)
                try:
                    with container.open(info) as member:
                        content = member.read(
                            self.max_zip_size - total + 1)
                except (zipfile.BadZipFile, ValueError, OSError,
                        NotImplementedError):
                    raise _attach(EbicsCryptoError(
                            "%s (zip)" % DECRYPTION_FAILED), result) from None
                total += len(content)
                if total > self.max_zip_size:
                    raise _attach(EbicsProtocolError(
                            "The files exceed %s bytes" % self.max_zip_size),
                        result)
                files.append((name, content))
        return files

    def btd_receipt(self, transaction_id, positive=True):
        """Send the receipt of a BTD download: TransactionPhase Receipt,
        TransferReceipt/ReceiptCode 0 (positive) or 1 (negative); the bank
        answers 011000 EBICS_DOWNLOAD_POSTPROCESS_DONE or 011001
        EBICS_DOWNLOAD_POSTPROCESS_SKIPPED (class info). The response is
        checked with the bank X002 key.

        Source: EBICS specification V 3.0.2 (DE) ch. 5.6.1.1.3 (Abbildung
        56, 57), ch. 5.6.1.2.3; Annex 1 ch. 2; specification account_ebics
        ch. 7.2, 7.3 (D5)."""
        self._require_bank_keys()
        if not re.fullmatch(_TRANSACTION_ID, transaction_id or ''):
            raise ValueError("Invalid transaction ID")
        result = DownloadResult('BTD', transaction_id=transaction_id)
        root = self._transaction_step(
            self._transaction_request(
                transaction_id, 'Receipt',
                receipt_code=RECEIPT_POSITIVE if positive
                else RECEIPT_NEGATIVE),
            result, 'Receipt')
        if result.ok:
            self._check_transaction_id(root, result)
            result.receipt = {
                '011000': 'positive',
                '011001': 'negative',
                }.get(result.technical.code)
            sent = 'positive' if positive else 'negative'
            if result.receipt != sent:
                result.warnings.append(
                    "Receipt %s sent, bank answered %s"
                    % (sent, result.technical.code))
        return result

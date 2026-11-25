# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Simulated EBICS bank for the tests (decision F4 of E03).

Independent of the transport: handle(request: bytes) -> response bytes. It
checks the requests (schema if an XSD directory is given, authentication
signature of HPB) and builds the responses for HEV, INI, HIA and HPB. The
bank keys and certificates are generated (test data only). The same core
can serve as local HTTPS test server later (block E12).

No Tryton imports; only the protocol layer of the module.
"""
import base64
import hashlib
import io
import os
import zipfile
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from trytond.modules.account_ebics.protocol import (
    compression, crypto, keys, returncodes, schema)
from trytond.modules.account_ebics.protocol import xml as ebics_xml
from trytond.modules.account_ebics.protocol.exceptions import (
    EbicsAuthenticationError, EbicsError)
from trytond.modules.account_ebics.protocol.xml import NS_DS, NS_HEV

# Participant states (EBICS specification V 3.0.2 (DE) ch. 4.4.1)
NEW = 'new'
PARTIALLY_INI = 'partially_initialised_ini'
PARTIALLY_HIA = 'partially_initialised_hia'
INITIALISED = 'initialised'
READY = 'ready'

BANK_SUBJECT = keys.Subject('TESTBANK', 'Testbank (Testdaten)', 'DE')


@dataclass
class Participant:
    "A participant as the bank knows it"
    state: str = NEW
    certificates: dict = field(default_factory=dict)
    security_medium: str = None


class FakeBank:
    """Simulated bank with its own (generated) X002 and E002 keys.

    participants: {(partner_id, user_id): Participant}; unknown pairs are
    added as NEW (convenience of the simulation). auto_release: after INI
    and HIA the bank "checks the letters" at once (state READY).
    faults: error cases, e.g. {'HPB': '091002'} (technical code),
    {'HPB_wrong_key': True} (order data for another key),
    {'HPB_garbage': True} (order data not decryptable),
    {'BTD_tamper': True} (response changed after the signature),
    {'BTD_endless': True} (lastSegment never true),
    {'BTD_num_segments': n} (announced number of segments),
    {'BTD_fewer': True} (announces one segment more than it sends),
    {'BTD_wrong_key': True} (order data for another key),
    {'short_transaction_key': True} (TransactionKey shorter than the modulus,
    i.e. with a leading zero byte that is not transmitted, ch. 11.3.2.2),
    {'full_transaction_key': True} (TransactionKey padded to the modulus).
    downloads: {msg_name: [(file name, data)]} for BTD; files are delivered
    until a positive receipt; segment_size splits the base64 order data
    (EBICS specification ch. 7: at most 1 MB).
    received: list of (order type, details) of the processed requests;
    receipts: list of (transaction ID, receipt code)."""

    def __init__(self, host_id='TESTHOST', bits=2048, xsd_dir=None,
            auto_release=True, keyring=None):
        self.host_id = host_id
        self.keyring = keyring or keys.generate_keyring(bits, BANK_SUBJECT)
        self.xsd_dir = xsd_dir
        self.auto_release = auto_release
        self.participants = {}
        self.faults = {}
        self.received = []
        self.schema_errors = []
        self._order_number = 0
        self.downloads = {}
        self.segment_size = 1048576
        self.transactions = {}
        self.receipts = []

    # public helpers for tests

    def participant(self, partner_id, user_id):
        return self.participants.setdefault(
            (partner_id, user_id), Participant())

    def release(self, partner_id, user_id):
        "The bank has checked the initialisation letters"
        self.participant(partner_id, user_id).state = READY

    def certificate(self, purpose):
        return self.keyring.certificate(purpose)

    def bank_hash(self, purpose):
        return keys.certificate_hash(self.certificate(purpose))

    def transport(self):
        return FakeBankTransport(self)

    # entry point

    def handle(self, request):
        """Process the request bytes and return the response bytes"""
        root = ebics_xml.parse(request)
        local = ebics_xml.etree.QName(root).localname
        if local == 'ebicsRequest':
            return self.handle_request(root)
        if local == 'ebicsHEVRequest':
            self._validate(root, 'hev')
            return self._hev(root)
        self._validate(root, 'keymgmt_request')
        if local == 'ebicsUnsecuredRequest':
            return self._unsecured(root)
        if local == 'ebicsNoPubKeyDigestsRequest':
            return self._hpb(root)
        return self._key_management_response('061002', '000000')

    def handle_request(self, root):
        "ebicsRequest (BTD) after the schema check"
        self._validate(root, 'request')
        return self._btd(root)

    # internals

    def _validate(self, document, kind):
        if self.xsd_dir:
            errors = schema.validate(document, kind, self.xsd_dir)
            if errors:
                self.schema_errors.append((kind, errors))

    def _next_order_id(self):
        self._order_number += 1
        return 'A%03d' % self._order_number

    def _hev(self, root):
        host_id = ebics_xml.get_text(root, 'hev:HostID')
        code = '000000' if host_id == self.host_id else '091011'
        self.received.append(('HEV', {'host_id': host_id}))
        response = ebics_xml.element(
            'ebicsHEVResponse', namespace=NS_HEV, nsmap={None: NS_HEV})
        system = ebics_xml.sub_element(
            response, 'SystemReturnCode', namespace=NS_HEV)
        ebics_xml.sub_element(system, 'ReturnCode', code, namespace=NS_HEV)
        # English report text (EBICS specification ch. 9.5.2)
        ebics_xml.sub_element(
            system, 'ReportText',
            returncodes.lookup(code).symbol, namespace=NS_HEV)
        if code == '000000':
            ebics_xml.sub_element(
                response, 'VersionNumber', '03.00', namespace=NS_HEV,
                ProtocolVersion='H005')
        return ebics_xml.to_bytes(response)

    def _key_management_response(self, technical, business,
            order_id=None, transfer=None):
        root = ebics_xml.root_element('ebicsKeyManagementResponse')
        header = ebics_xml.sub_element(root, 'header', authenticate='true')
        ebics_xml.sub_element(header, 'static')
        mutable = ebics_xml.sub_element(header, 'mutable')
        if order_id:
            ebics_xml.sub_element(mutable, 'OrderID', order_id)
        ebics_xml.sub_element(mutable, 'ReturnCode', technical)
        ebics_xml.sub_element(
            mutable, 'ReportText',
            returncodes.report_text(returncodes.lookup(technical)))
        body = ebics_xml.sub_element(root, 'body')
        if transfer is not None:
            transfer(body)
        ebics_xml.sub_element(
            body, 'ReturnCode', business, authenticate='true')
        return ebics_xml.to_bytes(root)

    def _static(self, root):
        static = ebics_xml.find(root, 'ebics:header/ebics:static')
        return {
            'host_id': ebics_xml.get_text(static, 'ebics:HostID'),
            'partner_id': ebics_xml.get_text(static, 'ebics:PartnerID'),
            'user_id': ebics_xml.get_text(static, 'ebics:UserID'),
            'order_type': ebics_xml.get_text(
                static, 'ebics:OrderDetails/ebics:AdminOrderType'),
            'security_medium': ebics_xml.get_text(
                static, 'ebics:SecurityMedium'),
            'product': ebics_xml.get_text(
                static, 'ebics:Product', required=False),
            'product_language': ebics_xml.get_attribute(
                static, 'ebics:Product', 'Language', required=False),
            'nonce': ebics_xml.get_text(
                static, 'ebics:Nonce', required=False),
            'timestamp': ebics_xml.get_text(
                static, 'ebics:Timestamp', required=False),
            }

    @staticmethod
    def _certificate(info):
        der = ebics_xml.get_base64(info, 'ds:X509Data/ds:X509Certificate')
        return x509.load_der_x509_certificate(der)

    def _unsecured(self, root):
        static = self._static(root)
        order_type = static['order_type']
        if static['host_id'] != self.host_id:
            return self._key_management_response('091002', '000000')
        participant = self.participant(
            static['partner_id'], static['user_id'])
        allowed = {
            'INI': {NEW, PARTIALLY_HIA},
            'HIA': {NEW, PARTIALLY_INI},
            }.get(order_type)
        if allowed is None:
            return self._key_management_response('091005', '000000')
        if participant.state not in allowed:
            # EBICS specification ch. 4.4.1.2: no details for attackers
            return self._key_management_response('091002', '000000')
        try:
            data = compression.decompress(
                ebics_xml.get_base64(
                    root, 'ebics:body/ebics:DataTransfer/ebics:OrderData'),
                10 * 1024 * 1024)
            order_data = ebics_xml.parse(data)
        except EbicsError:
            return self._key_management_response('000000', '090004')
        certificates = {}
        if order_type == 'INI':
            self._validate(order_data, 'signature')
            info = ebics_xml.find(order_data, 'esig:SignaturePubKeyInfo')
            version = ebics_xml.get_text(info, 'esig:SignatureVersion')
            if version != 'A006':
                return self._key_management_response('000000', '091201')
            certificates['A006'] = self._certificate(info)
            ns = 'esig:'
            participant.state = (
                PARTIALLY_INI if participant.state == NEW else INITIALISED)
            participant.security_medium = static['security_medium']
        else:
            self._validate(order_data, 'orders')
            for purpose, name, version_name in [
                    ('X002', 'AuthenticationPubKeyInfo',
                        'AuthenticationVersion'),
                    ('E002', 'EncryptionPubKeyInfo', 'EncryptionVersion')]:
                info = ebics_xml.find(order_data, 'ebics:' + name)
                version = ebics_xml.get_text(info, 'ebics:' + version_name)
                if version != purpose:
                    return self._key_management_response(
                        '000000',
                        '091202' if purpose == 'X002' else '091203')
                certificates[purpose] = self._certificate(info)
            ns = 'ebics:'
            participant.state = (
                PARTIALLY_HIA if participant.state == NEW else INITIALISED)
        participant.certificates.update(certificates)
        if participant.state == INITIALISED and self.auto_release:
            participant.state = READY
        self.received.append((order_type, {
                    'static': static,
                    'order_data': order_data,
                    'partner_id': ebics_xml.get_text(
                        order_data, ns + 'PartnerID'),
                    'user_id': ebics_xml.get_text(order_data, ns + 'UserID'),
                    'hashes': {p: keys.certificate_hash(c)
                        for p, c in certificates.items()},
                    }))
        return self._key_management_response(
            '000000', '000000', order_id=self._next_order_id())

    def _hpb(self, root):
        static = self._static(root)
        participant = self.participants.get(
            (static['partner_id'], static['user_id']))
        if (static['host_id'] != self.host_id or participant is None
                or 'X002' not in participant.certificates):
            return self._key_management_response('091002', '000000')
        try:
            ebics_xml.verify_auth(
                root, participant.certificates['X002'].public_key())
        except EbicsAuthenticationError:
            return self._key_management_response('061001', '000000')
        self.received.append(('HPB', {'static': static}))
        if self.faults.get('HPB'):
            return self._key_management_response(
                self.faults['HPB'], '000000')
        if participant.state != READY:
            return self._key_management_response('091002', '000000')

        order_data = ebics_xml.root_element(
            'HPBResponseOrderData', version=False)
        for purpose, name, version_name in [
                ('X002', 'AuthenticationPubKeyInfo',
                    'AuthenticationVersion'),
                ('E002', 'EncryptionPubKeyInfo', 'EncryptionVersion')]:
            info = ebics_xml.sub_element(order_data, name)
            x509_data = ebics_xml.sub_element(
                info, 'X509Data', namespace=NS_DS)
            ebics_xml.sub_element(
                x509_data, 'X509Certificate',
                base64.b64encode(self.certificate(purpose).public_bytes(
                        serialization.Encoding.DER)).decode('ascii'),
                namespace=NS_DS)
            ebics_xml.sub_element(info, version_name, purpose)
        ebics_xml.sub_element(order_data, 'HostID', self.host_id)

        user_certificate = participant.certificates['E002']
        recipient = user_certificate
        if self.faults.get('HPB_wrong_key'):
            recipient = keys.create_certificate(
                keys.generate_key(2048), 'E002', BANK_SUBJECT)
        data = compression.compress(ebics_xml.to_bytes(order_data))
        if self.faults.get('HPB_garbage'):
            # encrypted for the right key, but not compressed XML
            data = b'not compressed order data'
        encrypted_key, ciphertext = self._encrypt(data, recipient)
        # the digest names the user's key, also if the data are not for it
        digest = hashlib.sha256(user_certificate.public_bytes(
                serialization.Encoding.DER)).digest()

        def transfer(body):
            node = ebics_xml.sub_element(body, 'DataTransfer')
            info = ebics_xml.sub_element(
                node, 'DataEncryptionInfo', authenticate='true')
            ebics_xml.sub_element(
                info, 'EncryptionPubKeyDigest',
                base64.b64encode(digest).decode('ascii'),
                Version='E002',
                Algorithm='http://www.w3.org/2001/04/xmlenc#sha256')
            ebics_xml.sub_element(
                info, 'TransactionKey',
                base64.b64encode(encrypted_key).decode('ascii'))
            ebics_xml.sub_element(
                node, 'OrderData',
                base64.b64encode(ciphertext).decode('ascii'))
        return self._key_management_response(
            '000000', '000000', transfer=transfer)

    def _encrypt(self, data, recipient):
        """E002 for HPB and BTD; the TransactionKey is not padded
        (ch. 11.3.2.2) unless the fault full_transaction_key is set"""
        public_key = recipient.public_key()
        length = (public_key.key_size + 7) // 8
        for _ in range(10000):
            encrypted_key, ciphertext = crypto.encrypt_e002(data, public_key)
            if (not self.faults.get('short_transaction_key')
                    or len(encrypted_key) < length):
                break
        else:
            raise RuntimeError("No short transaction key found")
        if self.faults.get('full_transaction_key'):
            encrypted_key = encrypted_key.rjust(length, b'\x00')
        return encrypted_key, ciphertext

    # BTD download (EBICS specification V 3.0.2 (DE) ch. 5.6, ch. 7)

    def _response(self, phase, technical, business, transaction_id=None,
            num_segments=None, segment=None, last=None, transfer=None):
        "Signed ebicsResponse"
        root = ebics_xml.root_element('ebicsResponse')
        header = ebics_xml.sub_element(root, 'header', authenticate='true')
        static = ebics_xml.sub_element(header, 'static')
        if transaction_id:
            ebics_xml.sub_element(static, 'TransactionID', transaction_id)
        if num_segments is not None:
            ebics_xml.sub_element(static, 'NumSegments', num_segments)
        mutable = ebics_xml.sub_element(header, 'mutable')
        ebics_xml.sub_element(mutable, 'TransactionPhase', phase)
        if segment is not None:
            ebics_xml.sub_element(
                mutable, 'SegmentNumber', segment,
                lastSegment='true' if last else 'false')
        ebics_xml.sub_element(mutable, 'ReturnCode', technical)
        ebics_xml.sub_element(
            mutable, 'ReportText',
            returncodes.report_text(returncodes.lookup(technical)))
        body = ebics_xml.sub_element(root, 'body')
        if transfer is not None:
            transfer(body)
        ebics_xml.sub_element(
            body, 'ReturnCode', business, authenticate='true')
        ebics_xml.sign_auth(root, self.keyring.private_key('X002'))
        if self.faults.get('BTD_tamper'):
            ebics_xml.find(root, 'ebics:body/ebics:ReturnCode').text = (
                '090005' if business == '000000' else '000000')
        return ebics_xml.to_bytes(root)

    def _container(self, files):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as container:
            for name, data in files:
                container.writestr(name, data)
        return buffer.getvalue()

    def _btd(self, root):
        phase = ebics_xml.get_text(
            root, 'ebics:header/ebics:mutable/ebics:TransactionPhase')
        if phase == 'Initialisation':
            return self._btd_initialisation(root)
        transaction_id = ebics_xml.get_text(
            root, 'ebics:header/ebics:static/ebics:TransactionID').upper()
        transaction = self.transactions.get(transaction_id)
        if transaction is None or transaction['closed']:
            return self._response(phase, '091101', '000000')
        participant = self.participants[transaction['participant']]
        try:
            ebics_xml.verify_auth(
                root, participant.certificates['X002'].public_key())
        except EbicsAuthenticationError:
            return self._response(phase, '061001', '000000')
        if phase == 'Transfer':
            number = int(ebics_xml.get_text(
                    root, 'ebics:header/ebics:mutable/ebics:SegmentNumber'))
            segments = transaction['segments']
            if self.faults.get('BTD_endless'):
                segment = segments[(number - 1) % len(segments)]
                last = False
            elif not 1 <= number <= len(segments):
                return self._response(
                    phase, '091104', '000000', transaction_id)
            else:
                segment = segments[number - 1]
                last = number == len(segments)
            self.received.append(('BTD', {
                        'phase': phase, 'segment': number}))

            def transfer(body):
                node = ebics_xml.sub_element(body, 'DataTransfer')
                ebics_xml.sub_element(node, 'OrderData', segment)
            return self._response(
                phase, '000000', '000000', transaction_id, segment=number,
                last=last, transfer=transfer)
        if phase == 'Receipt':
            code = int(ebics_xml.get_text(
                    root, 'ebics:body/ebics:TransferReceipt/'
                    'ebics:ReceiptCode'))
            self.receipts.append((transaction_id, code))
            transaction['closed'] = True
            if code == 0:
                # delivered: the data are no longer offered without range
                self.downloads.pop(transaction['msg_name'], None)
            return self._response(
                phase, '011000' if code == 0 else '011001', '000000',
                transaction_id)
        return self._response(phase, '061002', '000000')

    def _btd_initialisation(self, root):
        static = self._static(root)
        participant = self.participants.get(
            (static['partner_id'], static['user_id']))
        if (static['host_id'] != self.host_id or participant is None
                or participant.state != READY):
            return self._response('Initialisation', '091002', '000000')
        try:
            ebics_xml.verify_auth(
                root, participant.certificates['X002'].public_key())
        except EbicsAuthenticationError:
            return self._response('Initialisation', '061001', '000000')
        header = ebics_xml.find(root, 'ebics:header/ebics:static')
        for name, purpose in [('Authentication', 'X002'),
                ('Encryption', 'E002')]:
            digest = ebics_xml.get_base64(
                header, 'ebics:BankPubKeyDigests/ebics:' + name)
            own = hashlib.sha256(self.certificate(purpose).public_bytes(
                    serialization.Encoding.DER)).digest()
            if digest != own:
                return self._response('Initialisation', '091008', '000000')
        params = ebics_xml.find(
            header, 'ebics:OrderDetails/ebics:BTDOrderParams')
        service = ebics_xml.find(params, 'ebics:Service')
        msg_name = ebics_xml.get_text(service, 'ebics:MsgName')
        date_range = None
        if ebics_xml.find(params, 'ebics:DateRange', required=False) \
                is not None:
            date_range = (
                ebics_xml.get_text(params, 'ebics:DateRange/ebics:Start'),
                ebics_xml.get_text(params, 'ebics:DateRange/ebics:End'))
        self.received.append(('BTD', {
                    'phase': 'Initialisation', 'static': static,
                    'service': {
                        etree_local(n): (n.text, dict(n.attrib))
                        for n in service},
                    'date_range': date_range}))
        files = self.downloads.get(msg_name)
        if not files:
            return self._response('Initialisation', '000000', '090005')

        user_certificate = participant.certificates['E002']
        recipient = user_certificate
        if self.faults.get('BTD_wrong_key'):
            recipient = keys.create_certificate(
                keys.generate_key(2048), 'E002', BANK_SUBJECT)
        encrypted_key, ciphertext = self._encrypt(
            compression.compress(self._container(files)), recipient)
        text = base64.b64encode(ciphertext).decode('ascii')
        size = self.segment_size
        segments = [text[i:i + size] for i in range(0, len(text), size)]
        transaction_id = os.urandom(16).hex().upper()
        self.transactions[transaction_id] = {
            'segments': segments, 'closed': False, 'msg_name': msg_name,
            'participant': (static['partner_id'], static['user_id'])}
        announced = self.faults.get('BTD_num_segments', len(segments))
        last = len(segments) == 1
        if self.faults.get('BTD_fewer'):
            # announces one segment more than it sends (ch. 7.2)
            announced = len(segments) + 1
        if self.faults.get('BTD_endless'):
            last = False
        digest = hashlib.sha256(user_certificate.public_bytes(
                serialization.Encoding.DER)).digest()

        def transfer(body):
            node = ebics_xml.sub_element(body, 'DataTransfer')
            info = ebics_xml.sub_element(
                node, 'DataEncryptionInfo', authenticate='true')
            ebics_xml.sub_element(
                info, 'EncryptionPubKeyDigest',
                base64.b64encode(digest).decode('ascii'),
                Version='E002',
                Algorithm='http://www.w3.org/2001/04/xmlenc#sha256')
            ebics_xml.sub_element(
                info, 'TransactionKey',
                base64.b64encode(encrypted_key).decode('ascii'))
            ebics_xml.sub_element(node, 'OrderData', segments[0])
        return self._response(
            'Initialisation', '000000', '000000', transaction_id,
            num_segments=announced, segment=1, last=last, transfer=transfer)


def etree_local(node):
    return ebics_xml.etree.QName(node).localname


class FakeBankTransport:
    """Transport adapter: post(bytes) -> bytes to the simulated bank;
    error raises the given exception instead (e.g. EbicsTransportError)."""

    def __init__(self, bank, error=None):
        self.bank = bank
        self.error = error
        self.requests = []
        self.responses = []

    def post(self, data):
        self.requests.append(bytes(data))
        if self.error is not None:
            raise self.error
        response = self.bank.handle(bytes(data))
        self.responses.append(response)
        return response

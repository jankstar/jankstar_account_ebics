# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Simulated EBICS bank for the tests (decision F4 of E03).

Independent of the transport: handle(request: bytes) -> response bytes. It
checks the requests (schema if an XSD directory is given, authentication
signatures) and builds the responses for HEV, INI, HIA, HPB and BTD. The
bank keys and certificates are generated (test data only). The same core
serves the local HTTPS test server tools/ebics_testserver.py (block E12):
its state is plain data (to_state()/from_state()), without files.

No Tryton imports; only the protocol layer of the module.
"""
import base64
import datetime
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
#: Locked by the bank (working paper E12 ch. 4.5): HPB and BTD -> 091004
SUSPENDED = 'suspended'
STATES = (NEW, PARTIALLY_INI, PARTIALLY_HIA, INITIALISED, READY, SUSPENDED)
#: Version of the data of to_state()
STATE_VERSION = 1
#: Parts of the BTF parameters (specification account_ebics ch. 5.5, D15)
BTF_PARTS = ('service_name', 'scope', 'service_option', 'msg_name',
    'msg_version', 'container')
#: Error cases of the attribute faults: name -> type of the value
FAULTS = {
    'HPB': str,
    'HPB_wrong_key': bool,
    'HPB_garbage': bool,
    'BTD': str,
    'BTD_tamper': bool,
    'BTD_endless': bool,
    'BTD_num_segments': int,
    'BTD_fewer': bool,
    'BTD_wrong_key': bool,
    'short_transaction_key': bool,
    'full_transaction_key': bool,
    }
_PHASES = ('Initialisation', 'Transfer', 'Receipt')

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
    {'full_transaction_key': True} (TransactionKey padded to the modulus),
    {'BTD': '091008'} (technical code of the BTD initialisation).
    files: downloads for BTD with BTF parameters and date (add_download(),
    selection by all BTF parts and DateRange, see select_downloads());
    downloads: short form {msg_name: [(file name, data)]} for the tests,
    selected only by the message name; both are delivered until a positive
    receipt; segment_size splits the base64 order data (EBICS specification
    ch. 7: at most 1 MB).
    received: list of (order type, details) of the processed requests;
    receipts: list of (transaction ID, receipt code).
    order_data: plaintext of the order data of the last handled request
    as (kind, bytes) with kind 'xml' or 'zip', else None: INI/HIA the
    decompressed order data of the request, HPB the bank keys
    (HPBResponseOrderData) and BTD the ZIP container before compression
    and encryption (block E13, working paper ch. 4.3); only public data,
    no private keys.
    A request that cannot be read or is unknown gets the technical code
    061002 EBICS_INVALID_REQUEST instead of an exception (working paper
    E12 ch. 4.4)."""

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
        self.files = []
        self.segment_size = 1048576
        self.transactions = {}
        self.receipts = []
        self.order_data = None

    # public helpers for tests

    def participant(self, partner_id, user_id):
        return self.participants.setdefault(
            (partner_id, user_id), Participant())

    def release(self, partner_id, user_id):
        """The bank has checked the initialisation letters (also: unlock a
        suspended participant); INI and HIA must be done"""
        participant = self.participant(partner_id, user_id)
        if not {'A006', 'X002', 'E002'} <= set(participant.certificates):
            raise ValueError("INI and HIA are missing")
        participant.state = READY

    def suspend(self, partner_id, user_id):
        "Lock a known participant (HPB and BTD -> 091004)"
        participant = self.participants.get((partner_id, user_id))
        if participant is None:
            raise ValueError("Unknown participant")
        participant.state = SUSPENDED

    def add_download(self, btf, name, data, date=None, file_id=None):
        """Provide a file for BTD with the BTF parameters (protocol.client.Btf
        or dict of BTF_PARTS) and its date (datetime.date, default today);
        return the entry {id, btf, name, data, date, delivered}"""
        if not name or '/' in name or '\\' in name or name.startswith('.'):
            raise ValueError("Invalid file name")
        entry = {
            'id': file_id or os.urandom(8).hex(),
            'btf': btf_dict(btf),
            'name': name,
            'data': bytes(data),
            'date': (date or datetime.date.today()).isoformat(),
            'delivered': False,
            }
        if any(e['id'] == entry['id'] for e in self.files):
            raise ValueError("Duplicate file ID")
        self.files.append(entry)
        return entry

    def select_downloads(self, btf, date_range=None):
        """Return the file entries for a BTD request: all BTF parts must be
        equal (a missing part only matches a missing part), except the
        message version, which only excludes if given on both sides;
        without date_range the files not yet delivered, with date_range
        (start, end; dates, inclusive) all files with a date in the range,
        also delivered ones (working paper E12 ch. 4.4, decision F9;
        specification account_ebics ch. 7.2)"""
        wanted = btf_dict(btf)
        if date_range is not None:
            start, end = (
                d.isoformat() if isinstance(d, datetime.date) else d
                for d in date_range)
        result = []
        for entry in self.files:
            if not btf_match(entry['btf'], wanted):
                continue
            if date_range is None:
                if entry['delivered']:
                    continue
            elif not start <= entry['date'] <= end:
                continue
            result.append(entry)
        return sorted(result, key=lambda e: e['date'])

    def certificate(self, purpose):
        return self.keyring.certificate(purpose)

    def bank_hash(self, purpose):
        return keys.certificate_hash(self.certificate(purpose))

    def transport(self):
        return FakeBankTransport(self)

    # entry point

    def handle(self, request):
        """Process the request bytes and return the response bytes; a
        request that cannot be read or is unknown gets 061002"""
        self.order_data = None
        try:
            root = ebics_xml.parse(request)
        except EbicsError:
            return self._invalid(None)
        try:
            if root.tag == ebics_xml.qname('ebicsRequest'):
                return self.handle_request(root)
            if root.tag == ebics_xml.qname('ebicsHEVRequest', NS_HEV):
                self._validate(root, 'hev')
                return self._hev(root)
            if root.tag == ebics_xml.qname('ebicsUnsecuredRequest'):
                self._validate(root, 'keymgmt_request')
                return self._unsecured(root)
            if root.tag == ebics_xml.qname('ebicsNoPubKeyDigestsRequest'):
                self._validate(root, 'keymgmt_request')
                return self._hpb(root)
        except (EbicsError, ValueError):
            # missing elements, invalid values (defensive reading)
            return self._invalid(root)
        return self._invalid(root)

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

    def _invalid(self, root):
        """061002 EBICS_INVALID_REQUEST in the kind of response that fits
        the request (EBICS specification V 3.0.2 (DE) annex 1: message not
        EBICS conform)"""
        code = '061002'
        tag = root.tag if root is not None else None
        self.received.append(('INVALID', {
                    'root': ebics_xml.etree.QName(root).localname
                    if root is not None else None}))
        if tag == ebics_xml.qname('ebicsRequest'):
            phase = ebics_xml.get_text(
                root, 'ebics:header/ebics:mutable/ebics:TransactionPhase',
                required=False)
            if phase not in _PHASES:
                phase = 'Initialisation'
            return self._response(phase, code, '000000')
        if tag == ebics_xml.qname('ebicsHEVRequest', NS_HEV):
            return self._hev_response(code)
        return self._key_management_response(code, '000000')

    def _next_order_id(self):
        self._order_number += 1
        return 'A%03d' % self._order_number

    def _hev(self, root):
        host_id = ebics_xml.get_text(root, 'hev:HostID')
        code = '000000' if host_id == self.host_id else '091011'
        self.received.append(('HEV', {'host_id': host_id}))
        return self._hev_response(code)

    def _hev_response(self, code):
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
        self.order_data = ('xml', data)
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
        if participant.state == SUSPENDED:
            return self._key_management_response('091004', '000000')
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
        plaintext = ebics_xml.to_bytes(order_data)
        self.order_data = ('xml', plaintext)
        data = compression.compress(plaintext)
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
        if participant.state == SUSPENDED:
            return self._response(phase, '091004', '000000', transaction_id)
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
                if transaction.get('legacy', True):
                    self.downloads.pop(transaction['msg_name'], None)
                ids = set(transaction.get('file_ids', []))
                for entry in self.files:
                    if entry['id'] in ids:
                        entry['delivered'] = True
            return self._response(
                phase, '011000' if code == 0 else '011001', '000000',
                transaction_id)
        return self._response(phase, '061002', '000000')

    def _btd_initialisation(self, root):
        static = self._static(root)
        participant = self.participants.get(
            (static['partner_id'], static['user_id']))
        if (static['host_id'] != self.host_id or participant is None
                or participant.state not in {READY, SUSPENDED}):
            return self._response('Initialisation', '091002', '000000')
        try:
            ebics_xml.verify_auth(
                root, participant.certificates['X002'].public_key())
        except EbicsAuthenticationError:
            return self._response('Initialisation', '061001', '000000')
        if participant.state == SUSPENDED:
            return self._response('Initialisation', '091004', '000000')
        if self.faults.get('BTD'):
            return self._response(
                'Initialisation', self.faults['BTD'], '000000')
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
            date_range = tuple(
                datetime.date.fromisoformat(ebics_xml.get_text(
                        params, 'ebics:DateRange/ebics:' + n)).isoformat()
                for n in ['Start', 'End'])
        requested = service_btf(service)
        self.received.append(('BTD', {
                    'phase': 'Initialisation', 'static': static,
                    'service': {
                        etree_local(n): (n.text, dict(n.attrib))
                        for n in service},
                    'date_range': date_range}))
        legacy = list(self.downloads.get(msg_name) or [])
        entries = self.select_downloads(requested, date_range)
        files = legacy + [(e['name'], e['data']) for e in entries]
        if not files:
            return self._response('Initialisation', '000000', '090005')

        user_certificate = participant.certificates['E002']
        recipient = user_certificate
        if self.faults.get('BTD_wrong_key'):
            recipient = keys.create_certificate(
                keys.generate_key(2048), 'E002', BANK_SUBJECT)
        container = self._container(files)
        self.order_data = ('zip', container)
        encrypted_key, ciphertext = self._encrypt(
            compression.compress(container), recipient)
        text = base64.b64encode(ciphertext).decode('ascii')
        size = self.segment_size
        segments = [text[i:i + size] for i in range(0, len(text), size)]
        transaction_id = os.urandom(16).hex().upper()
        self.transactions[transaction_id] = {
            'segments': segments, 'closed': False, 'msg_name': msg_name,
            'participant': (static['partner_id'], static['user_id']),
            'btf': requested, 'date_range': date_range,
            'legacy': bool(legacy), 'file_ids': [e['id'] for e in entries]}
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

    # state as plain data (working paper E12 ch. 4.3, ch. 6)

    def to_state(self):
        """Return the state as JSON-compatible data: participants with
        certificates (DER, base64), downloads with data (base64), open and
        closed transactions, receipts, faults; no private keys (the bank
        keyring is kept separately), only the hash values of the bank
        certificates for the check in from_state()"""
        def b64(data):
            return base64.b64encode(data).decode('ascii')
        return {
            'version': STATE_VERSION,
            'host_id': self.host_id,
            'auto_release': self.auto_release,
            'bank_keys': {p: self.bank_hash(p) for p in ('X002', 'E002')},
            'order_number': self._order_number,
            'segment_size': self.segment_size,
            'participants': [{
                    'partner_id': partner_id,
                    'user_id': user_id,
                    'state': participant.state,
                    'security_medium': participant.security_medium,
                    'certificates': {
                        purpose: b64(certificate.public_bytes(
                                serialization.Encoding.DER))
                        for purpose, certificate in sorted(
                            participant.certificates.items())},
                    } for (partner_id, user_id), participant in sorted(
                    self.participants.items())],
            'downloads': {
                msg_name: [[name, b64(data)] for name, data in files]
                for msg_name, files in sorted(self.downloads.items())},
            'files': [dict(entry, btf=dict(entry['btf']),
                    data=b64(entry['data'])) for entry in self.files],
            'transactions': {
                transaction_id: dict(transaction,
                    segments=list(transaction['segments']),
                    participant=list(transaction['participant']),
                    btf=dict(transaction.get('btf') or {}) or None,
                    date_range=list(transaction['date_range'])
                    if transaction.get('date_range') else None,
                    file_ids=list(transaction.get('file_ids', [])))
                for transaction_id, transaction in sorted(
                    self.transactions.items())},
            'receipts': [list(r) for r in self.receipts],
            'faults': dict(self.faults),
            }

    @classmethod
    def from_state(cls, state, keyring, xsd_dir=None, auto_release=None):
        """Return a bank with the state of to_state() and the bank keyring
        (the hash values of its X002/E002 certificates must match the
        state); auto_release overrides the stored value if given"""
        if state.get('version') != STATE_VERSION:
            raise ValueError("Unknown version of the state")
        bank = cls(
            host_id=state['host_id'], xsd_dir=xsd_dir, keyring=keyring,
            auto_release=(state.get('auto_release', False)
                if auto_release is None else auto_release))
        for purpose, value in (state.get('bank_keys') or {}).items():
            if bank.bank_hash(purpose) != value:
                raise ValueError(
                    "The bank keyring does not match the state")
        bank._order_number = int(state.get('order_number', 0))
        bank.segment_size = int(state.get('segment_size', 1048576))
        for values in state.get('participants', []):
            state_ = values['state']
            if state_ not in STATES:
                raise ValueError("Unknown participant state")
            bank.participants[(values['partner_id'], values['user_id'])] = (
                Participant(
                    state=state_,
                    certificates={
                        purpose: x509.load_der_x509_certificate(
                            base64.b64decode(der))
                        for purpose, der in values['certificates'].items()},
                    security_medium=values.get('security_medium')))
        bank.downloads = {
            msg_name: [(name, base64.b64decode(data))
                for name, data in files]
            for msg_name, files in state.get('downloads', {}).items()}
        bank.files = [dict(entry, btf=btf_dict(entry['btf']),
                data=base64.b64decode(entry['data']),
                delivered=bool(entry.get('delivered')))
            for entry in state.get('files', [])]
        bank.transactions = {
            transaction_id: dict(transaction,
                segments=list(transaction['segments']),
                participant=tuple(transaction['participant']),
                date_range=tuple(transaction['date_range'])
                if transaction.get('date_range') else None,
                file_ids=list(transaction.get('file_ids', [])))
            for transaction_id, transaction in state.get(
                'transactions', {}).items()}
        bank.receipts = [tuple(r) for r in state.get('receipts', [])]
        bank.faults = dict(state.get('faults', {}))
        return bank


def etree_local(node):
    return ebics_xml.etree.QName(node).localname


def btf_dict(btf):
    """BTF parameters as dict of BTF_PARTS (empty parts None) from a
    protocol.client.Btf or a dict"""
    if not isinstance(btf, dict):
        btf = {part: getattr(btf, part) for part in BTF_PARTS}
    result = {}
    for part in BTF_PARTS:
        value = btf.get(part)
        value = value.strip() if isinstance(value, str) else value
        result[part] = value or None
    if not result['service_name'] or not result['msg_name']:
        raise ValueError("Service name and message name are required")
    return result


def btf_match(offered, wanted):
    """True if the BTF parameters of a provided file fit the request:
    equal parts, the message version only differs if given on both
    sides"""
    for part in BTF_PARTS:
        a, b = offered.get(part), wanted.get(part)
        if part == 'msg_version' and (a is None or b is None):
            continue
        if a != b:
            return False
    return True


def service_btf(service):
    """BTF parameters of the element Service of BTDOrderParams
    (ebics_orders_H005.xsd RestrictedServiceType)"""
    def text(name):
        return ebics_xml.get_text(service, 'ebics:' + name, required=False)
    container = ebics_xml.get_attribute(
        service, 'ebics:Container', 'containerType', required=False)
    return btf_dict({
            'service_name': text('ServiceName'),
            'scope': text('Scope'),
            'service_option': text('ServiceOption'),
            'msg_name': text('MsgName'),
            'msg_version': ebics_xml.get_attribute(
                service, 'ebics:MsgName', 'version', required=False),
            'container': container,
            })


def btf_text(btf):
    """BTF parameters as text in the order of D15, e.g.
    EOP/DE/camt.053/ZIP (specification account_ebics ch. 5.5)"""
    btf = btf_dict(btf)
    return '/'.join(btf[p] for p in BTF_PARTS if btf[p])


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

#!/usr/bin/env python3
# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Local EBICS test server for tests by hand (block E12).

HTTPS frame and command line around the simulated bank of the tests
(tests/fake_bank.py): HEV, INI, HIA, HPB, BTD with receipt. Only for the
development computer: bound to 127.0.0.1, own self-signed TLS certificate,
test data only. Not part of the installed module (no package).

Usage: see tools/README.md; ebics_testserver.py <command> --help.
Source: working paper E12 ch. 4 (decisions F1-F12).
"""
import argparse
import base64
import contextlib
import datetime
import fcntl
import http.server
import ipaddress
import json
import os
import re
import shutil
import ssl
import sys
import threading
from decimal import Decimal, InvalidOperation

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from trytond.modules.account_ebics.protocol import client, keys, returncodes
from trytond.modules.account_ebics.protocol import xml as ebics_xml
from trytond.modules.account_ebics.protocol.exceptions import EbicsError
from trytond.modules.account_ebics.protocol.transport import HttpsTransport
from trytond.modules.account_ebics.protocol.xml import NS_HEV
from trytond.modules.account_ebics.tests import camt_generator, fake_bank
from trytond.modules.account_ebics.tests.fake_bank import (
    BANK_SUBJECT, BTF_PARTS, FAULTS, FakeBank)

#: The server is bound only to this address (decision F4)
HOST = '127.0.0.1'
DEFAULT_PORT = 8443
PATH = '/ebics'
HOST_ID = 'TESTBANK'
#: Fixed passphrase of the bank keyring, test data only (decision F12)
PASSPHRASE = 'testserver'
DEFAULT_STATE_DIR = os.path.join('~', 'python', 'ebics_testserver_state')
BANK_BITS = 2048
MAX_REQUEST_SIZE = 10 * 1024 * 1024
MAX_FILE_SIZE = 50 * 1024 * 1024
CAMT053 = client.Btf('EOP', 'camt.053', scope='DE', container='ZIP')
DEMO_PARTNER = 'DEMOPART'
DEMO_USER = 'DEMOUSER'

KEYRING = 'bank-keyring.zip'
SERVER_CERT = 'server-cert.pem'
SERVER_KEY = 'server-key.pem'
LOCK = 'state.lock'
BANK = 'bank.json'
PARTICIPANTS = 'participants.json'
TRANSACTIONS = 'transactions.json'
DOWNLOADS = 'downloads'
DELIVERED = 'delivered'
MESSAGES = 'messages'
FILES = 'files.json'
#: Kept by reset, so that ca_bundle stays valid
TLS_FILES = (SERVER_CERT, SERVER_KEY)


# State directory (working paper E12 ch. 4.3)

def _write_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write('\n')
    os.replace(tmp, path)


def _read_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def btf_directory(btf):
    "Directory name of the BTF parameters, e.g. EOP_DE_camt.053_ZIP"
    return fake_bank.btf_text(btf).replace('/', '_')


def parse_btf(text):
    """Return the BTF parameters (dict) of a text in the order of D15:
    the short form without empty parts (EOP/DE/camt.053/ZIP) or the long
    form with six parts and '-' for empty ones (SDD/-/COR/pain.008/-/XML).

    Source: specification account_ebics ch. 5.5 (D15);
    ebics_types_H005.xsd (Scope 2-3, ServiceOption at least 3 characters,
    MsgName [a-z.0-9])."""
    parts = [p.strip() for p in (text or '').split('/')]
    if len(parts) == len(BTF_PARTS):
        return fake_bank.btf_dict({
                part: (None if value in {'', '-'} else value)
                for part, value in zip(BTF_PARTS, parts)})
    if not all(parts):
        raise ValueError("Empty part in BTF %r" % text)
    for index, part in enumerate(parts):
        if index and re.fullmatch(r'[a-z0-9.]*[a-z][a-z0-9.]*', part):
            break
    else:
        raise ValueError("No message name in BTF %r" % text)
    result = dict.fromkeys(BTF_PARTS)
    result['service_name'] = parts[0]
    result['msg_name'] = parts[index]
    middle = parts[1:index]
    if len(middle) == 2:
        result['scope'], result['service_option'] = middle
    elif len(middle) == 1:
        if len(middle[0]) == 2:
            result['scope'] = middle[0]
        elif len(middle[0]) > 3:
            result['service_option'] = middle[0]
        else:
            raise ValueError(
                "Scope or option %r? Use the long form with six parts, "
                "e.g. SDD/-/COR/pain.008/-/XML" % middle[0])
    elif middle:
        raise ValueError("Too many parts in BTF %r" % text)
    for part in parts[index + 1:]:
        if part.isdigit() and result['msg_version'] is None:
            result['msg_version'] = part
        elif part in {'ZIP', 'XML', 'SVC'} and result['container'] is None:
            result['container'] = part
        else:
            raise ValueError("Unknown part %r in BTF %r" % (part, text))
    return fake_bank.btf_dict(result)


def create_tls_certificate(now=None):
    """Return (certificate, private key) of a self-signed TLS server
    certificate for localhost and 127.0.0.1 (Subject Alternative Name)
    that serves as its own CA bundle (decision F3)"""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, 'EBICS-Testserver (Testdaten)'),
            ])
    public_key = key.public_key()
    certificate = (x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName('localhost'),
                    x509.IPAddress(ipaddress.ip_address(HOST)),
                    ]), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False)
        .sign(key, hashes.SHA256()))
    return certificate, key


class StateStore:
    """State of the test server in a directory: bank keyring, TLS
    certificate, participants, transactions, downloads and delivered files,
    messages. Server and commands change it only under the file lock
    state.lock (decision F7); the server reads it again before every
    request.

    Source: working paper E12 ch. 4.3."""

    _keyrings = {}
    _thread_lock = threading.Lock()

    def __init__(self, directory):
        self.directory = os.path.abspath(os.path.expanduser(directory))

    def path(self, *names):
        return os.path.join(self.directory, *names)

    @property
    def certificate_path(self):
        return self.path(SERVER_CERT)

    @contextlib.contextmanager
    def lock(self):
        "Exclusive lock for threads of this process and other processes"
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        with self._thread_lock:
            with open(self.path(LOCK), 'a') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

    def ensure(self, out=None):
        """Create what is missing: directory, bank keyring, TLS certificate
        (call under the lock)"""
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        for name in [DOWNLOADS, DELIVERED, MESSAGES]:
            os.makedirs(self.path(name), exist_ok=True)
        if not os.path.exists(self.path(KEYRING)):
            keyring = keys.generate_keyring(BANK_BITS, BANK_SUBJECT)
            with open(self.path(KEYRING) + '.tmp', 'wb') as f:
                f.write(keys.dump_keyring(keyring, PASSPHRASE))
            os.replace(self.path(KEYRING) + '.tmp', self.path(KEYRING))
            if out:
                print("Neue Bankschlüssel erzeugt: %s" % self.path(KEYRING),
                    file=out)
        if not (os.path.exists(self.path(SERVER_CERT))
                and os.path.exists(self.path(SERVER_KEY))):
            certificate, key = create_tls_certificate()
            fd = os.open(self.path(SERVER_KEY),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()))
            with open(self.path(SERVER_CERT), 'wb') as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            if out:
                print("Neues TLS-Zertifikat erzeugt: %s"
                    % self.path(SERVER_CERT), file=out)

    def keyring(self):
        "The bank keyring (cached while the file is unchanged)"
        path = self.path(KEYRING)
        stat = os.stat(path)
        key = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
        cached = self._keyrings.get(path)
        if cached is None or cached[0] != key:
            with open(path, 'rb') as f:
                cached = (key, keys.load_keyring(f.read(), PASSPHRASE))
            self._keyrings[path] = cached
        return cached[1]

    # load and save (under the lock)

    def _file_dirs(self):
        for base in [DOWNLOADS, DELIVERED]:
            root = self.path(base)
            if not os.path.isdir(root):
                continue
            for name in sorted(os.listdir(root)):
                if os.path.isfile(os.path.join(root, name, FILES)):
                    yield base, name

    def _stored_files(self):
        "{file id: (base, directory, metadata)} of the files.json"
        result = {}
        for base, name in self._file_dirs():
            for meta in _read_json(self.path(base, name, FILES), []):
                result[meta['id']] = (base, name, meta)
        return result

    def load_state(self):
        """Return the state in the form of FakeBank.to_state(); a new bank
        if the directory holds no state yet"""
        bank = _read_json(self.path(BANK), None)
        if bank is None:
            return FakeBank(
                host_id=HOST_ID, keyring=self.keyring(),
                auto_release=False).to_state()
        transactions = _read_json(self.path(TRANSACTIONS), {})
        files = []
        for base, name, meta in self._stored_files().values():
            with open(self.path(base, name, meta['name']), 'rb') as f:
                data = f.read()
            files.append(dict(meta, data=data, delivered=base == DELIVERED))
        files.sort(key=lambda e: (e.get('added', ''), e['id']))
        state = dict(bank)
        state['participants'] = _read_json(self.path(PARTICIPANTS), [])
        state['transactions'] = transactions.get('transactions', {})
        state['receipts'] = transactions.get('receipts', [])
        # FakeBank.from_state expects the data base64 encoded
        state['files'] = [dict(e, data=_b64(e['data'])) for e in files]
        return state

    def save_state(self, state):
        "Write the state of FakeBank.to_state() into the directory"
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        bank = {k: v for k, v in state.items() if k not in {
                'participants', 'transactions', 'receipts', 'files'}}
        _write_json(self.path(BANK), bank)
        _write_json(self.path(PARTICIPANTS), state['participants'])
        _write_json(self.path(TRANSACTIONS), {
                'transactions': state['transactions'],
                'receipts': state['receipts'],
                })
        stored = self._stored_files()
        wanted = {}
        directories = {(b, n) for b, n, _ in stored.values()}
        for entry in state['files']:
            base = DELIVERED if entry['delivered'] else DOWNLOADS
            name = btf_directory(entry['btf'])
            meta = {k: v for k, v in entry.items()
                if k not in {'data', 'delivered'}}
            wanted[entry['id']] = (base, name, meta)
            directories.add((base, name))
            os.makedirs(self.path(base, name), exist_ok=True)
            target = self.path(base, name, meta['name'])
            if entry['id'] in stored:
                old_base, old_name, old_meta = stored[entry['id']]
                source = self.path(old_base, old_name, old_meta['name'])
                if source != target:
                    os.replace(source, target)
            else:
                with open(target, 'wb') as f:
                    f.write(_unb64(entry['data']))
        for file_id, (base, name, meta) in stored.items():
            if file_id not in wanted:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(self.path(base, name, meta['name']))
        for base, name in directories:
            metas = [m for b, n, m in wanted.values()
                if (b, n) == (base, name)]
            if metas:
                _write_json(self.path(base, name, FILES), metas)
            else:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(self.path(base, name, FILES))
                with contextlib.suppress(OSError):
                    os.rmdir(self.path(base, name))

    def bank(self, auto_release=None, xsd_dir=None):
        "The simulated bank with the stored state"
        return FakeBank.from_state(
            self.load_state(), self.keyring(), xsd_dir=xsd_dir,
            auto_release=auto_release)

    def save_message(self, order_type, request, response, now=None):
        """Store request and response under messages/ (test data only);
        return the path of the request"""
        now = now or datetime.datetime.now()
        directory = self.path(MESSAGES)
        os.makedirs(directory, exist_ok=True)
        stem = '%s-%s' % (now.strftime('%Y%m%d-%H%M%S-%f'),
            re.sub(r'[^A-Za-z0-9]', '_', order_type or 'UNKNOWN'))
        paths = []
        for kind, data in [('request', request), ('response', response)]:
            path = os.path.join(directory, '%s-%s.xml' % (stem, kind))
            with open(path, 'wb') as f:
                f.write(data or b'')
            paths.append(path)
        return paths[0]

    def reset(self):
        "Delete the state except the TLS certificate (and the lock file)"
        if not os.path.isdir(self.directory):
            return
        for name in os.listdir(self.directory):
            if name in TLS_FILES or name == LOCK:
                continue
            path = self.path(name)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _unb64(text):
    return base64.b64decode(text)


# Server (working paper E12 ch. 4.2)

def describe_request(data, bank):
    """Return (order type, phase, participant) of a request for the console
    and the message file names"""
    try:
        root = ebics_xml.parse(data)
    except EbicsError:
        return 'UNKNOWN', None, None
    local = ebics_xml.etree.QName(root).localname
    if root.tag == ebics_xml.qname('ebicsHEVRequest', NS_HEV):
        return 'HEV', None, None
    static = root.find(ebics_xml.qname('header') + '/'
        + ebics_xml.qname('static'))
    if static is None:
        return local, None, None

    def text(name):
        node = static.find(ebics_xml.qname(name))
        return node.text.strip() if node is not None and node.text else None
    order = static.find(ebics_xml.qname('OrderDetails') + '/'
        + ebics_xml.qname('AdminOrderType'))
    order_type = order.text.strip() if order is not None and order.text \
        else None
    participant = None
    if text('PartnerID') or text('UserID'):
        participant = '%s/%s' % (text('PartnerID'), text('UserID'))
    phase = None
    if root.tag == ebics_xml.qname('ebicsRequest'):
        node = root.find('/'.join(ebics_xml.qname(n)
                for n in ['header', 'mutable', 'TransactionPhase']))
        phase = node.text.strip() if node is not None and node.text else None
        transaction = bank.transactions.get((text('TransactionID') or '')
            .upper())
        if transaction is not None:
            order_type = order_type or 'BTD'
            participant = participant or '/'.join(transaction['participant'])
    return order_type or local, phase, participant


def response_codes(data):
    "Return (technical code, business code) of a response"
    try:
        root = ebics_xml.parse(data)
    except EbicsError:
        return None, None
    if root.tag == ebics_xml.qname('ebicsHEVResponse', NS_HEV):
        return ebics_xml.get_text(
            root, 'hev:SystemReturnCode/hev:ReturnCode', required=False), None
    return (
        ebics_xml.get_text(
            root, 'ebics:header/ebics:mutable/ebics:ReturnCode',
            required=False),
        ebics_xml.get_text(root, 'ebics:body/ebics:ReturnCode',
            required=False))


class TestServerApp:
    """Processing of one request: load the state, let the simulated bank
    answer, store state and messages, print one line"""

    def __init__(self, store, auto_release=False, xsd_dir=None, out=None):
        self.store = store
        self.auto_release = auto_release
        self.xsd_dir = xsd_dir
        self.out = out or sys.stdout

    def process(self, data):
        now = datetime.datetime.now()
        with self.store.lock():
            bank = self.store.bank(
                auto_release=self.auto_release, xsd_dir=self.xsd_dir)
            order_type, phase, participant = describe_request(data, bank)
            response = bank.handle(data)
            self.store.save_state(bank.to_state())
            self.store.save_message(order_type, data, response, now)
        technical, business = response_codes(response)
        symbol = returncodes.lookup(technical).symbol if technical else ''
        line = '%s  %-4s %-14s %-24s %s / %s  %s' % (
            now.strftime('%H:%M:%S'), order_type, phase or '',
            participant or '-', technical, business or '-', symbol)
        if business and business != '000000':
            line += ', ' + returncodes.lookup(business, 'business').symbol
        print(line, file=self.out, flush=True)
        for kind, errors in bank.schema_errors:
            print('          Schema %s: %s' % (kind, '; '.join(errors[:3])),
                file=self.out, flush=True)
        return response


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'ebics-testserver'
    sys_version = ''

    def _reply(self, status, body=b'', content_type='text/plain'):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != PATH:
            return self._reply(404, b'not found\n')
        content_type = self.headers.get('Content-Type', '')
        if content_type.split(';')[0].strip().lower() != 'text/xml':
            return self._reply(415, b'text/xml required\n')
        length = self.headers.get('Content-Length', '')
        if not length.isdigit():
            return self._reply(411, b'Content-Length required\n')
        if int(length) > MAX_REQUEST_SIZE:
            return self._reply(413, b'request too big\n')
        data = self.rfile.read(int(length))
        try:
            response = self.server.app.process(data)
        except Exception as exception:
            print('Interner Fehler: %s' % type(exception).__name__,
                file=self.server.app.out, flush=True)
            return self._reply(500, b'internal error\n')
        self._reply(200, response, 'text/xml; charset=UTF-8')

    def do_GET(self):
        self._reply(405, b'only POST\n')

    do_PUT = do_DELETE = do_HEAD = do_GET

    def log_message(self, format, *args):
        # one line per request is printed by TestServerApp
        pass


class TestServer(http.server.ThreadingHTTPServer):
    """HTTPS server bound to 127.0.0.1; the TLS handshake runs in the
    thread of the connection"""
    daemon_threads = True

    def __init__(self, app, port, context):
        self.app = app
        self.ssl_context = context
        super().__init__((HOST, port), _Handler)

    def finish_request(self, request, client_address):
        request.settimeout(30)
        try:
            request = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            # e.g. the client does not trust the certificate
            request.close()
            return
        try:
            super().finish_request(request, client_address)
        finally:
            # socketserver closes only the original (detached) socket
            self.shutdown_request(request)

    def handle_error(self, request, client_address):
        print('Verbindungsfehler: %s' % sys.exc_info()[0].__name__,
            file=self.app.out, flush=True)


def tls_context(store):
    "Server TLS context, at least TLS 1.2 (specification ch. 8.2)"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(store.path(SERVER_CERT), store.path(SERVER_KEY))
    return context


def make_server(store, port=DEFAULT_PORT, auto_release=False, xsd_dir=None,
        out=None):
    """Return the HTTPS test server (not yet started) for the state
    directory; port 0 chooses a free port"""
    with store.lock():
        store.ensure(out)
        store.save_state(store.load_state())
    app = TestServerApp(store, auto_release, xsd_dir, out)
    return TestServer(app, port, tls_context(store))


def url(port=DEFAULT_PORT):
    return 'https://%s:%s%s' % (HOST, port, PATH)


# Commands (working paper E12 ch. 4.5)

def _changed(store):
    "Context: load the bank under the lock and save it afterwards"
    @contextlib.contextmanager
    def context():
        with store.lock():
            store.ensure()
            bank = store.bank()
            yield bank
            store.save_state(bank.to_state())
    return context()


def cmd_serve(args, store, out):
    server = make_server(store, args.port, args.auto_release, args.xsd_dir,
        out)
    port = server.server_address[1]
    print("EBICS-Testserver (nur Testdaten)", file=out)
    print("  URL:          %s" % url(port), file=out)
    print("  Host-ID:      %s" % HOST_ID, file=out)
    print("  ca_bundle:    %s" % store.certificate_path, file=out)
    print("  Zustand:      %s" % store.directory, file=out)
    print("  Freigabe:     %s" % (
            'automatisch' if args.auto_release else 'von Hand (release)'),
        file=out)
    if args.xsd_dir:
        print("  Schemas:      %s" % args.xsd_dir, file=out)
    print("Beenden mit Strg+C.", file=out, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def cmd_status(args, store, out):
    with store.lock():
        store.ensure()
        bank = store.bank()
    print("Zustand:   %s" % store.directory, file=out)
    print("ca_bundle: %s" % store.certificate_path, file=out)
    print("Host-ID:   %s" % bank.host_id, file=out)
    print("Bankschlüssel (Hashwerte SHA-256 für „Bankschlüssel bestätigen“):",
        file=out)
    for purpose in ['X002', 'E002']:
        print("  %s  %s" % (purpose, bank.bank_hash(purpose)), file=out)
    print("Teilnehmer:", file=out)
    if not bank.participants:
        print("  keine", file=out)
    for (partner_id, user_id), participant in sorted(
            bank.participants.items()):
        print("  %-12s %-12s %-26s %s" % (
                partner_id, user_id, participant.state,
                ' '.join(sorted(participant.certificates))), file=out)
    print("Dateien je BTF (bereitgestellt / ausgeliefert):", file=out)
    counts = {}
    for entry in bank.files:
        count = counts.setdefault(fake_bank.btf_text(entry['btf']), [0, 0])
        count[1 if entry['delivered'] else 0] += 1
    if not counts:
        print("  keine", file=out)
    for text, (open_, delivered) in sorted(counts.items()):
        print("  %-28s %3d / %3d" % (text, open_, delivered), file=out)
    open_transactions = [t for t in bank.transactions.values()
        if not t['closed']]
    print("Offene Download-Transaktionen: %d" % len(open_transactions),
        file=out)
    print("Fehlerfälle: %s" % (', '.join(
                '%s=%s' % i for i in sorted(bank.faults.items()))
            or 'keine'), file=out)
    return 0


def _participant_command(method):
    def command(args, store, out):
        with _changed(store) as bank:
            try:
                getattr(bank, method)(args.partner_id, args.user_id)
            except ValueError as exception:
                print("Fehler: %s" % exception, file=out)
                return 1
            state = bank.participants[(args.partner_id, args.user_id)].state
        print("%s/%s: %s" % (args.partner_id, args.user_id, state), file=out)
        return 0
    return command


cmd_release = _participant_command('release')
cmd_suspend = _participant_command('suspend')


def _add_file(bank, btf, name, data, date):
    text = fake_bank.btf_text(btf)
    if any(fake_bank.btf_text(e['btf']) == text and e['name'] == name
            for e in bank.files):
        raise ValueError("File %s already provided for %s" % (name, text))
    entry = bank.add_download(btf, name, data, date)
    entry['added'] = datetime.datetime.now().isoformat()
    return entry


def cmd_add_file(args, store, out):
    try:
        btf = parse_btf(args.btf)
    except ValueError as exception:
        print("Fehler: %s" % exception, file=out)
        return 1
    if os.path.getsize(args.file) > MAX_FILE_SIZE:
        print("Fehler: Datei zu groß", file=out)
        return 1
    with open(args.file, 'rb') as f:
        data = f.read()
    name = args.name or os.path.basename(args.file)
    with _changed(store) as bank:
        try:
            entry = _add_file(bank, btf, name, data, args.date)
        except ValueError as exception:
            print("Fehler: %s" % exception, file=out)
            return 1
    print("Bereitgestellt: %s/%s (Datum %s)" % (
            btf_directory(btf), entry['name'], entry['date']), file=out)
    return 0


def make_camt053_file(bank, iban, date=None, entries=5, currency='EUR',
        start_balance=Decimal('1000.00'), seed=None):
    """Generate an invented camt.053 and provide it under
    EOP/DE/camt.053/ZIP; return the file entry"""
    name, data = camt_generator.make_camt053(
        iban, date, entries, currency, start_balance, seed=seed)
    errors = camt_generator.check_camt053(data)
    if errors:
        raise ValueError('; '.join(errors))
    return _add_file(bank, CAMT053, name, data, date)


def cmd_make_camt053(args, store, out):
    try:
        start_balance = Decimal(args.start_balance)
    except InvalidOperation:
        print("Fehler: ungültiger Anfangssaldo", file=out)
        return 1
    with _changed(store) as bank:
        try:
            entry = make_camt053_file(
                bank, args.iban, args.date, args.entries, args.currency,
                start_balance)
        except ValueError as exception:
            print("Fehler: %s" % exception, file=out)
            return 1
    print("Bereitgestellt: %s/%s (Datum %s, %d Buchungen)" % (
            btf_directory(CAMT053), entry['name'], entry['date'],
            args.entries), file=out)
    return 0


def _fault_value(name, value):
    kind = FAULTS[name]
    if kind is bool:
        if value is None or value.lower() in {'1', 'true', 'ja', 'on'}:
            return True
        if value.lower() in {'0', 'false', 'nein', 'off'}:
            return False
        raise ValueError("Value for %s: true or false" % name)
    if kind is int:
        return int(value)
    if value is None or not re.fullmatch(r'[0-9]{6}', value):
        raise ValueError("Value for %s: technical return code, e.g. 091008"
            % name)
    return value


def cmd_fault(args, store, out):
    with _changed(store) as bank:
        if args.clear:
            bank.faults.clear()
        elif args.name:
            if args.name not in FAULTS:
                print("Fehler: unbekannter Fehlerfall; bekannt: %s"
                    % ', '.join(sorted(FAULTS)), file=out)
                return 1
            try:
                value = _fault_value(args.name, args.value)
            except ValueError as exception:
                print("Fehler: %s" % exception, file=out)
                return 1
            if value is False:
                bank.faults.pop(args.name, None)
            else:
                bank.faults[args.name] = value
        faults = dict(bank.faults)
    print("Fehlerfälle: %s" % (', '.join(
                '%s=%s' % i for i in sorted(faults.items())) or 'keine'),
        file=out)
    if not args.name and not args.clear:
        print("Bekannt: %s" % ', '.join(sorted(FAULTS)), file=out)
    return 0


def _step(out, name, result):
    codes = '%s / %s' % (
        result.technical.code if result.technical else '-',
        result.business.code if result.business else '-')
    print("  %-8s %-15s %s" % (name, codes, result.klass), file=out,
        flush=True)


def run_demo(store, port, partner_id=DEMO_PARTNER, user_id=DEMO_USER,
        positive=True, out=None, keyring=None):
    """Self-test without Tryton against the running server: HEV, INI, HIA,
    (release), HPB, BTD, receipt with the protocol client over HTTPS with
    ca_bundle. Return the download result."""
    out = out or sys.stdout
    with _changed(store) as bank:
        # the demo participant starts again with INI
        bank.participants.pop((partner_id, user_id), None)
        if not bank.select_downloads(CAMT053):
            entry = make_camt053_file(
                bank, camt_generator.make_iban(4711), entries=3)
            print("camt.053 bereitgestellt: %s" % entry['name'], file=out)
        bank_hashes = {p: bank.bank_hash(p) for p in ['X002', 'E002']}
    keyring = keyring or keys.generate_keyring(
        2048, keys.Subject(user_id, 'Demo (Testdaten)', 'DE'))
    connection = client.Connection(HOST_ID, partner_id, user_id, url(port))
    ebics = client.EbicsClient(connection, keyring, HttpsTransport(
            connection.url, ca_bundle=store.certificate_path))
    print("Demo %s/%s gegen %s" % (partner_id, user_id, connection.url),
        file=out)
    result = ebics.hev()
    _step(out, 'HEV', result)
    for name in ['ini', 'hia']:
        result = getattr(ebics, name)()
        _step(out, name.upper(), result)
        if not result.ok:
            raise RuntimeError("%s failed" % name.upper())
    result = ebics.hpb()
    _step(out, 'HPB', result)
    if result.klass == returncodes.USER_STATE:
        with _changed(store) as bank:
            bank.release(partner_id, user_id)
        print("  release  (Prüfung der Briefe durch die Bank)", file=out)
        result = ebics.hpb()
        _step(out, 'HPB', result)
    if not result.ok:
        raise RuntimeError("HPB failed")
    bank_keys = result.data['bank_keys']
    for purpose in ['X002', 'E002']:
        if bank_keys[purpose]['hash'] != bank_hashes[purpose]:
            raise RuntimeError("Bank key %s differs" % purpose)
    print("  Bankschlüssel bestätigt (Hashwerte wie bei status)", file=out)
    ebics.bank_keys = bank_keys
    download = ebics.btd_download(CAMT053)
    _step(out, 'BTD', download)
    for name, data in download.files:
        print("           %s (%d Byte)" % (name, len(data)), file=out)
    if download.transaction_id:
        receipt = ebics.btd_receipt(download.transaction_id, positive)
        _step(out, 'Quittung', receipt)
        download.receipt = receipt.receipt
    return download


def cmd_demo(args, store, out):
    try:
        run_demo(store, args.port, args.partner_id, args.user_id,
            not args.negative, out)
    except (EbicsError, RuntimeError) as exception:
        print("Fehler: %s (läuft der Server? serve)" % exception, file=out)
        return 1
    return 0


def cmd_reset(args, store, out):
    if not args.yes:
        answer = input("Zustand in %s löschen (TLS-Zertifikat bleibt)? "
            "[j/N] " % store.directory)
        if answer.strip().lower() not in {'j', 'ja', 'y', 'yes'}:
            print("Abgebrochen.", file=out)
            return 1
    with store.lock():
        store.reset()
    print("Zustand gelöscht; neue Bankschlüssel beim nächsten Start "
        "(in Tryton erneut HPB und Bankschlüssel bestätigen).", file=out)
    return 0


def _date(value):
    return datetime.date.fromisoformat(value)


def parser():
    "Command line (working paper E12 ch. 4.5)"
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        '--state-dir',
        default=os.environ.get('EBICS_TESTSERVER_STATE', DEFAULT_STATE_DIR),
        help="Zustandsverzeichnis (Vorgabe %(default)s)")
    result = argparse.ArgumentParser(
        description="Lokaler EBICS-Testserver (nur Testdaten, nur %s)"
        % HOST)
    commands = result.add_subparsers(dest='command', required=True)

    command = commands.add_parser(
        'serve', parents=[common], help="Server starten")
    command.add_argument('--port', type=int, default=DEFAULT_PORT)
    command.add_argument('--auto-release', action='store_true',
        help="Freigabe sofort nach INI und HIA")
    command.add_argument('--xsd-dir', default=os.environ.get('EBICS_XSD_DIR'),
        help="Schemas H005 für die Prüfung der Requests")
    command.set_defaults(func=cmd_serve)

    command = commands.add_parser(
        'status', parents=[common], help="Zustand anzeigen")
    command.set_defaults(func=cmd_status)

    for name, func, text in [
            ('release', cmd_release, "Freigabe nach Prüfung der Briefe"),
            ('suspend', cmd_suspend, "Teilnehmer sperren (091004)")]:
        command = commands.add_parser(name, parents=[common], help=text)
        command.add_argument('partner_id')
        command.add_argument('user_id')
        command.set_defaults(func=func)

    command = commands.add_parser(
        'add-file', parents=[common], help="Datei für BTD bereitstellen")
    command.add_argument('btf', help="z. B. EOP/DE/camt.053/ZIP")
    command.add_argument('file')
    command.add_argument('--date', type=_date,
        help="Datum der Datei (Vorgabe heute)")
    command.add_argument('--name', help="Dateiname im Container")
    command.set_defaults(func=cmd_add_file)

    command = commands.add_parser(
        'make-camt053', parents=[common],
        help="erfundene camt.053 unter EOP/DE/camt.053/ZIP bereitstellen")
    command.add_argument('--iban', required=True)
    command.add_argument('--date', type=_date,
        help="Buchungstag (Vorgabe heute)")
    command.add_argument('--entries', type=int, default=5)
    command.add_argument('--currency', default='EUR')
    command.add_argument('--start-balance', default='1000.00')
    command.set_defaults(func=cmd_make_camt053)

    command = commands.add_parser(
        'fault', parents=[common], help="Fehlerfall schalten")
    command.add_argument('name', nargs='?')
    command.add_argument('value', nargs='?')
    command.add_argument('--clear', action='store_true')
    command.set_defaults(func=cmd_fault)

    command = commands.add_parser(
        'demo', parents=[common],
        help="Selbsttest HEV bis Quittung gegen den laufenden Server")
    command.add_argument('--port', type=int, default=DEFAULT_PORT)
    command.add_argument('--partner-id', default=DEMO_PARTNER)
    command.add_argument('--user-id', default=DEMO_USER)
    command.add_argument('--negative', action='store_true',
        help="negative Quittung (Dateien bleiben bereitgestellt)")
    command.set_defaults(func=cmd_demo)

    command = commands.add_parser(
        'reset', parents=[common], help="Zustand löschen (TLS bleibt)")
    command.add_argument('--yes', action='store_true')
    command.set_defaults(func=cmd_reset)
    return result


def main(argv=None, out=None):
    out = out or sys.stdout
    args = parser().parse_args(argv)
    store = StateStore(args.state_dir)
    return args.func(args, store, out)


if __name__ == '__main__':
    sys.exit(main())

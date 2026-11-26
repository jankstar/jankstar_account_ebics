# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Tests of the local EBICS test server (block E12, working paper ch. 7)
and of its web page (block E13, working paper ch. 7: AdminTestCase).

T1-T5 of E12 without network; T6-T8 of E12 and T1-T5 of E13 start the
server in the test process on a random port at 127.0.0.1 with a temporary
state directory (decision F11 of E12, the only exception from "no
network": local only). Test data only.
"""
import contextlib
import datetime
import http.client
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
import threading
import unittest
from decimal import Decimal

from lxml import etree

from trytond.modules.account_ebics.protocol import client, keys, schema
from trytond.modules.account_ebics.protocol import xml as ebics_xml
from trytond.modules.account_ebics.protocol.exceptions import (
    EbicsTransportError)
from trytond.modules.account_ebics.protocol.transport import HttpsTransport
from trytond.modules.account_ebics.tests import camt_generator, fake_bank
from trytond.modules.account_ebics.tests.fake_bank import FakeBank
from trytond.modules.account_ebics.tests.test_protocol import (
    CAMT053, HAS_XSD, XSD_DIR, cached_bank_keyring, cached_keyring, camt053,
    new_bank, new_client, ready_client)

HERE = os.path.dirname(__file__)
TOOL = os.path.join(os.path.dirname(HERE), 'tools', 'ebics_testserver.py')
ADMIN_PAGE = os.path.join(
    os.path.dirname(HERE), 'tools', 'testserver_admin.html')
CAMT053_XSD = os.environ.get('CAMT053_XSD')
TEST_IBAN = 'DE14123456780000004711'
STM_CAMT052 = client.Btf('STM', 'camt.052', scope='DE', container='ZIP')


def load_tool():
    "Load tools/ebics_testserver.py by its path (it is not a package)"
    spec = importlib.util.spec_from_file_location('ebics_testserver', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


testserver = load_tool() if os.path.isfile(TOOL) else None
SKIP_TOOL = "tools/ebics_testserver.py not found (installed package)"


def codes(response):
    root = ebics_xml.parse(response)
    if root.tag == ebics_xml.qname('ebicsHEVResponse', ebics_xml.NS_HEV):
        return (ebics_xml.get_text(
                root, 'hev:SystemReturnCode/hev:ReturnCode'), None)
    return (
        ebics_xml.get_text(
            root, 'ebics:header/ebics:mutable/ebics:ReturnCode'),
        ebics_xml.get_text(root, 'ebics:body/ebics:ReturnCode'))


def read_json(*path):
    with open(os.path.join(*path), encoding='utf-8') as f:
        return json.load(f)


def roundtrip(bank, **kwargs):
    "Bank after to_state, JSON and from_state (as after a restart)"
    state = json.loads(json.dumps(bank.to_state()))
    return FakeBank.from_state(state, bank.keyring, **kwargs)


class RestartTransport:
    """Transport that restarts the bank before every request: state as JSON
    and back (working paper E12 T4)"""

    def __init__(self, bank):
        self.bank = bank
        self.requests = []

    def post(self, data):
        self.requests.append(data)
        self.bank = roundtrip(self.bank, xsd_dir=self.bank.xsd_dir)
        return self.bank.handle(bytes(data))


class FakeBankE12TestCase(unittest.TestCase):
    "Extensions of the simulated bank (E12 T1-T4)"

    # T1
    def test_invalid_request(self):
        "Unreadable or unknown request: 061002, no exception"
        bank = new_bank()
        ns = 'xmlns="urn:org:ebics:H005" Version="H005" Revision="1"'
        cases = {
            'garbage': (b'not xml at all', 'ebicsKeyManagementResponse'),
            'empty': (b'', 'ebicsKeyManagementResponse'),
            'doctype': (
                b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]><a/>',
                'ebicsKeyManagementResponse'),
            'unknown root': (b'<foo/>', 'ebicsKeyManagementResponse'),
            'unknown root H005': (
                ('<ebicsFoo %s/>' % ns).encode(),
                'ebicsKeyManagementResponse'),
            'request without header': (
                ('<ebicsRequest %s/>' % ns).encode(), 'ebicsResponse'),
            'unsecured without header': (
                ('<ebicsUnsecuredRequest %s/>' % ns).encode(),
                'ebicsKeyManagementResponse'),
            'hpb without header': (
                ('<ebicsNoPubKeyDigestsRequest %s/>' % ns).encode(),
                'ebicsKeyManagementResponse'),
            'hev without host': (
                b'<ebicsHEVRequest xmlns="http://www.ebics.org/H000"/>',
                'ebicsHEVResponse'),
            }
        for name, (request, root_name) in cases.items():
            with self.subTest(case=name):
                response = bank.handle(request)
                root = ebics_xml.parse(response)
                self.assertEqual(
                    etree.QName(root).localname, root_name)
                self.assertEqual(codes(response)[0], '061002')
                if root_name == 'ebicsResponse':
                    # signed like every ebicsResponse
                    ebics_xml.verify_auth(
                        root, bank.certificate('X002').public_key())
                    if HAS_XSD:
                        self.assertEqual(schema.validate(
                                root, 'response', XSD_DIR), [])
                elif HAS_XSD and root_name == 'ebicsKeyManagementResponse':
                    self.assertEqual(schema.validate(
                            root, 'keymgmt_response', XSD_DIR), [])

    def test_invalid_btd_parameters(self):
        "Invalid values in a signed BTD request: 061002"
        bank, ebics = ready_client()
        request = ebics_xml.parse(ebics.btd_request(
                CAMT053, (datetime.date(2026, 11, 1),
                    datetime.date(2026, 11, 2))))
        start = ebics_xml.find(request, '//ebics:DateRange/ebics:Start')
        start.text = '2026-02-30'
        ebics_xml.sign_auth(request, cached_keyring().private_key('X002'))
        response = bank.handle(ebics_xml.to_bytes(request))
        self.assertEqual(codes(response)[0], '061002')

    def test_suspend(self):
        "Suspended participant: HPB and BTD -> 091004; release unlocks"
        bank, ebics = ready_client()
        bank.suspend('TESTPARTNER', 'TESTUSER')
        result = ebics.hpb()
        self.assertEqual(
            (result.technical.code, result.klass), ('091004', 'user_state'))
        result = ebics.btd_download(CAMT053)
        self.assertEqual(
            (result.technical.code, result.klass), ('091004', 'user_state'))
        self.assertEqual(bank.receipts, [])
        bank.release('TESTPARTNER', 'TESTUSER')
        self.assertTrue(ebics.btd_download(CAMT053).ok)
        with self.assertRaises(ValueError):
            bank.suspend('UNKNOWN', 'UNKNOWN')
        with self.assertRaises(ValueError):
            # release only after INI and HIA
            bank.release('NEWPART', 'NEWUSER')

    def test_fault_btd(self):
        "Fault BTD: technical code of the initialisation, e.g. 091008"
        bank, ebics = ready_client()
        bank.faults['BTD'] = '091008'
        result = ebics.btd_download(CAMT053)
        self.assertEqual(
            (result.technical.code, result.klass), ('091008', 'bank_keys'))
        self.assertIsNone(result.transaction_id)

    # T2
    def test_select_by_btf(self):
        "Downloads are selected by all BTF parts"
        bank, ebics = ready_client(files=[])
        bank.add_download(CAMT053, 'statement.xml', camt053(),
            datetime.date(2026, 11, 24))
        bank.add_download(
            {'service_name': 'STM', 'scope': 'DE', 'msg_name': 'camt.054',
                'container': 'ZIP'}, 'details.xml', b'<a/>')
        cases = [
            (CAMT053, ['statement.xml']),
            (STM_CAMT052, []),
            (client.Btf('STM', 'camt.053', scope='DE', container='ZIP'), []),
            (client.Btf('EOP', 'camt.053', container='ZIP'), []),
            (client.Btf('EOP', 'camt.053', scope='CH', container='ZIP'), []),
            (client.Btf('EOP', 'camt.053', scope='DE', container='XML'), []),
            (client.Btf('EOP', 'camt.053', scope='DE'), []),
            # option given only in the request
            (client.Btf('EOP', 'camt.053', scope='DE', service_option='COR',
                    container='ZIP'), []),
            # version given only in the request: the file has none
            (client.Btf('EOP', 'camt.053', scope='DE', msg_version='08',
                    container='ZIP'), ['statement.xml']),
            (client.Btf('STM', 'camt.054', scope='DE', container='ZIP'),
                ['details.xml']),
            ]
        for btf, names in cases:
            with self.subTest(btf=btf.text):
                self.assertEqual(
                    [e['name'] for e in bank.select_downloads(btf)], names)
                result = ebics.btd_download(btf)
                if names:
                    self.assertTrue(result.ok)
                    self.assertEqual([n for n, _ in result.files], names)
                    ebics.btd_receipt(result.transaction_id, False)
                else:
                    self.assertEqual(result.klass, 'no_data')
        # versions on both sides must be equal; option on the file only
        bank.files.clear()
        bank.add_download(client.Btf('EOP', 'camt.053', scope='DE',
                msg_version='08', container='ZIP'), 'v08.xml', b'<a/>')
        bank.add_download(client.Btf('SDD', 'pain.002', scope='DE',
                service_option='COR', container='ZIP'), 'cor.xml', b'<a/>')
        for btf, names in [
                (client.Btf('EOP', 'camt.053', scope='DE', msg_version='08',
                        container='ZIP'), ['v08.xml']),
                (client.Btf('EOP', 'camt.053', scope='DE', msg_version='02',
                        container='ZIP'), []),
                (CAMT053, ['v08.xml']),
                (client.Btf('SDD', 'pain.002', scope='DE', container='ZIP'),
                    []),
                (client.Btf('SDD', 'pain.002', scope='DE',
                        service_option='COR', container='ZIP'), ['cor.xml']),
                ]:
            with self.subTest(btf=btf.text):
                self.assertEqual(
                    [e['name'] for e in bank.select_downloads(btf)], names)
        # the requested BTF is recorded by the bank
        received = [d for t, d in bank.received
            if t == 'BTD' and d.get('phase') == 'Initialisation']
        self.assertEqual(
            received[0]['service']['MsgName'], ('camt.053', {}))

    def test_btf_helpers(self):
        "BTF as text and back (D15), invalid BTF parameters"
        self.assertEqual(fake_bank.btf_text(CAMT053), 'EOP/DE/camt.053/ZIP')
        with self.assertRaises(ValueError):
            fake_bank.btf_dict({'service_name': 'EOP'})
        with self.assertRaises(ValueError):
            new_bank().add_download(CAMT053, '../a.xml', b'')

    # T3
    def test_date_range(self):
        "Without DateRange only open files, with DateRange all in the range"
        bank, ebics = ready_client(files=[])
        for day in [20, 21, 22]:
            bank.add_download(CAMT053, 'stmt-%s.xml' % day, b'<a/>',
                datetime.date(2026, 11, day))

        def names(date_range=None):
            result = ebics.btd_download(CAMT053, date_range)
            if result.klass == 'no_data':
                return [], result
            return [n for n, _ in result.files], result
        found, result = names()
        self.assertEqual(found, ['stmt-20.xml', 'stmt-21.xml', 'stmt-22.xml'])
        # negative receipt: still open
        ebics.btd_receipt(result.transaction_id, False)
        found, result = names()
        self.assertEqual(len(found), 3)
        ebics.btd_receipt(result.transaction_id, True)
        self.assertTrue(all(e['delivered'] for e in bank.files))
        self.assertEqual(names()[0], [])
        # with range: also delivered files, boundaries inclusive
        found, result = names(
            (datetime.date(2026, 11, 21), datetime.date(2026, 11, 22)))
        self.assertEqual(found, ['stmt-21.xml', 'stmt-22.xml'])
        ebics.btd_receipt(result.transaction_id, True)
        self.assertEqual(names(
                (datetime.date(2026, 11, 23), datetime.date(2026, 11, 30)))[0],
            [])
        self.assertEqual(names(
                (datetime.date(2026, 11, 20), datetime.date(2026, 11, 20)))[0],
            ['stmt-20.xml'])
        # a new file: without range only this one
        bank.add_download(CAMT053, 'stmt-23.xml', b'<a/>',
            datetime.date(2026, 11, 23))
        self.assertEqual(names()[0], ['stmt-23.xml'])

    # T4
    def test_state_roundtrip(self):
        "to_state/from_state keep participants, files, transactions"
        bank, ebics = ready_client(files=[])
        bank.add_download(CAMT053, 'a.xml', camt053(),
            datetime.date(2026, 11, 24))
        bank.downloads['camt.052'] = [('short.xml', b'<b/>')]
        bank.segment_size = 4000
        # open transaction: downloaded, not yet acknowledged
        open_ = ebics.btd_download(CAMT053)
        state = bank.to_state()
        text = json.dumps(state)
        # no private key material in the state
        for purpose in keys.PURPOSES:
            for keyring in [bank.keyring, cached_keyring()]:
                d = keyring.private_key(purpose).private_numbers().d
                self.assertNotIn(str(d), text)
        again = FakeBank.from_state(json.loads(text), bank.keyring)
        self.assertEqual(again.to_state(), state)
        self.assertEqual(
            again.participants[('TESTPARTNER', 'TESTUSER')].state, 'ready')
        self.assertEqual(again.participants[('TESTPARTNER', 'TESTUSER')]
            .certificates, bank.participants[('TESTPARTNER', 'TESTUSER')]
            .certificates)
        self.assertIn(open_.transaction_id, again.transactions)
        # the receipt of the open transaction goes to the restarted bank
        ebics.transport = again.transport()
        self.assertEqual(
            ebics.btd_receipt(open_.transaction_id).receipt, 'positive')
        self.assertTrue(again.files[0]['delivered'])
        self.assertFalse(bank.files[0]['delivered'])
        # other keyring or unknown version
        with self.assertRaises(ValueError):
            FakeBank.from_state(state, keys.generate_keyring(
                    2048, fake_bank.BANK_SUBJECT))
        with self.assertRaises(ValueError):
            FakeBank.from_state(dict(state, version=99), bank.keyring)

    def test_restart_during_download(self):
        "Restart before every request: same sequence as without restart"
        bank = new_bank(auto_release=False)
        transport_ = RestartTransport(bank)
        ebics = new_client(bank, transport_)
        self.assertTrue(ebics.ini().ok)
        self.assertTrue(ebics.hia().ok)
        self.assertEqual(ebics.hpb().klass, 'user_state')
        transport_.bank.release('TESTPARTNER', 'TESTUSER')
        result = ebics.hpb()
        self.assertTrue(result.ok)
        ebics.bank_keys = result.data['bank_keys']
        name, data = camt_generator.make_camt053(
            TEST_IBAN, datetime.date(2026, 11, 24), entries=40, seed=7)
        transport_.bank.add_download(
            CAMT053, name, data, datetime.date(2026, 11, 24))
        transport_.bank.segment_size = 2000
        download = ebics.btd_download(CAMT053)
        self.assertTrue(download.ok)
        self.assertGreater(download.num_segments, 2)
        self.assertEqual(download.files, [(name, data)])
        self.assertEqual(
            ebics.btd_receipt(download.transaction_id).receipt, 'positive')
        self.assertTrue(transport_.bank.files[0]['delivered'])
        self.assertEqual(ebics.btd_download(CAMT053).klass, 'no_data')
        self.assertEqual(
            len(transport_.requests), 4 + download.num_segments + 2)


class CamtGeneratorTestCase(unittest.TestCase):
    "camt.053 generator (E12 T5, without database)"

    def test_iban(self):
        "IBAN check digits (ISO 13616, mod 97-10)"
        self.assertEqual(camt_generator.make_iban(4711), TEST_IBAN)
        self.assertTrue(camt_generator.iban_valid(TEST_IBAN))
        self.assertTrue(
            camt_generator.iban_valid('DE14 1234 5678 0000 0047 11'))
        self.assertFalse(camt_generator.iban_valid('DE15123456780000004711'))
        self.assertFalse(camt_generator.iban_valid('not an iban'))

    def test_statement(self):
        "Well-formed, consistent balances, valid IBANs, unique IDs"
        date = datetime.date(2026, 11, 24)
        name, data = camt_generator.make_camt053(
            TEST_IBAN, date, entries=7, start_balance=Decimal('250.00'))
        self.assertEqual(camt_generator.check_camt053(data), [])
        root = ebics_xml.parse(data)
        ns = {'c': camt_generator.NAMESPACE}
        self.assertEqual(root.tag, '{%s}Document' % camt_generator.NAMESPACE)
        self.assertEqual(len(root.findall('.//c:Ntry', ns)), 7)
        self.assertEqual(root.findtext('.//c:Acct/c:Id/c:IBAN',
                namespaces=ns), TEST_IBAN)
        ibans = [n.text for n in root.iterfind('.//c:IBAN', ns)]
        self.assertEqual(len(ibans), 8)
        self.assertTrue(all(camt_generator.iban_valid(i) for i in ibans))
        self.assertTrue(all(re.search(r'12345678', i) for i in ibans))
        self.assertIn(date.strftime('%Y%m%d'), name)
        start = root.find('.//c:Bal', ns)
        self.assertEqual(start.findtext('c:Amt', namespaces=ns), '250.00')
        # unique Stmt/Id and MsgId
        other = ebics_xml.parse(camt_generator.make_camt053(
                TEST_IBAN, date, entries=7)[1])
        for path in ['.//c:GrpHdr/c:MsgId', './/c:Stmt/c:Id']:
            self.assertNotEqual(root.findtext(path, namespaces=ns),
                other.findtext(path, namespaces=ns))
        # reproducible with seed
        self.assertEqual(
            camt_generator.make_camt053(TEST_IBAN, date, seed=3),
            camt_generator.make_camt053(TEST_IBAN, date, seed=3))
        # no entries, negative closing balance
        for entries, balance in [(0, '0.00'), (30, '-50000.00')]:
            data = camt_generator.make_camt053(
                TEST_IBAN, date, entries=entries,
                start_balance=Decimal(balance), seed=1)[1]
            self.assertEqual(camt_generator.check_camt053(data), [])
        with self.assertRaises(ValueError):
            camt_generator.make_camt053('DE15123456780000004711')
        with self.assertRaises(ValueError):
            camt_generator.make_camt053(TEST_IBAN, currency='euro')

    def test_check_detects_errors(self):
        "check_camt053 finds inconsistent balances and invalid IBANs"
        data = camt_generator.make_camt053(TEST_IBAN, entries=2, seed=2)[1]
        changed = data.replace(b'<Cd>CLBD</Cd>', b'<Cd>XXXX</Cd>')
        self.assertTrue(camt_generator.check_camt053(changed))
        root = ebics_xml.parse(data)
        ns = {'c': camt_generator.NAMESPACE}
        root.find('.//c:Ntry/c:Amt', ns).text = '0.01'
        self.assertIn('balances not consistent with the entries',
            camt_generator.check_camt053(etree.tostring(root)))
        changed = data.replace(TEST_IBAN.encode(), b'DE15123456780000004711')
        self.assertIn('invalid IBAN DE15123456780000004711',
            camt_generator.check_camt053(changed))

    @unittest.skipUnless(CAMT053_XSD, "CAMT053_XSD not set (ISO 20022 "
        "schema camt.053.001.08)")
    def test_schema(self):
        "Valid against the local ISO 20022 schema"
        data = camt_generator.make_camt053(TEST_IBAN, entries=5)[1]
        self.assertEqual(camt_generator.check_camt053(data, CAMT053_XSD), [])


@unittest.skipUnless(testserver, SKIP_TOOL)
class StateStoreTestCase(unittest.TestCase):
    "State directory of the test server (E12 T4, ch. 4.3)"

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix='ebics-ts-')
        self.addCleanup(shutil.rmtree, self.directory)
        self.store = testserver.StateStore(self.directory)
        # reuse the cached bank keyring (generation is slow)
        with open(os.path.join(self.directory, testserver.KEYRING), 'wb') as f:
            f.write(keys.dump_keyring(
                    cached_bank_keyring(), testserver.PASSPHRASE))
        self.out = io.StringIO()

    def run_tool(self, *args):
        out = io.StringIO()
        code = testserver.main(
            [args[0], '--state-dir', self.directory] + list(args[1:]), out)
        return code, out.getvalue()

    def test_layout_and_roundtrip(self):
        "Files after ch. 4.3; save and load give the same state"
        app = testserver.TestServerApp(self.store, out=self.out)
        with self.store.lock():
            self.store.ensure()
        bank = new_bank(host_id=testserver.HOST_ID)
        ebics = new_client(bank)
        ebics.connection = client.Connection(
            testserver.HOST_ID, 'TESTPARTNER', 'TESTUSER',
            'https://ebics.example.invalid/ebics')

        class AppTransport:
            def post(self, data):
                # a new app for each request: as a restart of the server
                return testserver.TestServerApp(
                    app.store, auto_release=True, out=app.out).process(data)
        ebics.transport = AppTransport()
        self.assertTrue(ebics.ini().ok)
        self.assertTrue(ebics.hia().ok)
        result = ebics.hpb()
        self.assertTrue(result.ok)
        ebics.bank_keys = result.data['bank_keys']
        code, _ = self.run_tool('make-camt053', '--iban', TEST_IBAN,
            '--date', '2026-11-24', '--entries', '30')
        self.assertEqual(code, 0)
        source = os.path.join(self.directory, 'input.xml')
        with open(source, 'wb') as f:
            f.write(b'<Document>camt.052 test</Document>')
        code, _ = self.run_tool('add-file', 'STM/DE/camt.052/ZIP', source,
            '--date', '2026-11-24')
        self.assertEqual(code, 0)
        code, output = self.run_tool('add-file', 'STM/DE/camt.052/ZIP',
            source)
        self.assertEqual(code, 1)
        self.assertIn('already provided', output)
        with self.store.lock():
            bank = self.store.bank()
            bank.segment_size = 1000
            self.store.save_state(bank.to_state())

        for name in [testserver.KEYRING, testserver.SERVER_CERT,
                testserver.SERVER_KEY, testserver.PARTICIPANTS,
                testserver.TRANSACTIONS, testserver.LOCK]:
            self.assertTrue(
                os.path.isfile(os.path.join(self.directory, name)), name)
        downloads = os.path.join(self.directory, testserver.DOWNLOADS)
        self.assertEqual(sorted(os.listdir(downloads)),
            ['EOP_DE_camt.053_ZIP', 'STM_DE_camt.052_ZIP'])
        with open(os.path.join(downloads, 'EOP_DE_camt.053_ZIP',
                    testserver.FILES)) as f:
            meta, = json.load(f)
        self.assertEqual(meta['date'], '2026-11-24')
        self.assertEqual(meta['btf']['msg_name'], 'camt.053')
        participants = read_json(self.directory, testserver.PARTICIPANTS)
        self.assertEqual(
            [(p['partner_id'], p['user_id'], p['state'])
                for p in participants],
            [('TESTPARTNER', 'TESTUSER', 'ready')])
        # key file of the TLS server only for the owner
        self.assertEqual(os.stat(os.path.join(
                    self.directory, testserver.SERVER_KEY)).st_mode & 0o077, 0)

        state = self.store.load_state()
        self.store.save_state(state)
        self.assertEqual(self.store.load_state(), state)

        # download with several segments, each request by a new app
        download = ebics.btd_download(CAMT053)
        self.assertTrue(download.ok)
        self.assertGreater(download.num_segments, 1)
        with open(os.path.join(downloads, 'EOP_DE_camt.053_ZIP',
                    meta['name']), 'rb') as f:
            self.assertEqual(download.files, [(meta['name'], f.read())])
        transactions = read_json(self.directory, testserver.TRANSACTIONS)
        self.assertIn(download.transaction_id, transactions['transactions'])
        self.assertEqual(
            ebics.btd_receipt(download.transaction_id).receipt, 'positive')
        delivered = os.path.join(self.directory, testserver.DELIVERED,
            'EOP_DE_camt.053_ZIP')
        self.assertEqual(sorted(os.listdir(delivered)),
            sorted([meta['name'], testserver.FILES]))
        self.assertFalse(os.path.exists(
                os.path.join(downloads, 'EOP_DE_camt.053_ZIP')))
        # camt.052 is still provided
        self.assertTrue(os.path.isdir(
                os.path.join(downloads, 'STM_DE_camt.052_ZIP')))
        # messages and one console line per request
        messages = os.listdir(os.path.join(
                self.directory, testserver.MESSAGES))
        self.assertEqual(
            len([m for m in messages if '-orderdata.' not in m]),
            2 * (4 + download.num_segments))
        # E13: plaintext of INI, HIA, HPB and the BTD initialisation
        self.assertEqual(
            sorted(m.rsplit('-', 2)[-2] + m[-4:] for m in messages
                if '-orderdata.' in m),
            ['BTD.zip', 'HIA.xml', 'HPB.xml', 'INI.xml'])
        self.assertTrue(any(re.search(r'-HPB-response\.xml$', m)
                for m in messages))
        lines = self.out.getvalue().splitlines()
        self.assertEqual(len(lines), 4 + download.num_segments)
        self.assertIn('BTD  Receipt', lines[-1])
        self.assertIn('011000', lines[-1])

        code, output = self.run_tool('status')
        self.assertEqual(code, 0)
        self.assertIn('EOP/DE/camt.053/ZIP', output)
        self.assertRegex(output, r'EOP/DE/camt\.053/ZIP\s+0 /\s+1')
        self.assertIn(bank.bank_hash('X002'), output)
        self.assertIn(self.store.certificate_path, output)
        self.assertNotIn(testserver.PASSPHRASE, output)

        # reset keeps the TLS certificate only
        with open(self.store.certificate_path, 'rb') as f:
            certificate = f.read()
        code, _ = self.run_tool('reset', '--yes')
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(self.directory)), sorted(
                [testserver.SERVER_CERT, testserver.SERVER_KEY,
                    testserver.LOCK]))
        with open(self.store.certificate_path, 'rb') as f:
            self.assertEqual(f.read(), certificate)

    def test_commands(self):
        "release, suspend, fault, add-file with BTF parsing"
        self.assertEqual(self.run_tool('release', 'P1', 'U1')[0], 1)
        with self.store.lock():
            self.store.ensure()
            bank = self.store.bank()
            participant = bank.participant('P1', 'U1')
            participant.certificates.update(
                {p: cached_keyring().certificate(p) for p in keys.PURPOSES})
            participant.state = fake_bank.INITIALISED
            self.store.save_state(bank.to_state())
        self.assertEqual(self.run_tool('release', 'P1', 'U1'),
            (0, 'P1/U1: ready\n'))
        self.assertEqual(self.run_tool('suspend', 'P1', 'U1'),
            (0, 'P1/U1: suspended\n'))
        self.assertEqual(self.run_tool('suspend', 'P2', 'U2')[0], 1)

        self.assertEqual(self.run_tool('fault', 'BTD', '091008')[0], 0)
        self.assertEqual(self.run_tool('fault', 'BTD_tamper')[0], 0)
        self.assertEqual(self.run_tool('fault', 'BTD_num_segments', '3')[0],
            0)
        self.assertEqual(self.store.bank().faults, {
                'BTD': '091008', 'BTD_tamper': True, 'BTD_num_segments': 3})
        self.assertEqual(self.run_tool('fault', 'BTD_tamper', 'false')[0], 0)
        self.assertNotIn('BTD_tamper', self.store.bank().faults)
        self.assertEqual(self.run_tool('fault', 'BTD', 'xyz')[0], 1)
        self.assertEqual(self.run_tool('fault', 'unknown')[0], 1)
        self.assertEqual(self.run_tool('fault', '--clear')[0], 0)
        self.assertEqual(self.store.bank().faults, {})

        self.assertEqual(
            testserver.parse_btf('EOP/DE/camt.053/ZIP'),
            fake_bank.btf_dict(CAMT053))
        self.assertEqual(
            testserver.parse_btf('SDD/DE/COR/pain.008/08/XML'),
            fake_bank.btf_dict(client.Btf('SDD', 'pain.008', scope='DE',
                    service_option='COR', msg_version='08',
                    container='XML')))
        self.assertEqual(
            testserver.parse_btf('SDD/-/COR/pain.008/-/XML'),
            fake_bank.btf_dict(client.Btf('SDD', 'pain.008',
                    service_option='COR', container='XML')))
        self.assertEqual(
            testserver.parse_btf('EOP/camt.053'),
            fake_bank.btf_dict(client.Btf('EOP', 'camt.053')))
        self.assertEqual(
            testserver.parse_btf('SCT/VOO1/pain.001'),
            fake_bank.btf_dict(client.Btf('SCT', 'pain.001',
                    service_option='VOO1')))
        for text in ['EOP/COR/camt.053', 'EOP', 'EOP//camt.053',
                'EOP/DE/camt.053/ABC', 'EOP/DE/X/Y/camt.053']:
            with self.subTest(btf=text):
                with self.assertRaises(ValueError):
                    testserver.parse_btf(text)
        code, output = self.run_tool(
            'add-file', 'EOP/COR/camt.053', __file__)
        self.assertEqual(code, 1)
        self.assertIn('long form', output)


@contextlib.contextmanager
def running_server(directory, **kwargs):
    "Test server in a thread on a random port at 127.0.0.1"
    store = testserver.StateStore(directory)
    out = io.StringIO()
    server = testserver.make_server(store, port=0, out=out, **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, store, out
    finally:
        server.shutdown()
        server.server_close()
        thread.join(10)


@unittest.skipUnless(testserver, SKIP_TOOL)
class HttpsTestCase(unittest.TestCase):
    "The test server over HTTPS at 127.0.0.1 (E12 T6-T8, decision F11)"

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix='ebics-ts-')
        self.addCleanup(shutil.rmtree, self.directory)
        with open(os.path.join(self.directory, testserver.KEYRING), 'wb') as f:
            f.write(keys.dump_keyring(
                    cached_bank_keyring(), testserver.PASSPHRASE))

    def client(self, server, store, ca_bundle=True):
        connection = client.Connection(
            testserver.HOST_ID, 'TESTPARTNER', 'TESTUSER',
            testserver.url(server.server_address[1]))
        return client.EbicsClient(
            connection, cached_keyring(), HttpsTransport(
                connection.url,
                ca_bundle=store.certificate_path if ca_bundle else None,
                timeout=20),
            xsd_dir=XSD_DIR if HAS_XSD else None)

    def tool(self, *args):
        out = io.StringIO()
        code = testserver.main(
            [args[0], '--state-dir', self.directory] + list(args[1:]), out)
        self.assertEqual(code, 0, out.getvalue())
        return out.getvalue()

    # T6
    def test_https_flow(self):
        "HEV, INI, HIA, 091002, release, HPB, BTD, receipt over HTTPS"
        xsd_dir = XSD_DIR if HAS_XSD else None
        with running_server(self.directory, xsd_dir=xsd_dir) as (
                server, store, out):
            ebics = self.client(server, store)
            result = ebics.hev()
            self.assertTrue(result.ok)
            self.assertIn(('H005', '03.00'), result.data['versions'])
            self.assertTrue(ebics.ini().ok)
            self.assertTrue(ebics.hia().ok)
            result = ebics.hpb()
            self.assertEqual(
                (result.technical.code, result.klass),
                ('091002', 'user_state'))
            self.tool('release', 'TESTPARTNER', 'TESTUSER')
            result = ebics.hpb()
            self.assertTrue(result.ok)
            status = self.tool('status')
            for purpose in ['X002', 'E002']:
                self.assertIn(
                    result.data['bank_keys'][purpose]['hash'], status)
            ebics.bank_keys = result.data['bank_keys']
            self.assertEqual(ebics.btd_download(CAMT053).klass, 'no_data')
            self.tool('make-camt053', '--iban', TEST_IBAN, '--entries', '4',
                '--date', '2026-11-24')
            download = ebics.btd_download(CAMT053)
            self.assertTrue(download.ok)
            self.assertEqual(download.warnings, [])
            (name, data), = download.files
            self.assertEqual(camt_generator.check_camt053(data), [])
            receipt = ebics.btd_receipt(download.transaction_id)
            self.assertEqual(
                (receipt.technical.code, receipt.receipt),
                ('011000', 'positive'))
            self.assertEqual(ebics.btd_download(CAMT053).klass, 'no_data')
            # again with date range
            again = ebics.btd_download(CAMT053, (
                    datetime.date(2026, 11, 24), datetime.date(2026, 11, 24)))
            self.assertEqual(again.files, download.files)
            ebics.btd_receipt(again.transaction_id, False)

            # self-test of the command demo against the same server
            demo_out = io.StringIO()
            demo = testserver.run_demo(
                store, server.server_address[1], out=demo_out,
                keyring=cached_keyring())
            self.assertTrue(demo.ok)
            self.assertEqual(demo.receipt, 'positive')
            self.assertIn('Bankschlüssel bestätigt', demo_out.getvalue())
            self.assertNotIn(testserver.PASSPHRASE, out.getvalue())
            self.assertNotIn('Schema', out.getvalue())

        messages = os.listdir(os.path.join(
                self.directory, testserver.MESSAGES))
        for order_type in ['HEV', 'INI', 'HIA', 'HPB', 'BTD']:
            with self.subTest(order_type=order_type):
                self.assertTrue(any('-%s-request.xml' % order_type in m
                        for m in messages))
                self.assertTrue(any('-%s-response.xml' % order_type in m
                        for m in messages))
        lines = out.getvalue().splitlines()
        self.assertTrue(any('HPB' in l and '091002' in l for l in lines))

    def test_http_errors(self):
        "Wrong path, method, content type; unreadable XML -> 061002"
        import requests
        with running_server(self.directory) as (server, store, out):
            base = 'https://%s:%s' % server.server_address
            verify = store.certificate_path
            self.assertEqual(requests.post(base + '/other', data=b'<a/>',
                    headers={'Content-Type': 'text/xml'}, verify=verify,
                    timeout=20).status_code, 404)
            self.assertEqual(requests.get(base + testserver.PATH,
                    verify=verify, timeout=20).status_code, 405)
            self.assertEqual(requests.post(base + testserver.PATH,
                    data=b'<a/>', headers={'Content-Type': 'text/plain'},
                    verify=verify, timeout=20).status_code, 415)
            response = HttpsTransport(
                base + testserver.PATH, ca_bundle=verify).post(b'garbage')
            self.assertEqual(codes(response)[0], '061002')
        self.assertIn('061002', out.getvalue())

    # E07 T8
    def test_rotate_bank_keys(self):
        "rotate-bank-keys changes X002/E002; HPB delivers the new keys"
        with running_server(self.directory) as (server, store, out):
            ebics = self.client(server, store)
            self.assertTrue(ebics.ini().ok)
            self.assertTrue(ebics.hia().ok)
            self.tool('release', 'TESTPARTNER', 'TESTUSER')
            before = ebics.hpb().data['bank_keys']
            a006 = store.bank().bank_hash('A006')
            output = self.tool('rotate-bank-keys')
            bank = store.bank()
            self.assertEqual(bank.bank_hash('A006'), a006)
            after = ebics.hpb().data['bank_keys']
            status = self.tool('status')
            bank_json = read_json(self.directory, testserver.BANK)
            for purpose in ['X002', 'E002']:
                with self.subTest(purpose=purpose):
                    self.assertNotEqual(
                        after[purpose]['hash'], before[purpose]['hash'])
                    self.assertEqual(
                        after[purpose]['hash'], bank.bank_hash(purpose))
                    self.assertIn(after[purpose]['hash'], output)
                    self.assertIn(before[purpose]['hash'], output)
                    self.assertIn(after[purpose]['hash'], status)
                    self.assertNotIn(before[purpose]['hash'], status)
                    self.assertEqual(bank_json['bank_keys'][purpose],
                        after[purpose]['hash'])
            # the participant and its state are kept
            self.assertEqual(
                bank.participants[('TESTPARTNER', 'TESTUSER')].state,
                fake_bank.READY)
            # no private key and no passphrase in the state files
            for name in [testserver.BANK, testserver.PARTICIPANTS]:
                with open(os.path.join(self.directory, name), 'rb') as f:
                    content = f.read()
                self.assertNotIn(b'PRIVATE', content)
                self.assertNotIn(testserver.PASSPHRASE.encode(), content)

    # T7
    def test_tls_verification(self):
        "Without ca_bundle the connection fails (unknown certificate)"
        with running_server(self.directory) as (server, store, out):
            ebics = self.client(server, store, ca_bundle=False)
            with self.assertRaises(EbicsTransportError) as cm:
                ebics.hev()
            self.assertIn('TLS', str(cm.exception))
            # another certificate as CA bundle
            other = os.path.join(self.directory, 'other.pem')
            certificate, _ = testserver.create_tls_certificate()
            with open(other, 'wb') as f:
                from cryptography.hazmat.primitives import serialization
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            transport_ = HttpsTransport(
                testserver.url(server.server_address[1]), ca_bundle=other)
            with self.assertRaises(EbicsTransportError):
                transport_.post(b'<a/>')
            # the server still works afterwards
            self.assertTrue(self.client(server, store).hev().ok)
        with open(TOOL, encoding='utf-8') as f:
            source = f.read()
        self.assertNotIn('verify=False', source)
        self.assertNotIn('CERT_NONE', source)

    # T8
    def test_local_only(self):
        "The server binds only to 127.0.0.1; no option for another address"
        with running_server(self.directory) as (server, store, out):
            self.assertEqual(server.server_address[0], '127.0.0.1')
            self.assertEqual(server.socket.getsockname()[0], '127.0.0.1')
            self.assertEqual(server.socket.family, socket.AF_INET)
        self.assertEqual(testserver.HOST, '127.0.0.1')
        for option in ['--host', '--bind', '--address']:
            with self.subTest(option=option):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        testserver.parser().parse_args(
                            ['serve', option, '0.0.0.0'])
        args = testserver.parser().parse_args(['serve'])
        self.assertEqual(args.port, 8443)
        self.assertEqual(testserver.url(), 'https://127.0.0.1:8443/ebics')
        self.assertEqual(testserver.HOST_ID, 'TESTBANK')
        self.assertTrue(args.state_dir.endswith(
                os.path.join('python', 'ebics_testserver_state'))
            or os.environ.get('EBICS_TESTSERVER_STATE'))


class AdminResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body)


@unittest.skipUnless(testserver, SKIP_TOOL)
class AdminTestCase(unittest.TestCase):
    "Web page /admin of the test server (E13 T1-T6, working paper ch. 7)"

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix='ebics-ts-')
        self.addCleanup(shutil.rmtree, self.directory)
        with open(os.path.join(self.directory, testserver.KEYRING), 'wb') as f:
            f.write(keys.dump_keyring(
                    cached_bank_keyring(), testserver.PASSPHRASE))

    def client(self, server, store, partner_id='TESTPARTNER',
            user_id='TESTUSER'):
        connection = client.Connection(
            testserver.HOST_ID, partner_id, user_id,
            testserver.url(server.server_address[1]))
        return client.EbicsClient(
            connection, cached_keyring(), HttpsTransport(
                connection.url, ca_bundle=store.certificate_path,
                timeout=20))

    def request(self, server, path, method='GET', token=True, host=None,
            body=None, content_type=None):
        """Request with http.client: the path is sent unchanged (also
        '../'), the Host header can be set"""
        store = server.app.store
        context = ssl.create_default_context(cafile=store.certificate_path)
        connection = http.client.HTTPSConnection(
            '127.0.0.1', server.server_address[1], context=context,
            timeout=60)
        headers = {}
        if token is True:
            token = server.admin.token
        if token:
            headers[testserver.TOKEN_HEADER] = token
        if host is not None:
            headers['Host'] = host
        if content_type:
            headers['Content-Type'] = content_type
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return AdminResponse(
                response.status, response.headers, response.read())
        finally:
            connection.close()

    def api(self, server, path, **kwargs):
        response = self.request(server, '/admin/api/' + path, **kwargs)
        self.assertEqual(response.status, 200, response.body)
        return response.json()

    def command(self, server, *argv):
        response = self.request(
            server, '/admin/api/command', method='POST',
            body=json.dumps({'argv': list(argv)}).encode('utf-8'),
            content_type='application/json')
        self.assertEqual(response.status, 200, response.body)
        data = response.json()
        return data['exit'], data['output']

    def flow(self, server, store):
        "HEV, INI, HIA, HPB 091002, release, HPB, camt.053, BTD, receipt"
        ebics = self.client(server, store)
        self.assertTrue(ebics.hev().ok)
        self.assertTrue(ebics.ini().ok)
        self.assertTrue(ebics.hia().ok)
        self.assertEqual(ebics.hpb().technical.code, '091002')
        self.assertEqual(
            self.command(server, 'release', 'TESTPARTNER', 'TESTUSER')[0], 0)
        result = ebics.hpb()
        self.assertTrue(result.ok)
        ebics.bank_keys = result.data['bank_keys']
        self.assertEqual(self.command(
                server, 'make-camt053', '--iban', TEST_IBAN, '--entries', '3',
                '--date', '2026-11-24')[0], 0)
        download = ebics.btd_download(CAMT053)
        self.assertTrue(download.ok)
        ebics.btd_receipt(download.transaction_id)
        return ebics, download

    # T1
    def test_access(self):
        "Token, Host header, security headers, --no-admin"
        with running_server(self.directory) as (server, store, out):
            port = server.server_address[1]
            token = server.admin.token
            self.assertGreaterEqual(len(token), 43)
            self.assertEqual(
                testserver.admin_url(port, token),
                'https://127.0.0.1:%s/admin#token=%s' % (port, token))
            for path in ['messages', 'status', 'messages/x']:
                with self.subTest(path=path):
                    for value in [None, 'wrong', token[:-1]]:
                        self.assertEqual(self.request(
                                server, '/admin/api/' + path,
                                token=value).status, 403)
            self.assertEqual(self.request(
                    server, '/admin/api/command', method='POST', token=None,
                    body=b'{"argv": ["status"]}',
                    content_type='application/json').status, 403)
            for host in ['ebics.example.invalid:%s' % port,
                    '127.0.0.1:1', '127.0.0.1', 'localhost',
                    '192.168.1.1:%s' % port, '']:
                with self.subTest(host=host):
                    self.assertEqual(self.request(
                            server, '/admin/api/status', host=host).status,
                        403)
                    self.assertEqual(self.request(
                            server, '/admin', host=host).status, 403)
            self.assertEqual(self.request(
                    server, '/admin/api/status',
                    host='localhost:%s' % port).status, 200)
            page = self.request(server, '/admin', token=None)
            self.assertEqual(page.status, 200)
            self.assertTrue(page.headers['Content-Type'].startswith(
                    'text/html'))
            with open(ADMIN_PAGE, 'rb') as f:
                self.assertEqual(page.body, f.read())
            for name, value in testserver.SECURITY_HEADERS.items():
                with self.subTest(header=name):
                    self.assertEqual(page.headers[name], value)
            self.assertIn("default-src 'self'",
                page.headers['Content-Security-Policy'])
            self.assertEqual(page.headers['X-Frame-Options'], 'DENY')
            self.assertEqual(page.headers['Cache-Control'], 'no-store')
            self.assertEqual(
                page.headers['X-Content-Type-Options'], 'nosniff')
            forbidden = self.request(server, '/admin/api/status', token=None)
            self.assertEqual(forbidden.headers['X-Frame-Options'], 'DENY')
            self.assertEqual(self.request(
                    server, '/admin/other').status, 404)
            self.assertEqual(self.request(
                    server, '/admin/api/unknown').status, 404)
            # EBICS unchanged: GET /ebics -> 405
            self.assertEqual(self.request(server, testserver.PATH).status,
                405)
            self.assertEqual(self.command(server, 'status')[0], 0)
            self.assertNotIn(token, out.getvalue())
        # the token is in no file of the state directory
        for root, _, names in os.walk(self.directory):
            for name in names:
                with open(os.path.join(root, name), 'rb') as f:
                    self.assertNotIn(token.encode('ascii'), f.read(), name)

        with running_server(self.directory, admin=False) as (
                server, store, out):
            self.assertIsNone(server.admin)
            for path in ['/admin', '/admin/api/status',
                    '/admin/api/messages']:
                with self.subTest(path=path):
                    self.assertEqual(
                        self.request(server, path, token='x').status, 404)
            self.assertTrue(self.client(server, store).hev().ok)
        self.assertTrue(testserver.parser().parse_args(
                ['serve', '--no-admin']).no_admin)
        self.assertFalse(testserver.parser().parse_args(['serve']).no_admin)

    # T2, T3, T4
    def test_messages(self):
        "List, after, detail formatted and raw, order data, 404"
        with running_server(self.directory) as (server, store, out):
            self.assertEqual(self.api(server, 'messages'),
                {'messages': [], 'total': 0, 'latest': None})
            self.flow(server, store)

            # T2 list
            data = self.api(server, 'messages')
            messages = data['messages']
            ids = [m['id'] for m in messages]
            self.assertEqual(ids, sorted(ids, reverse=True))
            self.assertEqual(data['total'], len(messages))
            self.assertEqual(data['latest'], ids[0])
            self.assertEqual(
                [(m['order_type'], m['phase']) for m in reversed(messages)],
                [('HEV', None), ('INI', None), ('HIA', None), ('HPB', None),
                    ('HPB', None), ('BTD', 'Initialisation'),
                    ('BTD', 'Receipt')])
            by_type = {}
            for message in messages:
                by_type.setdefault(message['order_type'], []).append(message)
            ok, failed = by_type['HPB']
            self.assertEqual(ok['technical']['code'], '000000')
            self.assertEqual(failed['technical'], {
                    'code': '091002',
                    'symbol': 'EBICS_INVALID_USER_OR_USER_STATE',
                    'klass': 'user_state'})
            receipt, initialisation = by_type['BTD']
            self.assertEqual(receipt['technical']['code'], '011000')
            self.assertEqual(receipt['participant'], 'TESTPARTNER/TESTUSER')
            self.assertEqual(initialisation['business']['symbol'],
                'EBICS_OK')
            self.assertIsNone(by_type['HEV'][0]['participant'])
            self.assertEqual(
                [m['order_data'] for m in reversed(messages)],
                [None, 'xml', 'xml', None, 'xml', 'zip', None])
            self.assertIsNone(failed['order_data'])
            self.assertIsNone(receipt['order_data'])

            # after: only newer messages
            self.assertEqual(self.api(
                    server, 'messages?after=' + ids[0])['messages'], [])
            self.assertTrue(self.client(server, store).hev().ok)
            newer = self.api(server, 'messages?after=' + ids[0])
            self.assertEqual(
                [m['order_type'] for m in newer['messages']], ['HEV'])
            self.assertEqual(newer['total'], len(ids) + 1)
            self.assertEqual(self.request(
                    server, '/admin/api/messages?after=../x').status, 400)

            # T3 detail formatted, raw, base64 shortened or full
            message_id = initialisation['id']
            detail = self.api(server, 'messages/' + message_id)
            self.assertEqual(detail['order_type'], 'BTD')
            path = os.path.join(store.path(testserver.MESSAGES), message_id)
            for kind in ['request', 'response']:
                with self.subTest(kind=kind):
                    with open(path + '-%s.xml' % kind, 'rb') as f:
                        original = f.read()
                    self.assertIsNone(detail[kind]['error'])
                    self.assertEqual(detail[kind]['size'], len(original))
                    self.assertIn('\n  <', detail[kind]['text'])
                    raw = self.api(
                        server, 'messages/%s?raw=1' % message_id)[kind]
                    self.assertEqual(raw['text'], original.decode('utf-8'))
            response = detail['response']['text']
            self.assertIn('Zeichen gekürzt', response)
            full = self.api(server, 'messages/%s?full=1' % message_id)
            self.assertNotIn('Zeichen gekürzt', full['response']['text'])
            self.assertGreater(
                len(full['response']['text']), len(response))
            ebics_xml.parse(full['response']['text'])
            for bad in ['20261126-000000-000000-HEV', 'unknown', '../bank',
                    '..%2F..%2Fbank.json', ids[0] + '/../../bank.json',
                    '%s-request' % ids[0], ids[0].replace('-', '/')]:
                with self.subTest(id=bad):
                    self.assertEqual(self.request(
                            server, '/admin/api/messages/' + bad).status,
                        404)
            self.assertIsNone(server.admin.message('../' + ids[0]))

            # T4 order data
            def order_data(message):
                return self.api(
                    server, 'messages/' + message['id'])['order_data']
            ini = order_data(by_type['INI'][0])
            self.assertEqual(ini['kind'], 'xml')
            self.assertIn('SignaturePubKeyInfo', ini['text'])
            self.assertEqual(
                [(c['purpose'], c['hash']) for c in ini['certificates']],
                [('A006', keys.certificate_hash(
                            cached_keyring().certificate('A006')))])
            hia = order_data(by_type['HIA'][0])
            self.assertEqual(
                [(c['purpose'], c['hash']) for c in hia['certificates']],
                [(p, keys.certificate_hash(cached_keyring().certificate(p)))
                    for p in ['X002', 'E002']])
            hpb = order_data(ok)
            self.assertIn('HPBResponseOrderData', hpb['text'])
            bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
            self.assertEqual(
                [(c['purpose'], c['hash']) for c in hpb['certificates']],
                [(p, bank.bank_hash(p)) for p in ['X002', 'E002']])
            btd = order_data(initialisation)
            self.assertEqual(btd['kind'], 'zip')
            (entry,) = btd['files']
            self.assertTrue(entry['name'].startswith('camt053_'))
            self.assertIn('camt.053.001.08', entry['text'])
            self.assertIn(TEST_IBAN, entry['text'])
            self.assertIsNone(entry['error'])
            names = os.listdir(store.path(testserver.MESSAGES))
            self.assertIn(initialisation['id'] + '-orderdata.zip', names)
            self.assertIn(ok['id'] + '-orderdata.xml', names)
            self.assertNotIn(failed['id'] + '-orderdata.xml', names)
            for name in names:
                with open(os.path.join(
                            store.path(testserver.MESSAGES), name),
                        'rb') as f:
                    content = f.read()
                self.assertNotIn(b'PRIVATE KEY', content, name)
                self.assertNotIn(testserver.PASSPHRASE.encode(), content,
                    name)

    def test_order_data_of_fake_bank(self):
        "FakeBank.order_data: plaintext of the last request, no keys"
        bank = new_bank()
        self.assertIsNone(bank.order_data)
        ebics = new_client(bank)
        self.assertTrue(ebics.hev().ok)
        self.assertIsNone(bank.order_data)
        self.assertTrue(ebics.ini().ok)
        kind, data = bank.order_data
        self.assertEqual(kind, 'xml')
        self.assertIn(b'SignaturePubKeyInfo', data)
        self.assertTrue(ebics.hia().ok)
        self.assertIn(b'AuthenticationPubKeyInfo', bank.order_data[1])
        result = ebics.hpb()
        kind, data = bank.order_data
        self.assertEqual(kind, 'xml')
        root = ebics_xml.parse(data)
        self.assertEqual(etree.QName(root).localname, 'HPBResponseOrderData')
        self.assertNotIn(b'PRIVATE', data)
        ebics.bank_keys = result.data['bank_keys']
        bank.downloads['camt.053'] = [('a.xml', camt053())]
        download = ebics.btd_download(CAMT053)
        # one segment: the last request was the initialisation
        self.assertEqual(download.num_segments, 1)
        kind, data = bank.order_data
        self.assertEqual(kind, 'zip')
        import zipfile
        with zipfile.ZipFile(io.BytesIO(data)) as container:
            self.assertEqual(container.read('a.xml'), camt053())
        ebics.btd_receipt(download.transaction_id)
        self.assertIsNone(bank.order_data)
        # not part of the state
        self.assertNotIn('order_data', bank.to_state())

    def test_order_data_view(self):
        "Display of a container: size limit, no XML, unreadable"
        buffer = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(buffer, 'w') as container:
            container.writestr('a.xml', b'<a><b>1</b></a>')
            container.writestr('b.txt', b'text')
            container.writestr('c.xml', b'<a>')
        view = testserver.order_data_view('zip', buffer.getvalue())
        self.assertIsNone(view['error'])
        a, b, c = view['files']
        self.assertEqual(a['text'], '<a>\n  <b>1</b>\n</a>')
        self.assertEqual(b['error'], 'keine XML-Datei')
        self.assertIsNotNone(c['error'])
        self.assertEqual(c['text'], '<a>')
        self.assertIn('nicht lesbar',
            testserver.order_data_view('zip', b'garbage')['error'])
        text, error = testserver.format_xml(
            b'<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>')
        self.assertIn('DOCTYPE', error)
        self.assertNotIn('<a>x</a>', text)

    # T5
    def test_commands(self):
        "Commands over the API with output and exit code"
        with running_server(self.directory) as (server, store, out):
            code, output = self.command(server, 'status')
            self.assertEqual(code, 0)
            self.assertIn('Host-ID:   TESTBANK', output)
            status = self.api(server, 'status')
            self.assertEqual(status['participants'], [])
            self.assertIn('Host-ID:   TESTBANK', status['output'])
            self.assertIn('BTD_tamper', status['known_faults'])

            self.assertEqual(self.command(server, 'release', 'P1', 'U1'),
                (1, 'Fehler: INI and HIA are missing\n'))
            ebics = self.client(server, store)
            self.assertTrue(ebics.ini().ok)
            self.assertTrue(ebics.hia().ok)
            self.assertEqual(
                self.command(server, 'release', 'TESTPARTNER', 'TESTUSER'),
                (0, 'TESTPARTNER/TESTUSER: ready\n'))
            # release of an unknown participant adds it as new (E12)
            self.assertEqual(self.api(server, 'status')['participants'], [
                    {'partner_id': 'P1', 'user_id': 'U1', 'state': 'new'},
                    {'partner_id': 'TESTPARTNER', 'user_id': 'TESTUSER',
                        'state': 'ready'}])
            code, output = self.command(
                server, 'make-camt053', '--iban', TEST_IBAN)
            self.assertEqual(code, 0)
            self.assertIn('Bereitgestellt: EOP_DE_camt.053_ZIP/', output)
            self.assertEqual(
                self.command(server, 'fault', 'BTD', '091008'),
                (0, 'Fehlerfälle: BTD=091008\n'))
            self.assertEqual(self.api(server, 'status')['faults'],
                {'BTD': '091008'})
            self.assertEqual(self.command(server, 'fault', 'BTD', 'x')[0], 1)
            self.assertEqual(self.command(server, 'fault', '--clear')[0], 0)
            self.assertEqual(store.bank().faults, {})

            # rejected
            code, output = self.command(server, 'serve')
            self.assertEqual(code, 2)
            self.assertIn('serve', output)
            code, output = self.command(server, 'reset')
            self.assertEqual(code, 1)
            self.assertIn('--yes', output)
            self.assertTrue(os.path.exists(store.path(
                        testserver.PARTICIPANTS)))
            other = tempfile.mkdtemp(prefix='ebics-ts-')
            self.addCleanup(shutil.rmtree, other)
            code, output = self.command(
                server, 'status', '--state-dir', other)
            self.assertEqual(code, 2)
            self.assertEqual(os.listdir(other), [])
            code, output = self.command(server, 'unknown')
            self.assertEqual(code, 2)
            self.assertIn('invalid choice', output)
            code, output = self.command(server, 'status', '--help')
            self.assertEqual(code, 0)
            self.assertIn('--state-dir', output)
            for body in [b'{"argv": "status"}', b'{"argv": []}',
                    b'{"argv": [1]}', b'[]']:
                with self.subTest(body=body):
                    response = self.request(
                        server, '/admin/api/command', method='POST',
                        body=body, content_type='application/json')
                    if body == b'[]':
                        self.assertEqual(response.status, 400)
                    else:
                        self.assertEqual(response.json()['exit'], 2)
            self.assertEqual(self.request(
                    server, '/admin/api/command', method='POST',
                    body=b'{"argv": ["status"]}',
                    content_type='text/plain').status, 415)
            self.assertEqual(self.request(
                    server, '/admin/api/command', method='POST',
                    body=b'{', content_type='application/json').status, 400)
            self.assertEqual(
                self.request(server, '/admin/api/command').status, 405)

            # demo calls the running server (no deadlock)
            code, output = self.command(server, 'demo', '--negative')
            self.assertEqual(code, 0, output)
            self.assertIn('Bankschlüssel bestätigt', output)
            self.assertIn('Quittung 011001', output)
            self.assertIn('Befehl über die Seite: demo (Exit 0)',
                out.getvalue())

            # reset with --yes (after the question in the page)
            self.assertEqual(self.command(server, 'reset', '--yes')[0], 0)
            self.assertFalse(os.path.exists(store.path(
                        testserver.PARTICIPANTS)))
            self.assertEqual(self.api(server, 'messages')['total'], 0)
            self.assertTrue(os.path.exists(store.certificate_path))

    # E07 T8
    def test_rotate_bank_keys_command(self):
        "rotate-bank-keys over the web page, with a question in the page"
        with open(ADMIN_PAGE, encoding='utf-8') as f:
            source = f.read()
        self.assertIn('data-cmd="rotate-bank-keys"', source)
        self.assertTrue(re.search(
                r'confirm\(.{0,300}?\)\)\s*\{\s*'
                r'run\(\["rotate-bank-keys"\]\)', source, re.DOTALL))
        with running_server(self.directory) as (server, store, out):
            before = store.bank().bank_hash('X002')
            code, output = self.command(server, 'rotate-bank-keys')
            self.assertEqual(code, 0, output)
            after = store.bank().bank_hash('X002')
            self.assertNotEqual(after, before)
            self.assertIn(after, output)
            self.assertIn('Befehl über die Seite: rotate-bank-keys (Exit 0)',
                out.getvalue())

    # T6
    def test_page_source(self):
        "Contents only via textContent/value; no external resources"
        with open(ADMIN_PAGE, encoding='utf-8') as f:
            source = f.read()
        for forbidden in ['innerHTML', 'outerHTML', 'insertAdjacentHTML',
                'document.write', 'eval(', 'new Function', 'srcdoc',
                'http://', 'https://', '@import', 'url(', '<link',
                '<iframe', 'localStorage', 'sessionStorage']:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIsNone(re.search(r'<script[^>]+src', source))
        self.assertIsNone(re.search(r'<img|<object|<embed', source))
        self.assertIn('textContent', source)
        self.assertIn('X-Testserver-Token', source)
        self.assertIn('location.hash', source)
        # reset only after a question in the page
        self.assertTrue(re.search(
                r'confirm\(.{0,300}?\)\)\s*\{\s*run\(\["reset", "--yes"\]\)',
                source, re.DOTALL))
        for command in ['status', 'release', 'suspend', 'make-camt053',
                'fault', 'demo', 'reset']:
            with self.subTest(command=command):
                self.assertIn('data-cmd="%s"' % command, source)
        self.assertIn('setInterval(poll, 2000)', source)


@unittest.skipUnless(testserver, SKIP_TOOL)
class PackagingTestCase(unittest.TestCase):
    "tools/ is not part of the installed package (decision F1)"

    def test_tools_excluded(self):
        root = os.path.dirname(HERE)
        self.assertFalse(os.path.exists(
                os.path.join(root, 'tools', '__init__.py')))
        with open(os.path.join(root, 'setup.py'), encoding='utf-8') as f:
            setup = f.read()
        self.assertIn("exclude=['tools', 'tools.*']", setup)
        with open(os.path.join(root, 'MANIFEST.in'), encoding='utf-8') as f:
            self.assertIn('prune tools', f.read().split('\n'))


if __name__ == '__main__':
    unittest.main()

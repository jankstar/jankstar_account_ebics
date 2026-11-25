# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Tests of the local EBICS test server (block E12, working paper ch. 7).

T1-T5 without network; T6-T8 start the server in the test process on a
random port at 127.0.0.1 with a temporary state directory (decision F11,
the only exception from "no network": local only). Test data only.
"""
import contextlib
import datetime
import importlib.util
import io
import json
import os
import re
import shutil
import socket
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
        self.assertEqual(len(messages), 2 * (4 + download.num_segments))
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

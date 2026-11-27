# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import contextlib
import datetime
import hashlib
import io
import json
import math
import threading
import unittest
import warnings
import zipfile
from decimal import Decimal
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from trytond import backend, config
from trytond.exceptions import UserError
from trytond.model.exceptions import AccessButtonError, AccessError
from trytond.modules.account.tests import create_chart
from trytond.modules.account_ebics.connection import \
    configuration as configuration_module
from trytond.modules.account_ebics.protocol import client, keys, returncodes
from trytond.modules.account_ebics.protocol.exceptions import (
    EbicsTransportError)
from trytond.modules.account_ebics.tests import camt_generator, fake_bank
from trytond.modules.account_ebics.tests.test_protocol import (
    cached_bank_keyring, cached_keyring)
from trytond.modules.company.tests import (
    CompanyTestMixin, create_company, set_company)
from trytond.modules.currency.tests import add_currency_rate, create_currency
from trytond.pool import Pool
from trytond.pyson import Eval, PYSONEncoder
from trytond.tests.test_tryton import DB_NAME, ModuleTestCase, with_transaction
from trytond.transaction import Transaction, without_check_access

# Test data only: invented bank, invented IBAN with valid check digits
# (bank code 12345678 does not exist), invented EBICS participant.
TEST_IBAN = 'DE14123456780000004711'
TEST_IBAN_2 = 'DE84123456780000004712'
TEST_HASH = '0123456789ABCDEF' * 4


def create_bank_account(company, iban=TEST_IBAN, owners=None):
    pool = Pool()
    Party = pool.get('party.party')
    Bank = pool.get('bank')
    BankAccount = pool.get('bank.account')
    bank_party, = Party.create([{'name': "Testbank"}])
    bank, = Bank.create([{'party': bank_party.id}])
    numbers = [('create', [{'type': 'iban', 'number': iban}])] if iban else []
    account, = BankAccount.create([{
                'bank': bank.id,
                'currency': company.currency.id,
                'owners': [('add', [
                            p.id for p in (owners or [company.party])])],
                'numbers': numbers,
                }])
    return account


def configuration_values(company, **values):
    result = {
        'name': "Test access",
        'company': company.id,
        'url': 'https://ebics.example.invalid/ebics',
        'host_id': 'TESTHOST',
        'partner_id': 'TESTPARTNER',
        'user_id': 'TESTUSER',
        }
    result.update(values)
    return result


def format_values(**values):
    result = {
        'name': "Test format",
        'direction': 'download',
        'service_name': 'STM',
        'scope': 'DE',
        'msg_name': 'camt.053',
        'container': 'XML',
        'processing': 'store',
        }
    result.update(values)
    return result


# Invented test files (no real statements)
TEST_FILES = [
    {'name': 'statement-1.xml', 'data': b'<Document>test 1</Document>',
        'message_type': 'camt.053.001.08', 'iban': TEST_IBAN},
    {'name': 'statement-2.xml', 'data': b'<Document>test 2</Document>',
        'message_type': 'camt.053.001.08', 'iban': TEST_IBAN_2},
    ]


def create_log(company, configuration=None, **values):
    "Create a log with the camt.053 format and the two test files"
    pool = Pool()
    Configuration = pool.get('account.ebics.configuration')
    Log = pool.get('account.ebics.log')
    ModelData = pool.get('ir.model.data')
    if configuration is None:
        configuration, = Configuration.create([configuration_values(
                    company)])
    log_values = {
        'format': ModelData.get_id('account_ebics', 'format_camt053_de'),
        'state': 'done',
        'transaction_id': 'TESTTRANSACTION',
        'technical_return_code': '000000',
        'business_return_code': '000000',
        'payload': b'PK test container',
        }
    log_values.update(values)
    return Log.record(configuration, 'BTD', log_values, files=TEST_FILES)


def create_user(login, company, groups):
    pool = Pool()
    User = pool.get('res.user')
    ModelData = pool.get('ir.model.data')
    user, = User.create([{
                'name': login,
                'login': login,
                'companies': [('add', [company.id])],
                'company': company.id,
                'groups': [('add', [
                            ModelData.get_id('account_ebics', g)
                            for g in groups])],
                }])
    return user


def as_user(user):
    "Context of a client call of the user"
    User = Pool().get('res.user')
    transaction = Transaction()
    with transaction.set_user(user.id):
        context = User.get_preferences(context_only=True)
    return transaction.set_user(user.id), transaction.set_context(
        context, _check_access=True)


def backdate(Model, records,
        timestamp=datetime.datetime(2000, 1, 1, 0, 0, 0, 1)):
    """Move the creation of the records to an earlier transaction: within one
    test transaction creation and change have the same timestamp and form
    only one revision"""
    cursor = Transaction().connection.cursor()
    ids = [r.id for r in records]
    for table in [Model.__table__(), Model.__table_history__()]:
        cursor.execute(*table.update(
                [table.create_date], [timestamp],
                where=table.id.in_(ids)))


# E08: BTF of the standard formats (specification ch. 5.5)
CAMT053_BTF = client.Btf('EOP', 'camt.053', scope='DE', container='ZIP')
CAMT052_BTF = client.Btf('STM', 'camt.052', scope='DE', container='ZIP')

# E06: passphrase of the tests only (test data)
TEST_PASSPHRASE = 'Testpassphrase E06 (Testdaten)'


@contextlib.contextmanager
def ebics_settings(**values):
    """Set values of [account_ebics] in the configuration for the block;
    None clears a value (an empty value counts as missing)"""
    section = 'account_ebics'
    if not config.has_section(section):
        config.add_section(section)
    old = {n: config.get(section, n) for n in values}
    for name, value in values.items():
        config.set(section, name, '' if value is None else str(value))
    try:
        yield
    finally:
        for name, value in old.items():
            config.set(section, name, '' if value is None else value)


class OrderTransport:
    """Transport to the simulated bank; errors: list of exceptions raised
    instead of the next requests (None: deliver)"""

    def __init__(self, bank, errors=None, before=None):
        self.bank = bank
        self.errors = list(errors or [])
        self.before = before
        self.requests = []

    def post(self, data):
        self.requests.append(bytes(data))
        if self.before:
            self.before()
        if self.errors:
            error = self.errors.pop(0)
            if error is not None:
                raise error
        return self.bank.handle(bytes(data))


def commit():
    """Commit the test transaction: the orders run in a transaction of
    their own and see only committed data (PostgreSQL); a new snapshot
    shows their changes afterwards"""
    transaction = Transaction()
    transaction.commit()
    transaction.cache.clear()


def payload_members(data):
    with zipfile.ZipFile(io.BytesIO(data)) as container:
        return {n: container.read(n) for n in container.namelist()}


class AccountEbicsTestCase(CompanyTestMixin, ModuleTestCase):
    "Test Account EBICS module"
    module = 'account_ebics'

    def assertRejected(self, check, action, expected, exception=UserError):
        """Run setup and action in a transaction of their own and expect the
        exception; a rejected record would otherwise stay in the test
        transaction (SQL constraints even roll the transaction back)"""
        @with_transaction()
        def run():
            with self.subTest(check=check):
                with self.assertRaises(exception) as cm:
                    action()
                if expected is not None:
                    self.assertIn(expected, str(cm.exception))
        run()

    # T2
    @with_transaction()
    def test_format_standard_data(self):
        "Standard formats with the BTF parameters of the DK mapping table"
        pool = Pool()
        Format = pool.get('account.ebics.format')
        ModelData = pool.get('ir.model.data')

        expected = {
            'format_camt053_de': ('EOP/DE/camt.053/ZIP', 'import_statement'),
            'format_camt052_de': ('STM/DE/camt.052/ZIP', 'store'),
            'format_camt054_de': ('STM/DE/camt.054/ZIP', 'store'),
            }
        for xml_id, (btf, processing) in expected.items():
            with self.subTest(xml_id=xml_id):
                format_ = Format(ModelData.get_id('account_ebics', xml_id))
                self.assertEqual(format_.btf_params, btf)
                self.assertEqual(format_.direction, 'download')
                self.assertEqual(format_.processing, processing)
                self.assertTrue(format_.active)
        records = ModelData.search([
                ('module', '=', 'account_ebics'),
                ('model', '=', 'account.ebics.format'),
                ])
        self.assertEqual(len(records), 3)
        self.assertTrue(all(r.noupdate for r in records))

    @with_transaction()
    def test_format_build_btf_params(self):
        "BTF parameters skip empty parts"
        pool = Pool()
        Format = pool.get('account.ebics.format')
        self.assertEqual(
            Format.build_btf_params('SDD', 'DE', 'COR', 'pain.008', '08',
                'XML'),
            'SDD/DE/COR/pain.008/08/XML')
        self.assertEqual(
            Format.build_btf_params('EOP', ' DE ', '', 'camt.053', None,
                'ZIP'),
            'EOP/DE/camt.053/ZIP')

    # T3
    def test_format_checks(self):
        "FO01-FO03 reject invalid formats"
        def create(**values):
            def action():
                Format = Pool().get('account.ebics.format')
                Format.create([format_values(**values)])
            return action

        def create_twice(first, second):
            def action():
                Format = Pool().get('account.ebics.format')
                Format.create([format_values(**first)])
                Format.create([format_values(**second)])
            return action

        self.assertRejected(
            'FO01 download without processing', create(processing=None),
            # rejected by the required state before check_processing
            'A value is required for field "Processing"')
        self.assertRejected(
            'FO01 upload with processing', create(
                direction='upload', service_name='SCT', msg_name='pain.001',
                processing='store'),
            'only allowed for downloads')
        self.assertRejected(
            'FO03 import only camt.053', create(
                msg_name='camt.052', processing='import_statement'),
            'only be imported as statement')
        self.assertRejected(
            'FO02 duplicate of standard data', create(
                service_name='EOP', container='ZIP',
                processing='import_statement'),
            'already exists')
        self.assertRejected(
            'FO02 empty values count as equal',
            create_twice({'scope': None}, {'scope': ''}), 'already exists')
        self.assertRejected(
            'FO02 inactive format counts',
            create_twice({'active': False}, {}), 'already exists')

    @with_transaction()
    def test_format_valid(self):
        "Valid download and upload formats"
        pool = Pool()
        Format = pool.get('account.ebics.format')
        download, = Format.create([format_values()])
        self.assertEqual(download.btf_params, 'STM/DE/camt.053/XML')
        upload, = Format.create([format_values(
                    direction='upload', service_name='SCT',
                    msg_name='pain.001', processing=None)])
        self.assertEqual(upload.btf_params, 'SCT/DE/pain.001/XML')

    @with_transaction()
    def test_format_delete_used_restricted(self):
        "A format used by a configuration cannot be deleted"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Format = pool.get('account.ebics.format')
        company = create_company()
        with set_company(company):
            format_, = Format.create([format_values()])
            Configuration.create([configuration_values(
                        company, formats=[('add', [format_.id])])])
            with self.assertRaises(Exception):
                Format.delete([format_])

    # T4
    def test_configuration_checks(self):
        "KF01-KF03 reject invalid configurations"
        def create(*vlist):
            def action():
                Configuration = Pool().get('account.ebics.configuration')
                company = create_company()
                with set_company(company):
                    for values in vlist:
                        Configuration.create([configuration_values(
                                    company, **values)])
            return action

        self.assertRejected(
            'KF01 http', create({'url': 'http://ebics.example.invalid'}),
            'must start with')
        self.assertRejected(
            'KF01 no scheme', create({'url': 'ebics.example.invalid'}),
            'must start with')
        self.assertRejected(
            'KF02 same participant', create({}, {'name': "Second"}),
            'must be unique per company')
        self.assertRejected(
            'KF03 hash too short',
            create({'bank_x002_hash_expected': 'ABCDEF'}),
            '64 hexadecimal characters')
        self.assertRejected(
            'KF03 hash not hexadecimal',
            create({'bank_e002_hash_expected': 'G' * 64}),
            '64 hexadecimal characters')

    @with_transaction()
    def test_configuration_participant(self):
        "KF02: another user ID is another participant"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company = create_company()
        with set_company(company):
            Configuration.create([
                    configuration_values(company),
                    configuration_values(
                        company, name="Second", user_id='TESTUSER2'),
                    ])

    @with_transaction()
    def test_configuration_participant_other_company(self):
        "KF02 is per company"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company_a = create_company("Company A")
        company_b = create_company("Company B")
        Configuration.create([
                configuration_values(company_a),
                configuration_values(company_b),
                ])

    @with_transaction()
    def test_configuration_hash_normalized(self):
        "Expected hash values are stored without spaces in upper case"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company = create_company()
        spaced = ' '.join(
            TEST_HASH.lower()[i:i + 2] for i in range(0, 64, 2))
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company, bank_x002_hash_expected=spaced)])
            self.assertEqual(configuration.bank_x002_hash_expected, TEST_HASH)
            Configuration.write([configuration], {
                    'bank_e002_hash_expected': '  ' + spaced + '\n',
                    })
            self.assertEqual(configuration.bank_e002_hash_expected, TEST_HASH)
            Configuration.write([configuration], {
                    'bank_e002_hash_expected': '   ',
                    })
            self.assertIsNone(configuration.bank_e002_hash_expected)

            configuration.bank_x002_hash_expected = spaced
            configuration.on_change_bank_x002_hash_expected()
            self.assertEqual(configuration.bank_x002_hash_expected, TEST_HASH)

    # T6
    @with_transaction()
    def test_configuration_defaults(self):
        "New configuration is draft with format camt.053"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        ModelData = pool.get('ir.model.data')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company)])
            self.assertEqual(configuration.state, 'draft')
            self.assertEqual(configuration.ebics_version, 'H005')
            self.assertEqual(configuration.key_bitlength, '2048')
            self.assertEqual(configuration.signature_class, 'T')
            self.assertFalse(configuration.ini_sent)
            self.assertFalse(configuration.hia_sent)
            self.assertEqual(
                [f.id for f in configuration.formats],
                [ModelData.get_id('account_ebics', 'format_camt053_de')])

    @with_transaction()
    def test_configuration_default_format_inactive(self):
        "No default format if camt.053 is deactivated"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Format = pool.get('account.ebics.format')
        ModelData = pool.get('ir.model.data')
        Format.write(
            [Format(ModelData.get_id('account_ebics', 'format_camt053_de'))],
            {'active': False})
        self.assertEqual(Configuration.default_formats(), [])

    @with_transaction()
    def test_configuration_copy_without_keys(self):
        "A copy has no keys and starts in draft"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company, user_a006_hash=TEST_HASH, state='ini_sent',
                        ini_sent=True)])
            copy, = Configuration.copy(
                [configuration], default={'user_id': 'TESTUSER2'})
            self.assertEqual(copy.state, 'draft')
            self.assertIsNone(copy.user_a006_hash)
            self.assertFalse(copy.ini_sent)

    # T5
    def test_account_checks(self):
        "KT01-KT03 and F4 reject invalid accounts"
        def create(bank_account_values, account_values=None,
                other_company=False, twice=False):
            def action():
                pool = Pool()
                Configuration = pool.get('account.ebics.configuration')
                Account = pool.get('account.ebics.account')
                company = create_company()
                other = create_company("Other Company")
                with set_company(company):
                    configuration, = Configuration.create([
                            configuration_values(company)])
                    owners = {
                        'company': [company.party],
                        'other': [other.party],
                        'both': [company.party, other.party],
                        }[bank_account_values.pop('owners', 'company')]
                    bank_account_values['owners'] = owners
                    bank_account = create_bank_account(
                        company, **bank_account_values)
                    values = {
                        'configuration': configuration.id,
                        'bank_account': bank_account.id,
                        }
                    if other_company:
                        values['company'] = other.id
                    values.update(account_values or {})
                    Account.create([values])
                    if twice:
                        Account.create([values])
            return action

        self.assertRejected(
            'KT01 duplicate', create({}, twice=True), 'only once')
        self.assertRejected(
            'KT02 without IBAN', create({'iban': None}),
            # rejected by the domain (F4) before check_iban
            'is not valid according to its domain')
        # owned by both companies, so that the domain F4 is fulfilled
        self.assertRejected(
            'KT03 other company',
            create({'owners': 'both'}, other_company=True),
            'must be the company of')
        self.assertRejected(
            'F4 bank account of another owner', create({'owners': 'other'}),
            'is not valid according to its domain')

    @with_transaction()
    def test_account(self):
        "KT01-KT03, IBAN and statement journal"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Account = pool.get('account.ebics.account')
        StatementJournal = pool.get('account.statement.journal')
        AccountJournal = pool.get('account.journal')
        AccountAccount = pool.get('account.account')
        company = create_company()
        with set_company(company):
            create_chart(company)
            configuration, = Configuration.create([configuration_values(
                        company)])
            bank_account = create_bank_account(company)

            account, = Account.create([{
                        'configuration': configuration.id,
                        'bank_account': bank_account.id,
                        }])
            # F6: company from the configuration
            self.assertEqual(account.company, company)
            self.assertTrue(account.import_statements)
            self.assertEqual(account.iban, 'DE14 1234 5678 0000 0047 11')
            self.assertEqual(
                Account.search([('iban', '=', TEST_IBAN)]), [account])
            # no statement journal yet: empty, no error
            self.assertIsNone(account.statement_journal)

            cash, = AccountAccount.search([
                    ('type', '!=', None),
                    ('closed', '!=', True),
                    ('company', '=', company.id),
                    ('party_required', '=', False),
                    ], limit=1)
            account_journal, = AccountJournal.search(
                [('code', '=', 'STA')], limit=1)
            journal, = StatementJournal.create([{
                        'name': "Test statement journal",
                        'journal': account_journal.id,
                        'account': cash.id,
                        'currency': company.currency.id,
                        'company': company.id,
                        'bank_account': bank_account.id,
                        }])
            account = Account(account.id)
            self.assertEqual(account.statement_journal, journal)

    @with_transaction()
    def test_account_on_change_company_party(self):
        "A new account offers the bank accounts of the connection's company"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Account = pool.get('account.ebics.account')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company)])
            # as the client: new line, company not yet set
            account = Account(configuration=configuration)
            self.assertEqual(account.on_change_with_company(), company)
            self.assertEqual(
                account.on_change_with_company_party(), company.party)

    @with_transaction()
    def test_account_on_change_iban_journal(self):
        "IBAN and statement journal are shown before the account is saved"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Account = pool.get('account.ebics.account')
        StatementJournal = pool.get('account.statement.journal')
        AccountJournal = pool.get('account.journal')
        AccountAccount = pool.get('account.account')
        company = create_company()
        with set_company(company):
            create_chart(company)
            configuration, = Configuration.create([configuration_values(
                        company)])
            bank_account = create_bank_account(company)
            cash, = AccountAccount.search([
                    ('type', '!=', None),
                    ('closed', '!=', True),
                    ('company', '=', company.id),
                    ('party_required', '=', False),
                    ], limit=1)
            account_journal, = AccountJournal.search(
                [('code', '=', 'STA')], limit=1)
            journal, = StatementJournal.create([{
                        'name': "Test statement journal",
                        'journal': account_journal.id,
                        'account': cash.id,
                        'currency': company.currency.id,
                        'company': company.id,
                        'bank_account': bank_account.id,
                        }])

            # as the client: new line, company not yet set
            account = Account(
                configuration=configuration, bank_account=bank_account)
            self.assertEqual(
                account.on_change_with_iban(), 'DE14 1234 5678 0000 0047 11')
            self.assertEqual(account.on_change_with_statement_journal(),
                journal)

            account = Account(configuration=configuration)
            self.assertIsNone(account.on_change_with_iban())
            self.assertIsNone(account.on_change_with_statement_journal())

    # T7
    @with_transaction()
    def test_key_fields_no_access(self):
        "Key fields are not readable or writable for the EBICS admin"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        User = pool.get('res.user')
        ModelData = pool.get('ir.model.data')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company)])
        admin_group = ModelData.get_id('account_ebics', 'group_ebics_admin')
        user, = User.create([{
                    'name': "EBICS admin",
                    'login': 'ebics_admin',
                    'companies': [('add', [company.id])],
                    'company': company.id,
                    'groups': [('add', [admin_group])],
                    }])
        with Transaction().set_user(user.id), \
                Transaction().set_context(
                    User.get_preferences(context_only=True),
                    _check_access=True):
            # other fields remain readable and writable
            Configuration.read([configuration.id], ['name', 'state'])
            Configuration.write([configuration], {'name': "Renamed"})
            for name in ['keyring_data', 'keyring_data_id', 'bank_keys_data',
                    'bank_keys_data_id']:
                with self.subTest(field=name, mode='read'):
                    with self.assertRaises(AccessError):
                        Configuration.read([configuration.id], [name])
                with self.subTest(field=name, mode='write'):
                    with self.assertRaises(AccessError):
                        Configuration.write(
                            [configuration], {name: b'x' if 'id' not in name
                                else 'x'})

    # T8
    @with_transaction()
    def test_company_rule(self):
        "Configurations and accounts of another company are not visible"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Account = pool.get('account.ebics.account')
        User = pool.get('res.user')
        ModelData = pool.get('ir.model.data')
        company_a = create_company("Company A")
        company_b = create_company("Company B")
        config_a, config_b = Configuration.create([
                configuration_values(company_a, name="A"),
                configuration_values(company_b, name="B"),
                ])
        account_a, = Account.create([{
                    'configuration': config_a.id,
                    'bank_account': create_bank_account(company_a).id,
                    }])
        account_b, = Account.create([{
                    'configuration': config_b.id,
                    'bank_account': create_bank_account(
                        company_b, iban=TEST_IBAN_2).id,
                    }])
        group = ModelData.get_id('account_ebics', 'group_ebics')
        user, = User.create([{
                    'name': "EBICS user",
                    'login': 'ebics_user',
                    'companies': [('add', [company_a.id])],
                    'company': company_a.id,
                    'groups': [('add', [group])],
                    }])
        with Transaction().set_user(user.id), \
                Transaction().set_context(
                    User.get_preferences(context_only=True),
                    _check_access=True):
            self.assertEqual(Configuration.search([]), [config_a])
            self.assertEqual(Account.search([]), [account_a])
            # group_ebics may read but not change
            with self.assertRaises(AccessError):
                Configuration.write([config_a], {'name': "Changed"})

    # E05 T2
    @with_transaction()
    def test_log_record(self):
        "Log.record creates the log with its files"
        company = create_company()
        with set_company(company):
            log = create_log(company)
        self.assertEqual(log.company, company)
        self.assertEqual(log.order_type, 'BTD')
        self.assertEqual(log.btf_params, 'EOP/DE/camt.053/ZIP')
        self.assertEqual(log.receipt, 'none')
        self.assertEqual(log.state, 'done')
        self.assertEqual(log.payload_filename, 'BTD-%s.zip' % log.id)
        self.assertEqual(bytes(log.payload), b'PK test container')
        self.assertEqual(len(log.files), 2)
        files = sorted(log.files, key=lambda f: f.name)
        for file_, values in zip(files, TEST_FILES):
            with self.subTest(file=values['name']):
                self.assertEqual(file_.company, company)
                self.assertEqual(file_.timestamp, log.timestamp)
                self.assertEqual(
                    file_.sha256,
                    hashlib.sha256(values['data']).hexdigest())
                self.assertEqual(file_.message_type, 'camt.053.001.08')
                self.assertEqual(file_.iban, values['iban'])
                self.assertEqual(file_.state, 'pending')
                self.assertIsNone(file_.account)

    @with_transaction()
    def test_log_record_btf_params_given(self):
        "Log.record keeps the BTF parameters actually sent"
        company = create_company()
        with set_company(company):
            log = create_log(company, btf_params='EOP/DE/camt.053/ZIP/X')
            self.assertEqual(log.btf_params, 'EOP/DE/camt.053/ZIP/X')

    # E05 T3
    def test_log_delete(self):
        "PR01: logs and files cannot be deleted, not even by server code"
        def delete(model, client=False):
            def action():
                pool = Pool()
                Model = pool.get(model)
                company = create_company()
                with set_company(company):
                    log = create_log(company)
                records = [log] if model == 'account.ebics.log' else log.files
                if client:
                    user = create_user(
                        'ebics_admin', company, ['group_ebics_admin'])
                    set_user, set_context = as_user(user)
                    with set_user, set_context:
                        Model.delete(Model.browse(records))
                else:
                    Model.delete(records)
            return action

        for model in ['account.ebics.log', 'account.ebics.log.file']:
            self.assertRejected(
                'PR01 server %s' % model, delete(model), 'cannot be deleted',
                AccessError)
            self.assertRejected(
                'PR01 client %s' % model, delete(model, client=True), None,
                AccessError)

    # E05 T4
    def test_log_client(self):
        "PR02, PR04: no change or creation from the client"
        def client(model, operation):
            def action():
                pool = Pool()
                Model = pool.get(model)
                Configuration = pool.get('account.ebics.configuration')
                company = create_company()
                with set_company(company):
                    log = create_log(company)
                user = create_user(
                    'ebics_admin', company, ['group_ebics_admin'])
                set_user, set_context = as_user(user)
                with set_user, set_context:
                    if operation == 'write':
                        records = (
                            [log] if model == 'account.ebics.log'
                            else list(log.files))
                        Model.write(Model.browse(records), {'state': 'error'})
                    elif model == 'account.ebics.log':
                        configuration = Configuration(log.configuration.id)
                        Model.create([{
                                    'configuration': configuration.id,
                                    'company': company.id,
                                    'order_type': 'BTD',
                                    'state': 'done',
                                    }])
                    else:
                        Model.create([{
                                    'ebics_log': log.id, 'name': 'x.xml'}])
            return action

        for model in ['account.ebics.log', 'account.ebics.log.file']:
            for operation in ['write', 'create']:
                self.assertRejected(
                    'PR02/PR04 %s %s' % (operation, model),
                    client(model, operation), None, AccessError)

    @with_transaction()
    def test_log_check_modification_external(self):
        "PR02, PR04: own check also without access rights check"
        pool = Pool()
        Log = pool.get('account.ebics.log')
        LogFile = pool.get('account.ebics.log.file')
        company = create_company()
        with set_company(company):
            log = create_log(company)
        for Model, records in [(Log, [log]), (LogFile, list(log.files))]:
            with self.subTest(model=Model.__name__):
                with self.assertRaises(AccessError) as cm:
                    Model.check_modification(
                        'write', records, {'state': 'error'}, external=True)
                self.assertIn('cannot be changed', str(cm.exception))
                with self.assertRaises(AccessError) as cm:
                    Model.check_modification(
                        'create', records, external=True)
                self.assertIn('created only by', str(cm.exception))

    # E05 T5
    @with_transaction()
    def test_log_write_internal_allowed(self):
        "PR03: the server code may change the status fields"
        pool = Pool()
        Log = pool.get('account.ebics.log')
        LogFile = pool.get('account.ebics.log.file')
        Account = pool.get('account.ebics.account')
        company = create_company()
        with set_company(company):
            log = create_log(company)
            account, = Account.create([{
                        'configuration': log.configuration.id,
                        'bank_account': create_bank_account(company).id,
                        }])
        Log.write_internal([log], {'state': 'error', 'receipt': 'positive'})
        self.assertEqual((log.state, log.receipt), ('error', 'positive'))
        file_ = log.files[0]
        LogFile.write_internal([file_], {
                'state': 'error',
                'account': account.id,
                'error_message': "Test error",
                })
        self.assertEqual(file_.state, 'error')
        self.assertEqual(file_.account, account)
        self.assertEqual(file_.error_message, "Test error")

    def test_log_write_internal_forbidden(self):
        "PR03: other fields are rejected also in server code"
        def write(model, values):
            def action():
                Model = Pool().get(model)
                company = create_company()
                with set_company(company):
                    log = create_log(company)
                records = (
                    [log] if model == 'account.ebics.log'
                    else list(log.files))
                Model.write_internal(records, values)
            return action

        for model, values in [
                ('account.ebics.log', {'technical_return_code': '091002'}),
                ('account.ebics.log', {'business_return_code': '090005'}),
                ('account.ebics.log', {'btf_params': 'X'}),
                ('account.ebics.log', {'payload': b'x'}),
                ('account.ebics.log',
                    {'state': 'error', 'return_message': 'x'}),
                ('account.ebics.log.file', {'message_type': 'camt.052'}),
                ('account.ebics.log.file', {'iban': TEST_IBAN_2}),
                ('account.ebics.log.file', {'data': b'x'}),
                ('account.ebics.log.file', {'sha256': '0' * 64}),
                ]:
            self.assertRejected(
                'PR03 %s %s' % (model, sorted(values)), write(model, values),
                'cannot be changed', AccessError)

    # E05 T6
    @with_transaction()
    def test_log_copy(self):
        "PR05: logs and files cannot be copied"
        pool = Pool()
        Log = pool.get('account.ebics.log')
        LogFile = pool.get('account.ebics.log.file')
        company = create_company()
        with set_company(company):
            log = create_log(company)
        for Model, records in [(Log, [log]), (LogFile, list(log.files))]:
            with self.subTest(model=Model.__name__):
                with self.assertRaises(AccessError) as cm:
                    Model.copy(records)
                self.assertIn('cannot be copied', str(cm.exception))

    # E05 T7
    def test_log_configuration_delete(self):
        "F1: a configuration with logs cannot be deleted"
        def delete():
            Configuration = Pool().get('account.ebics.configuration')
            company = create_company()
            with set_company(company):
                log = create_log(company)
            Configuration.delete([log.configuration])
        self.assertRejected(
            'F1 delete configuration with log', delete,
            'used by field "Connection" of "EBICS Log"')

    @with_transaction()
    def test_configuration_delete_without_log(self):
        "A configuration without logs can still be deleted"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company)])
            Configuration.delete([configuration])

    # E05 T8
    @with_transaction()
    def test_log_file_statement_delete(self):
        "Deleting a draft statement removes only the link"
        pool = Pool()
        LogFile = pool.get('account.ebics.log.file')
        Statement = pool.get('account.statement')
        StatementJournal = pool.get('account.statement.journal')
        AccountJournal = pool.get('account.journal')
        AccountAccount = pool.get('account.account')
        company = create_company()
        with set_company(company):
            create_chart(company)
            log = create_log(company)
            cash, = AccountAccount.search([
                    ('type', '!=', None),
                    ('closed', '!=', True),
                    ('company', '=', company.id),
                    ('party_required', '=', False),
                    ], limit=1)
            account_journal, = AccountJournal.search(
                [('code', '=', 'STA')], limit=1)
            journal, = StatementJournal.create([{
                        'name': "Test statement journal",
                        'journal': account_journal.id,
                        'account': cash.id,
                        'currency': company.currency.id,
                        'company': company.id,
                        'validation': 'number_of_lines',
                        }])
            statement, = Statement.create([{
                        'name': "Test statement",
                        'company': company.id,
                        'journal': journal.id,
                        'date': datetime.date.today(),
                        'number_of_lines': 0,
                        }])
            file_ = log.files[0]
            LogFile.write_internal([file_], {
                    'state': 'imported',
                    'statements': [('add', [statement.id])],
                    })
            self.assertEqual(list(file_.statements), [statement])

            Statement.delete([statement])
            file_ = LogFile(file_.id)
            self.assertEqual(list(file_.statements), [])
            self.assertEqual(file_.state, 'imported')

    # E05 T9
    @with_transaction()
    def test_log_company_rule(self):
        "Logs and files of another company are not visible"
        pool = Pool()
        Log = pool.get('account.ebics.log')
        LogFile = pool.get('account.ebics.log.file')
        company_a = create_company("Company A")
        company_b = create_company("Company B")
        log_a = create_log(company_a)
        create_log(company_b)
        user = create_user('ebics_user', company_a, ['group_ebics'])
        set_user, set_context = as_user(user)
        with set_user, set_context:
            self.assertEqual(Log.search([]), [log_a])
            self.assertEqual(
                sorted(LogFile.search([])), sorted(log_a.files))
            Log.read([log_a.id], ['state', 'payload'])

    # E05 T10
    @with_transaction()
    def test_history(self):
        "Changes create revisions; earlier versions remain readable"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Account = pool.get('account.ebics.account')
        Format = pool.get('account.ebics.format')
        LogFile = pool.get('account.ebics.log.file')
        Relation = pool.get(
            'account.ebics.configuration-account.ebics.format')
        company = create_company()
        with set_company(company):
            log = create_log(company)
            configuration = log.configuration
            account, = Account.create([{
                        'configuration': configuration.id,
                        'bank_account': create_bank_account(company).id,
                        }])
            format_, = Format.create([format_values()])
            file_ = log.files[0]

            for Model, record, field, old, new, write in [
                    (Configuration, configuration, 'name', "Test access",
                        "Renamed", Configuration.write),
                    (Account, account, 'import_statements', True, False,
                        Account.write),
                    # not 'name': translated fields are not in the history
                    (Format, format_, 'scope', 'DE', 'AT', Format.write),
                    (LogFile, file_, 'state', 'pending', 'error',
                        LogFile.write_internal),
                    ]:
                with self.subTest(model=Model.__name__):
                    created = Model.history_revisions([record.id])
                    self.assertEqual(len(created), 1)
                    backdate(Model, [record])
                    write([record], {field: new})
                    revisions = Model.history_revisions([record.id])
                    self.assertEqual(len(revisions), 2)
                    first = revisions[-1][0]
                    with Transaction().set_context(_datetime=first):
                        self.assertEqual(
                            getattr(Model(record.id), field), old)
                    self.assertEqual(getattr(Model(record.id), field), new)

            relations = Relation.search(
                [('configuration', '=', configuration.id)])
            self.assertTrue(
                Relation.history_revisions([r.id for r in relations]))

    # E14 T1
    @with_transaction()
    def test_history_fill_missing(self):
        "Records without history get exactly one first revision, sliced"
        pool = Pool()
        Format = pool.get('account.ebics.format')
        cursor = Transaction().connection.cursor()
        history = Format.__table_history__()
        count = 250
        formats = Format.create([
                format_values(name="Format %s" % i, msg_version='%03d' % i)
                for i in range(count)])
        ids = [f.id for f in formats]
        self.assertGreater(count, min(backend.MAX_QUERY_PARAMS, 200))
        # records without history as before E05
        cursor.execute(*history.delete(where=history.id.in_(ids)))

        def revisions():
            cursor.execute(*history.select(
                    history.id, history.msg_version,
                    where=history.id.in_(ids)))
            return sorted(cursor)
        self.assertEqual(revisions(), [])

        insert = Format._insert_history
        with patch.object(Format, '_insert_history',
                side_effect=insert) as mock:
            Format._fill_missing_history()
        self.assertEqual(revisions(), sorted(
                (f.id, f.msg_version) for f in formats))
        # slices of MAX_QUERY_PARAMS as in the Tryton standard
        sizes = [len(c.args[0]) for c in mock.call_args_list]
        self.assertEqual(sum(sizes), count)
        self.assertEqual(
            len(sizes), math.ceil(count / backend.MAX_QUERY_PARAMS))
        self.assertLessEqual(max(sizes), backend.MAX_QUERY_PARAMS)
        self.assertEqual(
            [len(Format.history_revisions([i])) for i in ids], [1] * count)

        # a second run changes nothing
        with patch.object(Format, '_insert_history',
                side_effect=insert) as mock:
            Format._fill_missing_history()
        self.assertEqual(mock.call_args_list, [])
        self.assertEqual(len(revisions()), count)

    # E14 T2
    def test_upgrade_no_grouped_slice_warning(self):
        "Upgrading the module raises no warning grouped_slice without size"
        with Transaction().start(DB_NAME, 1, close=True) as transaction:
            pool = Pool()
            Module = pool.get('ir.module')
            Format = pool.get('account.ebics.format')
            ActivateUpgrade = pool.get(
                'ir.module.activate_upgrade', type='wizard')
            # some records without history, so that the migration works
            with transaction.set_context(active_test=False):
                ids = [f.id for f in Format.search([])]
            self.assertTrue(ids)
            history = Format.__table_history__()
            transaction.connection.cursor().execute(
                *history.delete(where=history.id.in_(ids)))
            module, = Module.search([('name', '=', 'account_ebics')])
            Module.upgrade([module])
            transaction.commit()

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                instance_id, _, _ = ActivateUpgrade.create()
                transaction.commit()
                ActivateUpgrade(instance_id).transition_upgrade()
                ActivateUpgrade.delete(instance_id)
                transaction.commit()
        messages = [str(w.message) for w in caught]
        self.assertNotIn("grouped_slice without size is deprecated", messages)

        with Transaction().start(DB_NAME, 1, close=True):
            pool = Pool()
            Module = pool.get('ir.module')
            Format = pool.get('account.ebics.format')
            module, = Module.search([('name', '=', 'account_ebics')])
            self.assertEqual(module.state, 'activated')
            # the upgrade filled the history again
            self.assertTrue(all(
                    len(Format.history_revisions([i])) == 1 for i in ids))

    @with_transaction()
    def test_history_key_fields_no_access(self):
        "The key fields stay inaccessible in earlier versions"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company)])
            backdate(Configuration, [configuration])
            Configuration.write([configuration], {'name': "Renamed"})
        revisions = Configuration.history_revisions([configuration.id])
        user = create_user('ebics_admin', company, ['group_ebics_admin'])
        set_user, set_context = as_user(user)
        with set_user, set_context, \
                Transaction().set_context(_datetime=revisions[-1][0]):
            self.assertEqual(
                Configuration.read([configuration.id], ['name'])[0]['name'],
                "Test access")
            with self.assertRaises(AccessError):
                Configuration.read([configuration.id], ['keyring_data'])

    # E05 T11
    @with_transaction()
    def test_log_write_internal_logged(self):
        "Internal changes are recorded in ir.model.log"
        pool = Pool()
        LogFile = pool.get('account.ebics.log.file')
        ModelLog = pool.get('ir.model.log')
        company = create_company()
        with set_company(company):
            log = create_log(company)
        file_ = log.files[0]
        LogFile.write_internal([file_], {'state': 'duplicate'})
        Transaction()._store_log_records()
        entries = ModelLog.search([
                ('resource', '=', str(file_)),
                ('event', '=', 'write'),
                ])
        self.assertEqual(len(entries), 1)
        entry, = entries
        self.assertEqual(entry.target, 'state')
        self.assertEqual(entry.user.id, Transaction().user)

    # E05 T12
    @with_transaction()
    def test_account_archive(self):
        "An archived account is no longer selectable"
        pool = Pool()
        Account = pool.get('account.ebics.account')
        Configuration = pool.get('account.ebics.configuration')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company)])
            account, = Account.create([{
                        'configuration': configuration.id,
                        'bank_account': create_bank_account(company).id,
                        }])
            self.assertTrue(account.active)
            self.assertIsNone(account.valid_from)
            self.assertIsNone(account.valid_to)
            Account.write([account], {'active': False})
            self.assertEqual(Account.search([]), [])
            self.assertEqual(
                Account.search([('active', '=', False)]), [account])
            Account.write([account], {
                    'valid_from': datetime.date(2026, 1, 1),
                    'valid_to': datetime.date(2026, 1, 1),
                    })

    def test_account_validity_and_delete(self):
        "KT04, KT01 for archived accounts and deletion of used accounts"
        def create(valid_from=None, valid_to=None, archived_twice=False,
                use=False, delete=False):
            def action():
                pool = Pool()
                Account = pool.get('account.ebics.account')
                LogFile = pool.get('account.ebics.log.file')
                company = create_company()
                with set_company(company):
                    log = create_log(company)
                    values = {
                        'configuration': log.configuration.id,
                        'bank_account': create_bank_account(company).id,
                        'valid_from': valid_from,
                        'valid_to': valid_to,
                        }
                    account, = Account.create([values])
                    if archived_twice:
                        Account.write([account], {'active': False})
                        Account.create([values])
                    if use:
                        LogFile.write_internal(
                            [log.files[0]], {'account': account.id})
                    if delete:
                        Account.delete([account])
            return action

        self.assertRejected(
            'KT04 from after to',
            create(datetime.date(2026, 2, 1), datetime.date(2026, 1, 31)),
            'must not be after its end')
        self.assertRejected(
            'KT01 archived account', create(archived_twice=True), 'only once')
        self.assertRejected(
            'delete used account', create(use=True, delete=True),
            'used by field "Account" of "EBICS Received File"')

    # E12 T5
    @with_transaction()
    def test_camt_generator_import(self):
        "A generated camt.053 is imported by account_statement_sepa"
        pool = Pool()
        StatementJournal = pool.get('account.statement.journal')
        AccountJournal = pool.get('account.journal')
        AccountAccount = pool.get('account.account')
        Statement = pool.get('account.statement')
        ImportStatement = pool.get('account.statement.import', type='wizard')
        # ISO code: the camt account currency selects the journal
        currency = create_currency('EUR')
        add_currency_rate(currency, 1)
        company = create_company(currency=currency)
        with set_company(company):
            create_chart(company)
            bank_account = create_bank_account(company)
            cash, = AccountAccount.search([
                    ('type', '!=', None),
                    ('closed', '!=', True),
                    ('company', '=', company.id),
                    ('party_required', '=', False),
                    ], limit=1)
            account_journal, = AccountJournal.search(
                [('code', '=', 'STA')], limit=1)
            journal, = StatementJournal.create([{
                        'name': "Test statement journal",
                        'journal': account_journal.id,
                        'account': cash.id,
                        'currency': company.currency.id,
                        'company': company.id,
                        'bank_account': bank_account.id,
                        'validation': 'balance',
                        }])
            date = datetime.date(2026, 11, 24)
            name, data = camt_generator.make_camt053(
                TEST_IBAN, date, entries=6, currency='EUR',
                start_balance=Decimal('1000.00'), seed=5)
            self.assertEqual(camt_generator.check_camt053(data), [])

            session_id, _, _ = ImportStatement.create()
            wizard = ImportStatement(session_id)
            wizard.start.company = company
            wizard.start.file_ = data
            wizard.start.file_format = 'camt_053_001'
            wizard.do_import_({'views': []})

            statement, = Statement.search([])
            self.assertEqual(statement.journal, journal)
            self.assertEqual(statement.date, date)
            self.assertEqual(len(statement.origins), 6)
            self.assertEqual(statement.number_of_lines, 6)
            self.assertEqual(statement.start_balance, Decimal('1000.00'))
            self.assertEqual(
                statement.start_balance + sum(
                    o.amount for o in statement.origins),
                statement.end_balance)
            self.assertEqual(statement.total_amount, sum(
                    o.amount for o in statement.origins))
            self.assertTrue(statement.name.startswith('TEST-STMT-20261124-'))
            self.assertTrue(all(
                    o.information.get('camt_remittance_information')
                    for o in statement.origins))
            self.assertTrue(all(
                    camt_generator.iban_valid(
                        o.information.get('camt_debtor_iban')
                        or o.information.get('camt_creditor_iban'))
                    for o in statement.origins))

    @with_transaction()
    def test_account_delete_unused(self):
        "An unused account can be deleted"
        pool = Pool()
        Account = pool.get('account.ebics.account')
        Configuration = pool.get('account.ebics.configuration')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company)])
            account, = Account.create([{
                        'configuration': configuration.id,
                        'bank_account': create_bank_account(company).id,
                        'valid_from': datetime.date(2026, 1, 1),
                        }])
            Account.delete([account])
            self.assertEqual(
                Account.search([('active', 'in', [True, False])]), [])

    # E06: keys, INI, HIA, initialisation letters

    def new_connection(self, user_id='TESTUSER', **values):
        "Company and connection in draft (invented participant)"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company = create_company()
        with set_company(company):
            configuration, = Configuration.create([configuration_values(
                        company, user_id=user_id, **values)])
        return company, configuration

    @contextlib.contextmanager
    def bank_connection(self, transport):
        "The connection talks to the simulated bank through transport"
        Configuration = Pool().get('account.ebics.configuration')
        with patch.object(Configuration, '_ebics_transport',
                    lambda self: transport), \
                ebics_settings(passphrase=TEST_PASSPHRASE):
            yield

    def generated(self, configuration):
        "Generate the keys with the cached test keyring (fast)"
        Configuration = Pool().get('account.ebics.configuration')
        with patch.object(keys, 'generate_keyring',
                    return_value=cached_keyring()), \
                ebics_settings(passphrase=TEST_PASSPHRASE):
            Configuration.generate_keys([configuration])

    def read(self, configuration, *names):
        Configuration = Pool().get('account.ebics.configuration')
        values, = Configuration.read([configuration.id], list(names))
        return tuple(values[n] for n in names)

    def logs(self, configuration):
        Log = Pool().get('account.ebics.log')
        return Log.search([('configuration', '=', configuration.id)],
            order=[('id', 'ASC')])

    def assertUserError(self, func, expected):
        with self.assertRaises(UserError) as cm:
            func()
        self.assertIn(expected, str(cm.exception))
        return cm.exception

    # E06 T1
    @with_transaction()
    def test_generate_keys(self):
        "Three key pairs, hash values, container, state, access data locked"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company, configuration = self.new_connection(user_id='T1USER')
        with ebics_settings(passphrase=None):
            self.assertUserError(
                lambda: Configuration.generate_keys([configuration]),
                'passphrase')
        self.assertEqual(
            self.read(configuration, 'state', 'user_a006_hash'),
            ('draft', None))
        with without_check_access():
            self.assertFalse(Configuration(configuration.id).keyring_data)

        with ebics_settings(passphrase=TEST_PASSPHRASE):
            Configuration.generate_keys([configuration])
        configuration = Configuration(configuration.id)
        self.assertEqual(configuration.state, 'keys_generated')
        self.assertFalse(configuration.ini_sent)
        self.assertFalse(configuration.hia_sent)
        with without_check_access():
            data = Configuration(configuration.id).keyring_data
        keyring = keys.load_keyring(data, TEST_PASSPHRASE)
        parts = keys.public_parts(keyring)
        for purpose in keys.PURPOSES:
            with self.subTest(purpose=purpose):
                value = getattr(
                    configuration, 'user_%s_hash' % purpose.lower())
                self.assertRegex(value, r'^[0-9A-F]{64}$')
                self.assertEqual(value, parts[purpose]['hash'])
                self.assertEqual(parts[purpose]['bits'], 2048)
                subject = keyring.certificate(purpose).subject
                self.assertEqual(
                    subject.get_attributes_for_oid(
                        NameOID.COMMON_NAME)[0].value, 'T1USER')
                self.assertEqual(
                    subject.get_attributes_for_oid(
                        NameOID.ORGANIZATION_NAME)[0].value,
                    company.party.name)
        self.assertEqual(len({configuration.user_a006_hash,
                    configuration.user_x002_hash,
                    configuration.user_e002_hash}), 3)
        with self.assertRaises(Exception):
            keys.load_keyring(data, 'wrong passphrase')
        # the passphrase is not stored in the database
        self.assertNotIn(TEST_PASSPHRASE.encode(), bytes(data))
        # access data readonly from keys_generated (spec. ch. 5.1)
        for name in ['company', 'url', 'host_id', 'partner_id', 'user_id',
                'key_bitlength']:
            with self.subTest(field=name):
                states = Configuration._fields[name].states
                self.assertIn('readonly', states)
        # again only from draft: nothing changes in keys_generated
        hashes = self.read(configuration, 'user_a006_hash')
        with ebics_settings(passphrase=TEST_PASSPHRASE):
            Configuration.generate_keys([configuration])
        self.assertEqual(self.read(configuration, 'user_a006_hash'), hashes)

    # E06 T1
    def test_generate_keys_invalid_ids(self):
        "Invalid EBICS identifiers are refused before the keys"
        def action():
            Configuration = Pool().get('account.ebics.configuration')
            company, configuration = self.new_connection(
                user_id='WITH SPACE')
            with ebics_settings(passphrase=TEST_PASSPHRASE):
                Configuration.generate_keys([configuration])
        self.assertRejected('ids', action, 'user_id')

    # E06 T2
    @with_transaction()
    def test_send_ini_hia(self):
        "INI, then HIA against the simulated bank: flags, state ini_sent"
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        transport = OrderTransport(bank)
        Configuration = Pool().get('account.ebics.configuration')
        _, configuration = self.new_connection()
        self.generated(configuration)
        commit()
        with self.bank_connection(transport):
            Configuration.send_ini([configuration])
            commit()
            self.assertEqual(
                self.read(configuration, 'state', 'ini_sent', 'hia_sent'),
                ('keys_generated', True, False))
            Configuration.send_hia([configuration])
            commit()
        self.assertEqual(
            self.read(configuration, 'state', 'ini_sent', 'hia_sent'),
            ('ini_sent', True, True))
        self.assertEqual([r[0] for r in bank.received], ['INI', 'HIA'])
        participant = bank.participants[('TESTPARTNER', 'TESTUSER')]
        self.assertEqual(participant.state, fake_bank.READY)
        self.assertEqual(bank.received[0][1]['hashes']['A006'],
            self.read(configuration, 'user_a006_hash')[0])
        logs = self.logs(configuration)
        self.assertEqual(
            [(log.order_type, log.state, log.technical_return_code,
                log.business_return_code) for log in logs],
            [('INI', 'done', '000000', '000000'),
                ('HIA', 'done', '000000', '000000')])
        self.assertTrue(all(log.ebics_order_id for log in logs))
        members = payload_members(logs[0].payload)
        self.assertEqual(sorted(members), ['request.xml', 'response.xml'])
        self.assertEqual(members['request.xml'], transport.requests[0])
        # nothing to send any more
        with self.bank_connection(transport):
            Configuration.send_ini([configuration])
        self.assertEqual(len(transport.requests), 2)

    # E06 T2
    @with_transaction()
    def test_send_hia_ini(self):
        "HIA, then INI: also state ini_sent"
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        Configuration = Pool().get('account.ebics.configuration')
        _, configuration = self.new_connection()
        self.generated(configuration)
        commit()
        with self.bank_connection(OrderTransport(bank)):
            Configuration.send_hia([configuration])
            commit()
            self.assertEqual(self.read(configuration, 'state', 'hia_sent'),
                ('keys_generated', True))
            Configuration.send_ini([configuration])
            commit()
        self.assertEqual(self.read(configuration, 'state'), ('ini_sent',))
        self.assertEqual([r[0] for r in bank.received], ['HIA', 'INI'])

    # E06 T3
    @with_transaction()
    def test_send_hia_retry(self):
        "HIA fails after INI: only HIA again, INI not sent again"
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        transport = OrderTransport(bank, errors=[
                None, EbicsTransportError("Timeout with 127.0.0.1")])
        Configuration = Pool().get('account.ebics.configuration')
        _, configuration = self.new_connection()
        self.generated(configuration)
        commit()
        with self.bank_connection(transport):
            Configuration.send_ini([configuration])
            commit()
            self.assertUserError(
                lambda: Configuration.send_hia([configuration]),
                'Timeout with 127.0.0.1')
            Transaction().rollback()
            self.assertEqual(
                self.read(configuration, 'state', 'ini_sent', 'hia_sent'),
                ('keys_generated', True, False))
            Configuration.send_hia([configuration])
            commit()
        self.assertEqual(self.read(configuration, 'state'), ('ini_sent',))
        self.assertEqual([r[0] for r in bank.received], ['INI', 'HIA'])
        self.assertEqual(
            [(l.order_type, l.state) for l in self.logs(configuration)],
            [('INI', 'done'), ('HIA', 'error'), ('HIA', 'done')])

    # E06 T4
    @with_transaction()
    def test_order_log_own_transaction(self):
        """The log of a failed order is committed in the transaction of the
        order (F3), without private keys or passphrase"""
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        # INI accepted, then the bank knows the participant: INI -> 091002
        bank.participant('TESTPARTNER', 'TESTUSER').state = fake_bank.READY
        Configuration = Pool().get('account.ebics.configuration')
        _, configuration = self.new_connection()
        self.generated(configuration)
        commit()
        with self.bank_connection(OrderTransport(bank)):
            self.assertUserError(
                lambda: Configuration.send_ini([configuration]),
                'not in the state "new"')
        # the request transaction is rolled back, the log stays
        Transaction().rollback()
        log, = self.logs(configuration)
        self.assertEqual(
            (log.order_type, log.state, log.technical_return_code),
            ('INI', 'error', '091002'))
        self.assertIn('EBICS_INVALID_USER_OR_USER_STATE', log.return_message)
        self.assertEqual(self.read(configuration, 'ini_sent'), (False,))
        private = [
            cached_keyring().private_key(p).private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            for p in keys.PURPOSES]
        members = payload_members(log.payload)
        for data in [bytes(log.payload)] + list(members.values()):
            self.assertNotIn(TEST_PASSPHRASE.encode(), data)
            self.assertNotIn(b'PRIVATE KEY', data)
            for der in private:
                self.assertNotIn(der, data)
        for name in ['return_message', 'technical_return_code',
                'business_return_code', 'ebics_order_id']:
            self.assertNotIn(TEST_PASSPHRASE, getattr(log, name) or '')

    # E06 T4, decision F11
    @unittest.skipUnless(backend.name == 'postgresql',
        "advisory and row locks only with PostgreSQL")
    @with_transaction()
    def test_order_lock_postgresql(self):
        """During the order the connection is locked by an advisory lock,
        not by a row lock: another transaction can take FOR KEY SHARE (the
        foreign key check of a log) but not the order lock; a second order
        is refused; the log is also kept on error"""
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        _, configuration = self.new_connection()
        self.generated(configuration)
        commit()
        seen = {}

        def during_order():
            # another transaction while the order is running
            with Transaction().new_transaction() as other:
                cursor = other.connection.cursor()
                # the lock of a foreign key check (python-sql has no
                # KEY SHARE)
                cursor.execute(
                    'SELECT id FROM "%s" WHERE id = %%s '
                    'FOR KEY SHARE NOWAIT' % Configuration._table,
                    (configuration.id,))
                seen['key_share'] = cursor.fetchall()
                current = Configuration(configuration.id)
                try:
                    Configuration._lock_order(current)
                except UserError as exception:
                    seen['lock'] = str(exception)
                # a log in another transaction is not blocked
                Pool().get('account.ebics.log').record(
                    current, 'HEV', {'state': 'done'})
                other.commit()

        transport = OrderTransport(bank, errors=[
                EbicsTransportError("Connection to 127.0.0.1 failed")],
            before=during_order)
        with self.bank_connection(transport):
            done = threading.Event()
            errors = []

            def run():
                try:
                    with Transaction().start(DB_NAME, 1) as transaction, \
                            without_check_access():
                        try:
                            Configuration.send_ini(
                                [Configuration(configuration.id)])
                        except UserError as exception:
                            errors.append(str(exception))
                        transaction.rollback()
                finally:
                    done.set()
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            # a blocked foreign key check would hang here
            self.assertTrue(done.wait(60), "The order hangs")
            thread.join(10)
        self.assertEqual(seen['key_share'], [(configuration.id,)])
        self.assertIn('is running', seen['lock'])
        self.assertEqual(len(errors), 1)
        self.assertIn('Connection to 127.0.0.1 failed', errors[0])
        commit()
        self.assertEqual(
            [(l.order_type, l.state) for l in self.logs(configuration)],
            [('HEV', 'done'), ('INI', 'error')])

        # a second order while the lock is held is refused
        with Transaction().new_transaction() as other:
            Configuration._lock_order(configuration)
            with self.bank_connection(OrderTransport(bank)):
                self.assertUserError(
                    lambda: Configuration.send_ini([configuration]),
                    'is running')
            other.rollback()
        self.assertEqual(len(self.logs(configuration)), 2)

    # E06 T5
    @with_transaction()
    def test_order_messages(self):
        "Messages: transport error, wrong and missing passphrase"
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        Configuration = Pool().get('account.ebics.configuration')
        _, configuration = self.new_connection()
        self.generated(configuration)
        commit()
        transport = OrderTransport(bank, errors=[
                EbicsTransportError("TLS error with 127.0.0.1")])
        with self.bank_connection(transport):
            exception = self.assertUserError(
                lambda: Configuration.send_hia([configuration]),
                'The connection to the bank failed')
            self.assertIn('TLS error with 127.0.0.1', str(exception))
            Transaction().rollback()
            with ebics_settings(passphrase='wrong passphrase'):
                exception = self.assertUserError(
                    lambda: Configuration.send_hia([configuration]),
                    'cannot be loaded (wrong passphrase?)')
                self.assertNotIn('wrong passphrase"', str(exception))
            with ebics_settings(passphrase=None):
                self.assertUserError(
                    lambda: Configuration.send_hia([configuration]),
                    'passphrase')
        # only the order with transport error has a log
        log, = self.logs(configuration)
        self.assertEqual((log.order_type, log.state), ('HIA', 'error'))
        self.assertIn('EbicsTransportError', log.return_message)
        self.assertEqual(sorted(payload_members(log.payload)),
            ['request.xml'])
        self.assertEqual(len(transport.requests), 1)

    # E06 T5
    @with_transaction()
    def test_order_messages_codes(self):
        "Other return codes: EBICS error with code, symbol and text"
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        Configuration = Pool().get('account.ebics.configuration')
        _, configuration = self.new_connection(host_id='OTHERHOST')
        self.generated(configuration)
        commit()
        bank.host_id = 'TESTHOST'
        with self.bank_connection(OrderTransport(bank)):
            # unknown host: the simulated bank answers 091002 as well
            self.assertUserError(
                lambda: Configuration.send_ini([configuration]),
                'not in the state "new"')
        with patch.object(fake_bank.FakeBank, '_unsecured',
                lambda self, root: self._key_management_response(
                    '000000', '091201')):
            with self.bank_connection(OrderTransport(bank)):
                exception = self.assertUserError(
                    lambda: Configuration.send_ini([configuration]),
                    'EBICS error in INI')
        self.assertIn('091201', str(exception))
        self.assertIn('EBICS_KEYMGMT_UNSUPPORTED_VERSION_SIGNATURE',
            str(exception))
        self.assertNotIn('EBICS_OK', str(exception))

    # E06 T6
    @with_transaction()
    def test_letters(self):
        "Initialisation letters: header, certificates, hash value groups"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        IniLetter = pool.get('account.ebics.ini_letter_ini', type='report')
        HiaLetter = pool.get('account.ebics.ini_letter_hia', type='report')
        Bank = pool.get('bank')
        Party = pool.get('party.party')
        bank_party, = Party.create([{'name': "Testbank (Testdaten)"}])
        bank_record, = Bank.create([{
                    'party': bank_party.id, 'bic': 'TESTDEFFXXX'}])
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        _, configuration = self.new_connection(
            name="Letter test", bank=bank_record.id)
        self.generated(configuration)
        commit()
        with ebics_settings(passphrase=TEST_PASSPHRASE):
            self.assertUserError(
                lambda: IniLetter.execute([configuration.id], {}),
                'can only be printed after the bank accepted INI')
        with self.bank_connection(OrderTransport(bank)):
            Configuration.send_ini([configuration])
            commit()
            extension, content, _, name = IniLetter.execute(
                [configuration.id], {})
            self.assertUserError(
                lambda: HiaLetter.execute([configuration.id], {}),
                'can only be printed after the bank accepted HIA')
            Configuration.send_hia([configuration])
            commit()
            _, hia_content, _, _ = HiaLetter.execute([configuration.id], {})
        # template .fodt, output OpenDocument (no fixed format, F5)
        self.assertEqual(extension, 'odt')
        self.assertEqual(name, 'INI Letter-Letter test')

        def document(data):
            with zipfile.ZipFile(io.BytesIO(bytes(data))) as container:
                return container.read('content.xml').decode('utf-8')
        text = document(content)
        hia = document(hia_content)
        for value in ['Letter test', 'TESTHOST', 'TESTPARTNER', 'TESTUSER',
                'Testbank (Testdaten)', 'TESTDEFFXXX',
                '-----BEGIN CERTIFICATE-----', 'Bank-technical signature',
                'Signature of the participant']:
            with self.subTest(value=value):
                self.assertIn(value, text)
        log = self.logs(configuration)[0]
        self.assertIn(log.timestamp.strftime('%H:%M:%S'), text)
        for purpose, document in [('A006', text), ('X002', hia),
                ('E002', hia)]:
            with self.subTest(purpose=purpose):
                value = cached_keyring().certificate(purpose)
                hash_ = keys.certificate_hash(value)
                lines = [' '.join(hash_[i:i + 2] for i in range(j, j + 32, 2))
                    for j in (0, 32)]
                for line in lines:
                    self.assertRegex(line, r'^([0-9A-F]{2} ){15}[0-9A-F]{2}$')
                    self.assertIn('>%s<' % line, document)
                pem = value.public_bytes(
                    serialization.Encoding.PEM).decode('ascii')
                self.assertIn(pem.splitlines()[1], document)
        self.assertNotIn('A006', hia.replace('ini_letter', ''))
        for value in ['Authentication', 'Encryption', 'X002', 'E002']:
            self.assertIn(value, hia)
        self.assertNotIn(TEST_PASSPHRASE, text + hia)
        self.assertNotIn('PRIVATE KEY', text + hia)

    def test_format_hash(self):
        "Groups of two hexadecimal characters, 16 per line (F6)"
        from trytond.modules.account_ebics.connection.configuration import (
            format_hash)
        value = ''.join('%02X' % i for i in range(32))
        self.assertEqual(format_hash(value), [
                '00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
                '10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F'])
        self.assertEqual(format_hash(None), [])

    # E06 T7
    @with_transaction()
    def test_reset_draft(self):
        "Dialog: without confirmation refused; with it draft, keys deleted"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        ResetDraft = pool.get(
            'account.ebics.configuration.reset_draft', type='wizard')
        ModelLog = pool.get('ir.model.log')
        _, configuration = self.new_connection()
        self.generated(configuration)
        log = create_log(configuration.company, configuration)
        with Transaction().set_context(
                active_model='account.ebics.configuration',
                active_id=configuration.id,
                active_ids=[configuration.id]):
            session_id, _, _ = ResetDraft.create()
            wizard = ResetDraft(session_id)
            defaults = wizard.default_start(None)
            self.assertEqual(defaults, {
                    'name': "Test access", 'host_id': 'TESTHOST',
                    'partner_id': 'TESTPARTNER', 'user_id': 'TESTUSER',
                    'confirm': False})
            button = dict(
                (b.state, b) for b in ResetDraft.start.buttons)['reset']
            self.assertEqual(button.states['readonly'].pyson(), (
                    ~Eval('confirm', False)).pyson())
            # the server checks the confirmation
            wizard.start.confirm = False
            self.assertUserError(wizard.transition_reset, 'Please confirm')
            self.assertEqual(self.read(configuration, 'state'),
                ('keys_generated',))
            wizard.start.confirm = True
            self.assertEqual(wizard.transition_reset(), 'end')
            ResetDraft.delete(session_id)
        configuration = Configuration(configuration.id)
        self.assertEqual(configuration.state, 'draft')
        for name in ['user_a006_hash', 'user_x002_hash', 'user_e002_hash',
                'bank_x002_hash', 'bank_e002_hash']:
            self.assertIsNone(getattr(configuration, name))
        self.assertFalse(configuration.ini_sent)
        self.assertFalse(configuration.hia_sent)
        with without_check_access():
            self.assertFalse(Configuration(configuration.id).keyring_data)
            self.assertFalse(Configuration(configuration.id).bank_keys_data)
        # the log is kept, the change is in ir.model.log
        self.assertEqual(self.logs(configuration), [log])
        Transaction()._store_log_records()
        entries = ModelLog.search([
                ('resource', '=', str(configuration)),
                ('event', '=', 'write'),
                ])
        self.assertTrue(any('state' in (e.target or '') for e in entries))
        # new keys are possible again
        self.generated(configuration)
        self.assertEqual(self.read(configuration, 'state'),
            ('keys_generated',))

    # E06 T8
    @with_transaction()
    def test_button_access(self):
        "Buttons, dialog and letters only for the EBICS administrator"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Button = pool.get('ir.model.button')
        ActionReport = pool.get('ir.action.report')
        ActionWizard = pool.get('ir.action.wizard')
        ModelData = pool.get('ir.model.data')
        admin_group = ModelData.get_id('account_ebics', 'group_ebics_admin')
        company, configuration = self.new_connection()
        names = ['generate_keys', 'send_ini', 'send_hia', 'reset_draft',
            'print_ini_letter', 'print_hia_letter',
            # E07
            'fetch_bank_keys', 'confirm_bank_keys', 'suspend', 'reactivate']
        # E08: download_statements for both groups (test_fetch_access)
        self.assertEqual(sorted(names + ['download_statements']), sorted(
                b.name for b in Button.search([
                        ('model', '=', 'account.ebics.configuration')])))
        for name in names:
            with self.subTest(button=name):
                self.assertEqual(
                    Button.get_groups('account.ebics.configuration', name),
                    {admin_group})
        for report in ['account.ebics.ini_letter_ini',
                'account.ebics.ini_letter_hia']:
            action, = ActionReport.search([('report_name', '=', report)])
            self.assertEqual([g.id for g in action.groups], [admin_group])
            self.assertFalse(action.extension)
            self.assertTrue(action.single)
        action, = ActionWizard.search([
                ('wiz_name', '=', 'account.ebics.configuration.reset_draft')])
        self.assertEqual([g.id for g in action.groups], [admin_group])

        user = create_user('ebics_user_e06', company, ['group_ebics'])
        admin = create_user('ebics_admin_e06', company, ['group_ebics_admin'])
        set_user, set_context = as_user(user)
        with set_user, set_context, \
                ebics_settings(passphrase=TEST_PASSPHRASE):
            for name in ['generate_keys', 'send_ini', 'send_hia']:
                with self.subTest(button=name, user='group_ebics'):
                    with self.assertRaises(AccessButtonError):
                        getattr(Configuration, name)([configuration])
        set_user, set_context = as_user(admin)
        with set_user, set_context:
            # not visible in draft: refused by the server
            with self.assertRaises(AccessButtonError):
                Configuration.send_ini([configuration])
            with patch.object(keys, 'generate_keyring',
                        return_value=cached_keyring()), \
                    ebics_settings(passphrase=TEST_PASSPHRASE):
                Configuration.generate_keys([configuration])
            with self.assertRaises(AccessButtonError):
                Configuration.generate_keys([configuration])
            # key fields still without field access (D8)
            for name in ['keyring_data', 'keyring_data_id']:
                with self.assertRaises(AccessError):
                    Configuration.read([configuration.id], [name])
        self.assertEqual(self.read(configuration, 'state'),
            ('keys_generated',))

    # E07: bank keys (HPB), confirmation, suspend

    def initialised(self, bank, user_id='TESTUSER', **values):
        """Connection after INI and HIA at the simulated bank (state
        ini_sent), committed"""
        Configuration = Pool().get('account.ebics.configuration')
        _, configuration = self.new_connection(user_id=user_id, **values)
        self.generated(configuration)
        commit()
        with self.bank_connection(OrderTransport(bank)):
            Configuration.send_ini([configuration])
            Configuration.send_hia([configuration])
        commit()
        return Configuration(configuration.id)

    def fetch(self, configuration, bank):
        Configuration = Pool().get('account.ebics.configuration')
        with self.bank_connection(OrderTransport(bank)):
            Configuration.fetch_bank_keys([configuration])
        commit()

    def confirm_wizard(self, configuration):
        ConfirmBankKeys = Pool().get(
            'account.ebics.configuration.confirm_bank_keys', type='wizard')
        context = Transaction().set_context(
            active_model='account.ebics.configuration',
            active_id=configuration.id, active_ids=[configuration.id])
        with context:
            session_id, _, _ = ConfirmBankKeys.create()
            wizard = ConfirmBankKeys(session_id)
            values = wizard.default_start(None)
            for name, value in values.items():
                setattr(wizard.start, name, value)
        return wizard, values

    def run_confirm(self, configuration, wizard):
        with Transaction().set_context(
                active_model='account.ebics.configuration',
                active_id=configuration.id, active_ids=[configuration.id]):
            return wizard.transition_confirm()

    def active(self, bank, **values):
        "Connection with confirmed bank keys (state active)"
        configuration = self.initialised(bank, **values)
        self.fetch(configuration, bank)
        wizard, _ = self.confirm_wizard(configuration)
        wizard.start.compared = True
        self.run_confirm(configuration, wizard)
        commit()
        return Pool().get('account.ebics.configuration')(configuration.id)

    def notifications(self, configuration):
        Notification = Pool().get('res.notification')
        return [n.label for n in Notification.search([
                    ('model', '=', 'account.ebics.configuration'),
                    ('records', '=', '[%s]' % configuration.id),
                    ], order=[('id', 'ASC')])]

    # E07 T1
    @with_transaction()
    def test_hpb_not_released(self):
        "HPB before the release: 091002, state stays ini_sent, log"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(
            keyring=cached_bank_keyring(), auto_release=False)
        configuration = self.initialised(bank)
        self.assertEqual(self.read(configuration, 'state'), ('ini_sent',))
        with self.bank_connection(OrderTransport(bank)):
            self.assertUserError(
                lambda: Configuration.fetch_bank_keys([configuration]),
                'is not yet released by the bank')
        Transaction().rollback()
        self.assertEqual(self.read(configuration, 'state', 'bank_x002_hash'),
            ('ini_sent', None))
        log = self.logs(configuration)[-1]
        self.assertEqual(
            (log.order_type, log.state, log.technical_return_code),
            ('HPB', 'error', '091002'))
        # locked at the bank: 091004
        participant = bank.participants[('TESTPARTNER', 'TESTUSER')]
        participant.state = fake_bank.SUSPENDED
        with self.bank_connection(OrderTransport(bank)):
            self.assertUserError(
                lambda: Configuration.fetch_bank_keys([configuration]),
                'locked at the bank (091004')
        Transaction().rollback()
        self.assertEqual(self.read(configuration, 'state'), ('ini_sent',))

    # E07 T2
    @with_transaction()
    def test_hpb(self):
        "HPB after the release: bank_keys_received, container, hash values"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.initialised(bank)
        self.fetch(configuration, bank)
        configuration = Configuration(configuration.id)
        self.assertEqual(configuration.state, 'bank_keys_received')
        self.assertEqual(configuration.bank_x002_hash, bank.bank_hash('X002'))
        self.assertEqual(configuration.bank_e002_hash, bank.bank_hash('E002'))
        with without_check_access():
            data = Configuration(configuration.id).bank_keys_data
        with zipfile.ZipFile(io.BytesIO(bytes(data))) as container:
            self.assertEqual(sorted(container.namelist()),
                ['E002.pem', 'X002.pem', 'manifest.json'])
            manifest = json.loads(container.read('manifest.json'))
            pem = container.read('X002.pem')
        self.assertEqual(manifest['version'], 1)
        self.assertEqual(manifest['host_id'], 'TESTHOST')
        self.assertTrue(manifest['received'])
        self.assertEqual(manifest['keys'], {
                p: {'version': p, 'hash': bank.bank_hash(p)}
                for p in ['X002', 'E002']})
        self.assertEqual(pem, bank.certificate('X002').public_bytes(
                serialization.Encoding.PEM))
        self.assertNotIn(b'PRIVATE', bytes(data))
        certificates = configuration_module.load_bank_keys(data)
        self.assertEqual(
            keys.certificate_hash(certificates['E002']),
            bank.bank_hash('E002'))
        # the confirmed keys only from active
        self.assertUserError(configuration.bank_keys, 'no confirmed bank')
        # display in groups of two (F8), no expected values yet
        lines = configuration.bank_x002_hash_groups.split('\n')
        self.assertEqual(len(lines), 2)
        self.assertRegex(lines[0], r'^([0-9A-F]{2} ){15}[0-9A-F]{2}$')
        self.assertEqual(lines[0].replace(' ', '') + lines[1].replace(
                ' ', ''), bank.bank_hash('X002'))
        self.assertEqual(configuration.bank_x002_hash_check, 'no_expected')
        self.assertIsNone(configuration.bank_x002_hash_expected_groups)
        log = self.logs(configuration)[-1]
        self.assertEqual((log.order_type, log.state), ('HPB', 'done'))
        members = payload_members(log.payload)
        self.assertEqual(sorted(members), ['request.xml', 'response.xml'])
        for value in members.values():
            self.assertNotIn(b'PRIVATE KEY', value)
            self.assertNotIn(TEST_PASSPHRASE.encode(), value)
        self.assertEqual(len(self.notifications(configuration)), 1)
        self.assertIn('were received', self.notifications(configuration)[0])

    # E07 T3
    @with_transaction()
    def test_confirm_bank_keys(self):
        "Confirmation: equal, different, without expected values"
        Configuration = Pool().get('account.ebics.configuration')
        ConfirmBankKeys = Pool().get(
            'account.ebics.configuration.confirm_bank_keys', type='wizard')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        x002, e002 = bank.bank_hash('X002'), bank.bank_hash('E002')

        def spaced(value):
            # as printed by a bank: groups, lower case
            return ' '.join(value[i:i + 2] for i in range(0, 64, 2)).lower()

        # the button is readonly for mismatch and without the tick
        button = dict(
            (b.state, b) for b in ConfirmBankKeys.start.buttons)['confirm']
        self.assertEqual(button.states['readonly'].pyson(), (
                (Eval('check') == 'mismatch')
                | ((Eval('check') == 'no_expected')
                    & ~Eval('compared', False))).pyson())

        # expected values equal: without tick
        equal = self.initialised(bank, user_id='EQUAL',
            bank_x002_hash_expected=spaced(x002),
            bank_e002_hash_expected=spaced(e002))
        self.fetch(equal, bank)
        wizard, values = self.confirm_wizard(equal)
        self.assertEqual(values['check'], 'match')
        self.assertEqual(values['x002_check'], 'match')
        self.assertEqual(values['host_id'], 'TESTHOST')
        self.assertEqual(values['x002_hash_groups'],
            '\n'.join(configuration_module.format_hash(x002)))
        self.assertEqual(values['x002_expected_groups'],
            values['x002_hash_groups'])
        self.assertEqual(self.run_confirm(equal, wizard), 'end')
        self.assertEqual(self.read(equal, 'state'), ('active',))
        self.assertEqual(Configuration(equal.id).bank_keys()['X002']
            .public_bytes(serialization.Encoding.DER),
            bank.certificate('X002').public_bytes(
                serialization.Encoding.DER))

        # expected values different: not confirmable
        different = self.initialised(bank, user_id='DIFFERENT',
            bank_x002_hash_expected=x002, bank_e002_hash_expected=TEST_HASH)
        self.fetch(different, bank)
        wizard, values = self.confirm_wizard(different)
        self.assertEqual(
            (values['x002_check'], values['e002_check'], values['check']),
            ('match', 'mismatch', 'mismatch'))
        wizard.start.compared = True
        self.assertUserError(
            lambda: self.run_confirm(different, wizard),
            'differ from the expected values')
        self.assertEqual(self.read(different, 'state'),
            ('bank_keys_received',))

        # without expected values: the tick is needed
        without = self.initialised(bank, user_id='WITHOUT')
        self.fetch(without, bank)
        wizard, values = self.confirm_wizard(without)
        self.assertEqual(values['check'], 'no_expected')
        self.assertFalse(values['compared'])
        self.assertUserError(
            lambda: self.run_confirm(without, wizard),
            'Please confirm that you compared')
        # one expected value only: the tick is still needed
        Configuration.write([Configuration(without.id)], {
                'bank_x002_hash_expected': x002})
        wizard, values = self.confirm_wizard(without)
        self.assertEqual(values['check'], 'no_expected')
        # keys changed since the dialog was opened
        wizard.start.compared = True
        wizard.start.e002_hash = TEST_HASH
        self.assertUserError(
            lambda: self.run_confirm(without, wizard),
            'changed in the meantime')
        wizard.start.e002_hash = e002
        self.assertEqual(self.run_confirm(without, wizard), 'end')
        self.assertEqual(self.read(without, 'state'), ('active',))
        # again: not in the state bank_keys_received
        self.assertUserError(
            lambda: self.run_confirm(without, wizard),
            'can only be confirmed')

    # E07 T4
    @with_transaction()
    def test_bank_keys_changed(self):
        "HPB in active: same keys stay active, new keys bank_keys_received"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        old = self.read(configuration, 'bank_x002_hash', 'bank_e002_hash')
        self.fetch(configuration, bank)
        self.assertEqual(self.read(configuration, 'state'), ('active',))
        self.assertIn('are unchanged', self.notifications(configuration)[-1])
        self.assertEqual([l.order_type for l in self.logs(configuration)],
            ['INI', 'HIA', 'HPB', 'HPB'])

        # new keys of the bank (as rotate-bank-keys of the test server)
        bank.keyring = keys.generate_keyring(2048, fake_bank.BANK_SUBJECT)
        self.fetch(configuration, bank)
        configuration = Configuration(configuration.id)
        self.assertEqual(configuration.state, 'bank_keys_received')
        self.assertEqual(
            (configuration.bank_x002_hash, configuration.bank_e002_hash),
            (bank.bank_hash('X002'), bank.bank_hash('E002')))
        self.assertNotEqual(
            (configuration.bank_x002_hash, configuration.bank_e002_hash),
            old)
        self.assertIn('have changed', self.notifications(configuration)[-1])

        # also from suspended
        wizard, _ = self.confirm_wizard(configuration)
        wizard.start.compared = True
        self.run_confirm(configuration, wizard)
        Configuration.suspend([configuration])
        commit()
        bank.keyring = cached_bank_keyring()
        self.fetch(configuration, bank)
        self.assertEqual(self.read(configuration, 'state', 'bank_x002_hash'),
            ('bank_keys_received', old[0]))

    # E07 T5
    @with_transaction()
    def test_suspend_reactivate(self):
        "Suspend only from active, reactivate only with confirmed keys"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        Configuration.suspend([configuration])
        self.assertEqual(self.read(configuration, 'state'), ('suspended',))
        # HPB with the same keys in suspended: stays suspended (F4)
        commit()
        self.fetch(configuration, bank)
        self.assertEqual(self.read(configuration, 'state'), ('suspended',))
        Configuration.reactivate([configuration])
        self.assertEqual(self.read(configuration, 'state'), ('active',))
        self.assertTrue(Configuration(configuration.id).bank_keys())

        # without the stored bank keys: refused
        Configuration.suspend([configuration])
        with without_check_access():
            Configuration.write([configuration], {'bank_keys_data': None})
        self.assertUserError(
            lambda: Configuration.reactivate([configuration]),
            'cannot be reactivated without confirmed bank keys')

        # only in the fitting states (checked by the button)
        company = configuration.company
        admin = create_user('ebics_admin_e07_t5', company,
            ['group_ebics_admin'])
        with set_company(company):
            draft, = Configuration.create([configuration_values(
                        company, user_id='DRAFTUSER')])
        set_user, set_context = as_user(admin)
        with set_user, set_context:
            for name in ['suspend', 'reactivate', 'fetch_bank_keys',
                    'confirm_bank_keys']:
                with self.subTest(button=name):
                    with self.assertRaises(AccessButtonError):
                        getattr(Configuration, name)(
                            [Configuration(draft.id)])

    # E07 T6
    @with_transaction()
    def test_bank_keys_update_required(self):
        "091008: state bank_keys_received, log, message (block for E08)"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        # the simulated bank answers HPB with 091008 (fault)
        bank.faults['HPB'] = '091008'
        with self.bank_connection(OrderTransport(bank)):
            self.assertUserError(
                lambda: Configuration.fetch_bank_keys([configuration]),
                'Fetch the bank keys (HPB) and confirm them')
        Transaction().rollback()
        self.assertEqual(self.read(configuration, 'state'),
            ('bank_keys_received',))
        log = self.logs(configuration)[-1]
        self.assertEqual(
            (log.order_type, log.state, log.technical_return_code),
            ('HPB', 'error', '091008'))

        # the block itself, as the orders of E08 will use it
        result = client.OrderResult(
            'BTD', technical=returncodes.lookup('091008'))
        configuration = Configuration(configuration.id)
        Configuration.write([configuration], {'state': 'active'})
        self.assertTrue(configuration._check_bank_keys_update(result))
        self.assertEqual(self.read(configuration, 'state'),
            ('bank_keys_received',))
        other = client.OrderResult(
            'BTD', technical=returncodes.lookup('091002'))
        self.assertFalse(configuration._check_bank_keys_update(other))
        self.assertUserError(
            lambda: configuration._raise_order_error('BTD', result, None),
            '(BTD: 091008 EBICS_BANK_PUBKEY_UPDATE_REQUIRED)')

    # E07 T7
    @with_transaction()
    def test_bank_keys_access(self):
        "Buttons and dialog of E07 only for the EBICS administrator"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Button = pool.get('ir.model.button')
        ActionWizard = pool.get('ir.action.wizard')
        ModelData = pool.get('ir.model.data')
        admin_group = ModelData.get_id('account_ebics', 'group_ebics_admin')
        for name in ['fetch_bank_keys', 'confirm_bank_keys', 'suspend',
                'reactivate']:
            with self.subTest(button=name):
                self.assertEqual(
                    Button.get_groups('account.ebics.configuration', name),
                    {admin_group})
        action, = ActionWizard.search([
                ('wiz_name', '=',
                    'account.ebics.configuration.confirm_bank_keys')])
        self.assertEqual([g.id for g in action.groups], [admin_group])
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        user = create_user(
            'ebics_user_e07', configuration.company, ['group_ebics'])
        set_user, set_context = as_user(user)
        with set_user, set_context, \
                ebics_settings(passphrase=TEST_PASSPHRASE):
            for name in ['fetch_bank_keys', 'suspend']:
                with self.subTest(button=name, user='group_ebics'):
                    with self.assertRaises(AccessButtonError):
                        getattr(Configuration, name)(
                            [Configuration(configuration.id)])
            # the bank keys container has no field access either (D8)
            with self.assertRaises(AccessError):
                Configuration.read([configuration.id], ['bank_keys_data'])
        self.assertEqual(self.read(configuration, 'state'), ('active',))

    # E07.1 (F9): confirmation after suspend

    def confirm(self, configuration, expect_suspended):
        wizard, values = self.confirm_wizard(configuration)
        self.assertEqual(values['stays_suspended'], expect_suspended)
        wizard.start.compared = True
        self.assertEqual(self.run_confirm(configuration, wizard), 'end')
        commit()

    @with_transaction()
    def test_confirm_after_suspend(self):
        "Suspended stays suspended after confirming new bank keys (F9)"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        self.assertIsNone(self.read(configuration, 'confirmed_state')[0])
        Configuration.suspend([configuration])
        commit()
        # new keys of the bank (rotate-bank-keys)
        bank.keyring = keys.generate_keyring(2048, fake_bank.BANK_SUBJECT)
        self.fetch(configuration, bank)
        self.assertEqual(
            self.read(configuration, 'state', 'confirmed_state'),
            ('bank_keys_received', 'suspended'))
        # HPB again in bank_keys_received keeps the remembered state
        self.fetch(configuration, bank)
        self.assertEqual(self.read(configuration, 'confirmed_state'),
            ('suspended',))
        self.confirm(configuration, True)
        self.assertEqual(
            self.read(configuration, 'state', 'confirmed_state'),
            ('suspended', None))
        Configuration.reactivate([Configuration(configuration.id)])
        commit()
        self.assertEqual(self.read(configuration, 'state'), ('active',))

        # from active: back to active as before
        bank.keyring = cached_bank_keyring()
        self.fetch(configuration, bank)
        self.assertEqual(
            self.read(configuration, 'state', 'confirmed_state'),
            ('bank_keys_received', 'active'))
        self.confirm(configuration, False)
        self.assertEqual(
            self.read(configuration, 'state', 'confirmed_state'),
            ('active', None))

    @with_transaction()
    def test_bank_keys_update_required_suspended(self):
        "091008 in suspended: stays suspended after the confirmation (F9)"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        Configuration.suspend([configuration])
        commit()
        bank.faults['HPB'] = '091008'
        with self.bank_connection(OrderTransport(bank)):
            self.assertUserError(
                lambda: Configuration.fetch_bank_keys(
                    [Configuration(configuration.id)]),
                '091008 EBICS_BANK_PUBKEY_UPDATE_REQUIRED')
        Transaction().rollback()
        self.assertEqual(
            self.read(configuration, 'state', 'confirmed_state'),
            ('bank_keys_received', 'suspended'))
        self.confirm(configuration, True)
        self.assertEqual(self.read(configuration, 'state'), ('suspended',))

        # the block itself from active: back to active
        Configuration.reactivate([Configuration(configuration.id)])
        result = client.OrderResult(
            'BTD', technical=returncodes.lookup('091008'))
        self.assertTrue(Configuration(configuration.id)
            ._check_bank_keys_update(result))
        self.assertEqual(
            self.read(configuration, 'state', 'confirmed_state'),
            ('bank_keys_received', 'active'))
        commit()
        self.confirm(configuration, False)
        self.assertEqual(self.read(configuration, 'state'), ('active',))

    @with_transaction()
    def test_confirmed_state_reset_and_copy(self):
        "Reset to draft and copy clear the remembered state"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        ResetDraft = pool.get(
            'account.ebics.configuration.reset_draft', type='wizard')
        Start = pool.get('account.ebics.configuration.confirm_bank_keys.start')
        _, configuration = self.new_connection()
        self.generated(configuration)
        Configuration.write([configuration], {
                'state': 'bank_keys_received',
                'confirmed_state': 'suspended'})
        copy, = Configuration.copy([configuration], {'user_id': 'COPYUSER'})
        self.assertIsNone(copy.confirmed_state)
        with Transaction().set_context(
                active_model='account.ebics.configuration',
                active_id=configuration.id, active_ids=[configuration.id]):
            session_id, _, _ = ResetDraft.create()
            wizard = ResetDraft(session_id)
            wizard.start.confirm = True
            wizard.transition_reset()
        self.assertEqual(
            self.read(configuration, 'state', 'confirmed_state'),
            ('draft', None))
        # the note of the dialog is shown only when it stays suspended
        attributes = dict(
            (x, s) for x, a, s in Start.view_attributes() if a == 'states')
        self.assertEqual(
            attributes['//label[@id="stays_suspended_note"]']['invisible']
            .pyson(), (~Eval('stays_suspended', False)).pyson())

    # E08: download of statements (BTD)

    def provide(self, bank, iban=TEST_IBAN, date=None, entries=3,
            btf=None, sequence=1, copy_duplicate=None):
        "An invented camt.053 at the simulated bank (test data)"
        name, data = camt_generator.make_camt053(
            iban, date or datetime.date.today(), entries,
            sequence=sequence, copy_duplicate=copy_duplicate)
        bank.add_download(
            btf or CAMT053_BTF, name, data, date or datetime.date.today())
        return name, data

    def fetch_wizard(self, configurations=None):
        """The dialog Fetch Statements: from the button of the connections
        (configurations) or from the menu (None)"""
        FetchStatements = Pool().get(
            'account.ebics.fetch_statements', type='wizard')
        context = {}
        if configurations is not None:
            context = {
                'active_model': 'account.ebics.configuration',
                'active_id': configurations[0].id,
                'active_ids': [c.id for c in configurations],
                }
        with Transaction().set_context(**context):
            session_id, _, _ = FetchStatements.create()
            return FetchStatements(session_id), context

    def download(self, configuration, bank, transport=None):
        """Button Fetch Statements against the simulated bank: the dialog
        fetches at once and returns the values of the result page"""
        wizard, context = self.fetch_wizard([configuration])
        with self.bank_connection(transport or OrderTransport(bank)), \
                Transaction().set_context(**context):
            try:
                self.assertEqual(wizard.transition_start(), 'fetch')
                self.assertEqual(wizard.transition_fetch(), 'result')
                return wizard.default_result(None)
            finally:
                commit()

    def assertFetchError(self, result, expected):
        "The result page shows an error with the expected text"
        errors = [l['message'] for l in result['lines']
            if l['state'] == 'error']
        self.assertTrue(any(expected in e for e in errors), errors)
        return result

    def btd_logs(self, configuration):
        return [l for l in self.logs(configuration) if l.order_type == 'BTD']

    # E08 T1
    @with_transaction()
    def test_fetch(self):
        "Download: log, files, receipt positive, last_fetch, notification"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        ModelData = pool.get('ir.model.data')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        # a second format with processing store
        camt052 = ModelData.get_id('account_ebics', 'format_camt052_de')
        Configuration.write([configuration], {
                'formats': [('add', [camt052])]})
        commit()
        name, data = self.provide(bank)
        stored_name, stored_data = self.provide(
            bank, btf=CAMT052_BTF, sequence=2)
        self.assertIsNone(self.read(configuration, 'last_fetch')[0])
        transport = OrderTransport(bank)
        result = self.download(configuration, bank, transport)
        self.assertEqual(result['summary'],
            '2 file(s) received, of them 0 repeated, '
            '0 format(s) without new data, 0 error(s).')
        self.assertEqual([(l['state'], l['files']) for l in result['lines']],
            [('done', 1), ('done', 1)])
        self.assertEqual(sorted(result['logs']),
            sorted(l.id for l in self.btd_logs(configuration)))

        logs = {l.btf_params: l for l in self.btd_logs(configuration)}
        self.assertEqual(sorted(logs),
            ['EOP/DE/camt.053/ZIP', 'STM/DE/camt.052/ZIP'])
        log = logs['EOP/DE/camt.053/ZIP']
        self.assertEqual(
            (log.state, log.receipt, log.technical_return_code,
                log.business_return_code, log.num_segments),
            ('done', 'positive', '000000', '000000', 1))
        self.assertRegex(log.transaction_id, r'^[0-9A-F]{32}$')
        self.assertEqual(log.format.id, ModelData.get_id(
                'account_ebics', 'format_camt053_de'))
        self.assertIsNone(log.date_from)
        with zipfile.ZipFile(io.BytesIO(bytes(log.payload))) as container:
            self.assertEqual(container.read(name), data)
        file_, = log.files
        self.assertEqual(
            (file_.name, bytes(file_.data), file_.sha256,
                file_.message_type, file_.iban, file_.state),
            (name, data, hashlib.sha256(data).hexdigest(),
                'camt.053.001.08', TEST_IBAN, 'pending'))
        stored, = logs['STM/DE/camt.052/ZIP'].files
        self.assertEqual((stored.name, stored.state),
            (stored_name, 'stored'))
        # F7: requests and responses are not stored
        self.assertNotIn(b'ebicsRequest', bytes(log.payload))
        # the bank got the positive receipts
        self.assertTrue(all(e['delivered'] for e in bank.files))
        self.assertEqual([code for _, code in bank.receipts], [0, 0])
        self.assertTrue(self.read(configuration, 'last_fetch')[0])
        labels = self.notifications(configuration)
        self.assertEqual(
            sum('1 file(s) received' in l for l in labels), 2)
        # no private key or passphrase in the log
        for value in [bytes(log.payload), log.return_message or '',
                log.warnings or '']:
            value = value if isinstance(value, bytes) else value.encode()
            self.assertNotIn(b'PRIVATE KEY', value)
            self.assertNotIn(TEST_PASSPHRASE.encode(), value)

    # E08 T2
    @with_transaction()
    def test_fetch_no_data(self):
        "090005: log no_data for the button, no log for the cron (F3)"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        self.download(configuration, bank)
        log, = self.btd_logs(configuration)
        self.assertEqual(
            (log.state, log.receipt, log.business_return_code),
            ('no_data', 'none', '090005'))
        self.assertFalse(log.files)
        self.assertIsNone(log.payload)
        self.assertIn('no new data', self.notifications(configuration)[-1])
        first = self.read(configuration, 'last_fetch')[0]
        self.assertTrue(first)
        count = len(self.notifications(configuration))
        with self.bank_connection(OrderTransport(bank)), \
                Transaction().set_context(
                    company=configuration.company.id):
            Configuration.fetch_statements()
        commit()
        self.assertEqual(len(self.btd_logs(configuration)), 1)
        self.assertEqual(len(self.notifications(configuration)), count)
        self.assertGreaterEqual(self.read(configuration, 'last_fetch')[0],
            first)

    # E08 T3
    @with_transaction()
    def test_fetch_segments(self):
        "Several segments; max_segments from trytond.conf; warnings (F4)"
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        name, data = self.provide(bank, entries=40)
        bank.segment_size = 1000
        self.download(configuration, bank)
        log, = self.btd_logs(configuration)
        self.assertGreater(log.num_segments, 2)
        self.assertEqual(log.receipt, 'positive')
        self.assertEqual(bytes(log.files[0].data), data)
        self.assertIsNone(log.warnings)

        # the bank announces one segment more than it sends: warning
        self.provide(bank, sequence=2)
        bank.faults['BTD_fewer'] = True
        self.download(configuration, bank)
        log = self.btd_logs(configuration)[-1]
        self.assertEqual(log.state, 'done')
        self.assertIn('announced segments', log.warnings)
        del bank.faults['BTD_fewer']

        # max_segments: refused, no receipt, the data stay at the bank
        self.provide(bank, entries=40, sequence=3)
        with ebics_settings(max_segments=2):
            self.assertFetchError(
                self.download(configuration, bank),
                'segments')
        log = self.btd_logs(configuration)[-1]
        self.assertEqual((log.state, log.receipt), ('error', 'none'))
        self.assertFalse(log.files)
        self.assertFalse(bank.files[-1]['delivered'])

    # E08 T4
    @with_transaction()
    def test_fetch_receipt_after_commit(self):
        "D5: error before the receipt keeps the log; the bank delivers again"
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        name, data = self.provide(bank)
        transport = OrderTransport(bank, errors=[
                None, EbicsTransportError("Timeout with 127.0.0.1")])
        self.assertFetchError(
                self.download(configuration, bank, transport),
                'the receipt failed')
        log, = self.btd_logs(configuration)
        self.assertEqual((log.state, log.receipt), ('done', 'none'))
        self.assertEqual(bytes(log.files[0].data), data)
        self.assertFalse(bank.files[0]['delivered'])
        self.assertIsNone(self.read(configuration, 'last_fetch')[0])
        # the next download delivers the same file again
        self.download(configuration, bank)
        again = self.btd_logs(configuration)[-1]
        self.assertEqual((again.state, again.receipt), ('done', 'positive'))
        self.assertEqual(again.files[0].sha256, log.files[0].sha256)
        self.assertTrue(bank.files[0]['delivered'])

    # E08 T5
    @with_transaction()
    def test_fetch_formats(self):
        "An error of one format does not stop the others; 091008 stops"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        ModelData = pool.get('ir.model.data')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        Configuration.write([configuration], {
                'formats': [('add', [ModelData.get_id(
                                'account_ebics', 'format_camt052_de')])]})
        commit()
        self.provide(bank)
        self.provide(bank, btf=CAMT052_BTF, sequence=2)
        transport = OrderTransport(bank, errors=[
                EbicsTransportError("Connection to 127.0.0.1 failed")])
        self.assertFetchError(
                self.download(configuration, bank, transport),
                'Connection to 127.0.0.1 failed')
        logs = self.btd_logs(configuration)
        self.assertEqual(sorted(l.state for l in logs), ['done', 'error'])
        self.assertIsNone(self.read(configuration, 'last_fetch')[0])
        self.assertEqual(self.read(configuration, 'state'), ('active',))

        # 091008: bank keys, the remaining format is skipped
        bank.faults['BTD'] = '091008'
        self.assertFetchError(
                self.download(configuration, bank),
                '091008 EBICS_BANK_PUBKEY_UPDATE_REQUIRED')
        logs = self.btd_logs(configuration)
        self.assertEqual(len(logs), 3)
        self.assertEqual(
            (logs[-1].state, logs[-1].technical_return_code),
            ('error', '091008'))
        self.assertEqual(
            self.read(configuration, 'state', 'confirmed_state'),
            ('bank_keys_received', 'active'))

    # E08 T6, D27
    @unittest.skipUnless(backend.name == 'postgresql',
        "advisory and row locks only with PostgreSQL")
    @with_transaction()
    def test_fetch_lock_postgresql(self):
        """The lock covers download and receipt (F2): during the receipt a
        second download is refused, the log is visible to other
        transactions and its row is not locked; nothing hangs"""
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        self.provide(bank)
        seen = {}

        def during_receipt():
            if not transport.requests[-1].count(b'Receipt'):
                return
            with Transaction().new_transaction() as other:
                cursor = other.connection.cursor()
                cursor.execute(
                    'SELECT id FROM "%s" WHERE id = %%s '
                    'FOR KEY SHARE NOWAIT' % Configuration._table,
                    (configuration.id,))
                seen['key_share'] = cursor.fetchall()
                Log = Pool().get('account.ebics.log')
                seen['logs'] = Log.search_count([
                        ('configuration', '=', configuration.id),
                        ('order_type', '=', 'BTD')])
                seen['second'] = Configuration.fetch(
                    [Configuration(configuration.id)])
                other.rollback()

        transport = OrderTransport(bank, before=during_receipt)
        done = threading.Event()
        errors = []

        def run():
            try:
                with Transaction().start(DB_NAME, 1) as transaction, \
                        without_check_access():
                    wizard, context = self.fetch_wizard(
                        [Configuration(configuration.id)])
                    with self.bank_connection(transport), \
                            Transaction().set_context(**context):
                        wizard.transition_start()
                        wizard.transition_fetch()
                        result = wizard.default_result(None)
                    errors.extend(l['message'] for l in result['lines']
                        if l['state'] != 'done')
                    transaction.commit()
            finally:
                done.set()
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.assertTrue(done.wait(60), "The download hangs")
        thread.join(10)
        self.assertEqual(errors, [])
        self.assertEqual(seen['key_share'], [(configuration.id,)])
        # transaction A was committed before the receipt (D5)
        self.assertEqual(seen['logs'], 1)
        second, = seen['second']
        self.assertEqual(second['state'], 'error')
        self.assertIn('is running', second['message'])
        commit()
        log, = self.btd_logs(configuration)
        self.assertEqual(log.receipt, 'positive')

    # E08 T7
    @with_transaction()
    def test_fetch_period(self):
        "Dialog: DateRange, checks of the dates and the format"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        FetchPeriod = pool.get('account.ebics.fetch_period', type='wizard')
        Date = pool.get('ir.date')
        ModelData = pool.get('ir.model.data')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        day = Date.today() - datetime.timedelta(days=3)
        name, data = self.provide(bank, date=day)
        self.download(configuration, bank)
        last_fetch = self.read(configuration, 'last_fetch')[0]
        camt053 = pool.get('account.ebics.format')(ModelData.get_id(
                'account_ebics', 'format_camt053_de'))
        camt052 = pool.get('account.ebics.format')(ModelData.get_id(
                'account_ebics', 'format_camt052_de'))

        def wizard(date_from, date_to, format_=camt053):
            with Transaction().set_context(
                    active_model='account.ebics.configuration',
                    active_id=configuration.id,
                    active_ids=[configuration.id]):
                session_id, _, _ = FetchPeriod.create()
                instance = FetchPeriod(session_id)
                defaults = instance.default_start(None)
                instance.start.configuration = Configuration(
                    configuration.id)
                instance.start.format = format_
                instance.start.date_from = date_from
                instance.start.date_to = date_to
                return instance, defaults

        # on_change of the client (as the RPC call on_change_configuration)
        Start = pool.get('account.ebics.fetch_period.start')
        start = Start(configuration=Configuration(configuration.id),
            format=None)
        start.on_change_configuration()
        changed = start._changed_values()
        self.assertEqual(changed['format'], camt053.id)
        self.assertIn('formats', changed)
        self.assertEqual([f.id for f in start.formats], [camt053.id])
        start = Start(configuration=None, format=camt053)
        start.on_change_configuration()
        self.assertEqual(start._changed_values()['format'], None)
        self.assertEqual(Start.on_change_configuration.depends,
            {'configuration', 'format', 'formats'})

        instance, defaults = wizard(day, day)
        self.assertEqual(defaults['configuration'], configuration.id)
        self.assertEqual(defaults['format'], camt053.id)
        self.assertEqual(defaults['date_to'], Date.today())
        for date_from, date_to, format_, expected in [
                (day, day - datetime.timedelta(days=1), camt053,
                    'must not be after'),
                (day, Date.today() + datetime.timedelta(days=1), camt053,
                    'must not be after'),
                (day, day, camt052, 'is not a format')]:
            with self.subTest(date_from=date_from, date_to=date_to):
                instance, _ = wizard(date_from, date_to, format_)
                self.assertUserError(instance.transition_fetch, expected)

        instance, _ = wizard(day, Date.today())
        with self.bank_connection(OrderTransport(bank)):
            self.assertEqual(instance.transition_fetch(), 'result')
        commit()
        result = instance.default_result(None)
        line, = result['lines']
        self.assertEqual((line['state'], line['files']), ('done', 1))
        log = self.btd_logs(configuration)[-1]
        self.assertEqual(
            (log.date_from, log.date_to, log.state, log.receipt),
            (day, Date.today(), 'done', 'positive'))
        self.assertEqual(bytes(log.files[0].data), data)
        initialisation = [d for o, d in bank.received
            if o == 'BTD' and d.get('phase') == 'Initialisation'][-1]
        self.assertEqual(initialisation['date_range'],
            (day.isoformat(), Date.today().isoformat()))
        # a period does not change last_fetch
        self.assertEqual(self.read(configuration, 'last_fetch')[0],
            last_fetch)

    # E08 T8
    @with_transaction()
    def test_fetch_state(self):
        "Suspended and not active connections are not fetched"
        Configuration = Pool().get('account.ebics.configuration')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        self.provide(bank)
        Configuration.suspend([configuration])
        commit()
        with self.bank_connection(OrderTransport(bank)):
            outcome, = Configuration.fetch([Configuration(configuration.id)])
            self.assertEqual(outcome['state'], 'skipped')
            with Transaction().set_context(
                    company=configuration.company.id):
                Configuration.fetch_statements()
        commit()
        self.assertEqual(self.btd_logs(configuration), [])
        self.assertFalse(bank.files[0]['delivered'])
        # the button is not available in suspended
        admin = create_user('ebics_admin_e08_t8', configuration.company,
            ['group_ebics_admin'])
        set_user, set_context = as_user(admin)
        with set_user, set_context:
            with self.assertRaises(AccessButtonError):
                Configuration.download_statements(
                    [Configuration(configuration.id)])

    # E08 T9
    @with_transaction()
    def test_fetch_access(self):
        "Button and dialogs for both groups; cron per company, inactive"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Button = pool.get('ir.model.button')
        ActionWizard = pool.get('ir.action.wizard')
        Cron = pool.get('ir.cron')
        Menu = pool.get('ir.ui.menu')
        ModelData = pool.get('ir.model.data')
        groups = {ModelData.get_id('account_ebics', g)
            for g in ['group_ebics', 'group_ebics_admin']}
        self.assertEqual(Button.get_groups(
                'account.ebics.configuration', 'download_statements'),
            groups)
        for wiz_name in ['account.ebics.fetch_statements',
                'account.ebics.fetch_period']:
            action, = ActionWizard.search([('wiz_name', '=', wiz_name)])
            self.assertEqual({g.id for g in action.groups}, groups)
        for xml_id in ['menu_fetch_statements', 'menu_fetch_period']:
            menu = Menu(ModelData.get_id('account_ebics', xml_id))
            self.assertEqual(menu.parent.id,
                ModelData.get_id('account_ebics', 'menu_ebics'))
        with Transaction().set_context(active_test=False):
            cron, = Cron.search([
                    ('method', '=',
                        'account.ebics.configuration|fetch_statements')])
        self.assertFalse(cron.active)
        self.assertEqual((cron.interval_number, cron.interval_type),
            (1, 'hours'))

        # a user of group_ebics fetches with the button
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        self.provide(bank)
        user = create_user('ebics_user_e08', configuration.company,
            ['group_ebics'])
        commit()
        set_user, set_context = as_user(user)
        wizard_action = ModelData.get_id(
            'account_ebics', 'wizard_fetch_statements')
        with set_user, set_context, \
                self.bank_connection(OrderTransport(bank)):
            # the button opens the dialog, which fetches at once
            action = Configuration.download_statements(
                [Configuration(configuration.id)])
            self.assertEqual(action, pool.get('ir.action').get_action_id(
                    wizard_action))
            wizard, context = self.fetch_wizard(
                [Configuration(configuration.id)])
            with Transaction().set_context(**context):
                self.assertEqual(wizard.transition_start(), 'fetch')
                self.assertEqual(wizard.transition_fetch(), 'result')
        commit()
        log, = self.btd_logs(configuration)
        self.assertEqual((log.create_uid.id, log.receipt),
            (user.id, 'positive'))

        # the menu: all active connections of the current companies
        self.provide(bank, sequence=2)
        FetchStatements = pool.get(
            'account.ebics.fetch_statements', type='wizard')
        with set_user, set_context, \
                self.bank_connection(OrderTransport(bank)):
            session_id, _, _ = FetchStatements.create()
            wizard = FetchStatements(session_id)
            # the menu shows the connections first
            self.assertEqual(wizard.transition_start(), 'confirm')
            confirm = wizard.default_confirm(None)
            self.assertEqual(confirm['configurations'], [configuration.id])
            wizard.confirm.configurations = [
                Configuration(i) for i in confirm['configurations']]
            self.assertEqual(wizard.transition_fetch(), 'result')
            result = wizard.default_result(None)
        commit()
        self.assertEqual(len(self.btd_logs(configuration)), 2)
        self.assertIn('1 file(s) received',
            self.notifications(configuration)[-1])
        self.assertEqual(result['summary'],
            '1 file(s) received, of them 0 repeated, '
            '0 format(s) without new data, 0 error(s).')
        line, = result['lines']
        self.assertEqual(
            (line['configuration'], line['state'], line['files']),
            (configuration.rec_name, 'done', 1))
        new_log = self.btd_logs(configuration)[-1]
        self.assertEqual(result['logs'], [new_log.id])
        # "Open Log" shows the logs of this run
        action, values = wizard.do_open_log({})
        self.assertEqual(values, {})
        self.assertEqual(action['pyson_domain'], PYSONEncoder().encode(
                [('id', 'in', [new_log.id])]))

        # no active connection: the button Fetch is readonly, the server
        # refuses
        other = create_user('ebics_user_e08_other', create_company(),
            ['group_ebics'])
        set_user, set_context = as_user(other)
        with set_user, set_context:
            session_id, _, _ = FetchStatements.create()
            wizard = FetchStatements(session_id)
            self.assertEqual(wizard.transition_start(), 'confirm')
            self.assertEqual(
                wizard.default_confirm(None)['configurations'], [])
            wizard.confirm.configurations = []
            self.assertUserError(wizard.transition_fetch,
                'no active EBICS connection')
        button = dict((b.state, b) for b in FetchStatements.confirm.buttons)
        self.assertEqual(button['fetch'].states['readonly'].pyson(),
            (~Eval('configurations', [])).pyson())

    # E08 T10
    @with_transaction()
    def test_fetch_limits(self):
        "max_zip_files and max_zip_size from trytond.conf"
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        self.provide(bank)
        self.provide(bank, sequence=2)
        with ebics_settings(max_zip_files=1):
            self.assertFetchError(
                self.download(configuration, bank),
                'files')
        with ebics_settings(max_zip_size=1000):
            self.assertFetchError(
                self.download(configuration, bank),
                'Entschlüsselung fehlgeschlagen')
        logs = self.btd_logs(configuration)
        self.assertEqual([(l.state, l.receipt) for l in logs],
            [('error', 'none'), ('error', 'none')])
        self.assertFalse(any(e['delivered'] for e in bank.files))
        self.download(configuration, bank)
        self.assertEqual(len(self.btd_logs(configuration)[-1].files), 2)

    def test_statement_info(self):
        "Message type from the namespace, IBAN of the first account"
        info = configuration_module.statement_info
        data = camt_generator.make_camt053(TEST_IBAN, entries=1)[1]
        self.assertEqual(info(data), ('camt.053.001.08', TEST_IBAN, None))
        self.assertEqual(info(b'not xml'), (None, None, None))
        self.assertEqual(info(b'<a/>'), (None, None, None))
        self.assertEqual(info(
                b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:'
                b'camt.052.001.08"><BkToCstmrAcctRpt><Rpt><Acct><Id>'
                b'<IBAN>' + TEST_IBAN_2.encode() + b'</IBAN></Id></Acct>'
                b'</Rpt></BkToCstmrAcctRpt></Document>'),
            ('camt.052.001.08', TEST_IBAN_2, None))

    # E08: run log (request of the user, 27.11.2026)

    def runs(self, **domain):
        Run = Pool().get('account.ebics.run')
        return Run.search(
            [(k, '=', v) for k, v in domain.items()],
            order=[('id', 'ASC')])

    def assertSteps(self, run, *fragments):
        "Every fragment appears in a line of the steps, in this order"
        lines = run.history.split('\n')
        position = 0
        for fragment in fragments:
            for index in range(position, len(lines)):
                if fragment in lines[index]:
                    position = index + 1
                    break
            else:
                self.fail('%r not in the steps after line %s:\n%s'
                    % (fragment, position, run.history))
        for line in lines:
            self.assertRegex(line, r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ')

    @with_transaction()
    def test_run_cron(self):
        "Cron automatic and manual: every step as text, never empty"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Cron = pool.get('ir.cron')
        ModelData = pool.get('ir.model.data')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        company = configuration.company
        with set_company(company):
            draft, = Configuration.create([configuration_values(
                        company, user_id='DRAFTUSER', name="Draft access")])
        cron = Cron(ModelData.get_id('account_ebics', 'cron_fetch_statements'))
        # "Run Once" is only possible on an active cron (Tryton standard)
        Cron.write([cron], {
                'companies': [('add', [company.id])],
                'active': True,
                })
        commit()
        self.provide(bank)

        # automatic: the scheduler runs as root
        with self.bank_connection(OrderTransport(bank)), \
                self.assertLogs(
                    'trytond.modules.account_ebics.log.run', 'INFO') as logs, \
                Transaction().set_user(0), \
                Transaction().set_context(
                    company=company.id, ebics_cron=cron.id):
            Configuration.fetch_statements()
        commit()
        run, = self.runs(company=company.id)
        log, = self.btd_logs(configuration)
        self.assertEqual(
            (run.trigger, run.cron.id, run.user.id, run.state),
            ('cron', cron.id, 0, 'done'))
        self.assertIn('Cron, started automatically', run.trigger_text)
        self.assertIn('cron %s' % cron.id, run.trigger_text)
        self.assertEqual(run.summary,
            '1 file(s) received, of them 0 repeated, '
            '0 format(s) without new data, 0 error(s).')
        self.assertTrue(run.end)
        self.assertSteps(run,
            'Run started: Cron, started automatically',
            'active EBICS connection(s)',
            'EBICS connection "Draft access" skipped: state Draft',
            'formats Daily Statement (camt.053)',
            'BTD request EOP/DE/camt.053/ZIP sent',
            '1 file(s) received, of them 0 repeated (1 segment(s)), stored in '
            'EBICS log %s' % log.id,
            'positive receipt sent, answer of the bank 011000',
            'last fetch set',
            'Run finished: 1 file(s) received')
        self.assertEqual(run.logs, (log,))
        self.assertEqual((log.trigger, log.run.id, log.create_uid.id),
            ('cron', run.id, 0))
        self.assertEqual(len(logs.output), len(run.history.split('\n')))

        # manual "Run Once" of the cron (only for the Tryton administrator):
        # no data, still a full run log
        admin = pool.get('res.user')(1)
        set_user, set_context = as_user(admin)
        with self.bank_connection(OrderTransport(bank)), \
                set_user, set_context:
            Cron.run_once([Cron(cron.id)])
        commit()
        run = self.runs(company=company.id)[-1]
        self.assertEqual((run.trigger, run.cron.id, run.user.id),
            ('cron_manual', cron.id, admin.id))
        self.assertIn('Cron, started manually', run.trigger_text)
        self.assertIn('user %s' % admin.rec_name, run.trigger_text)
        self.assertSteps(run,
            'Run started: Cron, started manually',
            'BTD request',
            'no new data',
            'Run finished: 0 file(s) received, of them 0 repeated, '
            '1 format(s) without new data')
        # F3: no EBICS log for the empty run of the cron
        self.assertEqual(len(self.btd_logs(configuration)), 1)
        self.assertEqual(run.logs, ())
        # the cron of the module stays inactive for the other tests
        Cron.write([Cron(cron.id)], {
                'active': False,
                'companies': [('remove', [company.id])],
                })
        commit()

    @with_transaction()
    def test_run_without_connection(self):
        "No active connection or no company: the run says so"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        company, configuration = self.new_connection()
        commit()
        with Transaction().set_user(0), \
                Transaction().set_context(company=company.id):
            Configuration.fetch_statements()
        with Transaction().set_user(0), \
                Transaction().set_context(company=None):
            Configuration.fetch_statements()
        commit()
        run, = self.runs(company=company.id)
        self.assertEqual(run.state, 'done')
        self.assertSteps(run, 'Run started',
            '0 active EBICS connection(s)',
            'skipped: state Draft',
            'Run finished: 0 file(s) received')
        run = self.runs(company=None, trigger='cron')[-1]
        self.assertEqual(run.state, 'error')
        self.assertSteps(run, 'Run started', 'No company in the context',
            'Run finished')

    @with_transaction()
    def test_run_dialogs(self):
        "Button, menu and period dialog write a run with user and trigger"
        pool = Pool()
        Run = pool.get('account.ebics.run')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        self.provide(bank)
        transport = OrderTransport(bank, errors=[
                None, EbicsTransportError("Timeout with 127.0.0.1")])
        with self.assertLogs(
                'trytond.modules.account_ebics.log.run', 'INFO') as logs:
            self.download(configuration, bank, transport)
        run = Run.search([], order=[('id', 'DESC')], limit=1)[0]
        log, = self.btd_logs(configuration)
        self.assertEqual((run.trigger, run.user.id, run.state),
            ('button', Transaction().user, 'error'))
        self.assertIn('Button', run.trigger_text)
        self.assertSteps(run, 'Run started: Button',
            '1 EBICS connection(s) to fetch',
            'BTD request', 'stored in EBICS log %s' % log.id,
            'the receipt failed', 'Run finished')
        self.assertEqual((log.trigger, log.run), ('button', run))
        self.assertTrue(any('ERROR' in o and 'the receipt failed' in o
                for o in logs.output))

    @with_transaction()
    def test_run_locked(self):
        "Runs cannot be changed, created or deleted from outside"
        pool = Pool()
        Run = pool.get('account.ebics.run')
        Configuration = pool.get('account.ebics.configuration')
        company, _ = self.new_connection()
        # the run is created in a transaction of its own (PostgreSQL)
        commit()
        with Transaction().set_user(0), \
                Transaction().set_context(company=company.id):
            Configuration.fetch_statements()
        commit()
        run, = self.runs(company=company.id)
        for action in [
                lambda: Run.write([run], {'summary': 'x'}),
                lambda: Run.delete([run]),
                lambda: Run.copy([run])]:
            with self.assertRaises(AccessError):
                with Transaction().set_context(_check_access=True):
                    action()
        with self.assertRaises(AccessError):
            Run.delete([run])
        # an unexpected error is written as last step and raised again
        with self.assertRaises(ZeroDivisionError):
            with Run.recording('menu', company=company.id) as recorder:
                recorder.step('before')
                1 / 0
        commit()
        run = self.runs(company=company.id)[-1]
        self.assertEqual(run.state, 'error')
        self.assertSteps(run, 'before',
            'Run aborted by an unexpected error: ZeroDivisionError')

    # E08.1: files received again (F11), CpyDplctInd (F12)

    def period_fetch(self, configuration, bank, day):
        "Dialog Fetch Statements for Period Again for one day"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        FetchPeriod = pool.get('account.ebics.fetch_period', type='wizard')
        ModelData = pool.get('ir.model.data')
        with Transaction().set_context(
                active_model='account.ebics.configuration',
                active_id=configuration.id,
                active_ids=[configuration.id]):
            session_id, _, _ = FetchPeriod.create()
            wizard = FetchPeriod(session_id)
            wizard.start.configuration = Configuration(configuration.id)
            wizard.start.format = pool.get('account.ebics.format')(
                ModelData.get_id('account_ebics', 'format_camt053_de'))
            wizard.start.date_from = day
            wizard.start.date_to = day
            with self.bank_connection(OrderTransport(bank)):
                self.assertEqual(wizard.transition_fetch(), 'result')
            commit()
            return wizard.default_result(None)

    @with_transaction()
    def test_repeated_file(self):
        "Fetched again for a period: the new file refers to the first one"
        pool = Pool()
        LogFile = pool.get('account.ebics.log.file')
        Run = pool.get('account.ebics.run')
        Date = pool.get('ir.date')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        name, data = self.provide(bank, copy_duplicate='DUPL')
        self.download(configuration, bank)
        first, = self.btd_logs(configuration)[0].files
        self.assertIsNone(first.first_file)
        self.assertFalse(first.repeated)
        self.assertEqual(first.copy_duplicate, 'DUPL')

        result = self.period_fetch(configuration, bank, Date.today())
        log = self.btd_logs(configuration)[-1]
        again, = log.files
        self.assertEqual(again.first_file, first)
        self.assertTrue(again.repeated)
        self.assertEqual(again.first_received, first.timestamp)
        self.assertEqual(again.first_log, first.ebics_log)
        self.assertEqual(again.sha256, first.sha256)
        # E09 sets duplicate; E08 keeps pending
        self.assertEqual(again.state, 'pending')
        # result page and run
        line, = result['lines']
        self.assertEqual((line['files'], line['repeated']), (1, 1))
        self.assertIn('1 file(s) received, of them 1 repeated',
            line['message'])
        self.assertIn('of them 1 repeated', result['summary'])
        run = Run.search([], order=[('id', 'DESC')], limit=1)[0]
        self.assertSteps(run,
            '1 file(s) received, of them 1 repeated',
            'Run finished: 1 file(s) received, of them 1 repeated')
        # filter "only repeated"
        files = LogFile.search([
                ('ebics_log.configuration', '=', configuration.id)])
        self.assertEqual(LogFile.search([
                    ('id', 'in', [f.id for f in files]),
                    ('repeated', '=', True)]), [again])
        self.assertEqual(LogFile.search([
                    ('id', 'in', [f.id for f in files]),
                    ('repeated', '=', False)]), [first])

    @with_transaction()
    def test_repeated_file_container_and_company(self):
        """Two equal files in one container: the second refers to the
        first; the same file in another company: no reference"""
        Date = Pool().get('ir.date')
        bank = fake_bank.FakeBank(keyring=cached_bank_keyring())
        configuration = self.active(bank)
        name, data = camt_generator.make_camt053(TEST_IBAN, entries=2)
        bank.add_download(CAMT053_BTF, 'a-' + name, data)
        bank.add_download(CAMT053_BTF, 'b-' + name, data)
        self.download(configuration, bank)
        log, = self.btd_logs(configuration)
        first, second = sorted(log.files, key=lambda f: f.id)
        self.assertIsNone(first.first_file)
        self.assertEqual(second.first_file, first)

        # another company fetches the same files again (period)
        other = self.active(bank, user_id='OTHERUSER')
        self.assertNotEqual(other.company, configuration.company)
        self.period_fetch(other, bank, Date.today())
        other_log, = self.btd_logs(other)
        a, b = sorted(other_log.files, key=lambda f: f.id)
        self.assertIsNone(a.first_file)
        self.assertEqual(b.first_file, a)

    @with_transaction()
    def test_copy_duplicate(self):
        "CpyDplctInd of camt.053 and camt.052 (first block), else empty"
        info = configuration_module.statement_info
        for value in ['COPY', 'DUPL', 'CODU']:
            with self.subTest(value=value):
                data = camt_generator.make_camt053(
                    TEST_IBAN, entries=1, copy_duplicate=value)[1]
                self.assertEqual(info(data)[2], value)
        data = camt_generator.make_camt053(TEST_IBAN, entries=1)[1]
        self.assertIsNone(info(data)[2])
        self.assertEqual(info(
                b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:'
                b'camt.052.001.08"><BkToCstmrAcctRpt><Rpt><Id>R1</Id>'
                b'<CpyDplctInd>DUPL</CpyDplctInd><Acct><Id><IBAN>'
                + TEST_IBAN_2.encode() + b'</IBAN></Id></Acct></Rpt>'
                b'</BkToCstmrAcctRpt></Document>'),
            ('camt.052.001.08', TEST_IBAN_2, 'DUPL'))
        # an older namespace version is read as well
        self.assertEqual(info(
                b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:'
                b'camt.054.001.02"><BkToCstmrDbtCdtNtfctn><Ntfctn>'
                b'<CpyDplctInd>COPY</CpyDplctInd></Ntfctn>'
                b'</BkToCstmrDbtCdtNtfctn></Document>')[2], 'COPY')
        # unknown values are not stored
        self.assertIsNone(info(
                b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:'
                b'camt.053.001.08"><BkToCstmrStmt><Stmt>'
                b'<CpyDplctInd>XXXX</CpyDplctInd></Stmt>'
                b'</BkToCstmrStmt></Document>')[2])
        with self.assertRaises(ValueError):
            camt_generator.make_camt053(TEST_IBAN, copy_duplicate='OTHER')

    @with_transaction()
    def test_repeated_fields_locked(self):
        "first_file and copy_duplicate cannot be changed (PR03)"
        pool = Pool()
        LogFile = pool.get('account.ebics.log.file')
        company = create_company()
        with set_company(company):
            log = create_log(company)
        file_ = log.files[0]
        for name, value in [('first_file', log.files[1].id),
                ('copy_duplicate', 'DUPL')]:
            with self.subTest(field=name):
                with self.assertRaises(AccessError):
                    LogFile.write_internal([file_], {name: value})
                with self.assertRaises(AccessError):
                    LogFile.write([file_], {name: value})
        self.assertIn('first_file', LogFile._fields)
        self.assertTrue(any(
                'sha256' in str(index.expressions[0][0])
                for index in LogFile._sql_indexes))

    @with_transaction()
    def test_fill_first_file(self):
        "Migration: earlier files get first_file once, idempotent"
        pool = Pool()
        LogFile = pool.get('account.ebics.log.file')
        company = create_company()
        with set_company(company):
            first_log = create_log(company)
            second_log = create_log(company, first_log.configuration)
        ids = [f.id for f in first_log.files + second_log.files]
        expected = {f.id: f.first_file.id if f.first_file else None
            for f in LogFile.browse(ids)}
        self.assertEqual(sorted(v for v in expected.values() if v),
            sorted(f.id for f in first_log.files))
        table = LogFile.__table__()
        cursor = Transaction().connection.cursor()
        cursor.execute(*table.update(
                [table.first_file], [None], where=table.id.in_(ids)))
        LogFile._fill_first_file()
        LogFile._fill_first_file()
        cursor.execute(*table.select(
                table.id, table.first_file, where=table.id.in_(ids)))
        self.assertEqual(dict(cursor), expected)


del ModuleTestCase

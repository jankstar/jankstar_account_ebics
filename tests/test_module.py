# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import contextlib
import datetime
import hashlib
import io
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
from trytond.modules.account_ebics.protocol import keys
from trytond.modules.account_ebics.protocol.exceptions import (
    EbicsTransportError)
from trytond.modules.account_ebics.tests import camt_generator, fake_bank
from trytond.modules.account_ebics.tests.test_protocol import (
    cached_bank_keyring, cached_keyring)
from trytond.modules.company.tests import (
    CompanyTestMixin, create_company, set_company)
from trytond.modules.currency.tests import add_currency_rate, create_currency
from trytond.pool import Pool
from trytond.pyson import Eval
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
            'print_ini_letter', 'print_hia_letter']
        self.assertEqual(sorted(names), sorted(
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


del ModuleTestCase

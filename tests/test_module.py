# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import datetime
import hashlib

from trytond.exceptions import UserError
from trytond.model.exceptions import AccessError
from trytond.modules.account.tests import create_chart
from trytond.modules.company.tests import (
    CompanyTestMixin, create_company, set_company)
from trytond.pool import Pool
from trytond.tests.test_tryton import ModuleTestCase, with_transaction
from trytond.transaction import Transaction

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


del ModuleTestCase

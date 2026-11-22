# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
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


del ModuleTestCase

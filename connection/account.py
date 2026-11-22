# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.i18n import gettext
from trytond.model import ModelSQL, ModelView, Unique, fields
from trytond.model.exceptions import ValidationError
from trytond.pool import Pool
from trytond.pyson import Eval
from trytond.transaction import without_check_access


class Account(ModelSQL, ModelView):
    __name__ = 'account.ebics.account'
    __string__ = "EBICS Account"

    configuration = fields.Many2One(
        'account.ebics.configuration', "Connection",
        required=True, ondelete='CASCADE')
    company = fields.Many2One(
        'company.company', "Company", required=True, readonly=True,
        help="The company of the connection.")
    company_party = fields.Function(
        fields.Many2One(
            'party.party', "Company Party",
            context={
                'company': Eval('company', -1),
                },
            depends={'company'}),
        'on_change_with_company_party')
    bank_account = fields.Many2One(
        'bank.account', "Bank Account", required=True, ondelete='RESTRICT',
        domain=[
            ('active', '=', True),
            ('owners.id', '=', Eval('company_party', -1)),
            ('numbers.type', '=', 'iban'),
            ],
        help="Active bank account of the company with an IBAN.")
    iban = fields.Function(
        fields.Char("IBAN"), 'on_change_with_iban', searcher='search_iban')
    import_statements = fields.Boolean(
        "Import Statements",
        help="Import the camt.053 statements of this account.")
    statement_journal = fields.Function(
        fields.Many2One(
            'account.statement.journal', "Statement Journal",
            help="The statement journal that account_statement_sepa finds "
            "for the IBAN and currency of the bank account.\n"
            "If empty, no or more than one journal matches; "
            "statements cannot be imported."),
        'on_change_with_statement_journal')

    @classmethod
    def __setup__(cls):
        super().__setup__()
        t = cls.__table__()
        cls._sql_constraints += [
            ('configuration_bank_account_unique',
                Unique(t, t.configuration, t.bank_account),
                'account_ebics.msg_account_bank_account_unique'),
            ]

    @classmethod
    def default_import_statements(cls):
        return True

    @fields.depends('configuration', '_parent_configuration.company')
    def on_change_with_company(self, name=None):
        if self.configuration and self.configuration.company:
            return self.configuration.company

    @fields.depends(
        'company', 'configuration', '_parent_configuration.company')
    def on_change_with_company_party(self, name=None):
        # The client computes each on_change_with from the current values;
        # for a new account the company is still empty (F4 domain).
        company = self.company
        if not company and self.configuration:
            company = self.configuration.company
        return company.party if company else None

    @classmethod
    def preprocess_values(cls, mode, values):
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        values = super().preprocess_values(mode, values)
        # F6: the company follows the connection
        if mode == 'create' and values.get('configuration') is not None:
            configuration = Configuration(values['configuration'])
            values.setdefault('company', configuration.company.id)
        return values

    @fields.depends('bank_account')
    def on_change_with_iban(self, name=None):
        if self.bank_account:
            return self.bank_account.iban

    @classmethod
    def search_iban(cls, name, clause):
        _, operator, operand, *extra = clause
        return [('bank_account.numbers', 'where', [
                    ('type', '=', 'iban'),
                    ['OR',
                        ('number', operator, operand, *extra),
                        ('number_compact', operator, operand, *extra),
                        ],
                    ])]

    @fields.depends(
        'bank_account', 'company', 'configuration',
        '_parent_configuration.company')
    def on_change_with_statement_journal(self, name=None):
        pool = Pool()
        Journal = pool.get('account.statement.journal')
        # for a new account the company is still empty (see company_party)
        company = self.company
        if not company and self.configuration:
            company = self.configuration.company
        if not company or not self.bank_account:
            return None
        iban = self.bank_account.iban_compact
        if not iban:
            return None
        currency = (
            self.bank_account.currency.code
            if self.bank_account.currency else None)
        with without_check_access():
            journal = Journal.get_by_bank_account(
                company.id, iban, currency=currency)
        return journal

    @classmethod
    def validate_fields(cls, accounts, field_names):
        super().validate_fields(accounts, field_names)
        cls.check_iban(accounts, field_names)
        cls.check_company(accounts, field_names)

    @classmethod
    def check_iban(cls, accounts, field_names=None):
        # KT02
        if field_names and 'bank_account' not in field_names:
            return
        for account in accounts:
            if not account.bank_account.iban:
                raise ValidationError(gettext(
                        'account_ebics.msg_account_iban_required',
                        bank_account=account.bank_account.rec_name))

    @classmethod
    def check_company(cls, accounts, field_names=None):
        # KT03 (variant A)
        if field_names and not (
                field_names & {'company', 'configuration'}):
            return
        for account in accounts:
            if account.company != account.configuration.company:
                raise ValidationError(gettext(
                        'account_ebics.msg_account_company',
                        account=account.rec_name,
                        configuration=account.configuration.rec_name))

    def get_rec_name(self, name):
        return '%s - %s' % (
            self.configuration.rec_name, self.bank_account.rec_name)

    @classmethod
    def search_rec_name(cls, name, clause):
        if clause[1].startswith('!') or clause[1].startswith('not '):
            bool_op = 'AND'
        else:
            bool_op = 'OR'
        return [bool_op,
            ('configuration.rec_name',) + tuple(clause[1:]),
            ('bank_account.rec_name',) + tuple(clause[1:]),
            ]

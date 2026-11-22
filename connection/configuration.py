# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import re

from trytond.i18n import gettext
from trytond.model import ModelSQL, ModelView, Unique, fields
from trytond.model.exceptions import ValidationError
from trytond.pool import Pool
from trytond.pyson import Eval
from trytond.transaction import Transaction

STATES = [
    ('draft', "Draft"),
    ('keys_generated', "Keys Generated"),
    ('ini_sent', "INI Sent"),
    ('bank_keys_received', "Bank Keys Received"),
    ('active', "Active"),
    ('suspended', "Suspended"),
    ]

# Access data that can only be changed in draft (F2)
_ACCESS_STATES = {
    'readonly': Eval('state') != 'draft',
    }

EXPECTED_HASH_FIELDS = ['bank_x002_hash_expected', 'bank_e002_hash_expected']
_HEX64 = re.compile(r'^[0-9A-F]{64}$')


def normalize_hash(value):
    "Remove all white space and return upper case, None for empty"
    if not value:
        return None
    value = re.sub(r'\s+', '', value).upper()
    return value or None


class Configuration(ModelSQL, ModelView):
    __name__ = 'account.ebics.configuration'
    __string__ = "EBICS Connection"

    name = fields.Char("Name", required=True)
    company = fields.Many2One(
        'company.company', "Company", required=True,
        states=_ACCESS_STATES,
        help="The company that holds the EBICS contract.")
    bank = fields.Many2One('bank', "Bank")
    url = fields.Char(
        "URL", required=True, states=_ACCESS_STATES,
        help="EBICS URL of the bank (https:// only).")
    host_id = fields.Char(
        "Host ID", required=True, states=_ACCESS_STATES)
    partner_id = fields.Char(
        "Partner ID", required=True, states=_ACCESS_STATES)
    user_id = fields.Char(
        "User ID", required=True, states=_ACCESS_STATES)
    ebics_version = fields.Selection([
            ('H005', "EBICS 3.0 (H005)"),
            ], "EBICS Version", required=True, readonly=True)
    key_bitlength = fields.Selection([
            ('2048', "2048"),
            ('3072', "3072"),
            ('4096', "4096"),
            ], "Key Length", required=True, sort=False,
        states=_ACCESS_STATES,
        help="Length of the RSA keys in bits, as required by the bank.")
    signature_class = fields.Selection([
            ('T', "T - Transport Signature"),
            ('E', "E - Single Signature"),
            ('A', "A - First Signature"),
            ('B', "B - Second Signature"),
            ], "Signature Class", required=True, sort=False,
        help="Only effective with payment upload (v2).")

    keyring_data = fields.Binary(
        "Keyring", readonly=True,
        file_id='keyring_data_id', store_prefix=None)
    keyring_data_id = fields.Char("Keyring ID", readonly=True)
    bank_keys_data = fields.Binary(
        "Bank Keys", readonly=True,
        file_id='bank_keys_data_id', store_prefix=None)
    bank_keys_data_id = fields.Char("Bank Keys ID", readonly=True)

    user_a006_hash = fields.Char("User A006 Hash", readonly=True)
    user_x002_hash = fields.Char("User X002 Hash", readonly=True)
    user_e002_hash = fields.Char("User E002 Hash", readonly=True)
    bank_x002_hash = fields.Char("Bank X002 Hash", readonly=True)
    bank_e002_hash = fields.Char("Bank E002 Hash", readonly=True)
    bank_x002_hash_expected = fields.Char(
        "Expected Bank X002 Hash",
        help="Hash value of the bank's X002 certificate as published by "
        "the bank (64 hexadecimal characters, spaces are ignored).")
    bank_e002_hash_expected = fields.Char(
        "Expected Bank E002 Hash",
        help="Hash value of the bank's E002 certificate as published by "
        "the bank (64 hexadecimal characters, spaces are ignored).")
    ini_sent = fields.Boolean("INI Sent", readonly=True)
    hia_sent = fields.Boolean("HIA Sent", readonly=True)

    formats = fields.Many2Many(
        'account.ebics.configuration-account.ebics.format',
        'configuration', 'format', "Formats",
        domain=[
            ('direction', '=', 'download'),
            ],
        help="The formats to download for all accounts of this connection.")
    last_fetch = fields.DateTime("Last Fetch", readonly=True)
    state = fields.Selection(
        STATES, "State", required=True, readonly=True, sort=False)
    accounts = fields.One2Many(
        'account.ebics.account', 'configuration', "Accounts")

    @classmethod
    def __setup__(cls):
        super().__setup__()
        t = cls.__table__()
        cls._sql_constraints += [
            ('participant_unique',
                Unique(t, t.company, t.host_id, t.partner_id, t.user_id),
                'account_ebics.msg_configuration_participant_unique'),
            ]
        cls._order.insert(0, ('name', 'ASC'))

    @classmethod
    def default_company(cls):
        return Transaction().context.get('company')

    @classmethod
    def default_ebics_version(cls):
        return 'H005'

    @classmethod
    def default_key_bitlength(cls):
        return '2048'

    @classmethod
    def default_signature_class(cls):
        return 'T'

    @classmethod
    def default_state(cls):
        return 'draft'

    @classmethod
    def default_ini_sent(cls):
        return False

    @classmethod
    def default_hia_sent(cls):
        return False

    @classmethod
    def default_formats(cls):
        pool = Pool()
        ModelData = pool.get('ir.model.data')
        Format = pool.get('account.ebics.format')
        try:
            format_id = ModelData.get_id('account_ebics', 'format_camt053_de')
        except KeyError:
            return []
        formats = Format.search([('id', '=', format_id)])
        return [f.id for f in formats]

    @fields.depends('bank_x002_hash_expected')
    def on_change_bank_x002_hash_expected(self):
        self.bank_x002_hash_expected = normalize_hash(
            self.bank_x002_hash_expected)

    @fields.depends('bank_e002_hash_expected')
    def on_change_bank_e002_hash_expected(self):
        self.bank_e002_hash_expected = normalize_hash(
            self.bank_e002_hash_expected)

    @classmethod
    def preprocess_values(cls, mode, values):
        values = super().preprocess_values(mode, values)
        for name in EXPECTED_HASH_FIELDS:
            if name in values:
                values[name] = normalize_hash(values[name])
        return values

    @classmethod
    def validate_fields(cls, configurations, field_names):
        super().validate_fields(configurations, field_names)
        cls.check_url(configurations, field_names)
        cls.check_expected_hashes(configurations, field_names)

    @classmethod
    def check_url(cls, configurations, field_names=None):
        # KF01
        if field_names and 'url' not in field_names:
            return
        for configuration in configurations:
            if not (configuration.url or '').startswith('https://'):
                raise ValidationError(gettext(
                        'account_ebics.msg_configuration_url_https',
                        configuration=configuration.rec_name))

    @classmethod
    def check_expected_hashes(cls, configurations, field_names=None):
        # KF03
        if field_names and not (field_names & set(EXPECTED_HASH_FIELDS)):
            return
        for configuration in configurations:
            for name in EXPECTED_HASH_FIELDS:
                value = getattr(configuration, name)
                if value and not _HEX64.match(value):
                    raise ValidationError(gettext(
                            'account_ebics.msg_configuration_hash_format',
                            configuration=configuration.rec_name,
                            field=cls.__names__(name)['field']))

    @classmethod
    def copy(cls, configurations, default=None):
        default = default.copy() if default is not None else {}
        # A copy is a new participant without keys or initialisation
        for name in ['keyring_data', 'keyring_data_id', 'bank_keys_data',
                'bank_keys_data_id', 'user_a006_hash', 'user_x002_hash',
                'user_e002_hash', 'bank_x002_hash', 'bank_e002_hash',
                'last_fetch']:
            default.setdefault(name, None)
        default.setdefault('ini_sent', False)
        default.setdefault('hia_sent', False)
        default.setdefault('state', 'draft')
        default.setdefault('accounts', None)
        return super().copy(configurations, default=default)


class ConfigurationFormat(ModelSQL):
    __name__ = 'account.ebics.configuration-account.ebics.format'
    __string__ = "EBICS Connection - Format"

    configuration = fields.Many2One(
        'account.ebics.configuration', "Connection",
        required=True, ondelete='CASCADE')
    format = fields.Many2One(
        'account.ebics.format', "Format", required=True, ondelete='RESTRICT')

    @classmethod
    def __setup__(cls):
        super().__setup__()
        t = cls.__table__()
        cls._sql_constraints += [
            ('configuration_format_unique',
                Unique(t, t.configuration, t.format),
                'account_ebics.msg_configuration_format_unique'),
            ]

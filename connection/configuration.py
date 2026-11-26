# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import hashlib
import io
import re
import zipfile

from sql import Select

from trytond import config
from trytond.exceptions import UserError
from trytond.i18n import gettext
from trytond.model import ModelSQL, ModelView, Unique, fields
from trytond.model.exceptions import ValidationError
from trytond.pool import Pool
from trytond.pyson import Bool, Eval
from trytond.transaction import Transaction, without_check_access
from trytond.wizard import Button, StateTransition, StateView, Wizard

from ..core.history import HistoryMixin
from ..protocol import client, keys, returncodes
from ..protocol import xml as ebics_xml
from ..protocol.exceptions import (
    EbicsError, EbicsKeyringError, EbicsTransportError)
from ..protocol.transport import HttpsTransport

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

#: Section of trytond.conf (specification ch. 12)
SECTION = 'account_ebics'
#: Order types of the key management with their flag (working paper E06
#: ch. 4.1)
KEY_ORDERS = {
    'INI': 'ini_sent',
    'HIA': 'hia_sent',
    }
#: Fields cleared when resetting to draft (working paper E06 ch. 4.6)
RESET_VALUES = {
    'keyring_data': None,
    'user_a006_hash': None,
    'user_x002_hash': None,
    'user_e002_hash': None,
    'bank_keys_data': None,
    'bank_x002_hash': None,
    'bank_e002_hash': None,
    'ini_sent': False,
    'hia_sent': False,
    'state': 'draft',
    }


def setting(name, default=None):
    "Value of [account_ebics] in trytond.conf (specification ch. 12)"
    value = config.get(SECTION, name, default=default)
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return default
    return value


def setting_int(name, default):
    value = setting(name)
    if value is None:
        return default
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise UserError(gettext(
                'account_ebics.msg_configuration_setting', name=name))
    if value <= 0:
        raise UserError(gettext(
                'account_ebics.msg_configuration_setting', name=name))
    return value


def passphrase():
    """Passphrase of the key containers from trytond.conf or the environment
    variable TRYTOND_ACCOUNT_EBICS__PASSPHRASE (specification ch. 8.1,
    decision F2 of E06); never stored, logged or shown"""
    value = config.get(SECTION, 'passphrase', default=None)
    if not value:
        raise UserError(gettext('account_ebics.msg_passphrase_missing'))
    return value


def format_hash(value):
    """Hash value in groups of two hexadecimal characters, 16 groups per
    line (decision F6 of E06; EBICS specification V 3.0.2 (DE) ch. 11.5.1,
    11.5.2)"""
    pairs = [value[i:i + 2] for i in range(0, len(value or ''), 2)]
    return [' '.join(pairs[i:i + 16]) for i in range(0, len(pairs), 16)]


def order_lock_id(configuration_id):
    """Key of the advisory lock of the orders of a connection (same
    derivation as str2bigint of trytond/ir/cron.py)"""
    key = 'account.ebics.configuration,order,%s' % configuration_id
    return int(hashlib.sha256(key.encode('utf-8')).hexdigest(), 16) % 10**8


def payload(result):
    """ZIP with request.xml and response.xml of an order for the log: only
    public data (INI/HIA contain only certificates; specification ch. 5.3)"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as container:
        if result is not None and result.request:
            container.writestr('request.xml', result.request)
        if result is not None and result.response:
            container.writestr('response.xml', result.response)
    return buffer.getvalue()


def normalize_hash(value):
    "Remove all white space and return upper case, None for empty"
    if not value:
        return None
    value = re.sub(r'\s+', '', value).upper()
    return value or None


class Configuration(HistoryMixin, ModelSQL, ModelView):
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
    logs = fields.One2Many(
        'account.ebics.log', 'configuration', "Logs", readonly=True)

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
        # visible only in the state they fit (decision F1 of E06)
        cls._buttons.update({
                'generate_keys': {
                    'invisible': Eval('state') != 'draft',
                    'depends': ['state'],
                    },
                'send_ini': {
                    'invisible': ((Eval('state') != 'keys_generated')
                        | Bool(Eval('ini_sent'))),
                    'depends': ['state', 'ini_sent'],
                    },
                'send_hia': {
                    'invisible': ((Eval('state') != 'keys_generated')
                        | Bool(Eval('hia_sent'))),
                    'depends': ['state', 'hia_sent'],
                    },
                'reset_draft': {
                    'invisible': Eval('state') == 'draft',
                    'depends': ['state'],
                    },
                'print_ini_letter': {
                    'invisible': ~Bool(Eval('ini_sent')),
                    'depends': ['ini_sent'],
                    },
                'print_hia_letter': {
                    'invisible': ~Bool(Eval('hia_sent')),
                    'depends': ['hia_sent'],
                    },
                })

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

    # Keys and orders (working paper E06 ch. 4)

    def _subject(self):
        """Subject of the certificates: CN=user ID, O=company, C=country of
        the company if it has a two-letter code (specification ch. 6.4)"""
        party = self.company.party
        country = None
        address = party.address_get()
        if address and address.country and address.country.code:
            code = address.country.code.strip().upper()
            if len(code) == 2:
                country = code
        organization = (party.rec_name or self.company.rec_name)[:64]
        return keys.Subject(self.user_id, organization, country)

    def _check_ids(self):
        errors = ebics_xml.validate_ids(
            host_id=self.host_id, partner_id=self.partner_id,
            user_id=self.user_id)
        if errors:
            raise UserError(gettext(
                    'account_ebics.msg_configuration_ids',
                    configuration=self.rec_name,
                    fields=', '.join(sorted(errors))))

    @classmethod
    def _lock_order(cls, configuration):
        """Advisory lock of the connection in the current transaction, held
        until its end; another order of the same connection is refused.

        No row lock (lock() is SELECT ... FOR UPDATE NOWAIT under
        PostgreSQL): the log is written in the same transaction, and a row
        lock of another transaction would block its foreign key check
        (FOR KEY SHARE); decision F11 of E06, pattern of trytond/ir/cron.py
        get_running. Under SQLite (development and tests only) lock_id is
        always true."""
        transaction = Transaction()
        cursor = transaction.connection.cursor()
        cursor.execute(*Select([
                    transaction.database.lock_id(
                        order_lock_id(configuration.id))]))
        if not cursor.fetchone()[0]:
            raise UserError(gettext(
                    'account_ebics.msg_order_running',
                    configuration=configuration.rec_name))

    def _load_keyring(self):
        "The key container of the connection (passphrase from trytond.conf)"
        secret = passphrase()
        with without_check_access():
            data = self.__class__(self.id).keyring_data
        if not data:
            raise UserError(gettext(
                    'account_ebics.msg_keyring_missing',
                    configuration=self.rec_name))
        try:
            return keys.load_keyring(bytes(data), secret)
        except EbicsKeyringError:
            # no details: never the passphrase or library messages
            raise UserError(gettext(
                    'account_ebics.msg_keyring_unreadable',
                    configuration=self.rec_name)) from None

    def _ebics_transport(self):
        """Transport to the bank (specification ch. 8.2, working paper E06
        ch. 4.7): HTTPS with TLS verification, values from trytond.conf;
        the tests replace it with the simulated bank"""
        return HttpsTransport(
            self.url,
            timeout=setting_int('timeout', 60),
            ca_bundle=setting('ca_bundle'),
            max_response_size=setting_int(
                'max_response_size', ebics_xml.DEFAULT_MAX_SIZE))

    def _ebics_client(self, keyring):
        try:
            connection = client.Connection(
                self.host_id, self.partner_id, self.user_id, self.url)
        except ValueError:
            self._check_ids()
            raise
        try:
            transport = self._ebics_transport()
        except EbicsTransportError as exception:
            raise UserError(gettext(
                    'account_ebics.msg_transport_error',
                    configuration=self.rec_name,
                    error=str(exception))) from None
        try:
            return client.EbicsClient(
                connection, keyring, transport,
                xsd_dir=setting('xsd_dir'), xsd_mode=setting('xsd_mode'),
                max_response_size=setting_int(
                    'max_response_size', ebics_xml.DEFAULT_MAX_SIZE))
        except ValueError:
            raise UserError(gettext(
                    'account_ebics.msg_configuration_setting',
                    name='xsd_mode')) from None

    @classmethod
    @ModelView.button
    def generate_keys(cls, configurations):
        """Three key pairs A006, X002, E002 with certificates, the container
        encrypted with the passphrase (specification ch. 6.2 step 1, 8.1)"""
        secret = passphrase()
        for configuration in configurations:
            cls._lock_order(configuration)
        to_save = []
        for configuration in configurations:
            if configuration.state != 'draft':
                continue
            configuration._check_ids()
            keyring = keys.generate_keyring(
                int(configuration.key_bitlength), configuration._subject())
            parts = keys.public_parts(keyring)
            configuration.keyring_data = keys.dump_keyring(keyring, secret)
            configuration.user_a006_hash = parts['A006']['hash']
            configuration.user_x002_hash = parts['X002']['hash']
            configuration.user_e002_hash = parts['E002']['hash']
            configuration.ini_sent = False
            configuration.hia_sent = False
            configuration.state = 'keys_generated'
            to_save.append(configuration)
        with Transaction().set_context(_log=True):
            cls.save(to_save)

    @classmethod
    @ModelView.button
    def send_ini(cls, configurations):
        "INI with the A006 certificate (specification ch. 6.2 step 2)"
        for configuration in configurations:
            configuration._send_key_order('INI')

    @classmethod
    @ModelView.button
    def send_hia(cls, configurations):
        "HIA with the X002 and E002 certificates (ch. 6.2 step 2)"
        for configuration in configurations:
            configuration._send_key_order('HIA')

    @classmethod
    @ModelView.button_action(
        'account_ebics.wizard_configuration_reset_draft')
    def reset_draft(cls, configurations):
        pass

    @classmethod
    @ModelView.button_action('account_ebics.report_ini_letter_ini')
    def print_ini_letter(cls, configurations):
        pass

    @classmethod
    @ModelView.button_action('account_ebics.report_ini_letter_hia')
    def print_hia_letter(cls, configurations):
        pass

    def _send_key_order(self, order_type):
        """Send INI or HIA in a transaction of its own: advisory lock,
        order, log and flags are committed together, also the log of a
        failed order (decisions F3, F11 of E06); then the message"""
        keyring = self._load_keyring()
        ebics = self._ebics_client(keyring)
        # committed at the end of the block, rolled back only on an
        # unexpected exception
        with Transaction().new_transaction(), without_check_access():
            result, error = self.__class__(self.id)._key_order(
                order_type, ebics)
        if result is None and error is None:
            # already sent or not in the state any more
            return
        self._raise_order_error(order_type, result, error)

    def _key_order(self, order_type, ebics):
        """In the transaction of the order: lock, check the state again, run
        the order, record the log, set the flag and maybe the state"""
        pool = Pool()
        Log = pool.get('account.ebics.log')
        flag = KEY_ORDERS[order_type]
        self._lock_order(self)
        if self.state != 'keys_generated' or getattr(self, flag):
            return None, None
        error = None
        try:
            result = getattr(ebics, order_type.lower())()
        except EbicsError as exception:
            error = exception
            result = getattr(exception, 'result', None)
        Log.record(self, order_type, self._log_values(result, error))
        if error is None and result.ok:
            values = {flag: True}
            other = [f for f in KEY_ORDERS.values() if f != flag]
            if all(getattr(self, f) for f in other):
                values['state'] = 'ini_sent'
            with Transaction().set_context(_log=True):
                self.__class__.write([self], values)
        return result, error

    @staticmethod
    def _log_values(result, error):
        "Values of the log: codes, text of the bank, public payload"
        values = {
            'state': 'done',
            'payload': payload(result),
            }
        if result is not None:
            values.update({
                    'technical_return_code': (
                        result.technical.code if result.technical else None),
                    'business_return_code': (
                        result.business.code if result.business else None),
                    'return_message': result.report_text,
                    'ebics_order_id': result.order_id,
                    })
        if error is not None:
            values['state'] = 'error'
            # protocol messages contain no key material (ch. 4.3, 8.1)
            values['return_message'] = '%s: %s' % (
                type(error).__name__, error)
        elif result is None or not result.ok:
            values['state'] = 'error'
        return values

    def _raise_order_error(self, order_type, result, error):
        "UserError after a failed order (working paper E06 ch. 4.5)"
        if isinstance(error, EbicsTransportError):
            raise UserError(gettext(
                    'account_ebics.msg_transport_error',
                    configuration=self.rec_name, error=str(error)))
        if error is not None:
            raise UserError(gettext(
                    'account_ebics.msg_order_failed',
                    configuration=self.rec_name, order_type=order_type,
                    error=str(error)))
        if result.ok:
            return
        code, text = result.technical, result.report_text
        if (code is None
                or code.klass in {returncodes.OK, returncodes.INFO}):
            # the report text of the bank belongs to the technical code;
            # for a business code the text of annex 1
            code = result.business or code
            text = code.text if code else None
        if (code is not None and code.code == '091002'
                and code.kind == returncodes.TECHNICAL):
            raise UserError(gettext(
                    'account_ebics.msg_order_user_state',
                    configuration=self.rec_name, order_type=order_type))
        raise UserError(gettext(
                'account_ebics.msg_order_ebics_error',
                configuration=self.rec_name, order_type=order_type,
                code=code.code if code else '-',
                symbol=(code.symbol if code else None) or '',
                text=text or (code.text if code else '')))

    def reset_to_draft(self):
        """Delete keys, hash values, flags and bank keys; the log stays
        (working paper E06 ch. 4.6)"""
        self._lock_order(self)
        with without_check_access(), \
                Transaction().set_context(_log=True):
            self.__class__.write([self], dict(RESET_VALUES))

    def last_order_log(self, order_type):
        "The last successful log of the order type (initialisation letters)"
        pool = Pool()
        Log = pool.get('account.ebics.log')
        with without_check_access():
            logs = Log.search([
                    ('configuration', '=', self.id),
                    ('order_type', '=', order_type),
                    ('state', '=', 'done'),
                    ], order=[('timestamp', 'DESC'), ('id', 'DESC')],
                limit=1)
        return logs[0] if logs else None

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
        default.setdefault('logs', None)
        return super().copy(configurations, default=default)


class ConfigurationFormat(HistoryMixin, ModelSQL):
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


class ConfigurationResetDraftStart(ModelView):
    __name__ = 'account.ebics.configuration.reset_draft.start'
    __string__ = "Reset EBICS Connection to Draft"

    name = fields.Char("Name", readonly=True)
    host_id = fields.Char("Host ID", readonly=True)
    partner_id = fields.Char("Partner ID", readonly=True)
    user_id = fields.Char("User ID", readonly=True)
    confirm = fields.Boolean(
        "Yes, I want to delete",
        help="The private keys of this connection are deleted for good.")


class ConfigurationResetDraft(Wizard):
    "Dialog to reset a connection to draft (working paper E06 ch. 4.6)"
    __name__ = 'account.ebics.configuration.reset_draft'

    start = StateView(
        'account.ebics.configuration.reset_draft.start',
        'account_ebics.configuration_reset_draft_start_view_form', [
            Button("Cancel", 'end', 'tryton-cancel'),
            Button("Reset", 'reset', 'tryton-clear', default=True,
                states={
                    'readonly': ~Eval('confirm', False),
                    }),
            ])
    reset = StateTransition()

    def default_start(self, fields):
        record = self._configuration()
        return {
            'name': record.name,
            'host_id': record.host_id,
            'partner_id': record.partner_id,
            'user_id': record.user_id,
            'confirm': False,
            }

    def transition_reset(self):
        pool = Pool()
        ModelAccess = pool.get('ir.model.access')
        # the server checks the confirmation again (F7 of E06)
        if not self.start.confirm:
            raise UserError(gettext(
                    'account_ebics.msg_reset_not_confirmed',
                    configuration=self._configuration().rec_name))
        ModelAccess.check('account.ebics.configuration', 'write')
        configuration = self._configuration()
        if configuration.state != 'draft':
            configuration.reset_to_draft()
        return 'end'

    def _configuration(self):
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        context = Transaction().context
        if (context.get('active_model') != Configuration.__name__
                or context.get('active_id') is None):
            raise UserError(gettext(
                    'account_ebics.msg_reset_not_confirmed',
                    configuration='-'))
        return Configuration(context['active_id'])

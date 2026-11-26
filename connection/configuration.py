# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import datetime
import hashlib
import io
import json
import re
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
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
#: States from which HPB is possible (working paper E07 ch. 4.1, F4)
HPB_STATES = {'ini_sent', 'bank_keys_received', 'active', 'suspended'}
#: States with confirmed bank keys (D7)
CONFIRMED_STATES = {'active', 'suspended'}
#: Purposes of the bank keys (EBICS specification V 3.0.2 (DE) ch. 4.4.2)
BANK_PURPOSES = ('X002', 'E002')
BANK_KEYS_VERSION = 1
#: Result of the comparison with the hash values published by the bank
HASH_CHECKS = [
    (None, ""),
    ('match', "Match"),
    ('mismatch', "Mismatch"),
    ('no_expected', "No Value of the Bank"),
    ]
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
    'confirmed_state': None,
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


def bank_keys_zip(bank_keys, host_id, now=None):
    """Container of the bank keys (working paper E07 F2): ZIP with X002.pem,
    E002.pem and manifest.json (version, received, host_id, per purpose
    version and hash value); public data only, not encrypted"""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    manifest = {
        'version': BANK_KEYS_VERSION,
        'received': now.astimezone(datetime.timezone.utc).isoformat(),
        'host_id': host_id,
        'keys': {},
        }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as container:
        for purpose in BANK_PURPOSES:
            certificate = bank_keys[purpose]['certificate']
            container.writestr(
                purpose + '.pem',
                certificate.public_bytes(serialization.Encoding.PEM))
            manifest['keys'][purpose] = {
                'version': bank_keys[purpose]['version'],
                'hash': keys.certificate_hash(certificate),
                }
        container.writestr(
            'manifest.json', json.dumps(manifest, indent=2, sort_keys=True))
    return buffer.getvalue()


def load_bank_keys(data):
    """{purpose: certificate} of the container of bank_keys_zip(); the hash
    values must match the manifest"""
    result = {}
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as container:
        names = set(container.namelist())
        expected = {p + '.pem' for p in BANK_PURPOSES} | {'manifest.json'}
        if names != expected:
            raise ValueError("Unexpected files in the bank keys")
        for name in expected:
            if container.getinfo(name).file_size > 1024 * 1024:
                raise ValueError("File too big in the bank keys")
        manifest = json.loads(container.read('manifest.json'))
        if manifest.get('version') != BANK_KEYS_VERSION:
            raise ValueError("Unknown version of the bank keys")
        for purpose in BANK_PURPOSES:
            certificate = x509.load_pem_x509_certificate(
                container.read(purpose + '.pem'))
            if (keys.certificate_hash(certificate)
                    != manifest['keys'][purpose]['hash']):
                raise ValueError("Hash value of the bank key %s" % purpose)
            result[purpose] = certificate
    return result


def compare_hash(value, expected):
    "Result of the comparison (HASH_CHECKS) of a bank hash value"
    if not value:
        return None
    if not expected:
        return 'no_expected'
    return 'match' if normalize_hash(expected) == value else 'mismatch'


def overall_check(checks):
    """One result for X002 and E002: mismatch if one differs, match only if
    both match, otherwise no_expected (the comparison by sight is needed)"""
    if any(c is None for c in checks):
        return None
    if 'mismatch' in checks:
        return 'mismatch'
    if all(c == 'match' for c in checks):
        return 'match'
    return 'no_expected'


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
    # display in groups of two (decision F8 of E07, F6 of E06)
    bank_x002_hash_groups = fields.Function(
        fields.Text("Bank X002 Hash"), 'get_hash_groups')
    bank_e002_hash_groups = fields.Function(
        fields.Text("Bank E002 Hash"), 'get_hash_groups')
    bank_x002_hash_expected_groups = fields.Function(
        fields.Text("Expected Bank X002 Hash"), 'get_hash_groups')
    bank_e002_hash_expected_groups = fields.Function(
        fields.Text("Expected Bank E002 Hash"), 'get_hash_groups')
    bank_x002_hash_check = fields.Function(
        fields.Selection(HASH_CHECKS, "X002 Comparison"), 'get_hash_check')
    bank_e002_hash_check = fields.Function(
        fields.Selection(HASH_CHECKS, "E002 Comparison"), 'get_hash_check')

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
    # E07.1 (F9): state before the fall back to bank_keys_received, the
    # state after the confirmation; empty means active (also for the
    # records before E07.1, no migration needed)
    confirmed_state = fields.Selection([
            (None, ""),
            ('active', "Active"),
            ('suspended', "Suspended"),
            ], "State after Confirmation", readonly=True, sort=False,
        help="The state the connection gets when the bank keys are "
        "confirmed.")
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
                # working paper E07 ch. 4.1
                'fetch_bank_keys': {
                    'invisible': ~Eval('state').in_(sorted(HPB_STATES)),
                    'depends': ['state'],
                    },
                'confirm_bank_keys': {
                    'invisible': Eval('state') != 'bank_keys_received',
                    'depends': ['state'],
                    },
                'suspend': {
                    'invisible': Eval('state') != 'active',
                    'depends': ['state'],
                    },
                'reactivate': {
                    'invisible': Eval('state') != 'suspended',
                    'depends': ['state'],
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

    def get_hash_groups(self, name):
        value = getattr(self, name[:-len('_groups')])
        return '\n'.join(format_hash(value)) if value else None

    def get_hash_check(self, name):
        purpose = name.split('_')[1]
        return compare_hash(
            getattr(self, 'bank_%s_hash' % purpose),
            getattr(self, 'bank_%s_hash_expected' % purpose))

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
        "Send INI or HIA (working paper E06 ch. 4.2)"
        flag = KEY_ORDERS[order_type]

        def allowed(configuration):
            return (configuration.state == 'keys_generated'
                and not getattr(configuration, flag))

        def succeeded(configuration, result):
            values = {flag: True}
            if all(getattr(configuration, f)
                    for f in KEY_ORDERS.values() if f != flag):
                values['state'] = 'ini_sent'
            configuration._write_internal(values)
        self._run_order(
            order_type, lambda ebics: getattr(ebics, order_type.lower())(),
            allowed, succeeded)

    def _run_order(self, order_type, call, allowed, succeeded):
        """Frame of every order (D27): in a transaction of its own an
        advisory lock, the state checked again, the order, the log, the
        changes of a success or of 091008; committed also when the order
        fails; then the message in the request transaction"""
        keyring = self._load_keyring()
        ebics = self._ebics_client(keyring)
        # committed at the end of the block, rolled back only on an
        # unexpected exception
        with Transaction().new_transaction(), without_check_access():
            result, error = self.__class__(self.id)._order_in_transaction(
                order_type, ebics, call, allowed, succeeded)
        if result is None and error is None:
            # already done or not in the state any more
            return None
        self._raise_order_error(order_type, result, error)
        return result

    def _order_in_transaction(
            self, order_type, ebics, call, allowed, succeeded):
        "Part of _run_order in the transaction of the order"
        pool = Pool()
        Log = pool.get('account.ebics.log')
        self._lock_order(self)
        if not allowed(self):
            return None, None
        error = None
        try:
            result = call(ebics)
        except EbicsError as exception:
            error = exception
            result = getattr(exception, 'result', None)
        Log.record(self, order_type, self._log_values(result, error))
        if error is None and result.ok:
            succeeded(self, result)
        else:
            self._check_bank_keys_update(result)
        return result, error

    def _write_internal(self, values):
        "Change of the server code, logged in ir.model.log"
        with without_check_access(), \
                Transaction().set_context(_log=True):
            self.__class__.write([self], values)

    @staticmethod
    def _technical_code(result):
        if result is not None and result.technical is not None:
            return result.technical.code

    def _check_bank_keys_update(self, result):
        """Common block for 091008 EBICS_BANK_PUBKEY_UPDATE_REQUIRED (working
        paper E07 ch. 4.4, F7; used by the orders from E08): the confirmed
        bank keys are no longer valid, state bank_keys_received; the log is
        written by the order frame, the message by _raise_order_error.
        Return True if the code was 091008."""
        if self._technical_code(result) != '091008':
            return False
        if self.state in CONFIRMED_STATES:
            self._write_internal(self._fall_back_values())
        return True

    def _fall_back_values(self):
        """Back to bank_keys_received from a state with confirmed bank keys;
        a suspended connection stays suspended after the confirmation
        (F9, variant A)"""
        return {
            'state': 'bank_keys_received',
            'confirmed_state': self.state,
            }

    @property
    def state_after_confirmation(self):
        "suspended if the connection was suspended before (F9), else active"
        return 'suspended' if self.confirmed_state == 'suspended' \
            else 'active'

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
        technical = self._technical_code(result)
        if technical == '091008':
            raise UserError(gettext(
                    'account_ebics.msg_bank_keys_update_required',
                    configuration=self.rec_name, order_type=order_type))
        if order_type == 'HPB' and technical == '091002':
            raise UserError(gettext(
                    'account_ebics.msg_hpb_not_released',
                    configuration=self.rec_name))
        if technical == '091004':
            raise UserError(gettext(
                    'account_ebics.msg_participant_suspended',
                    configuration=self.rec_name, order_type=order_type))
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

    # Bank keys (working paper E07)

    @classmethod
    @ModelView.button
    def fetch_bank_keys(cls, configurations):
        "HPB (specification ch. 6.2 step 4)"
        for configuration in configurations:
            configuration._fetch_bank_keys()

    @classmethod
    @ModelView.button_action(
        'account_ebics.wizard_configuration_confirm_bank_keys')
    def confirm_bank_keys(cls, configurations):
        pass

    @classmethod
    @ModelView.button
    def suspend(cls, configurations):
        "No downloads any more; no message to the bank (F4)"
        for configuration in configurations:
            cls._lock_order(configuration)
            if configuration.state == 'active':
                configuration._write_internal({'state': 'suspended'})

    @classmethod
    @ModelView.button
    def reactivate(cls, configurations):
        "Back to active, only with confirmed bank keys (F4)"
        for configuration in configurations:
            cls._lock_order(configuration)
            if configuration.state != 'suspended':
                continue
            if not configuration._has_bank_keys():
                raise UserError(gettext(
                        'account_ebics.msg_reactivate_no_bank_keys',
                        configuration=configuration.rec_name))
            configuration._write_internal({'state': 'active'})

    def _has_bank_keys(self):
        with without_check_access():
            data = self.__class__(self.id).bank_keys_data
        return bool(data and self.bank_x002_hash and self.bank_e002_hash)

    def bank_keys(self):
        """The confirmed bank keys {purpose: certificate} for the orders
        from E08; the stored hash values must match"""
        with without_check_access():
            data = self.__class__(self.id).bank_keys_data
        try:
            if not data or self.state not in CONFIRMED_STATES:
                raise ValueError("No confirmed bank keys")
            result = load_bank_keys(data)
            for purpose in BANK_PURPOSES:
                if (keys.certificate_hash(result[purpose])
                        != getattr(self, 'bank_%s_hash' % purpose.lower())):
                    raise ValueError("Hash value of %s" % purpose)
        except (ValueError, KeyError, zipfile.BadZipFile):
            raise UserError(gettext(
                    'account_ebics.msg_bank_keys_missing',
                    configuration=self.rec_name)) from None
        return result

    def _fetch_bank_keys(self):
        "HPB in the order frame; the result as notification"
        def allowed(configuration):
            return configuration.state in HPB_STATES

        def succeeded(configuration, result):
            bank_keys = result.data['bank_keys']
            hashes = {p: bank_keys[p]['hash'] for p in BANK_PURPOSES}
            old = {p: getattr(configuration, 'bank_%s_hash' % p.lower())
                for p in BANK_PURPOSES}
            if configuration.state in CONFIRMED_STATES:
                if hashes == old:
                    # F6: unchanged, the state stays
                    configuration._notify(
                        'msg_bank_keys_unchanged', 'tryton-info')
                    return
                message, icon = 'msg_bank_keys_changed', 'tryton-warning'
            else:
                message, icon = 'msg_bank_keys_received', 'tryton-info'
            values = {
                'bank_keys_data': bank_keys_zip(
                    bank_keys, configuration.host_id),
                'bank_x002_hash': hashes['X002'],
                'bank_e002_hash': hashes['E002'],
                'state': 'bank_keys_received',
                }
            if configuration.state in CONFIRMED_STATES:
                # remember active or suspended (F9); from ini_sent or
                # bank_keys_received the remembered value stays
                values.update(configuration._fall_back_values())
            configuration._write_internal(values)
            configuration._notify(message, icon)
        self._run_order(
            'HPB', lambda ebics: ebics.hpb(), allowed, succeeded)

    def _notify(self, message, icon):
        "Notification of the user who started the order"
        # notify_user is a dualmethod: call it on the class
        self.__class__.notify_user(
            [self], icon, gettext(
                'account_ebics.' + message, configuration=self.rec_name))

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
        default.setdefault('confirmed_state', None)
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


class ConfigurationConfirmBankKeysStart(ModelView):
    __name__ = 'account.ebics.configuration.confirm_bank_keys.start'
    __string__ = "Confirm Bank Keys"

    bank = fields.Char("Bank", readonly=True)
    host_id = fields.Char("Host ID", readonly=True)
    x002_hash = fields.Char("X002 Hash", readonly=True)
    e002_hash = fields.Char("E002 Hash", readonly=True)
    x002_hash_groups = fields.Text("Bank X002 Hash", readonly=True)
    e002_hash_groups = fields.Text("Bank E002 Hash", readonly=True)
    x002_expected_groups = fields.Text(
        "Expected Bank X002 Hash", readonly=True)
    e002_expected_groups = fields.Text(
        "Expected Bank E002 Hash", readonly=True)
    x002_check = fields.Selection(
        HASH_CHECKS, "X002 Comparison", readonly=True)
    e002_check = fields.Selection(
        HASH_CHECKS, "E002 Comparison", readonly=True)
    check = fields.Selection(HASH_CHECKS, "Result", readonly=True)
    stays_suspended = fields.Boolean(
        "Stays Suspended", readonly=True,
        help="The connection was suspended before; after the confirmation "
        "it stays suspended until it is reactivated.")
    compared = fields.Boolean(
        "I compared the hash values with the information of the bank",
        states={
            'invisible': Eval('check') != 'no_expected',
            })

    @classmethod
    def view_attributes(cls):
        return super().view_attributes() + [
            ('//label[@id="stays_suspended_note"]', 'states', {
                    'invisible': ~Eval('stays_suspended', False),
                    }),
            ]


class ConfigurationConfirmBankKeys(Wizard):
    "Dialog to confirm the bank keys (working paper E07 ch. 4.3)"
    __name__ = 'account.ebics.configuration.confirm_bank_keys'

    start = StateView(
        'account.ebics.configuration.confirm_bank_keys.start',
        'account_ebics.configuration_confirm_bank_keys_start_view_form', [
            Button("Cancel", 'end', 'tryton-cancel'),
            Button("Confirm", 'confirm', 'tryton-ok', default=True,
                states={
                    'readonly': ((Eval('check') == 'mismatch')
                        | ((Eval('check') == 'no_expected')
                            & ~Eval('compared', False))),
                    }),
            ])
    confirm = StateTransition()

    def _configuration(self):
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        context = Transaction().context
        if (context.get('active_model') != Configuration.__name__
                or context.get('active_id') is None):
            raise UserError(gettext(
                    'account_ebics.msg_bank_keys_wrong_state',
                    configuration='-'))
        return Configuration(context['active_id'])

    def default_start(self, fields):
        configuration = self._configuration()
        checks = [configuration.bank_x002_hash_check,
            configuration.bank_e002_hash_check]
        bank = configuration.bank
        return {
            'bank': ' '.join(filter(None, [
                        bank.rec_name if bank else None,
                        bank.bic if bank else None])),
            'host_id': configuration.host_id,
            'x002_hash': configuration.bank_x002_hash,
            'e002_hash': configuration.bank_e002_hash,
            'x002_hash_groups': configuration.bank_x002_hash_groups,
            'e002_hash_groups': configuration.bank_e002_hash_groups,
            'x002_expected_groups': (
                configuration.bank_x002_hash_expected_groups),
            'e002_expected_groups': (
                configuration.bank_e002_hash_expected_groups),
            'x002_check': checks[0],
            'e002_check': checks[1],
            'check': overall_check(checks),
            'compared': False,
            'stays_suspended': (
                configuration.state_after_confirmation == 'suspended'),
            }

    def transition_confirm(self):
        "The server checks again (F1, F3); state active with _log"
        pool = Pool()
        ModelAccess = pool.get('ir.model.access')
        ModelAccess.check('account.ebics.configuration', 'write')
        configuration = self._configuration()
        configuration._lock_order(configuration)
        if configuration.state != 'bank_keys_received':
            raise UserError(gettext(
                    'account_ebics.msg_bank_keys_wrong_state',
                    configuration=configuration.rec_name))
        # the keys shown must still be the stored ones
        if (self.start.x002_hash != configuration.bank_x002_hash
                or self.start.e002_hash != configuration.bank_e002_hash
                or not configuration._has_bank_keys()):
            raise UserError(gettext(
                    'account_ebics.msg_bank_keys_changed_meanwhile',
                    configuration=configuration.rec_name))
        check = overall_check([configuration.bank_x002_hash_check,
                configuration.bank_e002_hash_check])
        if check == 'mismatch':
            raise UserError(gettext(
                    'account_ebics.msg_bank_keys_mismatch',
                    configuration=configuration.rec_name))
        if check != 'match' and not self.start.compared:
            raise UserError(gettext(
                    'account_ebics.msg_bank_keys_not_compared',
                    configuration=configuration.rec_name))
        # back to suspended if it was suspended before (F9)
        configuration._write_internal({
                'state': configuration.state_after_confirmation,
                'confirmed_state': None,
                })
        return 'end'

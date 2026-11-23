# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import datetime
import hashlib

from trytond.i18n import gettext
from trytond.model import ModelSQL, ModelView, fields
from trytond.model.exceptions import AccessError
from trytond.pool import Pool
from trytond.pyson import Eval, If
from trytond.transaction import Transaction, without_check_access

from ..core.history import HistoryMixin

LOG_STATES = [
    ('done', "Done"),
    ('no_data', "No Data"),
    ('error', "Error"),
    ]
FILE_STATES = [
    ('pending', "Pending"),
    ('imported', "Imported"),
    ('stored', "Stored"),
    ('duplicate', "Duplicate"),
    ('unknown_account', "Unknown Account"),
    ('error', "Error"),
    ]


class LockedMixin:
    """Protocol records cannot be changed or deleted (specification ch. 5.6,
    PR01-PR05)"""
    __slots__ = ()
    # Fields the server code may change after the creation (PR03)
    _internal_fields = set()

    @classmethod
    def check_modification(cls, mode, records, values=None, external=False):
        super().check_modification(
            mode, records, values=values, external=external)
        model = cls.__names__()['model']
        if mode == 'delete':
            # PR01
            raise AccessError(gettext(
                    'account_ebics.msg_log_delete', model=model))
        if mode == 'create' and external:
            # PR04
            raise AccessError(gettext(
                    'account_ebics.msg_log_create', model=model))
        if mode == 'write':
            if external:
                # PR02
                raise AccessError(gettext(
                        'account_ebics.msg_log_write', model=model))
            forbidden = set(values or {}) - cls._internal_fields
            if forbidden:
                # PR03
                raise AccessError(gettext(
                        'account_ebics.msg_log_write_fields', model=model,
                        fields=', '.join(
                            cls.__names__(f)['field']
                            for f in sorted(forbidden))))

    @classmethod
    def copy(cls, records, default=None):
        # PR05
        if records:
            raise AccessError(gettext(
                    'account_ebics.msg_log_copy',
                    model=cls.__names__()['model']))
        return super().copy(records, default=default)

    @classmethod
    def write_internal(cls, records, values):
        "Change the fields allowed by PR03, logged in ir.model.log"
        with without_check_access(), Transaction().set_context(_log=True):
            cls.write(records, values)


class Log(LockedMixin, ModelSQL, ModelView):
    __name__ = 'account.ebics.log'
    __string__ = "EBICS Log"
    _internal_fields = {'state', 'receipt'}

    configuration = fields.Many2One(
        'account.ebics.configuration', "Connection",
        required=True, ondelete='RESTRICT')
    company = fields.Many2One(
        'company.company', "Company", required=True, ondelete='RESTRICT')
    timestamp = fields.DateTime("Timestamp", required=True)
    order_type = fields.Char(
        "Order Type", required=True, help="E.g. INI, HIA, HPB, BTD.")
    format = fields.Many2One(
        'account.ebics.format', "Format", ondelete='RESTRICT')
    btf_params = fields.Char(
        "BTF Parameters",
        help="The BTF parameters actually sent to the bank.")
    date_from = fields.Date("From Date")
    date_to = fields.Date("To Date")
    transaction_id = fields.Char("Transaction ID")
    ebics_order_id = fields.Char("Order ID")
    technical_return_code = fields.Char("Technical Return Code")
    business_return_code = fields.Char("Business Return Code")
    return_message = fields.Char("Return Message")
    receipt = fields.Selection([
            ('none', "None"),
            ('positive', "Positive"),
            ('negative', "Negative"),
            ], "Receipt", required=True, sort=False,
        help="Receipt of the download sent to the bank.")
    state = fields.Selection(LOG_STATES, "State", required=True, sort=False)
    payload = fields.Binary(
        "Payload", filename='payload_filename',
        file_id='payload_id', store_prefix=None,
        help="Container received from or data sent to the bank.")
    payload_id = fields.Char("Payload ID", readonly=True)
    payload_filename = fields.Function(
        fields.Char("Payload File Name"), 'get_payload_filename')
    files = fields.One2Many(
        'account.ebics.log.file', 'ebics_log', "Files")

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls._order = [
            ('timestamp', 'DESC'),
            ('id', 'DESC'),
            ]

    @classmethod
    def default_timestamp(cls):
        return datetime.datetime.now()

    @classmethod
    def default_receipt(cls):
        return 'none'

    def get_rec_name(self, name):
        timestamp = self.timestamp.replace(microsecond=0)
        return ' '.join(
            str(p) for p in [self.order_type, self.btf_params, timestamp]
            if p)

    @classmethod
    def search_rec_name(cls, name, clause):
        if clause[1].startswith('!') or clause[1].startswith('not '):
            bool_op = 'AND'
        else:
            bool_op = 'OR'
        return [bool_op,
            ('order_type',) + tuple(clause[1:]),
            ('btf_params',) + tuple(clause[1:]),
            ]

    def get_payload_filename(self, name):
        return '%s-%s.zip' % (self.order_type, self.id)

    @classmethod
    def view_attributes(cls):
        return super().view_attributes() + [
            ('/tree/field[@name="state"]', 'visual',
                If(Eval('state') == 'error', 'danger',
                    If(Eval('state') == 'no_data', 'muted', ''))),
            ]

    @classmethod
    def record(cls, configuration, order_type, values, files=None):
        """Create a log of the configuration with its files and return it.

        values: field values of the log; 'format' may be a record or an id.
        files: list of values per file, at least 'name' and 'data',
        optional 'message_type' and 'iban'.
        The caller controls the transaction (specification ch. 7.3, D5).
        Never pass private keys or the passphrase (ch. 8.1)."""
        pool = Pool()
        Format = pool.get('account.ebics.format')
        values = dict(values)
        values['configuration'] = configuration.id
        values['company'] = configuration.company.id
        values['order_type'] = order_type
        format_ = values.get('format')
        if format_ is not None:
            if not isinstance(format_, Format):
                format_ = Format(format_)
            values['format'] = format_.id
            values.setdefault('btf_params', format_.btf_text)
        if files:
            values['files'] = [('create', [dict(f) for f in files])]
        with without_check_access():
            log, = cls.create([values])
        return log


class LogFile(LockedMixin, HistoryMixin, ModelSQL, ModelView):
    __name__ = 'account.ebics.log.file'
    __string__ = "EBICS Received File"
    _internal_fields = {'state', 'account', 'statements', 'error_message'}

    # not 'log': it would hide ModelStorage.log() (F10)
    ebics_log = fields.Many2One(
        'account.ebics.log', "Log", required=True, ondelete='CASCADE')
    company = fields.Function(
        fields.Many2One('company.company', "Company"),
        'on_change_with_company', searcher='search_company')
    timestamp = fields.Function(
        fields.DateTime("Timestamp"), 'get_timestamp')
    name = fields.Char("Name", required=True)
    data = fields.Binary(
        "Data", filename='name', file_id='data_id', store_prefix=None)
    data_id = fields.Char("Data ID", readonly=True)
    sha256 = fields.Char(
        "SHA-256", readonly=True,
        help="Hash value of the data to detect duplicates.")
    message_type = fields.Char(
        "Message Type", help="E.g. camt.053.001.08.")
    iban = fields.Char("IBAN")
    account = fields.Many2One(
        'account.ebics.account', "Account", ondelete='RESTRICT')
    state = fields.Selection(FILE_STATES, "State", required=True, sort=False)
    statements = fields.Many2Many(
        'account.ebics.log.file-account.statement', 'file', 'statement',
        "Statements")
    error_message = fields.Text("Error Message")

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls._order = [
            ('timestamp', 'DESC'),
            ('id', 'DESC'),
            ]

    @classmethod
    def default_state(cls):
        return 'pending'

    @fields.depends('ebics_log', '_parent_ebics_log.company')
    def on_change_with_company(self, name=None):
        return self.ebics_log.company if self.ebics_log else None

    @classmethod
    def search_company(cls, name, clause):
        return [('ebics_log.company',) + tuple(clause[1:])]

    def get_timestamp(self, name):
        return self.ebics_log.timestamp

    @staticmethod
    def order_timestamp(tables):
        pool = Pool()
        Log = pool.get('account.ebics.log')
        table, _ = tables[None]
        if 'ebics_log' not in tables:
            log = Log.__table__()
            tables['ebics_log'] = {
                None: (log, table.ebics_log == log.id),
                }
        log, _ = tables['ebics_log'][None]
        return [log.timestamp]

    @classmethod
    def preprocess_values(cls, mode, values):
        values = super().preprocess_values(mode, values)
        if mode == 'create':
            data = values.get('data')
            values['sha256'] = (
                hashlib.sha256(bytes(data)).hexdigest()
                if data is not None else None)
        return values

    @classmethod
    def view_attributes(cls):
        return super().view_attributes() + [
            ('/tree/field[@name="state"]', 'visual',
                If(Eval('state').in_(['error', 'unknown_account']), 'danger',
                    If(Eval('state') == 'duplicate', 'muted', ''))),
            ]


class LogFileStatement(ModelSQL):
    __name__ = 'account.ebics.log.file-account.statement'
    __string__ = "EBICS Received File - Statement"

    file = fields.Many2One(
        'account.ebics.log.file', "File", required=True, ondelete='CASCADE')
    statement = fields.Many2One(
        'account.statement', "Statement", required=True, ondelete='CASCADE')

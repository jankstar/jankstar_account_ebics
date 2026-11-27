# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import datetime
import hashlib

from trytond import backend
from trytond.i18n import gettext
from trytond.model import Index, ModelSQL, ModelView, fields
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
    # set at the creation, not changeable afterwards (PR03; F4, F7 of E08)
    warnings = fields.Text(
        "Warnings", readonly=True,
        help="Schema warnings (xsd_mode warn) and other notes of the "
        "order.")
    num_segments = fields.Integer(
        "Segments", readonly=True,
        help="Number of segments announced by the bank (BTD).")
    # who or what started the order (request of the user, 27.11.2026); the
    # user is create_uid
    trigger = fields.Selection([
            ('button', "Button"),
            ('menu', "Menu"),
            ('period', "Period Dialog"),
            ('cron', "Cron, started automatically"),
            ('cron_manual', "Cron, started manually"),
            ], "Trigger", readonly=True, sort=False)
    run = fields.Many2One(
        'account.ebics.run', "Run", readonly=True, ondelete='RESTRICT',
        help="The run of the download that created this log.")
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

    @classmethod
    def default_trigger(cls):
        # INI, HIA, HPB come from the buttons of the connection
        return Transaction().context.get('ebics_trigger', 'button')

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
        LogFile = pool.get('account.ebics.log.file')
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
        with without_check_access():
            log, = cls.create([values])
            # one file after the other, so that a repeated file finds also
            # an earlier equal file of the same container (F11 of E08)
            for file_values in files or []:
                LogFile.create([dict(file_values, ebics_log=log.id)])
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
    # F11 of E08: set only when the file is created (not in PR03)
    first_file = fields.Many2One(
        'account.ebics.log.file', "Already Received", readonly=True,
        ondelete='RESTRICT',
        help="The first file of the company with the same content (SHA-256); "
        "empty for the first one.")
    repeated = fields.Function(
        fields.Boolean("Repeated",
            help="The same file was received before."),
        'get_repeated', searcher='search_repeated')
    first_received = fields.Function(
        fields.DateTime("First Received"), 'get_first')
    first_log = fields.Function(
        fields.Many2One('account.ebics.log', "First Log"), 'get_first')
    # F12 of E08: CpyDplctInd of the bank, set only when created
    copy_duplicate = fields.Char(
        "Copy/Duplicate", readonly=True,
        help="Indicator of the bank in the statement (CpyDplctInd): COPY, "
        "DUPL or CODU; empty if the bank sent none.")

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls._order = [
            ('timestamp', 'DESC'),
            ('id', 'DESC'),
            ]
        table = cls.__table__()
        # duplicates are searched by the hash value (F11)
        cls._sql_indexes.add(
            Index(table, (table.sha256, Index.Equality())))

    @classmethod
    def __register__(cls, module_name):
        table_h = cls.__table_handler__(module_name)
        new_column = not table_h.column_exist('first_file')
        super().__register__(module_name)
        if new_column:
            cls._fill_first_file()

    @classmethod
    def _fill_first_file(cls):
        """Migration (E08.1): files received before get first_file once,
        the earliest file (id) of the company with the same hash value;
        idempotent (only empty values, the first file stays empty)"""
        pool = Pool()
        Log = pool.get('account.ebics.log')
        cursor = Transaction().connection.cursor()
        table = cls.__table__()
        log = Log.__table__()
        cursor.execute(*table.join(
                log, condition=table.ebics_log == log.id).select(
                table.id, table.sha256, log.company, table.first_file,
                where=table.sha256 != None,  # noqa: E711
                order_by=table.id.asc))
        first = {}
        updates = {}
        for id_, sha256, company, first_file in cursor:
            key = (company, sha256)
            if key not in first:
                first[key] = id_
            elif first_file is None:
                updates.setdefault(first[key], []).append(id_)
        for first_id, ids in updates.items():
            for start in range(0, len(ids), backend.MAX_QUERY_PARAMS):
                cursor.execute(*table.update(
                        [table.first_file], [first_id],
                        where=table.id.in_(
                            ids[start:start + backend.MAX_QUERY_PARAMS])))

    def get_repeated(self, name):
        return bool(self.first_file)

    @classmethod
    def search_repeated(cls, name, clause):
        _, operator, value = clause[:3]
        repeated = bool(value) if operator == '=' else not bool(value)
        return [('first_file', '!=' if repeated else '=', None)]

    @classmethod
    def get_first(cls, files, names):
        result = {n: {f.id: None for f in files} for n in names}
        for file_ in files:
            if file_.first_file:
                if 'first_received' in names:
                    result['first_received'][file_.id] = (
                        file_.first_file.timestamp)
                if 'first_log' in names:
                    result['first_log'][file_.id] = (
                        file_.first_file.ebics_log.id)
        return result

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
            values['first_file'] = cls._find_first_file(
                values['sha256'], values.get('ebics_log'))
        return values

    @classmethod
    def _find_first_file(cls, sha256, log_id):
        """The earliest file of the same company with the same hash value
        (F11 of E08), None for a new content"""
        pool = Pool()
        Log = pool.get('account.ebics.log')
        if not sha256 or not log_id:
            return None
        with without_check_access():
            company = Log(log_id).company
            files = cls.search([
                    ('sha256', '=', sha256),
                    ('ebics_log.company', '=', company.id),
                    ], order=[('id', 'ASC')], limit=1)
        return files[0].id if files else None

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

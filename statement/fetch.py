# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Dialogs to download statements (working paper E08 ch. 4.1, 4.3)."""
import datetime
import json

from trytond.exceptions import UserError
from trytond.i18n import gettext
from trytond.model import ModelView, fields
from trytond.pool import Pool
from trytond.pyson import Eval, If, PYSONEncoder
from trytond.transaction import Transaction, without_check_access
from trytond.wizard import (
    Button, StateAction, StateTransition, StateView, Wizard)


def _check_read():
    "Read access to the connections (group_ebics or group_ebics_admin)"
    pool = Pool()
    ModelAccess = pool.get('ir.model.access')
    ModelAccess.check('account.ebics.configuration', 'read')


OUTCOME_STATES = [
    ('done', "Received"),
    ('no_data', "No New Data"),
    ('error', "Error"),
    ('skipped', "Skipped"),
    ]


class FetchResult(ModelView):
    "Result page of the downloads (variant C, 27.11.2026)"
    __name__ = 'account.ebics.fetch.result'
    __string__ = "Result of the Download"

    summary = fields.Char("Summary", readonly=True)
    lines = fields.One2Many(
        'account.ebics.fetch.result.line', None, "Results", readonly=True)
    logs = fields.Many2Many(
        'account.ebics.log', None, None, "Logs", readonly=True)
    outcomes = fields.Text("Outcomes", readonly=True)


class FetchResultLine(ModelView):
    "One connection and format of a download"
    __name__ = 'account.ebics.fetch.result.line'
    __string__ = "Result of the Download per Format"

    configuration = fields.Char("Connection", readonly=True)
    format = fields.Char("Format", readonly=True)
    state = fields.Selection(OUTCOME_STATES, "State", readonly=True)
    files = fields.Integer("Files", readonly=True)
    repeated = fields.Integer(
        "Repeated", readonly=True,
        help="Files received before (same content).")
    message = fields.Text("Message", readonly=True)

    @classmethod
    def view_attributes(cls):
        return super().view_attributes() + [
            ('/tree/field[@name="state"]', 'visual',
                If(Eval('state') == 'error', 'danger',
                    If(Eval('state') == 'done', 'success', 'muted'))),
            ]


class FetchResultMixin:
    """Result page with summary, one line per connection and format and the
    button to open the logs of this run"""
    __slots__ = ()

    result = StateView(
        'account.ebics.fetch.result',
        'account_ebics.fetch_result_view_form', [
            Button("Open Log", 'open_log', 'tryton-list'),
            Button("Close", 'end', 'tryton-close', default=True),
            ])
    open_log = StateAction('account_ebics.act_log_form')

    def _run(self, trigger, configurations, format_=None, date_range=None):
        """Download with run log, notifications, result kept for the result
        page"""
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Run = pool.get('account.ebics.run')
        company = Transaction().context.get('company')
        with Run.recording(trigger, company=company) as recorder:
            recorder.step(gettext(
                    'account_ebics.msg_run_connections',
                    count=len(configurations),
                    configurations=', '.join(
                        c.rec_name for c in configurations)))
            with without_check_access():
                outcomes = Configuration.fetch(
                    configurations, format_=format_, date_range=date_range,
                    recorder=recorder)
            recorder.finish(Configuration.summary(outcomes))
        Configuration.notify_outcomes(outcomes)
        self.result.outcomes = json.dumps(outcomes)
        return 'result'

    def default_result(self, fields):
        outcomes = json.loads(self.result.outcomes or '[]')
        counts = {s: 0 for s, _ in OUTCOME_STATES}
        files = repeated = 0
        for outcome in outcomes:
            counts[outcome['state']] += 1
            files += outcome['files'] or 0
            repeated += outcome.get('repeated') or 0
        return {
            'summary': gettext(
                'account_ebics.msg_fetch_summary', files=files,
                repeated=repeated, no_data=counts['no_data'],
                errors=counts['error'] + counts['skipped']),
            'lines': [{
                    'configuration': o['configuration'],
                    'format': o['format'],
                    'state': o['state'],
                    'files': o['files'],
                    'repeated': o.get('repeated') or 0,
                    'message': o['message'],
                    } for o in outcomes],
            'logs': [o['log_id'] for o in outcomes if o.get('log_id')],
            'outcomes': self.result.outcomes,
            }

    def do_open_log(self, action):
        "The logs of this run"
        ids = [o['log_id'] for o in json.loads(self.result.outcomes or '[]')
            if o.get('log_id')]
        action['pyson_domain'] = PYSONEncoder().encode([('id', 'in', ids)])
        return action, {}


class FetchStatementsStart(ModelView):
    "Start page of the menu: the connections that are fetched"
    __name__ = 'account.ebics.fetch_statements.start'
    __string__ = "Fetch Statements"

    configurations = fields.Many2Many(
        'account.ebics.configuration', None, None, "Connections",
        readonly=True)


class FetchStatements(FetchResultMixin, Wizard):
    """Menu "Fetch Statements" and button of the connection (variant C):
    from the menu a start page with the active connections of the current
    companies, from the button at once; then the result page"""
    __name__ = 'account.ebics.fetch_statements'

    start = StateTransition()
    confirm = StateView(
        'account.ebics.fetch_statements.start',
        'account_ebics.fetch_statements_start_view_form', [
            Button("Cancel", 'end', 'tryton-cancel'),
            Button("Fetch", 'fetch', 'tryton-ok', default=True,
                states={
                    'readonly': ~Eval('configurations', []),
                    }),
            ])
    fetch = StateTransition()

    def _button_configurations(self):
        "The connections of the button, None from the menu"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        context = Transaction().context
        if (context.get('active_model') == Configuration.__name__
                and context.get('active_ids')):
            # the record rules of the user apply to the search
            return Configuration.search([
                    ('id', 'in', context['active_ids']),
                    ])
        return None

    def transition_start(self):
        _check_read()
        configurations = self._button_configurations()
        if configurations is None:
            return 'confirm'
        self.confirm.configurations = configurations
        return 'fetch'

    def default_confirm(self, fields):
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        User = pool.get('res.user')
        # the current companies of the user (company filter), the record
        # rules of the user apply to the search
        configurations = Configuration.search([
                ('company', 'in', User.get_companies()),
                ('state', '=', 'active'),
                ])
        return {
            'configurations': [c.id for c in configurations],
            }

    def transition_fetch(self):
        _check_read()
        configurations = list(self.confirm.configurations or [])
        if not configurations:
            raise UserError(gettext('account_ebics.msg_fetch_none'))
        trigger = ('button' if self._button_configurations() is not None
            else 'menu')
        return self._run(trigger, configurations)


class FetchPeriodStart(ModelView):
    __name__ = 'account.ebics.fetch_period.start'
    __string__ = "Fetch Statements for Period Again"

    configuration = fields.Many2One(
        'account.ebics.configuration', "Connection", required=True,
        domain=[
            ('state', '=', 'active'),
            ])
    formats = fields.Many2Many(
        'account.ebics.format', None, None, "Formats", readonly=True)
    format = fields.Many2One(
        'account.ebics.format', "Format", required=True,
        domain=[
            ('id', 'in', Eval('formats', [])),
            ])
    date_from = fields.Date(
        "From", required=True,
        domain=[
            If(Eval('date_to'),
                ('date_from', '<=', Eval('date_to', None)),
                ()),
            ])
    date_to = fields.Date(
        "To", required=True,
        domain=[
            If(Eval('today'),
                ('date_to', '<=', Eval('today', None)),
                ()),
            ],
        help="The bank delivers the statements of the period again, also "
        "those already fetched; how far back depends on the bank.")
    today = fields.Date("Today", readonly=True)

    @fields.depends('configuration', 'format', 'formats')
    def on_change_configuration(self):
        formats = []
        if self.configuration:
            formats = [f for f in self.configuration.formats if f.active]
        self.formats = formats
        if self.format not in formats:
            self.format = formats[0] if len(formats) == 1 else None


class FetchPeriod(FetchResultMixin, Wizard):
    """Dialog "Fetch Statements for Period Again" (F10, working paper E08
    ch. 4.3): one connection, one format, DateRange"""
    __name__ = 'account.ebics.fetch_period'

    start = StateView(
        'account.ebics.fetch_period.start',
        'account_ebics.fetch_period_start_view_form', [
            Button("Cancel", 'end', 'tryton-cancel'),
            Button("Fetch", 'fetch', 'tryton-ok', default=True),
            ])
    fetch = StateTransition()

    def default_start(self, fields):
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Date = pool.get('ir.date')
        today = Date.today()
        values = {
            'today': today,
            'date_from': today,
            'date_to': today,
            }
        context = Transaction().context
        if (context.get('active_model') == Configuration.__name__
                and context.get('active_id')):
            configuration = Configuration(context['active_id'])
            if configuration.state == 'active':
                values['configuration'] = configuration.id
                formats = [f.id for f in configuration.formats if f.active]
                values['formats'] = formats
                if len(formats) == 1:
                    values['format'] = formats[0]
        return values

    def transition_fetch(self):
        "The server checks the values again"
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        Date = pool.get('ir.date')
        _check_read()
        configuration = Configuration(self.start.configuration.id)
        format_ = self.start.format
        date_from, date_to = self.start.date_from, self.start.date_to
        if configuration.state != 'active':
            raise UserError(gettext(
                    'account_ebics.msg_fetch_not_active',
                    configuration=configuration.rec_name))
        if format_ not in configuration.formats or not format_.active:
            raise UserError(gettext(
                    'account_ebics.msg_fetch_period_format',
                    configuration=configuration.rec_name,
                    format=format_.rec_name))
        if (not isinstance(date_from, datetime.date)
                or not isinstance(date_to, datetime.date)
                or date_from > date_to or date_to > Date.today()):
            raise UserError(gettext('account_ebics.msg_fetch_period_dates'))
        return self._run(
            'period', [configuration], format_=format_,
            date_range=(date_from, date_to))

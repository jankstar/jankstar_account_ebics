# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Run log of the downloads (E08, request of the user 27.11.2026): one
record per run (cron automatic or started manually, button, menu, period
dialog) with every step as a line of text; the same lines go to the Python
logger. A run is never empty: at least the start, the companies or
connections and the end are written."""
import contextlib
import datetime
import logging

from trytond.i18n import gettext
from trytond.model import ModelSQL, ModelView, fields
from trytond.pool import Pool
from trytond.pyson import Eval, If
from trytond.transaction import Transaction, without_check_access

from .log import LockedMixin

logger = logging.getLogger(__name__)

#: Who or what started a download (run and EBICS log)
TRIGGERS = [
    ('button', "Button"),
    ('menu', "Menu"),
    ('period', "Period Dialog"),
    ('cron', "Cron, started automatically"),
    ('cron_manual', "Cron, started manually"),
    ]
RUN_STATES = [
    ('running', "Running"),
    ('done', "Done"),
    ('error', "Error"),
    ]


class Run(LockedMixin, ModelSQL, ModelView):
    __name__ = 'account.ebics.run'
    __string__ = "EBICS Run"
    # the steps are added while the run goes on (PR03)
    _internal_fields = {'history', 'end', 'state', 'summary'}

    trigger = fields.Selection(TRIGGERS, "Trigger", required=True,
        readonly=True, sort=False)
    trigger_text = fields.Char("Started", readonly=True,
        help="How the run was started, with cron and user.")
    company = fields.Many2One(
        'company.company', "Company", readonly=True, ondelete='RESTRICT')
    cron = fields.Many2One(
        'ir.cron', "Cron", readonly=True, ondelete='SET NULL')
    user = fields.Many2One(
        'res.user', "User", readonly=True, ondelete='RESTRICT',
        help="The user who started the run (root for the scheduler).")
    start = fields.DateTime("Start", required=True, readonly=True)
    end = fields.DateTime("End", readonly=True)
    state = fields.Selection(RUN_STATES, "State", required=True,
        readonly=True, sort=False)
    summary = fields.Char("Summary", readonly=True)
    history = fields.Text("Steps", readonly=True)
    logs = fields.One2Many(
        'account.ebics.log', 'run', "EBICS Logs", readonly=True)

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls._order = [
            ('start', 'DESC'),
            ('id', 'DESC'),
            ]

    @classmethod
    def default_state(cls):
        return 'running'

    def get_rec_name(self, name):
        return '%s %s' % (
            self.trigger_text or self.trigger,
            self.start.replace(microsecond=0))

    @classmethod
    def view_attributes(cls):
        return super().view_attributes() + [
            ('/tree/field[@name="state"]', 'visual',
                If(Eval('state') == 'error', 'danger',
                    If(Eval('state') == 'running', 'warning', ''))),
            ]

    @classmethod
    @contextlib.contextmanager
    def recording(cls, trigger, company=None, cron=None):
        """Context of a run: the record is created and committed at once,
        every step is committed on its own; an unexpected error is written
        as last step and raised again"""
        recorder = RunRecorder(trigger, company, cron)
        try:
            yield recorder
        except Exception as exception:
            recorder.step(gettext(
                    'account_ebics.msg_run_aborted',
                    error='%s: %s' % (type(exception).__name__, exception)))
            recorder.finish(error=True)
            raise
        else:
            if not recorder.finished:
                recorder.finish()


class RunRecorder:
    "Writes the steps of a run (not a model)"

    def __init__(self, trigger, company=None, cron=None):
        pool = Pool()
        Run = pool.get('account.ebics.run')
        User = pool.get('res.user')
        transaction = Transaction()
        self.trigger = trigger
        self.lines = []
        self.errors = 0
        self.finished = False
        user_id = transaction.user
        with without_check_access():
            user_name = User(user_id).rec_name
        label = dict(Run.fields_get(['trigger'])['trigger']['selection'])[
            trigger]
        parts = [label]
        if cron is not None:
            parts.append(gettext('account_ebics.msg_run_cron', cron=cron))
        if trigger != 'cron':
            parts.append(gettext('account_ebics.msg_run_user',
                    user=user_name))
        self.trigger_text = ', '.join(parts)
        values = {
            'trigger': trigger,
            'trigger_text': self.trigger_text,
            'company': company,
            'cron': cron,
            'user': user_id,
            'start': datetime.datetime.now(),
            'state': 'running',
            }
        with transaction.new_transaction(), without_check_access():
            run, = Run.create([values])
            self.run_id = run.id
        self.step(gettext(
                'account_ebics.msg_run_started', trigger=self.trigger_text))

    def _write(self, values):
        pool = Pool()
        Run = pool.get('account.ebics.run')
        with Transaction().new_transaction(), without_check_access():
            Run.write([Run(self.run_id)], values)

    def step(self, text, error=False):
        "One line with the time; committed at once, also to the logger"
        if error:
            self.errors += 1
        line = '%s %s' % (
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), text)
        self.lines.append(line)
        (logger.error if error else logger.info)(
            "EBICS run %s: %s", self.run_id, text)
        self._write({'history': '\n'.join(self.lines)})

    def outcome(self, outcome):
        "The result of a connection and format as step"
        text = outcome['message'] or outcome['state']
        if outcome.get('log_id'):
            text = gettext('account_ebics.msg_run_with_log',
                text=text, log=outcome['log_id'])
        self.step(text, error=outcome['state'] == 'error')

    def finish(self, summary=None, error=False):
        if self.finished:
            return
        if summary:
            self.step(gettext('account_ebics.msg_run_finished',
                    summary=summary))
        else:
            self.step(gettext('account_ebics.msg_run_finished',
                    summary='-'))
        self.finished = True
        self._write({
                'end': datetime.datetime.now(),
                'state': 'error' if (error or self.errors) else 'done',
                'summary': summary,
                })

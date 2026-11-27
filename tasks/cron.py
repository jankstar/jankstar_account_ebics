# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.model import dualmethod
from trytond.pool import PoolMeta
from trytond.transaction import Transaction


class Cron(metaclass=PoolMeta):
    __name__ = 'ir.cron'

    @classmethod
    def __setup__(cls):
        super().__setup__()
        # working paper E08 ch. 4.1 (specification ch. 7.1)
        cls.method.selection.append(
            ('account.ebics.configuration|fetch_statements',
                "Fetch EBICS Statements"))

    @dualmethod
    def run_once(cls, crons):
        """The cron in the context, so that the run log names it (also
        when started manually with "Run Once")"""
        for cron in crons:
            with Transaction().set_context(ebics_cron=cron.id):
                super().run_once([cron])

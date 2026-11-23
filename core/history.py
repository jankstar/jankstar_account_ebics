# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.tools import grouped_slice
from trytond.transaction import Transaction


class HistoryMixin:
    "Keep the history of the records (D16)"
    __slots__ = ()
    _history = True

    @classmethod
    def __register__(cls, module_name):
        super().__register__(module_name)
        cls._fill_missing_history()

    @classmethod
    def _fill_missing_history(cls):
        """Migration (E05): records created before the history was enabled
        get their current version as first revision; idempotent"""
        cursor = Transaction().connection.cursor()
        table = cls.__table__()
        history = cls.__table_history__()
        cursor.execute(*table.select(table.id,
                where=~table.id.in_(history.select(history.id))))
        ids = [i for i, in cursor]
        for sub_ids in grouped_slice(ids):
            cls._insert_history(list(sub_ids))

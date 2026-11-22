# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.tests.test_tryton import ModuleTestCase


class AccountEbicsTestCase(ModuleTestCase):
    "Test Account EBICS module"
    module = 'account_ebics'


del ModuleTestCase

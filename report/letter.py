# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Initialisation letters INI and HIA (specification ch. 6.3, working paper
E06 ch. 4.3).

Source: EBICS specification V 3.0.2 (DE) ch. 4.4.1.2.3 (content, hash
value), ch. 11.5.1 and 11.5.2 (examples of the letters).
"""
from cryptography.hazmat.primitives import serialization

from trytond.exceptions import UserError
from trytond.i18n import gettext
from trytond.pool import Pool
from trytond.report import Report
from trytond.transaction import without_check_access

from ..connection.configuration import format_hash
from ..protocol import keys


class _IniLetter(Report):
    #: order type and its flag on the connection
    order_type = None
    flag = None
    #: purposes of the certificates in the letter
    purposes = ()

    @classmethod
    def get_context(cls, records, header, data):
        pool = Pool()
        Configuration = pool.get('account.ebics.configuration')
        context = super().get_context(records, header, data)
        letters = []
        for record in records:
            with without_check_access():
                configuration = Configuration(int(record))
                letters.append(cls.letter(configuration))
        context['letters'] = letters
        context['letter'] = letters[0] if letters else None
        return context

    @classmethod
    def letter(cls, configuration):
        """Data of the letter: header and per purpose PEM lines and hash
        value in groups (decision F6); only after the bank accepted the
        order"""
        if not getattr(configuration, cls.flag):
            raise UserError(gettext(
                    'account_ebics.msg_letter_not_sent',
                    configuration=configuration.rec_name,
                    order_type=cls.order_type))
        keyring = configuration._load_keyring()
        log = configuration.last_order_log(cls.order_type)
        bank = configuration.bank
        certificates = {}
        for purpose in cls.purposes:
            certificate = keyring.certificate(purpose)
            pem = certificate.public_bytes(
                serialization.Encoding.PEM).decode('ascii')
            value = keys.certificate_hash(certificate)
            certificates[purpose] = {
                'version': purpose,
                'pem_lines': pem.strip().splitlines(),
                'hash': value,
                'hash_lines': format_hash(value),
                }
        return {
            'user_name': configuration.name,
            'timestamp': log.timestamp if log else None,
            'bank_name': bank.rec_name if bank else '',
            'bic': (bank.bic or '') if bank else '',
            'host_id': configuration.host_id,
            'partner_id': configuration.partner_id,
            'user_id': configuration.user_id,
            'company': configuration.company.rec_name,
            'certificates': certificates,
            }


class IniLetterIni(_IniLetter):
    "Initialisation letter INI: bank-technical signature (A006)"
    __name__ = 'account.ebics.ini_letter_ini'
    order_type = 'INI'
    flag = 'ini_sent'
    purposes = ('A006',)


class IniLetterHia(_IniLetter):
    "Initialisation letter HIA: authentication (X002), encryption (E002)"
    __name__ = 'account.ebics.ini_letter_hia'
    order_type = 'HIA'
    flag = 'hia_sent'
    purposes = ('X002', 'E002')

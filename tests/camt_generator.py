# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Generator of invented camt.053.001.08 statements (working paper E12
ch. 4.6, decision F8).

Test data only: invented counterparties and IBANs (bank code 12345678, not
assigned) with valid check digits, consistent balances, unique Stmt/Id and
MsgId. Suitable for the import with account_statement_sepa (E09).

No Tryton imports; only the protocol layer of the module.
"""
import datetime
import random
import re
from decimal import Decimal

from lxml import etree

from trytond.modules.account_ebics.protocol import xml as ebics_xml

NAMESPACE = 'urn:iso:std:iso:20022:tech:xsd:camt.053.001.08'
#: Invented bank code (not assigned), as in the module tests
TEST_BANK_CODE = '12345678'
BANK_NAME = 'Testbank (Testdaten)'

_COUNTERPARTIES = [
    'Muster Bau GmbH (Testdaten)',
    'Beispiel Handel KG (Testdaten)',
    'Erika Mustermann (Testdaten)',
    'Max Beispiel (Testdaten)',
    'Probe Logistik AG (Testdaten)',
    'Test Energie eG (Testdaten)',
    'Fiktiv Software UG (Testdaten)',
    'Demo Versicherung AG (Testdaten)',
    ]
_PURPOSES = {
    'CRDT': ['Rechnung RE-{n:05d}', 'Zahlung Auftrag {n:05d}',
        'Gutschrift Kundennummer {n:05d}'],
    'DBIT': ['Miete Lager {n:05d}', 'Lieferantenrechnung LR-{n:05d}',
        'Abschlag Energie {n:05d}'],
    }
# Bank transaction codes: ISO domain PMNT (received / issued credit
# transfer, SEPA credit transfer) and DK proprietary code (GVC)
_BANK_TRANSACTION_CODES = {
    'CRDT': ('RCDT', 'ESCT', 'NTRF+166'),
    'DBIT': ('ICDT', 'ESCT', 'NTRF+177'),
    }


def iban_check_digits(country, bban):
    """Return the two check digits of an IBAN (ISO 13616, mod 97-10).

    Source: ISO 13616-1 (IBAN), ISO 7064 MOD 97-10."""
    digits = ''.join(str(int(c, 36)) for c in (bban + country + '00').upper())
    return '%02d' % (98 - int(digits) % 97)


def make_iban(account, bank_code=TEST_BANK_CODE, country='DE'):
    """Return a German IBAN with valid check digits for the bank code and
    the account number (10 digits, zero-padded).

    Source: ISO 13616-1; IBAN DE: 8 digits bank code, 10 digits account."""
    bban = '%s%010d' % (bank_code, int(account))
    return country + iban_check_digits(country, bban) + bban


def iban_valid(iban):
    """Return True if the IBAN (without spaces) has valid check digits.

    Source: ISO 13616-1, ISO 7064 MOD 97-10."""
    iban = re.sub(r'\s', '', iban or '').upper()
    if not re.fullmatch(r'[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}', iban):
        return False
    digits = ''.join(str(int(c, 36)) for c in iban[4:] + iban[:4])
    return int(digits) % 97 == 1


def _amount(value):
    return '%.2f' % value


def _sub(parent, name, text=None, **attributes):
    node = etree.SubElement(parent, '{%s}%s' % (NAMESPACE, name))
    for key, value in attributes.items():
        node.set(key, str(value))
    if text is not None:
        node.text = str(text)
    return node


def _balance(parent, code, amount, currency, date):
    balance = _sub(parent, 'Bal')
    _sub(_sub(_sub(balance, 'Tp'), 'CdOrPrtry'), 'Cd', code)
    _sub(balance, 'Amt', _amount(abs(amount)), Ccy=currency)
    _sub(balance, 'CdtDbtInd', 'CRDT' if amount >= 0 else 'DBIT')
    _sub(_sub(balance, 'Dt'), 'Dt', date.isoformat())


def make_entries(count, rnd, start=1):
    """Return count invented entries as dicts (sign, amount, name, iban,
    purpose, reference)"""
    entries = []
    for number in range(start, start + count):
        sign = rnd.choice(['CRDT', 'CRDT', 'DBIT'])
        amount = Decimal(rnd.randint(100, 250000)) / 100
        entries.append({
                'sign': sign,
                'amount': amount,
                'name': rnd.choice(_COUNTERPARTIES),
                'iban': make_iban(rnd.randint(1, 9999999999)),
                'purpose': rnd.choice(_PURPOSES[sign]).format(
                    n=rnd.randint(1, 99999)),
                'reference': 'E2E-%06d' % rnd.randint(1, 999999),
                'number': number,
                })
    return entries


def make_camt053(iban, date=None, entries=5, currency='EUR',
        start_balance=Decimal('1000.00'), sequence=1, seed=None,
        copy_duplicate=None):
    """Return (file name, data) of an invented camt.053.001.08 statement
    for the IBAN and the booking date.

    Opening balance PRCD (previous day) + sum of the entries = closing
    balance CLBD (booking date); TxsSummry with the number and the net
    sum; credits and debits with remittance information and an invented
    counterparty with a valid IBAN; Stmt/Id and MsgId unique (date and
    random part). seed makes the output reproducible. copy_duplicate:
    optional Stmt/CpyDplctInd (COPY, DUPL or CODU; E08.1 F12).

    Source: working paper E12 ch. 4.6; specification account_ebics ch. 7.2
    (ISO 20022 version 2019, camt.053.001.08)."""
    if not iban_valid(iban):
        raise ValueError("Invalid IBAN")
    iban = re.sub(r'\s', '', iban).upper()
    if not re.fullmatch(r'[A-Z]{3}', currency or ''):
        raise ValueError("Invalid currency")
    if entries < 0:
        raise ValueError("The number of entries must not be negative")
    date = date or datetime.date.today()
    rnd = random.Random(seed) if seed is not None else random.SystemRandom()
    unique = '%08X' % rnd.getrandbits(32)
    stamp = date.strftime('%Y%m%d')
    msg_id = 'TEST-MSG-%s-%s' % (stamp, unique)
    statement_id = 'TEST-STMT-%s-%s' % (stamp, unique)
    created = datetime.datetime.combine(date, datetime.time(20, 0))
    items = make_entries(entries, rnd)
    start_balance = Decimal(start_balance)
    net = sum((e['amount'] if e['sign'] == 'CRDT' else -e['amount'])
        for e in items)
    end_balance = start_balance + net

    document = etree.Element('{%s}Document' % NAMESPACE,
        nsmap={None: NAMESPACE})
    document.addprevious(etree.Comment(
            ' Invented test data: no real account, bank or booking '))
    root = _sub(document, 'BkToCstmrStmt')
    header = _sub(root, 'GrpHdr')
    _sub(header, 'MsgId', msg_id)
    _sub(header, 'CreDtTm', created.isoformat())
    statement = _sub(root, 'Stmt')
    _sub(statement, 'Id', statement_id)
    _sub(statement, 'ElctrncSeqNb', sequence)
    _sub(statement, 'CreDtTm', created.isoformat())
    period = _sub(statement, 'FrToDt')
    _sub(period, 'FrDtTm', datetime.datetime.combine(
            date, datetime.time(0, 0)).isoformat())
    _sub(period, 'ToDtTm', datetime.datetime.combine(
            date, datetime.time(23, 59, 59)).isoformat())
    if copy_duplicate:
        # schema order: after FrToDt, before Acct (camt.053.001.08)
        if copy_duplicate not in {'COPY', 'DUPL', 'CODU'}:
            raise ValueError("Invalid CpyDplctInd")
        _sub(statement, 'CpyDplctInd', copy_duplicate)
    account = _sub(statement, 'Acct')
    _sub(_sub(account, 'Id'), 'IBAN', iban)
    _sub(account, 'Ccy', currency)
    _sub(_sub(_sub(account, 'Svcr'), 'FinInstnId'), 'Nm', BANK_NAME)
    _balance(statement, 'PRCD', start_balance, currency,
        date - datetime.timedelta(days=1))
    _balance(statement, 'CLBD', end_balance, currency, date)

    summary = _sub(statement, 'TxsSummry')
    total = _sub(summary, 'TtlNtries')
    _sub(total, 'NbOfNtries', len(items))
    _sub(total, 'Sum', _amount(sum(e['amount'] for e in items)))
    net_entry = _sub(total, 'TtlNetNtry')
    _sub(net_entry, 'Amt', _amount(abs(net)))
    _sub(net_entry, 'CdtDbtInd', 'CRDT' if net >= 0 else 'DBIT')
    for sign, name in [('CRDT', 'TtlCdtNtries'), ('DBIT', 'TtlDbtNtries')]:
        selected = [e for e in items if e['sign'] == sign]
        node = _sub(summary, name)
        _sub(node, 'NbOfNtries', len(selected))
        _sub(node, 'Sum', _amount(sum(e['amount'] for e in selected)))

    for item in items:
        entry = _sub(statement, 'Ntry')
        _sub(entry, 'NtryRef', '%s-%03d' % (unique, item['number']))
        _sub(entry, 'Amt', _amount(item['amount']), Ccy=currency)
        _sub(entry, 'CdtDbtInd', item['sign'])
        _sub(_sub(entry, 'Sts'), 'Cd', 'BOOK')
        _sub(_sub(entry, 'BookgDt'), 'Dt', date.isoformat())
        _sub(_sub(entry, 'ValDt'), 'Dt', date.isoformat())
        family, sub_family, proprietary = _BANK_TRANSACTION_CODES[
            item['sign']]
        code = _sub(entry, 'BkTxCd')
        domain = _sub(code, 'Domn')
        _sub(domain, 'Cd', 'PMNT')
        family_node = _sub(domain, 'Fmly')
        _sub(family_node, 'Cd', family)
        _sub(family_node, 'SubFmlyCd', sub_family)
        prtry = _sub(code, 'Prtry')
        _sub(prtry, 'Cd', proprietary)
        _sub(prtry, 'Issr', 'DK')
        details = _sub(_sub(entry, 'NtryDtls'), 'TxDtls')
        _sub(_sub(details, 'Refs'), 'EndToEndId', item['reference'])
        parties = _sub(details, 'RltdPties')
        if item['sign'] == 'CRDT':
            # credit: the counterparty is the debtor
            _sub(_sub(_sub(parties, 'Dbtr'), 'Pty'), 'Nm', item['name'])
            _sub(_sub(_sub(parties, 'DbtrAcct'), 'Id'), 'IBAN', item['iban'])
        else:
            _sub(_sub(_sub(parties, 'Cdtr'), 'Pty'), 'Nm', item['name'])
            _sub(_sub(_sub(parties, 'CdtrAcct'), 'Id'), 'IBAN', item['iban'])
        _sub(_sub(details, 'RmtInf'), 'Ustrd', item['purpose'])

    data = etree.tostring(
        document.getroottree(), xml_declaration=True, encoding='UTF-8',
        pretty_print=True)
    name = 'camt053_%s_%s_%s.xml' % (iban, stamp, unique)
    return name, data


def check_camt053(data, xsd_path=None):
    """Check a generated statement: well-formed (central parser of the
    module), namespace camt.053.001.08, balances consistent with the
    entries, valid IBANs; with xsd_path also against the local ISO 20022
    schema. Return the list of deviations (empty if valid).

    Source: working paper E12 ch. 4.6."""
    root = ebics_xml.parse(data)
    errors = []
    if root.tag != '{%s}Document' % NAMESPACE:
        return ['not a camt.053.001.08 document']
    ns = {'c': NAMESPACE}

    def signed(node):
        amount = Decimal(node.findtext('c:Amt', namespaces=ns))
        return -amount if node.findtext(
            'c:CdtDbtInd', namespaces=ns) == 'DBIT' else amount
    for statement in root.iterfind('c:BkToCstmrStmt/c:Stmt', ns):
        balances = {}
        for balance in statement.iterfind('c:Bal', ns):
            balances[balance.findtext(
                    'c:Tp/c:CdOrPrtry/c:Cd', namespaces=ns)] = signed(balance)
        entries = statement.findall('c:Ntry', ns)
        net = sum((signed(e) for e in entries), Decimal(0))
        if 'PRCD' not in balances or 'CLBD' not in balances:
            errors.append('balances PRCD/CLBD missing')
        elif balances['PRCD'] + net != balances['CLBD']:
            errors.append('balances not consistent with the entries')
        summary = statement.find('c:TxsSummry/c:TtlNtries', ns)
        if summary is not None:
            if int(summary.findtext('c:NbOfNtries', namespaces=ns)) != len(
                    entries):
                errors.append('number of entries differs')
            if signed(summary.find('c:TtlNetNtry', ns)) != net:
                errors.append('net sum differs')
        ibans = [n.text for n in statement.iterfind('.//c:IBAN', ns)]
        errors.extend('invalid IBAN %s' % i for i in ibans
            if not iban_valid(i))
    if xsd_path:
        parser = etree.XMLParser(
            resolve_entities=False, no_network=True, load_dtd=False)
        schema = etree.XMLSchema(etree.parse(xsd_path, parser))
        if not schema.validate(root.getroottree()):
            errors.extend('line %s: %s' % (e.line, e.message)
                for e in list(schema.error_log)[:20])
    return errors

# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""EBICS return codes.

Source: EBICS specification V 3.0.2, annex 1 "Return Codes" (DE, final
version 27.06.2022): ch. 2 technical return codes
(ebicsResponse/header/mutable/ReturnCode, with short text), ch. 3 business
return codes (ebicsResponse/body/ReturnCode, without short text; the text is
the meaning of the annex). Both tables use the same value range but not the
same meanings (e.g. 091002), so a code is looked up per kind.

No Tryton imports (specification account_ebics ch. 4.1).
"""
import re
from collections import namedtuple

TECHNICAL = 'technical'
BUSINESS = 'business'

#: Classes of the working paper E03 ch. 4.5
OK = 'ok'
INFO = 'info'
NO_DATA = 'no_data'
USER_STATE = 'user_state'
BANK_KEYS = 'bank_keys'
ERROR = 'error'
CLASSES = (OK, INFO, NO_DATA, USER_STATE, BANK_KEYS, ERROR)

ReturnCode = namedtuple(
    'ReturnCode', ['code', 'kind', 'symbol', 'text', 'klass'])

# Annex 1 ch. 2: (code, symbolic name, short text)
_TECHNICAL = [
    ('000000', 'EBICS_OK', "OK"),
    ('011000', 'EBICS_DOWNLOAD_POSTPROCESS_DONE',
        "positive Quittung erhalten"),
    ('011001', 'EBICS_DOWNLOAD_POSTPROCESS_SKIPPED',
        "negative Quittung erhalten"),
    ('011101', 'EBICS_TX_SEGMENT_NUMBER_UNDERRUN',
        "Segmentanzahl unterschritten"),
    ('031001', 'EBICS_ORDER_PARAMS_IGNORED',
        "unbekannte Auftrags-parameter werden ignoriert"),
    ('061001', 'EBICS_AUTHENTICATION_FAILED',
        "Authentifikationssignatur fehlerhaft"),
    ('061002', 'EBICS_INVALID_REQUEST', "Nachricht nicht EBICS-konform"),
    ('061099', 'EBICS_INTERNAL_ERROR', "interner EBICS-Fehler"),
    ('061101', 'EBICS_TX_RECOVERY_SYNC', "Synchronisation erforderlich"),
    ('091002', 'EBICS_INVALID_USER_OR_USER_STATE',
        "Teilnehmer unbekannt oder Teilnehmerzustand unzulässig"),
    ('091003', 'EBICS_USER_UNKNOWN', "Teilnehmer unbekannt"),
    ('091004', 'EBICS_INVALID_USER_STATE', "Teilnehmerzustand unzulässig"),
    ('091005', 'EBICS_INVALID_ORDER_IDENTIFIER',
        "Auftragsart bzw. BTF-Parameterkombination unzulässig"),
    ('091006', 'EBICS_UNSUPPORTED_ORDER_IDENTIFIER',
        "Auftragsart bzw. BTF-Parameterkombination nicht unterstützt"),
    ('091007', 'EBICS_DISTRIBUTED_SIGNATURE_AUTHORISATION_FAILED',
        "Teilnehmer hat keine Unterschriftsberechtigung für den "
        "referenzierten Auftrag in der VEU-Verwaltung (Aktuelle "
        "Unterschriftsmappe anfordern)"),
    ('091008', 'EBICS_BANK_PUBKEY_UPDATE_REQUIRED', "Bankschlüssel ungültig"),
    ('091009', 'EBICS_SEGMENT_SIZE_EXCEEDED', "Segmentgröße überschritten"),
    ('091010', 'EBICS_INVALID_XML',
        "XML nicht valide gemäß EBICS XML Schema"),
    ('091011', 'EBICS_INVALID_HOST_ID',
        "Die übertragene HostID ist bankseitig unbekannt"),
    ('091101', 'EBICS_TX_UNKNOWN_TXID', "Transaktions-ID ungültig"),
    ('091102', 'EBICS_TX_ABORT', "Transaktion abgebrochen"),
    ('091103', 'EBICS_TX_MESSAGE_REPLAY',
        "Verdacht auf Nachrichten-Replay (falsche Uhrzeit/Zeitzone oder "
        "Nonce-Fehler"),
    ('091104', 'EBICS_TX_SEGMENT_NUMBER_EXCEEDED',
        "Segmentanzahl überschritten"),
    ('091112', 'EBICS_INVALID_ORDER_PARAMS', "ungültige Auftragsparameter"),
    ('091113', 'EBICS_INVALID_REQUEST_CONTENT',
        "Nachrichteninhalt semantisch nicht EBICS-konform"),
    ('091117', 'EBICS_MAX_ORDER_DATA_SIZE_EXCEEDED',
        "Das Banksystem unterstützt die angeforderte Auftragsgröße nicht"),
    ('091118', 'EBICS_MAX_SEGMENTS_EXCEEDED',
        "Die übergebene Anzahl der Segmente für den Upload ist zu groß"),
    ('091119', 'EBICS_MAX_TRANSACTIONS_EXCEEDED',
        "Maximale Anzahl paralleler Transaktionen pro Kunde überschritten"),
    ('091120', 'EBICS_PARTNER_ID_MISMATCH',
        "Die PartnerID (=KundenID) der EU-Datei stimmt nicht mit der "
        "PartnerID (=KundenID) des Einreichers überein"),
    ('091122', 'EBICS_ORDER_ALREADY_EXISTS',
        "Der EBICS-Auftrag existiert bereits"),
    ]

# Annex 1 ch. 3: (code, symbolic name, meaning)
_BUSINESS = [
    ('000000', 'EBICS_OK',
        "Bei der Verarbeitung des EBICS-Requests sind keine fachlichen "
        "Fehler aufgetreten"),
    ('011301', 'EBICS_NO_ONLINE_CHECKS',
        "Die optionale Vorabprüfung wird vom Banksystem nicht unterstützt"),
    ('091001', 'EBICS_DOWNLOAD_SIGNED_ONLY',
        "Das Banksystem unterstützt für den vorliegenden Auftrag nur "
        "bankfachlich signierte Download-Auftragsdaten (für eine "
        "zukünftige Verwendung reserviert)"),
    ('091002', 'EBICS_DOWNLOAD_UNSIGNED_ONLY',
        "Das Banksystem unterstützt für den vorliegenden Auftrag nur "
        "unsignierte Download-Auftragsdaten (für eine zukünftige "
        "Verwendung reserviert)"),
    ('090003', 'EBICS_AUTHORISATION_ORDER_IDENTIFIER_FAILED',
        "Der Teilnehmer ist nicht zur Einreichung des Auftrags mit der "
        "gewählten administrativen Auftragsart bzw. der Kombination von "
        "BTF-Parameterwerten befugt"),
    ('090004', 'EBICS_INVALID_ORDER_DATA_FORMAT',
        "Die übergebenen Auftragsdaten entsprechen nicht dem festgelegten "
        "Format"),
    ('090005', 'EBICS_NO_DOWNLOAD_DATA_AVAILABLE',
        "Für die gewählte Download-Auftragsart sind derzeit keine Daten "
        "verfügbar"),
    ('090006', 'EBICS_UNSUPPORTED_REQUEST_FOR_ORDER_INSTANCE',
        "Das Banksystem unterstützt für den konkreten Geschäftsvorfall des "
        "Auftrags die gewählte Auftragsanfrage nicht"),
    ('091105', 'EBICS_RECOVERY_NOT_SUPPORTED',
        "Das Banksystem unterstützt Recovery nicht"),
    ('091111', 'EBICS_INVALID_SIGNATURE_FILE_FORMAT',
        "Die übergebenen EU-Dateien entsprechen nicht dem festgelegten "
        "Format"),
    ('091114', 'EBICS_ORDERID_UNKNOWN',
        "Die übergebene Auftragsnummer ist unbekannt"),
    ('091115', 'EBICS_ORDERID_ALREADY_FINAL',
        "Die Auftragsnummer, die per HVE oder HVS übertragen wurde, kann "
        "nicht zugeordnet werden."),
    ('091116', 'EBICS_PROCESSING_ERROR',
        "Bei der Verarbeitung des EBICS-Requests sind sonstige fachliche "
        "Fehler aufgetreten"),
    ('091201', 'EBICS_KEYMGMT_UNSUPPORTED_VERSION_SIGNATURE',
        "Die Algorithmenversion des bankfachlichen Signaturschlüssels wird "
        "vom Kreditinstitut nicht unterstützt (Auftragsarten INI, HCS und "
        "PUB)"),
    ('091202', 'EBICS_KEYMGMT_UNSUPPORTED_VERSION_AUTHENTICATION',
        "Die Algorithmenversion des Authentifikationsschlüssels wird vom "
        "Kreditinstitut nicht unterstützt (Auftragsarten HIA, HSA, HCS und "
        "HCA)."),
    ('091203', 'EBICS_KEYMGMT_UNSUPPORTED_VERSION_ENCRYPTION',
        "Die Algorithmenversion des Verschlüsselungsschlüssels wird vom "
        "Kreditinstitut nicht unterstützt (Auftragsarten HIA, HSA, HCS und "
        "HCA)."),
    ('091204', 'EBICS_KEYMGMT_KEYLENGTH_ERROR_SIGNATURE',
        "Die Schlüssellänge des bankfachlichen Signaturschlüssels wird vom "
        "Kreditinstitut nicht unterstützt (Auftragsarten INI und PUB bzw. "
        "HCS)."),
    ('091205', 'EBICS_KEYMGMT_KEYLENGTH_ERROR_AUTHENTICATION',
        "Die Schlüssellänge des Authentifikationsschlüssels wird vom "
        "Kreditinstitut nicht unterstützt (Auftragsarten HIA, HSA, HCS und "
        "HCA)."),
    ('091206', 'EBICS_KEYMGMT_KEYLENGTH_ERROR_ENCRYPTION',
        "Die Schlüssellänge des Verschlüsselungsschlüssels wird vom "
        "Kreditinstitut nicht unterstützt (Auftragsarten HIA, HSA, HCS und "
        "HCA)."),
    ('091208', 'EBICS_X509_CERTIFICATE_EXPIRED',
        "Das Zertifikat ist abgelaufen und daher ungültig."),
    ('091209', 'EBICS_X509_CERTIFICATE_NOT_VALID_YET',
        "Das Zertifikat ist noch nicht gültig, da das Gültig-ab-Datum noch "
        "nicht erreicht ist."),
    ('091210', 'EBICS_X509_WRONG_KEY_USAGE',
        "Bei der Zertifikatsprüfung wurde festgestellt, dass das Zertifikat "
        "nicht für den aktuellen Einsatzzweck ausgegeben wurde (ist nur bei "
        "Auftragsarten des Schlüsselmanagements möglich)."),
    ('091211', 'EBICS_X509_WRONG_ALGORITHM',
        "Bei der Prüfung des Zertifikatsalgorithmus (Signaturalgorithmus) "
        "wurde festgestellt, dass das Zertifikat nicht für den aktuellen "
        "Einsatzzweck ausgegeben wurde (ist nur bei Auftragsarten des "
        "Schlüsselmanagements möglich)."),
    ('091212', 'EBICS_X509_INVALID_THUMBPRINT',
        "Reserviert für die nächste Version"),
    ('091213', 'EBICS_X509_CTL_INVALID',
        "Bei der Zertifikatsprüfung wurde festgestellt, dass die Certificate "
        "Trust List (CTL) nicht gültig ist, da sie beispielsweise abgelaufen "
        "ist."),
    ('091214', 'EBICS_X509_UNKNOWN_CERTIFICATE_AUTHORITY',
        "Die Zertifikatskette kann wegen einer unbekannten "
        "Zertifizierungsinstanz (Certificate Authority (CA)) nicht "
        "verifiziert werden."),
    ('091215', 'EBICS_X509_INVALID_POLICY',
        "Reserviert für die nächste Version"),
    ('091216', 'EBICS_X509_INVALID_BASIC_CONSTRAINTS',
        "Reserviert für die nächste Version"),
    ('091217', 'EBICS_ONLY_X509_SUPPORT',
        "Im Falle von Zertifikaten unterstützt das Banksystem ausschließlich "
        "die Auswertung von X.509-Daten."),
    ('091218', 'EBICS_KEYMGMT_DUPLICATE_KEY',
        "Während eines Requests des Schlüsselmanagements wurde festgestellt, "
        "dass der Schlüssel oder das Zertifikat (die Authentifikation oder "
        "die Verschlüsselung betreffend) gleich dem Schlüssel/Zertifikat für "
        "die EU ist (INI, HIA, PUB, HCS,..)"),
    ('091219', 'EBICS_CERTIFICATE_VALIDATION_ERROR',
        "Der Bankrechner ist nicht in der Lage, das Zertifikat (EU "
        "Schlüssel) den vorher mitgeteilten Informationen automatisch "
        "zuzuordnen"),
    ('091301', 'EBICS_SIGNATURE_VERIFICATION_FAILED',
        "Die Verifikation einer EU ist fehlgeschlagen. Bei asynchron "
        "durchgeführten Aufträgen kann der Fehler während der Vorabprüfung "
        "auftreten."),
    ('091302', 'EBICS_ACCOUNT_AUTHORISATION_FAILED',
        "Die Vorabprüfung der Kontoberechtigung ist fehlgeschlagen"),
    ('091303', 'EBICS_AMOUNT_CHECK_FAILED',
        "Die Vorabprüfung des Kontobetragslimits ist fehlgeschlagen"),
    ('091304', 'EBICS_SIGNER_UNKNOWN',
        "Ein Unterzeichner des vorliegenden Auftrags ist kein gültiger "
        "Teilnehmer."),
    ('091305', 'EBICS_INVALID_SIGNER_STATE',
        "Der Zustand eines Unterzeichners des vorliegenden Auftrags ist "
        "nicht zulässig."),
    ('091306', 'EBICS_DUPLICATE_SIGNATURE',
        "Der Unterzeichner hat den vorliegenden Auftrag bereits "
        "unterschrieben."),
    ]

# Classes of single codes (working paper E03 ch. 4.5); otherwise by error
# class kk of annex 1 ch. 1: 00 ok, 01 note and 03 warning -> info,
# 06 and 09 -> error
_SPECIAL = {
    (TECHNICAL, '091002'): USER_STATE,
    (TECHNICAL, '091004'): USER_STATE,
    (TECHNICAL, '091008'): BANK_KEYS,
    (BUSINESS, '090005'): NO_DATA,
    }
_CODE = re.compile(r'^\d{6}$')


def _klass(kind, code):
    if (kind, code) in _SPECIAL:
        return _SPECIAL[kind, code]
    if code == '000000':
        return OK
    if code[:2] in {'00', '01', '03'}:
        return INFO
    return ERROR


def _table(kind, rows):
    return {code: ReturnCode(code, kind, symbol, text, _klass(kind, code))
        for code, symbol, text in rows}


TECHNICAL_CODES = _table(TECHNICAL, _TECHNICAL)
BUSINESS_CODES = _table(BUSINESS, _BUSINESS)


def lookup(code, kind=TECHNICAL):
    """Return the ReturnCode (code, kind, symbol, text, class) of a technical
    (header/mutable/ReturnCode) or business (body/ReturnCode) return code.

    Unknown or malformed codes return the class error with the code in the
    text.
    Source: EBICS specification V 3.0.2, annex 1 ch. 1-3; working paper E03
    ch. 4.5."""
    if kind not in {TECHNICAL, BUSINESS}:
        raise ValueError("Unknown kind %r" % kind)
    table = TECHNICAL_CODES if kind == TECHNICAL else BUSINESS_CODES
    code = (code or '').strip() if isinstance(code, str) else code
    if code in table:
        return table[code]
    if isinstance(code, str) and _CODE.match(code):
        text = "Unbekannter Rückgabecode %s" % code
    else:
        code = str(code)[:20]
        text = "Ungültiger Rückgabecode %s" % code
    return ReturnCode(code, kind, None, text, ERROR)


def report_text(return_code):
    """Return the report text "[<symbolic name>] <short text>" as the bank
    puts it into header/mutable/ReportText.

    Source: EBICS specification V 3.0.2, annex 1 ch. 1."""
    if return_code.symbol:
        return '[%s] %s' % (return_code.symbol, return_code.text)
    return return_code.text

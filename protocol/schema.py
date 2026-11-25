# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""Validation of EBICS messages against the XML schemas H005.

The schemas are not part of the package (open point O12); they are loaded
only locally from a directory, never from the network, once per process.
No Tryton imports (specification account_ebics ch. 4.1).
"""
import os
import threading
from urllib.parse import unquote, urlparse

from lxml import etree

from .exceptions import EbicsProtocolError

#: Kind of document -> schema file (working paper E03 ch. 4.9)
SCHEMA_FILES = {
    'request': 'ebics_request_H005.xsd',
    'response': 'ebics_response_H005.xsd',
    'keymgmt_request': 'ebics_keymgmt_request_H005.xsd',
    'keymgmt_response': 'ebics_keymgmt_response_H005.xsd',
    'hev': 'ebics_hev.xsd',
    'orders': 'ebics_orders_H005.xsd',
    'signature': 'ebics_signature_S002.xsd',
    }
MODE_OFF = 'off'
MODE_WARN = 'warn'
MODE_STRICT = 'strict'
MODES = (MODE_OFF, MODE_WARN, MODE_STRICT)
_MAX_SCHEMA_SIZE = 2 * 1024 * 1024
_MAX_ERRORS = 20

_cache = {}
_lock = threading.Lock()


class _LocalResolver(etree.Resolver):
    "Resolve imports and includes only to files of the schema directory"

    def __init__(self, directory):
        super().__init__()
        self.directory = os.path.realpath(directory)

    def resolve(self, url, public_id, context):
        parsed = urlparse(url)
        if parsed.scheme not in {'', 'file'}:
            raise EbicsProtocolError(
                "Schema import from %s is not allowed" % parsed.scheme)
        path = unquote(parsed.path) if parsed.scheme else url
        path = os.path.realpath(
            path if os.path.isabs(path)
            else os.path.join(self.directory, path))
        if (os.path.dirname(path) != self.directory
                or not os.path.isfile(path)):
            raise EbicsProtocolError(
                "Schema file %s is not in the schema directory"
                % os.path.basename(path))
        return self.resolve_filename(path, context)


def _schema_parser(directory):
    # Same settings as the central parser (protocol.xml.parse): no entity
    # resolution, no network, no DTD loading; the DOCTYPE of the W3C file
    # xmldsig-core-schema.xsd is tolerated but neither loaded nor applied
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, huge_tree=False,
        load_dtd=False, dtd_validation=False, attribute_defaults=False)
    parser.resolvers.add(_LocalResolver(directory))
    return parser


def _load(directory, filename):
    path = os.path.join(directory, filename)
    if not os.path.isfile(path):
        raise EbicsProtocolError("Schema file %s is missing" % filename)
    if os.path.getsize(path) > _MAX_SCHEMA_SIZE:
        raise EbicsProtocolError("Schema file %s is too big" % filename)
    try:
        document = etree.parse(path, _schema_parser(directory))
        return etree.XMLSchema(document)
    except EbicsProtocolError:
        raise
    except (etree.XMLSyntaxError, etree.XMLSchemaParseError) as exception:
        raise EbicsProtocolError(
            "Schema %s cannot be loaded (%s)"
            % (filename, str(exception)[:200])) from None


def load_schemas(directory):
    """Return {kind: XMLSchema} for the schema files of the directory.

    Loaded only from local files with the settings of the secure parser,
    imports and includes only from the same directory, never from the
    network; cached once per process and directory.
    Source: working paper E03 ch. 4.9 (decision F5); schemas
    EBICS_3.0_schema_H005 (ebics_*_H005.xsd, ebics_hev.xsd,
    ebics_signature_S002.xsd)."""
    if not directory or not os.path.isdir(directory):
        raise EbicsProtocolError("The schema directory does not exist")
    key = os.path.realpath(directory)
    with _lock:
        if key not in _cache:
            _cache[key] = {
                kind: _load(key, filename)
                for kind, filename in SCHEMA_FILES.items()}
        return _cache[key]


def validate(document, kind, directory):
    """Validate the document (root element or bytes parsed by the caller)
    against the schema of the kind and return the list of deviations
    ("line N: message", at most 20; empty if valid).

    Source: working paper E03 ch. 4.9 (decision F5)."""
    schemas = load_schemas(directory)
    if kind not in schemas:
        raise ValueError("Unknown kind of document %r" % kind)
    schema = schemas[kind]
    tree = document.getroottree() if hasattr(document, 'getroottree') \
        else document
    if schema.validate(tree):
        return []
    return ['line %s: %s' % (error.line, error.message)
        for error in list(schema.error_log)[:_MAX_ERRORS]]


def default_mode(directory):
    """Return the default mode: warn if a schema directory is configured,
    otherwise off.

    Source: working paper E03 ch. 4.8 (xsd_mode)."""
    return MODE_WARN if directory else MODE_OFF


def check(document, kind, directory, mode=None):
    """Validate according to the mode and return the warnings.

    off: no validation; warn: deviations are returned (the processing
    continues); strict: deviations raise EbicsProtocolError (for BTD the
    caller does not send a receipt).
    Source: working paper E03 ch. 4.8, ch. 4.9 (decision F5)."""
    if mode is None:
        mode = default_mode(directory)
    if mode not in MODES:
        raise ValueError("Unknown schema mode %r" % mode)
    if mode == MODE_OFF:
        return []
    deviations = validate(document, kind, directory)
    if deviations and mode == MODE_STRICT:
        raise EbicsProtocolError(
            "The %s does not match the schema: %s"
            % (kind, '; '.join(deviations[:3])))
    return ['Schema %s: %s' % (kind, d) for d in deviations]

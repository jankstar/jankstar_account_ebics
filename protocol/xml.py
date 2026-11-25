# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""XML of the EBICS messages: secure parser, namespaces, building and
defensive reading, canonicalisation and the authentication signature X002.

No Tryton imports (specification account_ebics ch. 4.1).
"""
import base64
import binascii
import hashlib
import hmac
import re

from lxml import etree

from .crypto import sign_x002, verify_x002
from .exceptions import (
    EbicsAuthenticationError, EbicsCryptoError, EbicsProtocolError)

#: Namespaces (schemas H005 targetNamespace)
NS_H005 = 'urn:org:ebics:H005'
NS_S002 = 'http://www.ebics.org/S002'
NS_HEV = 'http://www.ebics.org/H000'
NS_DS = 'http://www.w3.org/2000/09/xmldsig#'
NS_XSI = 'http://www.w3.org/2001/XMLSchema-instance'
NSMAP = {
    'ebics': NS_H005,
    'esig': NS_S002,
    'hev': NS_HEV,
    'ds': NS_DS,
    }
VERSION = 'H005'
REVISION = '1'

#: Algorithms of the authentication signature X002, exactly as in the
#: example of EBICS specification V 3.0.2 (DE) ch. 4.4.2 (HPB request)
#: and ch. 11.1
C14N_ALGORITHM = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
SIGNATURE_ALGORITHM = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
DIGEST_ALGORITHM = 'http://www.w3.org/2001/04/xmlenc#sha256'
REFERENCE_URI = "#xpointer(//*[@authenticate='true'])"
AUTHENTICATE_XPATH = "//*[@authenticate='true']"

#: Default size limit of a message in bytes
DEFAULT_MAX_SIZE = 10 * 1024 * 1024


def _parser():
    # specification account_ebics ch. 8.4, working paper E03 ch. 4.2
    return etree.XMLParser(
        resolve_entities=False, no_network=True, huge_tree=False,
        remove_blank_text=False, load_dtd=False, dtd_validation=False,
        attribute_defaults=False)


def parse(data, max_size=DEFAULT_MAX_SIZE):
    """Parse XML received from the bank and return the root element.

    The only parser for data of the bank: no entity resolution, no network,
    no huge trees, no DTD (a DOCTYPE is rejected), size limited to max_size
    bytes. Errors raise EbicsProtocolError without the content of the data.
    Source: specification account_ebics ch. 8.4; working paper E03 ch. 4.2.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = bytes(data)
    if max_size is not None and len(data) > max_size:
        raise EbicsProtocolError(
            "The XML document exceeds %s bytes" % max_size)
    try:
        root = etree.fromstring(data, _parser())
    except etree.XMLSyntaxError as exception:
        position = exception.position or (0, 0)
        raise EbicsProtocolError(
            "The XML document is not well-formed (line %s, column %s)"
            % position) from None
    if root.getroottree().docinfo.doctype:
        raise EbicsProtocolError("A DOCTYPE is not allowed")
    return root


def qname(name, namespace=NS_H005):
    """Return the Clark notation {namespace}name.

    Source: schemas H005 (targetNamespace urn:org:ebics:H005)."""
    return '{%s}%s' % (namespace, name)


def element(name, text=None, namespace=NS_H005, nsmap=None, **attributes):
    """Return a new element of the EBICS namespace (or of namespace) with
    optional text and attributes (values converted to str).

    Source: schemas H005 (elementFormDefault qualified)."""
    node = etree.Element(qname(name, namespace), nsmap=nsmap)
    for key, value in attributes.items():
        node.set(key, str(value))
    if text is not None:
        node.text = str(text)
    return node


def sub_element(parent, name, text=None, namespace=NS_H005, **attributes):
    """Append a new element to parent and return it (see element).

    Source: schemas H005 (elementFormDefault qualified)."""
    # created in the tree, so that the prefixes of the ancestors are used
    node = etree.SubElement(parent, qname(name, namespace))
    for key, value in attributes.items():
        node.set(key, str(value))
    if text is not None:
        node.text = str(text)
    return node


def root_element(name, namespace=NS_H005, version=True):
    """Return the root element of an EBICS message with the namespaces H005
    (default) and ds and the attributes Version="H005" and Revision="1".

    Source: EBICS specification V 3.0.2 (DE) ch. 4.4.2 (example);
    ebics_request_H005.xsd, ebics_keymgmt_request_H005.xsd (attributes
    Version, Revision)."""
    node = etree.Element(
        qname(name, namespace), nsmap={None: namespace, 'ds': NS_DS})
    if version:
        node.set('Version', VERSION)
        node.set('Revision', REVISION)
    return node


def to_bytes(root):
    """Return the message as UTF-8 bytes with XML declaration.

    Source: EBICS specification V 3.0.2 (DE) ch. 4.4.2 (example)."""
    return etree.tostring(
        root.getroottree() if hasattr(root, 'getroottree') else root,
        xml_declaration=True, encoding='UTF-8')


def c14n(node):
    """Return the canonical form of the element and its descendants:
    Canonical XML 1.0, inclusive, without comments (namespaces in scope are
    taken over to the element).

    Source: EBICS specification V 3.0.2 (DE) ch. 11.1
    (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)."""
    return etree.tostring(
        node, method='c14n', exclusive=False, with_comments=False)


# Defensive reading (working paper E03 ch. 4.9)

def _path_of(node):
    names = []
    while node is not None:
        names.append(etree.QName(node).localname)
        node = node.getparent()
    return '/'.join(reversed(names))


def _describe(node, path):
    return '%s/%s' % (_path_of(node), re.sub(r'\w+:', '', path))


def find(node, path, required=True):
    """Return the first element at the path (XPath with the prefixes of
    NSMAP, e.g. 'ebics:header/ebics:mutable/ebics:ReturnCode') or None;
    a missing required element raises EbicsProtocolError with the element
    path.

    Source: working paper E03 ch. 4.9 (defensive reading)."""
    result = node.xpath(path, namespaces=NSMAP)
    if result and isinstance(result[0], etree._Element):
        return result[0]
    if required:
        raise EbicsProtocolError(
            "Missing element %s" % _describe(node, path))
    return None


def find_all(node, path):
    """Return all elements at the path (see find).

    Source: working paper E03 ch. 4.9 (defensive reading)."""
    return [n for n in node.xpath(path, namespaces=NSMAP)
        if isinstance(n, etree._Element)]


def get_text(node, path, required=True, pattern=None, max_length=None):
    """Return the stripped text of the element at the path.

    A missing or empty required element, a text longer than max_length or
    not matching the regular expression pattern raises EbicsProtocolError
    with the element path (the value is not part of the message).
    Source: working paper E03 ch. 4.9 (defensive reading)."""
    found = find(node, path, required=required)
    text = (found.text or '').strip() if found is not None else ''
    if not text:
        if required:
            raise EbicsProtocolError(
                "Empty element %s" % _describe(node, path))
        return None
    if max_length is not None and len(text) > max_length:
        raise EbicsProtocolError(
            "Element %s is too long" % _describe(node, path))
    if pattern is not None and not re.fullmatch(pattern, text):
        raise EbicsProtocolError(
            "Invalid content of element %s" % _describe(node, path))
    return text


def get_attribute(node, path, name, required=True, pattern=None):
    """Return the attribute name of the element at the path ('.' for node).

    Source: working paper E03 ch. 4.9 (defensive reading)."""
    found = node if path in {'', '.'} else find(node, path, required)
    value = found.get(name) if found is not None else None
    where = _path_of(node) if path in {'', '.'} else _describe(node, path)
    if value is None:
        if required:
            raise EbicsProtocolError(
                "Missing attribute %s of element %s" % (name, where))
        return None
    if pattern is not None and not re.fullmatch(pattern, value):
        raise EbicsProtocolError(
            "Invalid attribute %s of element %s" % (name, where))
    return value


def get_base64(node, path, required=True):
    """Return the base64 decoded content of the element at the path.

    Source: working paper E03 ch. 4.9 (defensive reading); EBICS
    specification V 3.0.2 (DE) ch. 3.2 (base64)."""
    text = get_text(node, path, required=required)
    if text is None:
        return None
    try:
        return base64.b64decode(''.join(text.split()), validate=True)
    except (binascii.Error, ValueError):
        raise EbicsProtocolError(
            "Invalid base64 content of element %s"
            % _describe(node, path)) from None


# Authentication signature X002 (EBICS specification V 3.0.2 (DE) ch. 3.8,
# ch. 11.1)

def authenticated_elements(root):
    """Return the elements marked with @authenticate="true" in document
    order; elements inside a marked element are part of it and not
    returned again.

    Source: EBICS specification V 3.0.2 (DE) ch. 3.8; ebics_orders_H005.xsd
    attributeGroup AuthenticationMarker."""
    marked = root.xpath(AUTHENTICATE_XPATH)
    result = []
    for node in marked:
        if not any(a.get('authenticate') == 'true'
                for a in node.iterancestors()):
            result.append(node)
    return result


def auth_digest(root):
    """Return the SHA-256 digest over the canonical forms (C14N 1.0
    inclusive) of all elements with @authenticate="true" in document order.

    Source: EBICS specification V 3.0.2 (DE) ch. 3.8, ch. 11.1; reference
    URI #xpointer(//*[@authenticate='true']) of the example in ch. 4.4.2."""
    nodes = authenticated_elements(root)
    if not nodes:
        raise EbicsProtocolError(
            "No element with authenticate=\"true\" in %s"
            % etree.QName(root).localname)
    digest = hashlib.sha256()
    for node in nodes:
        digest.update(c14n(node))
    return digest.digest()


def _signature_bytes(signature):
    # ch. 11.1.2: no padding to the full length of the modulus
    stripped = signature.lstrip(b'\x00')
    return stripped or b'\x00'


def _signed_info(auth, digest):
    signed_info = sub_element(auth, 'SignedInfo', namespace=NS_DS)
    sub_element(
        signed_info, 'CanonicalizationMethod', namespace=NS_DS,
        Algorithm=C14N_ALGORITHM)
    sub_element(
        signed_info, 'SignatureMethod', namespace=NS_DS,
        Algorithm=SIGNATURE_ALGORITHM)
    reference = sub_element(
        signed_info, 'Reference', namespace=NS_DS, URI=REFERENCE_URI)
    transforms = sub_element(reference, 'Transforms', namespace=NS_DS)
    sub_element(
        transforms, 'Transform', namespace=NS_DS, Algorithm=C14N_ALGORITHM)
    sub_element(
        reference, 'DigestMethod', namespace=NS_DS,
        Algorithm=DIGEST_ALGORITHM)
    sub_element(
        reference, 'DigestValue', base64.b64encode(digest).decode('ascii'),
        namespace=NS_DS)
    return signed_info


def sign_auth(root, private_key):
    """Add the authentication signature X002 to the message and return it.

    AuthSignature (namespace H005) directly after header with ds:SignedInfo
    (C14N, rsa-sha256, Reference to the elements with authenticate="true",
    Transform C14N, DigestMethod sha256, DigestValue) and ds:SignatureValue;
    SignedInfo is canonicalised in its place in the document and signed
    with sign_x002; the signature value is not padded to the length of the
    modulus; KeyInfo and Object stay empty (omitted). An existing
    AuthSignature is replaced.
    Source: EBICS specification V 3.0.2 (DE) ch. 3.8, ch. 11.1, example in
    ch. 4.4.2."""
    digest = auth_digest(root)
    old = find(root, 'ebics:AuthSignature', required=False)
    if old is not None:
        root.remove(old)
    header = find(root, 'ebics:header')
    auth = sub_element(root, 'AuthSignature')
    header.addnext(auth)
    signed_info = _signed_info(auth, digest)
    signature = sign_x002(private_key, c14n(signed_info))
    sub_element(
        auth, 'SignatureValue',
        base64.b64encode(_signature_bytes(signature)).decode('ascii'),
        namespace=NS_DS)
    return root


def _check_algorithm(signed_info, path, attribute, expected):
    value = get_attribute(signed_info, path, attribute)
    if value != expected:
        raise EbicsAuthenticationError(
            "Unexpected algorithm in %s" % _describe(signed_info, path))


def verify_auth(root, public_key):
    """Check the authentication signature X002 of a message with the public
    X002 key of the sender; raise EbicsAuthenticationError if it is missing,
    uses other algorithms or is not valid.

    Source: EBICS specification V 3.0.2 (DE) ch. 3.8 (the receiver must
    check the signature; an invalid response aborts the transaction),
    ch. 11.1."""
    try:
        signed_info = find(root, 'ebics:AuthSignature/ds:SignedInfo')
        _check_algorithm(
            signed_info, 'ds:CanonicalizationMethod', 'Algorithm',
            C14N_ALGORITHM)
        _check_algorithm(
            signed_info, 'ds:SignatureMethod', 'Algorithm',
            SIGNATURE_ALGORITHM)
        references = find_all(signed_info, 'ds:Reference')
        if len(references) != 1:
            raise EbicsAuthenticationError(
                "The authentication signature needs exactly one reference")
        _check_algorithm(signed_info, 'ds:Reference', 'URI', REFERENCE_URI)
        transforms = find_all(signed_info, 'ds:Reference/ds:Transforms/*')
        if (len(transforms) != 1
                or transforms[0].tag != qname('Transform', NS_DS)
                or transforms[0].get('Algorithm') != C14N_ALGORITHM):
            raise EbicsAuthenticationError(
                "Unexpected transforms of the authentication signature")
        _check_algorithm(
            signed_info, 'ds:Reference/ds:DigestMethod', 'Algorithm',
            DIGEST_ALGORITHM)
        expected = get_base64(signed_info, 'ds:Reference/ds:DigestValue')
        signature = get_base64(
            root, 'ebics:AuthSignature/ds:SignatureValue')
        digest = auth_digest(root)
    except EbicsProtocolError as exception:
        raise EbicsAuthenticationError(
            "Invalid authentication signature (%s)" % exception) from None
    if not hmac.compare_digest(digest, expected):
        raise EbicsAuthenticationError(
            "The digest of the authentication signature does not match")
    length = (public_key.key_size + 7) // 8
    if len(signature) > length:
        raise EbicsAuthenticationError(
            "The authentication signature is too long")
    signature = signature.rjust(length, b'\x00')
    try:
        verify_x002(public_key, c14n(signed_info), signature)
    except EbicsCryptoError:
        raise EbicsAuthenticationError(
            "The authentication signature is not valid") from None


# Identifiers (EBICS specification V 3.0.2 (DE) ch. 12.4,
# ebics_types_H005.xsd)

_ID_PATTERNS = {
    'user_id': r'[a-zA-Z0-9,=]{1,35}',
    'partner_id': r'[a-zA-Z0-9,=]{1,35}',
    'order_id': r'[A-Z][A-Z0-9]{3}',
    }


def _valid_token(value, max_length):
    # xs:token: no leading, trailing or double spaces, no tab or line feed
    return (0 < len(value) <= max_length
        and value == ' '.join(value.split())
        and not re.search(r'[\t\r\n]', value))


def validate_ids(host_id=None, partner_id=None, user_id=None,
        order_id=None):
    """Check the identifiers and return a dict {name: reason} of the
    invalid ones (empty if all given values are valid; None is not
    checked).

    UserID and PartnerID [a-zA-Z0-9,=]{1,35}, OrderID [A-Z][A-Z0-9]{3},
    HostID without pattern: token of at most 35 characters.
    Source: EBICS specification V 3.0.2 (DE) ch. 12.4; ebics_types_H005.xsd
    UserIDType, PartnerIDType, OrderIDType, HostIDType."""
    values = {
        'host_id': host_id, 'partner_id': partner_id, 'user_id': user_id,
        'order_id': order_id,
        }
    errors = {}
    for name, value in values.items():
        if value is None:
            continue
        if not isinstance(value, str):
            errors[name] = "not a text"
        elif name == 'host_id':
            if not _valid_token(value, 35):
                errors[name] = "1 to 35 characters without surrounding or " \
                    "double spaces"
        elif not re.fullmatch(_ID_PATTERNS[name], value):
            errors[name] = "does not match %s" % _ID_PATTERNS[name]
    return errors

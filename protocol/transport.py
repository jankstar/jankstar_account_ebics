# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
"""HTTPS transport of the EBICS messages.

Interface of every transport: post(request: bytes) -> response bytes; the
fake bank of the tests implements the same interface.
No Tryton imports (specification account_ebics ch. 4.1).
"""
import os
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from .exceptions import EbicsTransportError

CONTENT_TYPE = 'text/xml; charset=UTF-8'
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_RESPONSE_SIZE = 10 * 1024 * 1024
_CHUNK_SIZE = 64 * 1024


class HttpsTransport:
    """HTTPS POST to the EBICS URL of the bank.

    Only https; the TLS certificate is always verified (default CA bundle
    of requests or ca_bundle), there is no option to switch it off; the
    response is read in chunks up to max_response_size; no automatic
    retries and no redirects.
    Source: specification account_ebics ch. 8.2; working paper E03 ch. 4.6
    (decisions F6, F12)."""

    def __init__(self, url, timeout=DEFAULT_TIMEOUT, ca_bundle=None,
            max_response_size=DEFAULT_MAX_RESPONSE_SIZE, session=None):
        parsed = urlparse(url or '')
        if parsed.scheme != 'https' or not parsed.hostname:
            raise EbicsTransportError("The EBICS URL must use https://")
        if ca_bundle and not os.path.exists(ca_bundle):
            raise EbicsTransportError("The CA bundle does not exist")
        if not max_response_size or max_response_size <= 0:
            raise ValueError("max_response_size must be positive")
        self.url = url
        self.host = parsed.hostname
        self.timeout = timeout
        self.ca_bundle = ca_bundle or None
        self.max_response_size = max_response_size
        if session is None:
            session = requests.Session()
            # no automatic retries
            session.mount('https://', HTTPAdapter(max_retries=0))
        self.session = session

    @property
    def verify(self):
        """Value for requests: True (default CA bundle) or the CA bundle
        path, never False.

        Source: specification account_ebics ch. 8.2 (decision F6)."""
        return self.ca_bundle or True

    def post(self, data):
        """Send the request and return the response body as bytes.

        Errors (network, TLS, timeout, HTTP status other than 200,
        redirect, size) raise EbicsTransportError without order data.
        Source: specification account_ebics ch. 8.2; working paper E03
        ch. 4.6."""
        try:
            response = self.session.post(
                self.url, data=bytes(data),
                headers={'Content-Type': CONTENT_TYPE},
                timeout=self.timeout, verify=self.verify, stream=True,
                allow_redirects=False)
        except requests.exceptions.SSLError:
            raise EbicsTransportError(
                "TLS error with %s" % self.host) from None
        except requests.exceptions.Timeout:
            raise EbicsTransportError(
                "Timeout with %s" % self.host) from None
        except requests.exceptions.ConnectionError:
            raise EbicsTransportError(
                "Connection to %s failed" % self.host) from None
        except requests.exceptions.RequestException:
            raise EbicsTransportError(
                "Request to %s failed" % self.host) from None
        try:
            if response.status_code != 200:
                raise EbicsTransportError(
                    "HTTP status %s from %s"
                    % (response.status_code, self.host))
            length = response.headers.get('Content-Length')
            if (length and length.isdigit()
                    and int(length) > self.max_response_size):
                raise EbicsTransportError(
                    "The response exceeds %s bytes" % self.max_response_size)
            body = bytearray()
            try:
                for chunk in response.iter_content(_CHUNK_SIZE):
                    body += chunk
                    if len(body) > self.max_response_size:
                        raise EbicsTransportError(
                            "The response exceeds %s bytes"
                            % self.max_response_size)
            except requests.exceptions.RequestException:
                raise EbicsTransportError(
                    "Reading the response from %s failed"
                    % self.host) from None
            return bytes(body)
        finally:
            response.close()

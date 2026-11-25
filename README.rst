#############
Account EBICS
#############

The *Account EBICS* module connects Tryton to banks over EBICS 3.0
(protocol version H005) without third-party middleware.

The module is a transport layer only: bank statements (camt.053) are
imported by ``account_statement_sepa``, payment files are created by
``account_payment_sepa``.

Status
******

In development, not yet usable with a bank. Available so far:

* Master data: EBICS access (``account.ebics.configuration``), released
  bank accounts (``account.ebics.account``) and EBICS formats with BTF
  parameters (``account.ebics.format``), with history.
* Log: EBICS orders (``account.ebics.log``) and received files
  (``account.ebics.log.file``), locked against changes.
* Protocol layer (``protocol/``, pure Python without Tryton imports):

  * keys, certificates and encrypted key container;
  * signature processes A006 and X002, encryption E002;
  * secure XML parser, authentication signature, return codes, schema
    validation;
  * HTTPS transport with TLS verification always on;
  * client for HEV, INI, HIA, HPB and BTD download with receipt.

Not yet available: the connection of the protocol layer to Tryton
(initialisation, bank keys, statement download and import) and payment
upload (BTU).

Dependencies
************

* Tryton 8.0 modules: ``company``, ``party``, ``bank``, ``account``,
  ``account_statement``, ``account_statement_sepa``.
* Python 3.10 to 3.13 with ``cryptography``, ``lxml`` and ``requests``.

Tests
*****

The tests run without a database server (SQLite in memory) and without a
bank:

.. code-block:: bash

    TRYTOND_CONFIG=/dev/null TRYTOND_DATABASE_URI=sqlite:// DB_NAME=:memory: \
        python -m unittest discover -s tests

* ``tests/test_module.py``: models, checks, access rights and the import
  of a generated camt.053 statement.
* ``tests/test_protocol.py``: protocol layer against a simulated bank
  (``tests/fake_bank.py``), without network.
* ``tests/test_testserver.py``: local test server, started in the test
  process on 127.0.0.1 only.

If the EBICS XML schemas H005 are available (environment variable
``EBICS_XSD_DIR``), all messages are validated against them; otherwise
these tests are skipped. The schemas are not part of the package.

Local test server
*****************

``tools/ebics_testserver.py`` acts as a bank on the development computer.
It listens on ``https://127.0.0.1:8443/ebics`` with host ID ``TESTBANK``,
supports HEV, INI, HIA, HPB and BTD with receipt and provides invented
camt.053 statements. It is meant for tests by hand without a real bank
and uses test data only. See ``tools/README.md`` (German).

The directory ``tools/`` is part of the repository but not of the
installed package.

License
*******

GPL-3.0-or-later, see ``LICENSE`` and ``COPYRIGHT``.

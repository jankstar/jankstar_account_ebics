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

* Initialisation, first part: generate the keys, send INI and HIA, print
  the initialisation letters, reset to draft (EBICS administrator only).
  The passphrase of the keys and the connection values are read from
  ``trytond.conf``, see ``doc/configuration.rst``.

* Initialisation, second part: fetch the bank keys (HPB), compare the hash
  values with the information of the bank and confirm them, suspend and
  reactivate the connection.

* Download of statements (BTD): button, menu, cron (inactive by default)
  and a dialog to fetch a period again; the files are stored in the EBICS
  log and acknowledged after the commit. A result page shows the outcome
  per connection and format.
* Every download writes a run log (*Runs*) with each step as text, also
  for the cron started automatically or manually; the EBICS log shows who
  or what started an order.
* Received files that were received before (same content) are marked as
  repeated with a reference to the first one; the copy/duplicate
  indicator of the bank (``CpyDplctInd``) is shown.

The menus are under *Financial › Electronic Banking (EBICS)* (operation)
and *Financial › Configuration › Electronic Banking (EBICS)* (settings).

Not yet available: import of the statements, and payment upload (BTU).

Dependencies
************

* Tryton 8.0 modules: ``company``, ``party``, ``bank``, ``account``,
  ``account_statement``, ``account_statement_sepa``.
* Python 3.10 to 3.13 with ``cryptography``, ``lxml`` and ``requests``.
* Database: PostgreSQL in production; SQLite only for development and
  tests.

Tests
*****

The tests run without a database server (SQLite in memory) and without a
bank:

.. code-block:: bash

    TRYTOND_CONFIG=/dev/null TRYTOND_DATABASE_URI=sqlite:// DB_NAME=:memory: \
        python -m unittest discover -s tests

To run them against PostgreSQL, set ``TRYTOND_DATABASE_URI`` to the
server and ``DB_NAME`` to a test database; a few tests about locking run
only there.

* ``tests/test_module.py``: models, checks, access rights, the orders
  INI, HIA, HPB and BTD against the simulated bank, and the import of a
  generated camt.053 statement.
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
camt.053 statements. A web page (``/admin``, with an access token per
start) shows the messages and runs the commands, e.g. a change of the
bank keys (``rotate-bank-keys``). It is meant for tests by hand without a
real bank and uses test data only. See ``tools/README.md`` (German).

The directory ``tools/`` is part of the repository but not of the
installed package.

License
*******

GPL-3.0-or-later, see ``LICENSE`` and ``COPYRIGHT``.

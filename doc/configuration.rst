*************
Configuration
*************

The *Account EBICS* module reads its settings from the section
``[account_ebics]`` of the :ref:`trytond:topics-configuration` file
(``trytond.conf``).
Every value can also be given by an environment variable
``TRYTOND_ACCOUNT_EBICS__<NAME>`` (upper case), e.g.
``TRYTOND_ACCOUNT_EBICS__PASSPHRASE``.

.. code-block:: ini

   [account_ebics]
   passphrase = ...
   timeout = 60
   ca_bundle =
   max_response_size = 10485760
   xsd_dir =
   xsd_mode =

The values ``max_zip_files``, ``max_zip_size`` and ``max_segments`` for the
download of statements follow with the download.

.. _config-account_ebics.passphrase:

``passphrase``
==============

The passphrase that encrypts the private keys of all EBICS connections
(key container of a connection, PKCS#12 with AES-256).
It is never stored in the database, never logged and never shown.

There is no default value: without passphrase, the keys can neither be
generated nor used, and the server refuses the action with a message.

.. warning::

   * Keep a copy of the passphrase in a safe place.
     Without it, the keys of the connections cannot be used any more and
     the initialisation with the bank must be done again (new keys, INI,
     HIA and initialisation letters).
   * The same passphrase is used for all connections.
   * The passphrase cannot be changed yet: changing it would make the
     existing key containers unreadable.
     Changing the passphrase (re-encrypting all containers) is planned as
     a separate step.

Prefer the environment variable ``TRYTOND_ACCOUNT_EBICS__PASSPHRASE`` or a
configuration file that only the user of the Tryton server can read.

.. _config-account_ebics.timeout:

``timeout``
===========

The connect and read timeout of the HTTPS requests to the bank in seconds.

The default value is: ``60``

.. _config-account_ebics.ca_bundle:

``ca_bundle``
=============

The path of a file with the CA certificates (PEM) used to verify the TLS
certificate of the bank.
When empty, the default CA certificates of ``requests`` are used.
The TLS certificate is always verified; there is no option to switch it
off.

The default value is: empty

.. _config-account_ebics.max_response_size:

``max_response_size``
=====================

The maximal size of a response of the bank in bytes.

The default value is: ``10485760``

.. _config-account_ebics.xsd_dir:

``xsd_dir``
===========

The directory with the EBICS schemas (H005).
When empty, the responses are not validated against the schemas at run
time.

The default value is: empty

.. _config-account_ebics.xsd_mode:

``xsd_mode``
============

How schema errors of the responses are handled, when ``xsd_dir`` is set:

``off``
   No validation.

``warn``
   The errors are noted and the order continues.

``strict``
   The order stops without receipt.

The default value is: ``warn`` when ``xsd_dir`` is set, otherwise ``off``

Local test server
=================

The repository contains a local EBICS test server
(``tools/ebics_testserver.py``, not part of the installed module) for tests
without bank.
Its TLS certificate is self-signed, so Tryton must trust it with
``ca_bundle`` (absolute path, ``~`` is not expanded):

.. code-block:: ini

   [account_ebics]
   passphrase = <test passphrase>
   ca_bundle = /Users/<name>/python/ebics_testserver_state/server-cert.pem

The EBICS connection then uses the URL ``https://127.0.0.1:8443/ebics`` and
the host ID ``TESTBANK``.
Use only test data with the test server; see ``tools/README.md``.

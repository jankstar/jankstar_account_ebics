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

In development. This release contains the module skeleton only (groups and
menus); the EBICS protocol and the models follow.

Dependencies
************

Tryton 8.0 modules: ``company``, ``party``, ``bank``, ``account``,
``account_statement``, ``account_statement_sepa``.

License
*******

GPL-3.0-or-later, see ``LICENSE`` and ``COPYRIGHT``.
